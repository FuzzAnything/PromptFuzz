pub mod ast;
pub mod logger;
pub mod sanitize;

use self::logger::ProgramError;
use crate::config::{get_config, get_minimize_compile_flag};
use crate::program::libfuzzer::respawn_libfuzzer_process;
use crate::program::transform::Transformer;
use crate::{
    config::{self, get_library_name},
    deopt::utils::get_file_dirname,
    feedback::clang_coverage::CodeCoverage,
    program::shim::FuzzerShim,
    Deopt,
};
use eyre::Result;
use regex::Regex;
use std::ffi::OsString;
use std::process::ChildStderr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::channel,
    Arc,
};
use std::{
    ffi::OsStr,
    fmt::Debug,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use threadpool::ThreadPool;
use wait_timeout::ChildExt;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum Compile {
    SANITIZE,
    FUZZER,
    COVERAGE,
    Minimize,
}

#[derive(Default, Clone)]
pub struct Executor {
    pub header_cmd: String,
    /// lib could be dynamic or static library. static library ends with "_static.a"
    pub deopt: Deopt,
}

impl Executor {
    pub fn new(deopt: &Deopt) -> Result<Self> {
        let include_path = &deopt.get_library_build_header_path()?;

        let header_cmd = "-I".to_owned() + include_path.to_str().unwrap();
        check_clang()?;
        Ok(Self {
            header_cmd,
            deopt: deopt.clone(),
        })
    }

    fn get_compile_flags(&self, kind: Compile) -> (Vec<&'static str>, &'static PathBuf) {
        let (cflags, lib) = match kind {
            Compile::SANITIZE => {
                let flags = crate::config::SANITIZER_FLAGS.to_vec();
                let san_lib = crate::deopt::utils::get_san_lib_path(&self.deopt);
                (flags, san_lib)
            }
            Compile::FUZZER => {
                let flags = crate::config::FUZZER_FLAGS.to_vec();
                let fuzz_lib = crate::deopt::utils::get_fuzzer_lib_path(&self.deopt);
                (flags, fuzz_lib)
            }
            Compile::COVERAGE => {
                let flags = crate::config::COVERAGE_FLAGS.to_vec();
                let cov_lib = crate::deopt::utils::get_cov_lib_path(&self.deopt, false);
                (flags, cov_lib)
            }
            Compile::Minimize => {
                let mut flags = crate::config::FUZZER_FLAGS.to_vec();
                let min_flag = get_minimize_compile_flag();
                flags.push(min_flag);
                let fuzz_lib = crate::deopt::utils::get_fuzzer_lib_path(&self.deopt);
                (flags, fuzz_lib)
            }
        };
        (cflags, lib)
    }

    /// compile programs into binary.
    pub fn compile(&self, programs: Vec<&Path>, out: &Path, kind: Compile) -> Result<()> {
        let (cflags, lib) = self.get_compile_flags(kind);

        let mut cmd = Command::new("clang++");
        for program in &programs {
            cmd.arg(*program);
        }
        let include_fdp = "-I".to_owned() + Deopt::get_fdp_path()?.to_str().unwrap();

        let cmd = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .args(cflags.as_slice())
            .arg(&self.header_cmd)
            .arg(include_fdp)
            .arg("-g")
            .arg("-o")
            .arg(out)
            .arg(lib);
        self.deopt.add_extra_c_flags(cmd)?;

        let output = cmd
            .output()
            .expect("failed to execute the syntax check process");
        let success = output.status.success();
        if !success {
            eyre::bail!(
                "fail to compile {programs:?}\n, {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    pub fn spawn<S: AsRef<OsStr> + Debug>(
        &self,
        binary: &Path,
        extra_args: Vec<S>,
        extra_envs: Vec<(S, S)>,
        current_dir: Option<PathBuf>,
        stderr: Option<Stdio>,
        enough_timeout: bool,
    ) -> Child {
        let mut exec = Command::new(binary);
        for arg in &extra_args {
            exec.arg(arg);
        }

        for (key, val) in &extra_envs {
            exec.env(key, val);
        }

        let asan_options = self.deopt.get_asan_options();
        let rss_limit = format!(
            "-rss_limit_mb={}",
            self.deopt.config.rss_limit_mb.unwrap_or_default()
        );
        let current_dir = current_dir.unwrap_or(get_file_dirname(binary));
        let stderr = stderr.unwrap_or(Stdio::piped());
        let timeout = if enough_timeout {
            crate::config::SANITIZATION_TIMEOUT
        } else {
            crate::config::EXECUTION_TIMEOUT
        };

        let child = exec
            .current_dir(current_dir)
            .env("ASAN_OPTIONS", asan_options)
            .arg(rss_limit)
            .arg(format!("-timeout={}", timeout))
            .arg("-close_fd_mask=3")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("unable to spawn the fuzzer");
        child
    }

    pub fn execute<S: AsRef<OsStr> + Debug>(
        &self,
        binary: &Path,
        extra_args: Vec<S>,
        extra_envs: Vec<(S, S)>,
        current_dir: Option<PathBuf>,
        stderr: Option<Stdio>,
        enough_timeout: bool,
    ) -> Result<Option<ProgramError>> {
        let mut child = self.spawn(
            binary,
            extra_args,
            extra_envs,
            current_dir,
            stderr,
            enough_timeout,
        );

        let timeout = if enough_timeout {
            crate::config::SANITIZATION_TIMEOUT + 1
        } else {
            crate::config::EXECUTION_TIMEOUT + 1
        };
        let timeout = Duration::from_secs(timeout + 3);
        let status_code = match child.wait_timeout(timeout)? {
            Some(status) => status,
            None => {
                child.kill()?;
                child.wait()?;
                return Ok(Some(ProgramError::Hang(format!(
                    "Execute hang!\n Cmd: {child:#?}"
                ))));
            }
        };

        if is_exit_normally(status_code.code()) {
            return Ok(None);
        }
        let mut err_msg = String::new();
        if let Some(childerr) = child.stderr.take() {
            err_msg = get_child_err(childerr);
        }
        if err_msg.contains("libFuzzer: timeout") {
            return Ok(Some(ProgramError::Hang(err_msg)));
        }
        Ok(Some(ProgramError::Execute(err_msg)))
    }

    pub fn execute_pool(&self, binary: &Path, corpus: &Path) -> Option<ProgramError> {
        let cpu_count = max_cpu_count();
        let corpus_files = crate::deopt::utils::read_all_files_in_dir(corpus).unwrap();

        let pool = ThreadPool::new(cpu_count);
        let (tx, rx) = channel();
        let error_occurred = Arc::new(AtomicBool::new(false));

        for corpus_file in &corpus_files {
            let tx = tx.clone();
            let binary = binary.to_path_buf();
            let corpus_file = corpus_file.to_path_buf();
            let error_occurred = Arc::clone(&error_occurred);
            let executor = self.clone();

            pool.execute(move || {
                // If an error has occurred in another thread, stop this one
                if error_occurred.load(Ordering::SeqCst) {
                    return;
                }

                let args = vec![corpus_file.as_os_str()];
                let has_err = executor
                    .execute(&binary, args, vec![], None, None, false)
                    .unwrap();
                if has_err.is_some() {
                    error_occurred.store(true, Ordering::SeqCst);
                }
                tx.send(has_err)
                    .expect("channel will be there waiting for the pool");
            });
        }
        pool.join();

        for _ in 0..corpus_files.len() {
            let has_err = rx.recv().unwrap_or(None);
            if let Some(err) = has_err {
                return Some(err);
            }
        }
        None
    }

    pub fn execute_fuzzer(&self, fuzzer: &Path, corpus: Vec<&Path>) -> Result<()> {
        // make up corpus for each standalone fuzzer.
        let dict = self.deopt.get_library_build_dict_path()?;

        let work_dir = fuzzer.parent().unwrap();
        let log_file: PathBuf = [PathBuf::from(work_dir), "fuzz.log".into()]
            .iter()
            .collect();

        let mut extra_args: Vec<OsString> = corpus
            .iter()
            .map(|x| x.as_os_str().to_os_string())
            .collect();
        if dict.exists() {
            let dict_arg = format!("-dict={}", dict.to_string_lossy());
            extra_args.push(OsString::from(dict_arg));
        }

        let mut child = self.spawn(
            fuzzer,
            extra_args,
            vec![],
            None,
            Some(std::fs::File::create(&log_file)?.into()),
            false,
        );

        let mut cost_time: u64 = 0;
        let mut previous_cov = None;
        let mut should_break = false;
        loop {
            if cost_time >= config::MAX_FUZZ_TIME {
                should_break = true;
            }
            let wait_time = config::MIN_FUZZ_TIME;
            // no coverage gained during config::MIN_FUZZ_TIME, break
            if cost_time >= wait_time && cost_time.is_multiple_of(wait_time) {
                let cov = parse_cov_from_log(&log_file)?;
                if let Some(cov) = cov {
                    if let Some(p_cov) = previous_cov {
                        if cov == p_cov {
                            should_break = true;
                        }
                    } else {
                        previous_cov = Some(cov)
                    }
                }
            }
            match child.try_wait() {
                Ok(Some(_status)) => {
                    let err_msg = std::fs::read_to_string(log_file)?;
                    eyre::bail!("cost time: {cost_time} \n{err_msg}")
                }
                Ok(None) => {
                    log::debug!("{fuzzer:?} running.");
                    if should_break {
                        child.kill()?;
                        child.wait()?;
                        return Ok(());
                    }
                }
                Err(e) => eyre::bail!("error attempting to wait: {e}"),
            }
            cost_time += 1;
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    pub fn execute_cov_fuzzer(
        &self,
        fuzzer_binary: &Path,
        corpus_dir: &Path,
        profraw: &Path,
    ) -> Result<()> {
        let extra_envs = vec![(OsStr::new("LLVM_PROFILE_FILE"), profraw.as_os_str())];
        let extra_args = vec![OsStr::new("-runs=0"), corpus_dir.as_os_str()];
        let mut child = self.spawn(fuzzer_binary, extra_args, extra_envs, None, None, false);
        let timeout = std::time::Duration::from_secs(crate::config::EXECUTION_TIMEOUT);
        let status = match child.wait_timeout(timeout).unwrap() {
            Some(status) => status.code(),
            None => {
                child.kill().unwrap();
                child.wait().unwrap().code()
            }
        };
        if !is_exit_normally(status) {
            log::warn!("execute fuzz_cov failed! {fuzzer_binary:?}, {corpus_dir:?}");
            if let Some(err) = child.stderr.take() {
                let err_msg = get_child_err(err);
                log::error!("Error: {err_msg}");
            }
        }
        Ok(())
    }

    pub fn execute_cov_fuzzer_pool(
        &self,
        fuzzer_binary: &Path,
        corpus_dirs: Vec<&Path>,
        profdata: &Path,
    ) -> Result<()> {
        let fuzzer_dir = get_file_dirname(fuzzer_binary);
        let profraw_dir: PathBuf = [fuzzer_dir.clone(), "profraw".into()].iter().collect();
        if profraw_dir.exists() {
            std::fs::remove_dir_all(&profraw_dir)?;
        }
        crate::deopt::utils::create_dir_if_nonexist(&profraw_dir)?;
        let corpus_files: Vec<Vec<PathBuf>> = corpus_dirs
            .iter()
            .map(|dir| crate::deopt::utils::read_sort_dir(dir).expect("read dir should not fial"))
            .collect();
        let corpus_files: Vec<PathBuf> = corpus_files.concat();
        let cpu_count = max_cpu_count();
        let pool = ThreadPool::new(cpu_count);

        for (id, corpus_file) in corpus_files.iter().enumerate() {
            let binary = fuzzer_binary.to_path_buf();
            let corpus_file = corpus_file.to_path_buf();
            let corpus_name = corpus_file
                .file_name()
                .expect("file name of corpus file should not be empty")
                .to_string_lossy()
                .to_string();
            let profraw_file: PathBuf = [
                PathBuf::from(&profraw_dir),
                format!("{corpus_name}.profraw").into(),
            ]
            .iter()
            .collect();
            let len = corpus_files.len();
            let executor = self.clone();

            pool.execute(move || {
                executor
                    .execute_cov_fuzzer(&binary, &corpus_file, &profraw_file)
                    .unwrap();
                log::trace!("execute fuzz_cov on corpus finished {id}/{}", len);
            });
        }
        pool.join();

        let profraws = crate::deopt::utils::read_all_files_in_dir(&profraw_dir)?;
        Self::merge_profdata(&profraws, profdata)?;
        std::fs::remove_dir_all(profraw_dir)?;
        Ok(())
    }

    pub fn collect_code_coverage(
        &self,
        fuzzer_code: Option<&Path>,
        fuzzer_binary: &Path,
        corpus_dir: Vec<&Path>,
    ) -> Result<CodeCoverage> {
        let work_dir = get_file_dirname(fuzzer_binary);
        let profdata: PathBuf = crate::deopt::Deopt::get_coverage_file_by_dir(&work_dir);
        if profdata.exists() {
            std::fs::remove_file(&profdata)?;
        }

        self.execute_cov_fuzzer_pool(fuzzer_binary, corpus_dir, &profdata)?;

        let cov = self.obtain_cov_from_profdata(&profdata)?;
        if let Some(fuzzer_code) = fuzzer_code {
            let lcov =
                self.obtain_fuzzer_cov_from_profdata(&profdata, fuzzer_code, fuzzer_binary)?;
            let cov = cov.set_fuzzer_lines(lcov);
            return Ok(cov);
        }
        Ok(cov)
    }

    pub fn minimize_corpus(
        &self,
        fuzzer_binary: &Path,
        minimize: &Path,
        corpus: &Path,
    ) -> Result<()> {
        log::trace!("merge corpus {corpus:?} to {minimize:?}");
        crate::deopt::utils::create_dir_if_nonexist(minimize)?;
        let extra_args = vec![
            OsStr::new("-merge=1"),
            minimize.as_os_str(),
            corpus.as_os_str(),
        ];
        let child = self.spawn(fuzzer_binary, extra_args, vec![], None, None, false);
        let output = child.wait_with_output()?;
        if !output.status.success() {
            eyre::bail!("Fail to merge corpus in {fuzzer_binary:?}")
        }
        Ok(())
    }

    pub fn minimize_by_control_file(
        &self,
        fuzzer_binary: &Path,
        corpus: &Path,
        control_file: &Path,
    ) -> Result<()> {
        let work_dir = get_file_dirname(fuzzer_binary);
        let minimize_dir: PathBuf = [work_dir, "temp_minimize".into()].iter().collect();
        crate::deopt::utils::create_dir_if_nonexist(&minimize_dir)?;
        let mcf_arg = format!(
            "-merge_control_file={}",
            control_file.to_string_lossy()
        );
        let extra_args = vec![
            OsStr::new("-merge=1"),
            OsStr::new(&mcf_arg),
            minimize_dir.as_os_str(),
            corpus.as_os_str(),
        ];
        let child = self.spawn(fuzzer_binary, extra_args, vec![], None, None, false);
        let output = child.wait_with_output()?;
        if !output.status.success() {
            eyre::bail!("Fail to merge corpus in {fuzzer_binary:?}")
        }
        std::fs::remove_dir_all(minimize_dir)?;
        Ok(())
    }

    /// concurrently transform programs to fuzzers.
    pub fn concurrent_transform(
        &self,
        programs: &Vec<PathBuf>,
        core: usize,
        use_cons: bool,
        corpora: Option<&Path>,
    ) -> Result<()> {
        let pool = ThreadPool::new(core);
        let error_occurred = Arc::new(AtomicBool::new(false));

        for program in programs {
            let error_occurred = Arc::clone(&error_occurred);
            let program = program.clone();
            let corpora = corpora.as_ref().map(|corpora| corpora.to_path_buf());

            // the constraints are load in harness.
            pool.execute(move || {
                // If an error has occurred in another thread, stop this one
                if error_occurred.load(Ordering::SeqCst) {
                    return;
                }
                let mut cmd = Command::new("cargo");
                let cmd = cmd
                    .arg("run")
                    .arg("--bin")
                    .arg("harness")
                    .arg("--")
                    .arg(get_library_name())
                    .arg("transform")
                    .arg(&program);
                if use_cons {
                    cmd.arg("-u");
                    cmd.arg("-p");
                    cmd.arg(corpora.expect("corpora must be passed when use constraint"));
                }
                let output = cmd
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .output()
                    .expect("failed to execute the concurrent transform process");
                if !output.status.success() {
                    error_occurred.store(true, Ordering::SeqCst);
                    log::error!(
                        "Transform {program:?} to fuzzer error!\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            });
        }
        pool.join();
        if error_occurred.load(Ordering::SeqCst) {
            eyre::bail!("Concurrent transform failed!");
        }
        Ok(())
    }

    pub fn compile_lib_fuzzers(
        &self,
        fuzzer_dir: &Path,
        fuzzer_binary: &Path,
        kind: Compile,
    ) -> Result<()> {
        let mut drivers = Vec::new();
        for entry in std::fs::read_dir(fuzzer_dir)? {
            let path = entry?.path();
            if path.is_file()
                && path.extension().is_some()
                && path.extension().unwrap().to_string_lossy() == "cc"
            {
                drivers.push(path);
            }
        }
        // compile all the fuzzers into one binary.
        let programs: Vec<&Path> = drivers.iter().map(|x| x.as_path()).collect();
        self.compile(programs, fuzzer_binary, kind)
    }

    pub fn spawn_libfuzzer(&self, fuzzer_binary: &Path, corpus: &Path) -> Result<Child> {
        let fuzzer_dir = crate::deopt::utils::get_file_dirname(fuzzer_binary);
        if !fuzzer_binary.exists() {
            eyre::bail!("fuzzer {fuzzer_binary:?} does not exist!")
        }

        // run fuzzer in an another dir to avoid fuzzer write or read garbage files.
        let fuzzer_work_dir: PathBuf = [fuzzer_dir.clone(), "work".into()].iter().collect();
        crate::deopt::utils::create_dir_if_nonexist(&fuzzer_work_dir)?;
        self.deopt.copy_library_init_file(&fuzzer_work_dir)?;

        if !corpus.exists() {
            eyre::bail!("fuzzer corpus {corpus:?} does not exist!")
        }

        let log_file: PathBuf = [fuzzer_dir.clone(), "fuzz.log".into()].iter().collect();
        let mut extra_args = Vec::new();

        let dict = self.deopt.get_library_build_dict_path()?;
        if dict.exists() {
            let dict_arg = format!("-dict={}", dict.to_string_lossy());
            extra_args.push(OsString::from(dict_arg));
        }

        if let Some(fork) = &self.deopt.config.fuzz_fork {
            if *fork {
                extra_args.push(OsString::from("-fork=1"));
            }
        }

        let child = self.spawn(
            fuzzer_binary,
            extra_args,
            vec![],
            Some(fuzzer_work_dir),
            Some(std::fs::File::create(log_file)?.into()),
            false,
        );
        Ok(child)
    }

    pub fn run_libfuzzer(
        &self,
        run_exploit: bool,
        time_limit: Option<u64>,
        min_corpus: Option<bool>,
    ) -> Result<()> {
        let fuzzer_dir = if run_exploit {
            self.deopt.get_library_fuzzer_dir(true)?
        } else {
            self.deopt.get_library_fuzzer_dir(false)?
        };
        let time_limit = if let Some(limit) = time_limit {
            if limit == 0 {
                u64::MAX
            } else {
                limit
            }
        } else {
            60 * 60 * 24
        };
        let should_minimize = min_corpus.unwrap_or(true);

        if !fuzzer_dir.is_dir() {
            eyre::bail!("Fuzzer_dir {fuzzer_dir:?} should be a dir")
        }

        let mut childs = Vec::new();
        for path in crate::deopt::utils::read_sort_dir(&fuzzer_dir)? {
            if !path.is_dir() {
                continue;
            }
            let fuzzer_binary: PathBuf = [path.clone(), "fuzzer".into()].iter().collect();
            let corpus: PathBuf = [path.clone(), "corpus".into()].iter().collect();
            let minimize: PathBuf = [path.clone(), "minimized".into()].iter().collect();
            let final_corpus: PathBuf = [path.clone(), "minimized_corpus".into()].iter().collect();
            if final_corpus.exists() {
                std::fs::rename(final_corpus, &corpus)?;
            }
            if should_minimize {
                self.minimize_corpus(&fuzzer_binary, &minimize, &corpus)?;
                std::fs::remove_dir_all(&corpus)?;
                std::fs::rename(minimize, &corpus)?;
            }

            let child = self.spawn_libfuzzer(&fuzzer_binary, &corpus)?;
            childs.push((child, path));
        }
        let start = std::time::Instant::now();

        loop {
            for (child, path) in childs.iter_mut() {
                match child.try_wait() {
                    Ok(Some(_status)) => {
                        let new_child = respawn_libfuzzer_process(path, self)?;
                        _ = std::mem::replace(child, new_child);
                    }
                    Ok(None) => {
                        log::debug!("{path:?} running.");
                    }
                    Err(e) => log::error!("error attempting to wait: {e}"),
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
            let elapsed = std::time::Instant::elapsed(&start);
            log::info!("fuzzing time: {}s\n\n", elapsed.as_secs());
            // reach time limit, kill all the running process and exit.
            if elapsed.as_secs() >= time_limit {
                for (child, path) in childs.iter_mut() {
                    match child.try_wait() {
                        Ok(Some(_status)) => log::warn!("{path:?} exited!"),
                        Ok(None) => {
                            log::debug!("{path:?} running.");
                            child.kill()?;
                            child.wait()?;
                        }
                        Err(e) => log::error!("error attempting to wait: {e}"),
                    }
                }
                break;
            }
        }
        log::info!("Libfuzzer run completed.");
        Ok(())
    }

    pub fn compile_seed(&self, seed_id: usize) -> Result<()> {
        let work_seed = self.deopt.get_work_seed_by_id(seed_id)?;
        if !work_seed.exists() {
            let seed_path = self.deopt.get_succ_seed_path_by_id(seed_id)?;
            std::fs::copy(seed_path, &work_seed)?;
        }

        let binary_out = work_seed.with_extension("out");
        if !binary_out.exists() {
            let mut transformer = Transformer::new(&work_seed, &self.deopt)?;
            transformer.add_fd_sanitizer()?;
            transformer.preprocess()?;
            self.compile(
                vec![&work_seed],
                &binary_out,
                crate::execution::Compile::FUZZER,
            )?;
        }
        let fuzzer_binary = work_seed.with_extension("cov.out");
        if !fuzzer_binary.exists() {
            self.compile(
                vec![&work_seed],
                &fuzzer_binary,
                crate::execution::Compile::COVERAGE,
            )?;
        }
        self.deopt
            .copy_library_init_file(&get_file_dirname(&work_seed))?;
        Ok(())
    }

    pub fn eval_seed_coverage(&self, seed_id: usize) -> Result<()> {
        let work_seed = self.deopt.get_work_seed_by_id(seed_id)?;
        let fuzzer_binary = work_seed.with_extension("cov.out");
        let corpus_dir = self.deopt.get_library_shared_corpus_dir()?;
        let profdata: PathBuf = self.deopt.get_seed_coverage_file(seed_id)?;
        self.compile_seed(seed_id)?;

        self.execute_cov_fuzzer_pool(&fuzzer_binary, vec![&corpus_dir], &profdata)?;
        Ok(())
    }
}

fn check_clang() -> Result<()> {
    let output = Command::new("clang++")
        .arg("-v")
        .output()
        .expect("failed to execute the clang check process.");
    if !output.status.success() {
        eyre::bail!("clang does not exist in your environment!");
    }
    Ok(())
}

/// if the exit code represent program executed normally.
fn is_exit_normally(code: Option<i32>) -> bool {
    if let Some(exit_code) = code {
        exit_code == 0
    } else {
        false
    }
}

pub fn get_child_err(mut err: ChildStderr) -> String {
    let mut err_buf = Vec::new();
    err.read_to_end(&mut err_buf).unwrap();
    let err_msg = String::from_utf8_lossy(&err_buf).to_string();
    err_msg
}

// mkdir the directory "corpus" under the same directory of fuzzer.
fn mkdir_fuzzer_corpus(fuzzer_path: &Path) -> PathBuf {
    let mut corpus_dir = PathBuf::from(fuzzer_path);
    if !fuzzer_path.is_dir() {
        corpus_dir.pop();
    }
    corpus_dir.push("corpus");
    crate::deopt::utils::create_dir_if_nonexist(&corpus_dir).unwrap();
    corpus_dir
}

/// create new corpus based on the literal extracted from program.
pub fn create_corpus_for_fuzzer(fuzzer_path: &Path, deopt: &Deopt) -> Result<PathBuf> {
    let corpus_dir = mkdir_fuzzer_corpus(fuzzer_path);
    let literal_corpus = fuzzer_path.with_extension("seed");
    let fuzzer_name = fuzzer_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    if !literal_corpus.exists() {
        eyre::bail!("fuzzer corpus {literal_corpus:?} not existed")
    }
    let lib_corpus_files = crate::deopt::utils::get_library_corpus_files(deopt);
    // make up new corpus which concatenated with lib corpus and program's literal corpus.
    for file in lib_corpus_files {
        let lib_corpus = std::fs::read(file)?;
        let literal_corpus = std::fs::read(&literal_corpus)?;
        let content = [lib_corpus, FuzzerShim::get_magic_bytes(), literal_corpus].concat();
        let to_file: PathBuf = [
            corpus_dir.clone(),
            format!(
                "{}_{fuzzer_name}",
                file.file_name().unwrap().to_string_lossy()
            )
            .into(),
        ]
        .iter()
        .collect();
        std::fs::write(to_file, content)?;
    }
    Ok(corpus_dir)
}

fn parse_cov_from_log(log_file: &Path) -> eyre::Result<Option<usize>> {
    let msg = std::fs::read_to_string(log_file)?;
    let last_line = msg.lines().last().ok_or_else(|| eyre::eyre!("{msg}"))?;
    let re = Regex::new(r"cov: (\d+)")?;
    if let Some(captures) = re.captures(last_line) {
        if let Some(cov) = captures.get(1) {
            let cov = cov.as_str();
            let cov: usize = cov.parse()?;
            return Ok(Some(cov));
        }
    }
    Ok(None)
}

pub fn max_cpu_count() -> usize {
    let max_cores = get_config().max_cores;
    if max_cores == 0 {
        num_cpus::get() - 1
    } else {
        max_cores
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_concurrent_checking() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let executor = Executor::new(&deopt)?;

        let test_dir: PathBuf = [deopt.get_library_output_dir()?, "tests".into()]
            .iter()
            .collect();
        let mut programs = Vec::new();
        for entry in std::fs::read_dir(test_dir)? {
            let entry = entry?.path();
            programs.push(entry);
        }
        let res = executor.concurrent_check_batch(&programs)?;
        assert_eq!(programs.len(), res.len());
        println!("{res:#?}");
        Ok(())
    }
}
