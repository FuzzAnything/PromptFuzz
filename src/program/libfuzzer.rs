use crate::ast::loc::is_valid_range;
use crate::ast::Clang;
use crate::deopt::utils::get_file_dirname;
use crate::deopt::{self, Deopt};
use crate::execution::logger::ProgramError;
use crate::execution::max_cpu_count;
use crate::program::gadget::get_func_gadget;
use crate::program::infer::dynamic_infer::find_testbed_corpora;
use crate::program::transform::Transformer;
use crate::program::Executor;
use base64::Engine;
use eyre::{Context, Result};
use once_cell::sync::OnceCell;
use std::collections::HashMap;
/// LibFuzzer's integeration: tranformation, synthesis, execution and sanitizaiton
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::RwLock;

use super::shim::{FuzzerShim, Integer};
use super::Program;

pub fn get_fuzzer_path(fuzz_dir: &Path) -> PathBuf {
    let mut fuzzer = fuzz_dir.to_path_buf();
    fuzzer.push("fuzzer");
    fuzzer
}

pub fn get_cov_fuzzer_path(fuzz_dir: &Path) -> PathBuf {
    let mut cov_fuzzer = fuzz_dir.to_path_buf();
    cov_fuzzer.push("fuzzer_cov");
    cov_fuzzer
}

pub fn get_fuzzer_log(fuzz_dir: &Path) -> PathBuf {
    let mut fuzzer_log = fuzz_dir.to_path_buf();
    fuzzer_log.push("fuzz.log");
    fuzzer_log
}

fn get_incident_dir(fuzz_dir: &Path, driver_id: u16) -> PathBuf {
    let mut incident_dir = fuzz_dir.to_path_buf();
    incident_dir.push(format!("error_{driver_id}"));
    incident_dir
}

#[derive(Clone)]
/// Given a set of programs, check their correctness and synthesize huge fuzzers.
pub struct LibFuzzer {
    /// programs to transform to fuzzers.
    programs: Vec<PathBuf>,
    /// number of fuzzers coalesced to a huge fuzzer.
    batch: usize,
    /// Deopt
    pub deopt: Deopt,
    /// whether transform drivers with constraints.
    use_constraint: bool,
}

impl LibFuzzer {
    pub fn new(
        programs: Vec<PathBuf>,
        batch_size: usize,
        deopt: Deopt,
        use_constraint: bool,
    ) -> Self {
        Self {
            programs,
            batch: batch_size,
            deopt,
            use_constraint,
        }
    }

    fn init(&self) -> Result<()> {
        let fuzzer_dir = self.deopt.get_library_fuzzer_dir(self.use_constraint)?;
        if fuzzer_dir.exists() {
            std::fs::remove_dir_all(fuzzer_dir)?;
        }
        let dst_dir = self.deopt.get_library_driver_dir()?;
        if dst_dir.exists() {
            std::fs::remove_dir_all(&dst_dir)?;
        }
        Ok(())
    }

    // clone the programs to a tmp directory.
    // avoid to edit the raw programs.
    fn clone_programs(&self) -> Result<Vec<PathBuf>> {
        let mut new_programs = Vec::new();

        let tmp_dir = self.deopt.get_library_driver_dir()?;
        for (id, program) in self.programs.iter().enumerate() {
            let mut dst_path = tmp_dir.clone();
            dst_path.push(format!("id_{number:>0width$}.cc", number = id, width = 6));
            std::fs::copy(program, &dst_path)
                .context(format!("Unable to copy {program:?} to {dst_path:?}"))?;
            new_programs.push(dst_path);
        }
        Ok(new_programs)
    }

    pub fn transform(&mut self) -> Result<()> {
        self.init()?;
        self.programs = self.clone_programs()?;

        if self.use_constraint {
            self.exploit_transform()
        } else {
            self.normal_transform()
        }
    }

    // Only transform the program to the Libfuzzer kind with the minimal pre-procession.
    fn normal_transform(&self) -> Result<()> {
        log::info!("Transform the correct programs to fuzzers!");

        for program in &self.programs {
            log::trace!("transform {program:?}");
            let mut transformer = Transformer::new(program, &self.deopt)?;
            transformer.add_fd_sanitizer()?;
            transformer.preprocess()?;
        }
        Ok(())
    }

    fn minimize_fuzzer_corpus_before_constraint_infer(
        &self,
        program_path: &Path,
    ) -> Result<PathBuf> {
        let executor = Executor::new(&self.deopt)?;
        let program = Program::load_from_path(program_path)?;
        let work_seed = self.deopt.get_work_seed_by_id(program.id)?;
        let fuzzer_sancov = work_seed.to_path_buf().with_extension("sancov");
        executor.compile(
            vec![program_path],
            &fuzzer_sancov,
            crate::execution::Compile::Minimize,
        )?;

        let work_dir = deopt::utils::get_file_dirname(&work_seed);
        let minimized: PathBuf = [work_dir.clone(), "corpus".into()].iter().collect();
        if minimized.exists() {
            let _ = std::fs::remove_dir_all(&minimized);
        }
        let shared_corpus = self.deopt.get_library_shared_corpus_dir()?;
        executor.minimize_corpus_by_efficient_sancov(&fuzzer_sancov, &minimized, &shared_corpus)?;
        Ok(minimized)
    }

    fn init_corpus_before_constraint_infer(&self, succ_programs: &Vec<PathBuf>) -> Result<()> {
        log::info!("Initialize the corpus for constraint inference!");
        for program in succ_programs {
            if let Err(e) = self.minimize_fuzzer_corpus_before_constraint_infer(program) {
                log::warn!("Skip program for constraint corpus infer: {:?} ({})", program, e);
            }
        }
        Ok(())
    }

    // transform the programs be more exploitable.
    // transform all array/scalar arguments be fuzzable and consider their constraints.
    fn exploit_transform(&mut self) -> Result<()> {
        log::info!("Transform the correct programs to fuzzers with Constraints!");
        if crate::program::infer::load_constraints(&self.deopt).is_err() {
            let succ_programs =
                crate::deopt::utils::read_sort_dir(&self.deopt.get_library_succ_seed_dir()?)?;
            self.init_corpus_before_constraint_infer(&succ_programs)?;
            crate::program::infer::infer_constraints(&succ_programs, &self.deopt)?;
        }

        let core = max_cpu_count();

        let mut test_corpus = vec![];
        let mut new_programs = vec![];
        for program in self.programs.iter() {
            if let Ok(corpora) = find_testbed_corpora(program, &self.deopt) {
                test_corpus.push(corpora);
                new_programs.push(program.to_path_buf());
            } else {
                log::error!("Failed to find testbed corpora for program: {program:?}, skip it and continue...");
            }
        }
        self.programs = new_programs;

        let executor = Executor::default();
        let mut tasks = Vec::new();
        let mut task_corpus = Vec::new();
        for (i, program) in self.programs.iter().enumerate() {
            let corpora = &test_corpus[i];
            let i = i + 1;
            tasks.push(program.clone());
            task_corpus.push(corpora.to_path_buf());

            if i % core == 0 || i == self.programs.len() {
                executor.concurrent_transform(&tasks, core, true, &task_corpus)?;
                tasks.clear();
                task_corpus.clear();
                log::debug!("transformed {i}/{}", self.programs.len());
            }
        }
        Ok(())
    }

    pub fn synthesis(&mut self) -> Result<()> {
        log::info!("synthesis huge fuzzers!");
        let driver_dir = self.deopt.get_library_driver_dir()?;
        let drivers: Vec<PathBuf> = deopt::utils::read_sort_dir(&driver_dir)?
            .iter()
            .filter(|x| x.extension().is_some() && x.extension().unwrap().to_string_lossy() == "cc")
            .cloned()
            .collect();

        let mut batch = Vec::new();
        let mut batch_id = Vec::new();
        let mut fuzzer_id = 0;

        for (i, driver) in drivers.iter().enumerate() {
            if !self.use_constraint || self.is_valid_driver(driver) {
                batch.push(driver.clone());
                batch_id.push(i);
            }
            if batch.len() == self.batch || i == drivers.len() - 1 {
                let fuzzer_content = self.synthesis_batch(&batch_id)?;
                self.fuse_fuzzer(fuzzer_content, fuzzer_id, &batch, &batch_id)?;
                self.fuse_corpus(fuzzer_id, &batch)?;
                batch.clear();
                batch_id.clear();
                fuzzer_id += 1;
            }
        }
        Ok(())
    }

    fn fuse_fuzzer(
        &self,
        fuzzer_content: String,
        fuzzer_id: usize,
        drivers: &[PathBuf],
        driver_id: &[usize],
    ) -> Result<()> {
        let fuzzer_dir = self.get_fuzzer_dir(fuzzer_id)?;
        crate::deopt::utils::create_dir_if_nonexist(&fuzzer_dir)?;
        // write the condensed fuzzer
        let fuzzer_path: PathBuf = [fuzzer_dir.clone(), "fuzzer.cc".into()].iter().collect();
        std::fs::write(fuzzer_path, fuzzer_content)?;

        for (id, driver) in drivers.iter().enumerate() {
            // write each unit driver with new driver id.
            let dst_driver: PathBuf = [fuzzer_dir.clone(), driver.file_name().unwrap().into()]
                .iter()
                .collect();
            self.change_driver_id(driver, &dst_driver, driver_id[id])?;
        }
        Ok(())
    }

    fn get_fuzzer_dir(&self, fuzzer_id: usize) -> Result<PathBuf> {
        let fuzzer_dir: PathBuf = [
            self.deopt.get_library_fuzzer_dir(self.use_constraint)?,
            format!("Fuzzer_{fuzzer_id:0>width$}", width = 3).into(),
        ]
        .iter()
        .collect();
        Ok(fuzzer_dir)
    }

    fn change_driver_id(
        &self,
        src_driver: &Path,
        dst_driver: &Path,
        driver_id: usize,
    ) -> Result<()> {
        let buf = std::fs::read_to_string(src_driver)?;
        let buf = buf.replace(
            "LLVMFuzzerTestOneInput",
            &format!("LLVMFuzzerTestOneInput_{driver_id}"),
        );
        std::fs::write(dst_driver, buf)?;
        Ok(())
    }

    fn fuse_corpus(&self, fuzzer_id: usize, drivers: &[PathBuf]) -> Result<()> {
        let fuzzer_dir = self.get_fuzzer_dir(fuzzer_id)?;
        let fuzzer_corpus: PathBuf = [fuzzer_dir.clone(), "corpus".into()].iter().collect();
        crate::deopt::utils::create_dir_if_nonexist(&fuzzer_corpus)?;

        for (id, driver) in drivers.iter().enumerate() {
            let seed_corpus: PathBuf = driver.with_extension("seed");
            let driver_corpus = self.get_minimized_corpus(driver)?;
            self.insert_switch_bytes_to_corpus(
                &seed_corpus,
                id as u16,
                &driver_corpus,
                &fuzzer_corpus,
            )?;
        }
        Ok(())
    }

    fn insert_switch_bytes_to_corpus(
        &self,
        seed_corpus: &Path,
        switch_id: u16,
        in_corpus_dir: &Path,
        out_corpus_dir: &Path,
    ) -> Result<()> {
        if !std::fs::exists(in_corpus_dir)? {
            log::warn!(
                "Corpus directory doesn't exist: {in_corpus_dir:?}, skip it and continue..."
            );
            return Ok(());
        }

        let files = crate::deopt::utils::read_all_files_in_dir(in_corpus_dir)?;
        for file in &files {
            let lib_corpus = std::fs::read(file)?;
            let content = if self.use_constraint {
                let literal_corpus = std::fs::read(seed_corpus)?;
                [
                    switch_id.to_bytes(),
                    lib_corpus,
                    FuzzerShim::get_magic_bytes(),
                    literal_corpus,
                ]
                .concat()
            } else {
                [switch_id.to_bytes(), lib_corpus].concat()
            };
            let to_file: PathBuf = [
                PathBuf::from(out_corpus_dir),
                format!(
                    "{}_{switch_id}",
                    file.file_name().unwrap().to_string_lossy()
                )
                .into(),
            ]
            .iter()
            .collect();
            std::fs::write(to_file, content)?;
        }
        Ok(())
    }

    fn synthesis_batch(&mut self, batch_id: &Vec<usize>) -> Result<String> {
        let mut stmts = String::new();
        stmts.push_str(crate::deopt::utils::format_library_header_strings(
            &self.deopt,
        ));
        stmts.push_str("#include <FuzzedDataProvider.h>\n");
        stmts.push_str("\n\n");

        for id in batch_id {
            stmts.push_str(&format!(
                "extern \"C\" int LLVMFuzzerTestOneInput_{id}(const uint8_t* data, size_t size);\n"
            ));
        }
        stmts.push_str("\n\n");

        stmts.push_str(
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)\n{\n",
        );
        stmts.push_str("\tFuzzedDataProvider fdp(data, size);\n");
        stmts.push_str("\tFDPConsumeIntegral(uint16_t, switch_id, fdp);\n");
        stmts.push_str("\tconst uint8_t *input = data + sizeof(uint16_t);\n");
        stmts.push_str("\tsize_t i_size = size - sizeof(uint16_t);\n");
        stmts.push_str("\tswitch (switch_id) {\n");
        for (i, id) in batch_id.iter().enumerate() {
            stmts.push_str(&format!("\t\tcase {i}:\n"));
            stmts.push_str(&format!(
                "\t\t\treturn LLVMFuzzerTestOneInput_{id}(input, i_size);\n"
            ));
            stmts.push_str("\t\t\tbreak;\n");
        }
        stmts.push_str("\t\tdefault:\n");
        stmts.push_str("\t\t\tbreak;\n");
        stmts.push_str("\t}\nreturn 0;\n}\n");
        Ok(stmts)
    }

    /// If a driver ends with ".cc" and has a seed corpus, it is valid.
    fn is_valid_driver(&self, driver: &Path) -> bool {
        if let Some(ex) = driver.extension() {
            if ex.to_string_lossy() == "cc" {
                let seed = driver.with_extension("seed");
                if seed.exists() {
                    return true;
                }
            }
        }
        false
    }

    /// compile the huge fuzzers with libfuzzer.
    pub fn compile(&self) -> Result<()> {
        let executor = Executor::new(&self.deopt)?;
        for dir in std::fs::read_dir(self.deopt.get_library_fuzzer_dir(self.use_constraint)?)? {
            let fuzzer_dir = dir?.path();
            if fuzzer_dir.is_dir() {
                log::info!("Compile to Fuzzer: {fuzzer_dir:?}");
                for entry in std::fs::read_dir(&fuzzer_dir)? {
                    let path = entry?.path();
                    if path.is_file()
                        && path.extension().is_some()
                        && path.extension().unwrap().to_string_lossy() == "cc"
                    {
                        fix_driver_naming_conflict(&path)?;
                    }
                }
                let fuzzer_binary = get_fuzzer_path(&fuzzer_dir);
                executor.compile_lib_fuzzers(
                    &fuzzer_dir,
                    &fuzzer_binary,
                    crate::execution::Compile::FUZZER,
                )?;
                let fuzzer_sancov = fuzzer_binary.with_extension("sancov");
                executor.compile_lib_fuzzers(
                    &fuzzer_dir,
                    &fuzzer_sancov,
                    crate::execution::Compile::Minimize,
                )?;
                self.deopt.copy_library_init_file(&fuzzer_dir)?;
            }
        }
        Ok(())
    }

    fn get_minimized_corpus(&self, driver: &Path) -> Result<PathBuf> {
        let program = Program::load_from_path(driver)?;
        let work_seed = self.deopt.get_work_seed_by_id(program.id)?;

        let work_dir = deopt::utils::get_file_dirname(&work_seed);
        let minimized: PathBuf = [work_dir, "corpus".into()].iter().collect();
        Ok(minimized)
    }
}

/// The function (except main and LLVMFuzzerTestOneInput*) and global variables declared in driver might cause redefinition
///     if it is also declared in other drivers.
/// To avoid that case, we should rename those functions as unique names in all drivers.
pub fn fix_driver_naming_conflict(program: &Path) -> Result<()> {
    let ast = Executor::extract_program_ast(program)?;
    let file_base = program
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string()
        .strip_suffix(".cc")
        .unwrap()
        .to_string();

    let mut decls = vec![];
    for child in &ast.inner {
        if let Clang::FunctionDecl(fd) = &child.kind {
            if is_valid_range(&fd.range) {
                decls.push(fd.get_name().trim().to_string());
            }
        }
        if let Clang::VarDecl(vd) = &child.kind {
            if is_valid_range(&vd.range) {
                let name = vd.get_name_as_string().trim().to_string();
                decls.push(name);
            }
        }
    }
    let mut content = std::fs::read_to_string(program)?;
    for decl in decls {
        if decl.starts_with("LLVM") || decl.starts_with("main") {
            continue;
        }
        if get_func_gadget(&decl).is_some() {
            continue;
        }
        log::debug!("fix definition conflict: {decl} in {program:?}");
        let match_str = format!(r"\b{decl}\b");
        let re = regex::Regex::new(&match_str)?;
        let new_func = format!(" {file_base}_{decl}");
        content = re.replace_all(&content, &new_func).to_string();
    }
    std::fs::write(program, content)?;
    Ok(())
}

fn parse_artifact_from_log(fuzz_log: &Path) -> Result<Vec<u8>> {
    let fuzzer_dir = get_file_dirname(fuzz_log);
    let log_vec = std::fs::read(fuzz_log).expect("cannot open fuzz log");
    let log_str = String::from_utf8_lossy(&log_vec).to_string();

    let mut err_buf = Vec::new();
    for line in log_str.lines().rev() {
        if let Some(c) = line.chars().next() {
            if c == '#' {
                break;
            }
        }
        err_buf.push(line);
    }
    err_buf.reverse();
    let err_buf = err_buf.join("\n");

    for line in err_buf.lines().rev() {
        if let Some(crash_input) = line.strip_prefix("Base64: ") {
            let bytes = base64::engine::general_purpose::STANDARD.decode(crash_input)?;
            return Ok(bytes);
        }
    }

    for line in err_buf.lines().rev() {
        if let Some(artifact_file) =
            line.strip_prefix("artifact_prefix='./'; Test unit written to ./")
        {
            let artifact_file: PathBuf = [fuzzer_dir, "work".into(), artifact_file.into()]
                .iter()
                .collect();
            let bytes = std::fs::read(artifact_file).expect("cannot read artifact");
            return Ok(bytes);
        }
    }
    eyre::bail!("cannot parse artifact from : {fuzz_log:?}")
}

fn parse_driver_id(artifact: &[u8]) -> Option<u16> {
    if artifact.len() < 2 {
        return None;
    }
    let switch_bytes: [u8; 2] = [artifact[0], artifact[1]];
    let switch_id: u16 = u16::from_be_bytes(switch_bytes);
    Some(switch_id)
}

fn mask_driver_from_fuzzer(fuzzer_path: &Path, driver_id: u16) -> Result<()> {
    let mut content = std::fs::read_to_string(fuzzer_path)?;
    let crashed_branch = format!("return LLVMFuzzerTestOneInput_{driver_id}(");
    if let Some(idx) = content.find(&crashed_branch) {
        content.insert_str(idx, "//");
        std::fs::write(fuzzer_path, &content)?;
        return Ok(());
    }
    eyre::bail!("Unable to find the crashed branch: {crashed_branch}\n")
}

// save the fuzzer and triger input that enables to reproduce this incident
fn save_the_incident(
    fuzzer_dir: &Path,
    incident_dir: &Path,
    artifact: &[u8],
    err_msg: Option<String>,
) -> Result<()> {
    if incident_dir.exists() {
        return Ok(());
    }
    log::info!("The incident is saved in {incident_dir:?}");
    crate::deopt::utils::create_dir_if_nonexist(incident_dir)?;

    let fuzz_binary = get_fuzzer_path(fuzzer_dir);
    let save_binary = get_fuzzer_path(incident_dir);
    std::fs::copy(fuzz_binary, save_binary)?;

    let save_log = get_fuzzer_log(incident_dir);
    if let Some(err_msg) = err_msg {
        std::fs::write(save_log, err_msg)?;
    } else {
        let fuzz_log = get_fuzzer_log(fuzzer_dir);
        std::fs::copy(fuzz_log, save_log)?;
    }

    let trigger_input: PathBuf = [incident_dir.to_path_buf(), "triger_input".into()]
        .iter()
        .collect();
    std::fs::write(trigger_input, artifact)?;
    Ok(())
}

pub fn is_incident_reproducible(incident_dir: &Path, deopt: &Deopt) -> Result<bool> {
    let fuzzer_binary = get_fuzzer_path(incident_dir);

    let executor = Executor::new(deopt)?;

    let trigger_input: PathBuf = [PathBuf::from(incident_dir), "triger_input".into()]
        .iter()
        .collect();
    let extra_args = vec![trigger_input.as_os_str()];

    let res = executor.execute(&fuzzer_binary, extra_args, vec![], None, None, true)?;
    if let Some(err) = &res {
        if matches!(err, ProgramError::Hang(_)) {
            log::error!("{incident_dir:?} executed with timeout! For efficient sanitizaiton, our timeour was set as 180s, 
            but it is not an enough timeout. So please run it by your hand with -timeout=1200 to filter out the false warnings.")
        }
    }
    Ok(res.is_some())
}

pub fn is_atrifact_reproducible(
    fuzzer: &Path,
    artifact_file: &Path,
    executor: &Executor,
) -> Result<Option<String>> {
    let extra_args = vec![artifact_file];
    let res = executor.execute(fuzzer, extra_args, vec![], None, None, true)?;
    if let Some(err) = res {
        let err_msg = err.get_err_msg();
        // suppress the ASAN false warnings
        if executor
            .deopt
            .get_asan_options()
            .contains("allocator_may_return_null=1")
            && err_msg.contains("you may set allocator_may_return_null=1")
        {
            return Ok(None);
        }
        return Ok(Some(err_msg));
    }
    Ok(None)
}

/// save the incident and respawn the libfuzzer
pub fn respawn_libfuzzer_process(fuzzer_dir: &Path, executor: &Executor) -> Result<Child> {
    static ERROR_COUNT: OnceCell<RwLock<HashMap<u16, usize>>> = OnceCell::new();

    let fuzzer = get_fuzzer_path(fuzzer_dir);
    let fuzz_log = get_fuzzer_log(fuzzer_dir);

    let artifact =
        parse_artifact_from_log(&fuzz_log).context(format!("parse artifact fail: {fuzz_log:?}"))?;

    if let Some(driver_id) = parse_driver_id(&artifact) {
        log::info!("Found an error happened in driver: {driver_id}");

        // if this driver error many times
        let err_count = {
            let error_count_map_guard = ERROR_COUNT
                .get_or_init(|| RwLock::new(HashMap::new()))
                .read()
                .unwrap();
            if let Some(value) = error_count_map_guard.get(&driver_id) {
                *value
            } else {
                1
            }
        };

        if let Ok(mut error_count_map_guard) = ERROR_COUNT
            .get_or_init(|| RwLock::new(HashMap::new()))
            .write()
        {
            *error_count_map_guard.entry(driver_id).or_default() += 1;
        }

        let incident_dir = get_incident_dir(fuzzer_dir, driver_id);
        save_the_incident(fuzzer_dir, &incident_dir, &artifact, None)?;

        if is_incident_reproducible(&incident_dir, &executor.deopt)? || err_count > 5 {
            let fuzz_code: PathBuf = get_fuzzer_path(fuzzer_dir).with_extension("cc");
            mask_driver_from_fuzzer(&fuzz_code, driver_id)?;
            executor.compile_lib_fuzzers(fuzzer_dir, &fuzzer, crate::execution::Compile::FUZZER)?;
        } else {
            std::fs::remove_dir_all(incident_dir)?;
        }
        log::warn!("{fuzzer_dir:?} found an error with id `{driver_id}` and re-execute");
    }

    let corpus: PathBuf = [fuzzer_dir.to_path_buf(), "corpus".into()].iter().collect();
    let child = executor.spawn_libfuzzer(&fuzzer, &corpus).context(format!(
        "Fail to spawn libfuzzer process: {fuzzer:?} on {corpus:?}"
    ))?;
    Ok(child)
}

pub mod sanitize_crash {
    use std::{collections::HashSet, ffi::OsStr};

    use crate::{deopt::utils::read_sort_dir, program::serde::Deserializer};

    use super::*;

    pub fn sanitize_crash(fuzzer_dir: &Path, deopt: &Deopt) -> Result<()> {
        log::info!("Sanitize the crashes found by libfuzzer! fuzzer_dir: {fuzzer_dir:?}");
        let executor = Executor::new(deopt)?;
        for fuzz_entry in crate::deopt::utils::read_sort_dir(fuzzer_dir)? {
            if !fuzz_entry.is_dir() {
                continue;
            }
            let mut crashes = Vec::new();
            sanitize_asan_artcraft_file(&fuzz_entry, &executor)?;

            for entry in crate::deopt::utils::read_sort_dir(&fuzz_entry)? {
                if entry
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("error_")
                {
                    crashes.push(entry);
                }
            }
            let crashes = sanitize_false_alarm_crashes(crashes, deopt)?;
            let unique_crashes = sanitize_crash_by_call_stack(crashes)?;
            let ubsan_crashes: Vec<String> = sanitize_ubsan_report(&fuzz_entry, &executor)?;
            log::info!("the unique ASAN crashes: {unique_crashes:#?}");
            log::info!("the unique UBSAN crashes: {ubsan_crashes:?}");
        }
        log::info!("Sanitizer automatically removed most of the duplicated crashes.");
        Ok(())
    }

    fn sanitize_false_alarm_crashes(crashes: Vec<PathBuf>, deopt: &Deopt) -> Result<Vec<PathBuf>> {
        let mut retained = Vec::new();
        for fuzz_entry in crashes {
            if is_incident_reproducible(&fuzz_entry, deopt)? {
                log::info!("{fuzz_entry:?} is reproducible.");
                retained.push(fuzz_entry);
            } else {
                log::debug!("{fuzz_entry:?} is sanitized due to irreproducible.");
                std::fs::remove_dir_all(fuzz_entry)?;
            }
        }
        Ok(retained)
    }

    fn is_artcraft_file(file: &Path) -> bool {
        if let Some(file_name) = file.file_name() {
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with("crash-")
                || file_name.starts_with("timeout-")
                || file_name.starts_with("oom-")
                || file_name.starts_with("leak-")
            {
                return true;
            }
        }
        false
    }

    /// test fuzzer on the ASAN produced artcrafted file
    fn sanitize_asan_artcraft_file(fuzzer_entry: &Path, executor: &Executor) -> Result<()> {
        log::info!("Sanitize the ASAN artcraft files in {fuzzer_entry:?}");
        let fuzz_work_dir: PathBuf = [fuzzer_entry.to_path_buf(), "work".into()].iter().collect();

        // get the artcraft files
        let mut artcraft_files = Vec::new();
        let files = [read_sort_dir(fuzzer_entry)?, read_sort_dir(&fuzz_work_dir)?].concat();
        for file in files {
            if file.is_file() && is_artcraft_file(&file) {
                artcraft_files.push(file);
            }
        }

        let fuzzer = get_fuzzer_path(fuzzer_entry);

        for artcraft in artcraft_files {
            log::info!("test on artifact: {artcraft:?}");
            if let Some(err_msg) = is_atrifact_reproducible(&fuzzer, &artcraft, executor)? {
                let artifact = std::fs::read(&artcraft)?;
                if let Some(driver_id) = parse_driver_id(&artifact) {
                    let incident_dir = get_incident_dir(fuzzer_entry, driver_id);
                    save_the_incident(fuzzer_entry, &incident_dir, &artifact, Some(err_msg))?;
                }
            }
            std::fs::remove_file(artcraft)?;
        }
        Ok(())
    }

    fn get_ubsan_crash_point(err_msg: &str) -> Option<String> {
        if !err_msg.contains("UndefinedBehaviorSanitizer")
            || err_msg.contains("applying zero offset to null pointer")
        {
            return None;
        }
        let mut de = Deserializer::from_input(err_msg);
        de.consume_token_until("UndefinedBehaviorSanitizer: undefined-behavior")
            .unwrap();
        let remain = de.remain();
        if let Some(index) = remain.rfind('/') {
            let reamin = &remain[index..];
            let mut loc = String::new();
            for c in reamin.chars() {
                if c.is_whitespace() {
                    break;
                }
                loc.push(c);
            }
            // suppress false warnings
            if loc.contains("id_") {
                return None;
            }

            return Some(loc);
        }
        None
    }

    fn save_ubsan_report(
        fuzzer_dir: &Path,
        ubsan_id: usize,
        corpora: &Path,
        err_msg: &str,
    ) -> Result<()> {
        let fuzzer = get_fuzzer_path(fuzzer_dir);
        let mut report_dir = fuzzer_dir.to_path_buf();
        report_dir.push(format!("ubsan_{ubsan_id}"));
        crate::deopt::utils::create_dir_if_nonexist(&report_dir)?;
        log::warn!("An valid UBSan report is found! The UBSan report is saved in {report_dir:?}");

        let report_fuzzer = get_fuzzer_path(&report_dir);
        std::fs::copy(fuzzer, report_fuzzer)?;

        let mut triger_input = report_dir.clone();
        triger_input.push("triger_input");
        std::fs::copy(corpora, triger_input).expect(&format!("cannot copy {}", corpora.display()));

        let mut fuzz_log = report_dir.clone();
        fuzz_log.push("fuzz.log");
        std::fs::write(fuzz_log, err_msg)?;
        Ok(())
    }

    fn sanitize_ubsan_report(fuzzer_entry: &Path, executor: &Executor) -> Result<Vec<String>> {
        let fuzzer = get_fuzzer_path(fuzzer_entry);
        let mut corpus = fuzzer_entry.to_path_buf();
        corpus.push("minimized_corpus");
        let mut ubsan_crashes = Vec::new();

        let corpora_files = read_sort_dir(&corpus)?;
        for corpora in corpora_files {
            log::info!("test UBSan on corpora: {corpora:?}");
            let extra_args = vec![corpora.as_os_str()];
            let extra_envs = vec![(
                OsStr::new("UBSAN_OPTIONS"),
                OsStr::new("symbolize=1:print_stacktrace=1:halt_on_error=1"),
            )];
            let child = executor.spawn(&fuzzer, extra_args, extra_envs, None, None, true);
            let output = child.wait_with_output()?;
            if output.status.success() {
                continue;
            }
            let err_msg = String::from_utf8_lossy(&output.stderr);
            if let Some(crash_point) = get_ubsan_crash_point(&err_msg) {
                if ubsan_crashes.contains(&crash_point) {
                    continue;
                }
                ubsan_crashes.push(crash_point);
                save_ubsan_report(fuzzer_entry, ubsan_crashes.len(), &corpora, &err_msg)?;
            }
        }
        Ok(ubsan_crashes)
    }

    fn parse_call_stack_line(line: &str) -> Result<(String, String)> {
        let mut de = Deserializer::from_input(line);
        de.consume_token_until(" in ")?;
        let trap_func = de.eat_token_until("/")?.trim();
        let trap_loc = de.remain().trim();
        Ok((trap_func.to_string(), trap_loc.to_string()))
    }

    fn parse_call_stack_from_err_msg(fuzz_entry: &Path) -> Result<Vec<(String, String)>> {
        let fuzz_log: PathBuf = [PathBuf::from(fuzz_entry), "fuzz.log".into()]
            .iter()
            .collect();
        if !fuzz_log.exists() {
            eyre::bail!("Fuzz log doesn't exist: {fuzz_log:?}")
        }
        let err_msg = std::fs::read_to_string(fuzz_log)?;
        let mut de = Deserializer::from_input(&err_msg);
        // the start of err msg
        de.eat_token_until("==")?;
        de.eat_token_until("#0")?;

        let mut call_stacks = Vec::new();
        let err_msg = de.remain();
        for line in err_msg.lines() {
            let line = line.trim();
            if !line.contains(" in ") {
                continue;
            }
            if !line.starts_with('#') {
                break;
            }
            let (trap_call, trap_loc) =
                parse_call_stack_line(line).context(format!("error when parse line: {line}"))?;
            if !trap_loc.contains(
                &crate::deopt::Deopt::get_crate_build_dir()?
                    .to_string_lossy()
                    .to_string(),
            ) {
                continue;
            }
            if trap_call.contains("LLVMFuzzerTestOneInput") {
                break;
            }
            call_stacks.push((trap_call, trap_loc));
        }
        Ok(call_stacks)
    }

    fn call_stack_to_hash(call_stack: Vec<(String, String)>) -> String {
        let mut hash = String::new();
        for (trap_call, _) in call_stack {
            hash.push_str(&trap_call);
        }
        hash
    }

    fn sanitize_crash_by_call_stack(crashes: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
        log::info!("Sanitze those crashes by call stacks");
        let mut unique_crashes = Vec::new();
        let mut sig_set: HashSet<String> = HashSet::new();
        for crash_dir in crashes {
            let call_stack = parse_call_stack_from_err_msg(&crash_dir)
                .context(format!("parse error happened in : {crash_dir:?}"));
            if let Err(err) = call_stack {
                log::error!("{crash_dir:?} doesn't contains the valid call stack, please sanitize it manually.\n {err:?}");
                unique_crashes.push(crash_dir);
                continue;
            }
            let sig = call_stack_to_hash(call_stack?);
            if sig_set.contains(&sig) {
                log::debug!("{crash_dir:?} is sanitized due bo dupliciated call stack.");
                std::fs::remove_dir_all(crash_dir)?;
                continue;
            }
            unique_crashes.push(crash_dir);
            sig_set.insert(sig);
        }

        Ok(unique_crashes)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    #[test]
    fn test_transform_lib_fuzzer() -> Result<()> {
        let deopt = Deopt::new("libjpeg-turbo".to_string())?;
        Config::init_test("libjpeg-turbo");
        let test_dir: PathBuf = [deopt.get_library_output_dir()?, "seeds".into()]
            .iter()
            .collect();
        let programs = crate::deopt::utils::read_sort_dir(&test_dir)?;
        let batch_size = programs.len() / max_cpu_count();
        let mut lib_fuzzer = LibFuzzer::new(programs, batch_size, deopt, true);
        lib_fuzzer.transform()?;
        lib_fuzzer.synthesis()?;
        lib_fuzzer.compile()?;
        Ok(())
    }

    #[test]
    fn test_sanitize_crash() -> Result<()> {
        let deopt = Deopt::new("libpcap".to_string())?;
        Config::init_test("libpcap");
        let fuzzer_dir = deopt.get_library_fuzzer_dir(false)?;
        sanitize_crash::sanitize_crash(&fuzzer_dir, &deopt)?;
        Ok(())
    }
}
