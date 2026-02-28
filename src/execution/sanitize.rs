use crate::{
    config::get_library_name,
    deopt::utils::get_file_dirname,
    feedback::clang_coverage::{
        utils::{dump_fuzzer_coverage, sanitize_by_fuzzer_coverage},
        CorporaFeatures, GlobalFeature,
    },
    program::{serde::Serialize, transform::Transformer, Program},
    Deopt,
};
use eyre::Result;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use self::utils::cleanup_sanitize_dir;

use super::{
    ast::remove_duplicate_definition,
    logger::{ProgramError, TimeUsage},
    Executor,
};

impl Executor {
    /// check whether the c program is syntactically and semantically correct.
    fn is_program_syntax_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        let output: std::process::Output = Command::new("clang++")
            .stdout(Stdio::null())
            .arg("-fsyntax-only")
            .arg(&self.header_cmd)
            .arg(program_path.as_os_str())
            .output()
            .expect("failed to execute the syntax check process");
        time_logger.log("syntax")?;
        let success = output.status.success();
        if success {
            return Ok(None);
        }
        let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(Some(ProgramError::Syntax(err_msg)))
    }

    /// check whether the program is correct in compilation and linkage.
    fn is_program_link_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        remove_duplicate_definition(program_path)?;
        let mut binary_out = PathBuf::from(program_path);
        binary_out.set_extension("out");

        let res = self.compile(vec![program_path], &binary_out, super::Compile::FUZZER);
        time_logger.log("link")?;

        if let Err(err) = res {
            let err_msg = err.to_string();
            return Ok(Some(ProgramError::Link(err_msg)));
        }
        Ok(None)
    }

    /// linked with AddressSanitizer, execute it to check whether code is correct.
    fn is_program_execute_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        let time_logger = TimeUsage::new(get_file_dirname(program_path));
        let mut transformer = Transformer::new(program_path, &self.deopt)?;
        transformer.add_fd_sanitizer()?;
        transformer.preprocess()?;

        let mut binary_out = PathBuf::from(program_path);
        binary_out.set_extension("out");

        self.deopt
            .copy_library_init_file(&get_file_dirname(program_path))?;

        self.compile(vec![program_path], &binary_out, super::Compile::FUZZER)?;

        // Execute the program on each corpus file and check error.
        let corpus = self.deopt.get_library_shared_corpus_dir()?;
        let has_err = self.execute_pool(&binary_out, &corpus);
        time_logger.log("execute")?;
        Ok(has_err)
    }

    /// linked with LibFuzzer and AddressSanitizer, to check whether code is correct.
    pub fn is_program_fuzz_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        log::trace!("test program is fuzz correct: {program_path:?}");
        let work_dir = get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());

        let binary_out = program_path.with_extension("out");

        // execute fuzzer for duration timeout.
        let corpus_dir: PathBuf = [work_dir, "corpus".into()].iter().collect();
        crate::deopt::utils::create_dir_if_nonexist(&corpus_dir)?;

        let res = self.execute_fuzzer(
            &binary_out,
            vec![&corpus_dir, &self.deopt.get_library_shared_corpus_dir()?],
        );
        time_logger.log("fuzz")?;
        if let Err(err) = res {
            return Ok(Some(ProgramError::Fuzzer(err.to_string())));
        }
        Ok(None)
    }

    pub fn is_program_coverage_correct(&self, program_path: &Path) -> Result<Option<ProgramError>> {
        log::trace!("test program is coverage correct: {program_path:?}");
        let work_dir = get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());

        // compile fuzzer with coverage instrumented library.
        let fuzzer_binary = program_path.with_extension("cov.out");
        self.compile(vec![program_path], &fuzzer_binary, super::Compile::COVERAGE)?;

        // Run the fuzzer on the previous synthesized corpus and collect coverage.
        let corpus_dir: PathBuf = [work_dir.clone(), "corpus".into()].iter().collect();
        let coverage = self.collect_code_coverage(
            Some(program_path),
            &fuzzer_binary,
            vec![&corpus_dir, &self.deopt.get_library_shared_corpus_dir()?],
        )?;

        // Sanitize the fuzzer by its reached lines
        let has_err = sanitize_by_fuzzer_coverage(program_path, &self.deopt, &coverage)?;
        time_logger.log("coverage")?;
        self.evolve_corpus(program_path)?;
        // remove the profraw dir to avoid the huge disk cost.
        std::fs::remove_dir_all(corpus_dir)?;

        if !has_err {
            return Ok(None);
        }
        let err_msg = dump_fuzzer_coverage(&fuzzer_binary)?;
        Ok(Some(ProgramError::Coverage(format!("The program cannot cover the callees along the path that contains maximum callees.\n{err_msg}"))))
    }

    pub fn check_program_is_correct(&self, seed_path: &Path) -> Result<Option<ProgramError>> {
        if let Some(err) = self.is_program_syntax_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_link_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_execute_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_fuzz_correct(seed_path)? {
            return Ok(Some(err));
        }
        if let Some(err) = self.is_program_coverage_correct(seed_path)? {
            return Ok(Some(err));
        }
        Ok(None)
    }

    pub fn check_programs_are_correct(
        &self,
        programs: &[Program],
        deopt: &Deopt,
    ) -> Result<Vec<Option<ProgramError>>> {
        let mut program_paths = Vec::new();
        for program in programs.iter() {
            let temp_path = deopt.get_work_seed_by_id(program.id)?;
            let mut content = String::new();
            content.push_str(crate::deopt::utils::format_library_header_strings(deopt));
            content.push_str(&program.serialize());
            std::fs::write(&temp_path, content)?;
            program_paths.push(temp_path);
        }
        let res = self.concurrent_check_batch(&program_paths)?;
        // print the time usage of the sanitization
        utils::print_san_cost(&program_paths)?;

        // clean out the failure cache.
        for (i, has_err) in res.iter().enumerate() {
            let path = &program_paths[i];
            let dir = get_file_dirname(path);
            cleanup_sanitize_dir(&dir)?;
            if let Some(err) = has_err {
                // skip delete the hang and fuzzer error programs, those may contain true bugs.
                if let ProgramError::Hang(_) = err {
                    continue;
                }
                if let ProgramError::Fuzzer(_) = err {
                    continue;
                }
                std::fs::remove_dir_all(dir)?;
            }
        }
        Ok(res)
    }

    /// Using multi-process to run a fixed size of batch of programs, and check the program correctness.
    pub fn concurrent_check_batch(
        &self,
        programs: &[PathBuf],
    ) -> Result<Vec<Option<ProgramError>>> {
        let mut childs = Vec::new();
        for program in programs {
            let child = Command::new("cargo")
                .env("RUST_BACKTRACE", "full")
                .arg("run")
                .arg("-q")
                .arg("--bin")
                .arg("harness")
                .arg("--")
                .arg(get_library_name())
                .arg("check")
                .arg(program)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to execute the concurrent transform process");
            childs.push(child);
        }
        let mut has_errs: Vec<Option<ProgramError>> = Vec::new();
        // for each child process, wait output and log the error reason.
        for (i, child) in childs.into_iter().enumerate() {
            let output = child.wait_with_output().expect("command wasn't running");
            let program = programs.get(i).unwrap();
            if !output.status.success() {
                let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
                let p_err = serde_json::from_str::<ProgramError>(&err_msg);
                if let Ok(err) = p_err {
                    has_errs.push(Some(err));
                } else {
                    has_errs.push(Some(ProgramError::Fuzzer(err_msg)));
                }
                log::trace!("error: {program:?}");
            } else {
                has_errs.push(None);
                log::trace!("correct: {program:?}");
            }
        }
        Ok(has_errs)
    }


    // Evolving the fuzzing corpus by finding the new coverage corpus files and merge them in shared corpus.
    fn evolve_corpus(&self, program_path: &Path) -> Result<()> {
        log::debug!("Evolve fuzzing corpus by merge new coverage corpora");
        let work_dir = crate::deopt::utils::get_file_dirname(program_path);
        let time_logger = TimeUsage::new(work_dir.clone());
        let fuzzer_binary = program_path.with_extension("evo.out");
        self.compile(vec![program_path], &fuzzer_binary, super::Compile::Minimize)?;

        let global_feature_file = self.deopt.get_library_global_feature_file()?;
        let mut global_featuers: GlobalFeature = if global_feature_file.exists() {
            let buf = std::fs::read(&global_feature_file)?;
            serde_json::from_slice(&buf)?
        } else {
            GlobalFeature::init_by_corpus(self, &fuzzer_binary)?
        };

        let corpus: PathBuf = [work_dir.clone(), "corpus".into()].iter().collect();
        let control_file: PathBuf = [work_dir, "merge_control_file".into()].iter().collect();
        self.minimize_by_control_file(&fuzzer_binary, &corpus, &control_file)?;

        if !control_file.exists() {
            panic!("{control_file:?} does not exist!");
        }

        let corpora_features = CorporaFeatures::parse(&control_file)?;
        let corpus_size = corpora_features.get_size();
        let mut intrestings = Vec::new();

        for i in 0..corpus_size {
            let mut has_new = false;
            let features = corpora_features.get_nth_feature(i);
            for fe in features {
                if global_featuers.insert_feature(*fe) {
                    has_new = true;
                }
            }
            if has_new {
                intrestings.push(corpora_features.get_nth_file(i));
            }
        }
        self.deopt.copy_file_to_shared_corpus(intrestings)?;
        let buf = serde_json::to_vec(&global_featuers)?;
        std::fs::write(global_feature_file, buf)?;
        std::fs::remove_file(control_file)?;
        time_logger.log("update")?;
        Ok(())
    }

    /// After the first half of converge, performs sanitization on the seeds again. It aims to:
    /// Sanitize the erroneous programs that were ignored due to no suitable fuzzing corpus to trigger the error.
    pub fn recheck_seed(&mut self, deopt: &mut Deopt) -> Result<()> {
        log::info!("Recheck the saved seeds and remove the error programs within them.");
        let succ_seed_dir = self.deopt.get_library_succ_seed_dir()?;
        let succ_seeds = crate::deopt::utils::read_sort_dir(&succ_seed_dir)?;
        for succ_seed in &succ_seeds {
            let seed_program = Program::load_from_path(succ_seed)?;
            let seed_id = seed_program.id;
            self.compile_seed(seed_id)?;
            // recheck the program
            let corpus = self.deopt.get_library_shared_corpus_dir()?;
            let work_seed_path = self.deopt.get_work_seed_by_id(seed_id)?;
            let binary_out = work_seed_path.with_extension("out");
            let has_err = self.execute_pool(&binary_out, &corpus);
            if let Some(err_msg) = has_err {
                log::warn!("seed: {} is rechecked as Error!", seed_id);
                let seed = self.deopt.get_seed_path_by_id(seed_id)?;
                self.deopt.save_err_program(&seed_program, &err_msg)?;
                std::fs::remove_file(succ_seed)?;
                if seed.exists() {
                    std::fs::remove_file(seed)?;
                    deopt.delete_seed_from_queue(&seed_program);
                }
            }
        }
        Ok(())
    }
}

pub mod utils {

    use crate::execution::logger::get_gtl_mut;

    use super::*;

    pub fn print_san_cost(program_paths: &Vec<PathBuf>) -> Result<()> {
        if program_paths.is_empty() {
            return Ok(());
        }

        let mut max_time = 0_f32;
        let mut usage = Vec::new();
        for program_path in program_paths {
            let program_dir = get_file_dirname(program_path);
            let time_logger = TimeUsage::new(program_dir);

            let syntax = time_logger.load("syntax")?;
            let link = time_logger.load("link")?;
            let execution = time_logger.load("execute")?;
            let fuzz = time_logger.load("fuzz")?;
            let coverage = time_logger.load("coverage")?;
            let update = time_logger.load("update")?;
            let total = syntax + link + execution + fuzz + coverage + update;
            usage.push(syntax);
            usage.push(link);
            usage.push(execution);
            usage.push(fuzz);
            usage.push(coverage);
            usage.push(update);
            if total > max_time {
                max_time = total;
                usage.clear();
                usage.push(syntax);
                usage.push(link);
                usage.push(execution);
                usage.push(fuzz);
                usage.push(coverage);
                usage.push(update);
            }
        }
        log::debug!("This round's sanitization Time Cost: total: {max_time}s, syntax: {}s, link: {}s, exec: {}s, fuzz: {}s, coverage: {}s, update: {}s", usage[0], usage[1], usage[2], usage[3], usage[4], usage[5]);
        get_gtl_mut().inc_san(usage[0], usage[1], usage[2], usage[3], usage[4], usage[5]);
        Ok(())
    }

    pub fn cleanup_sanitize_dir(sanitize_dir: &Path) -> Result<()> {
        let files = crate::deopt::utils::read_sort_dir(sanitize_dir)?;
        for file in files {
            if let Some(ext) = file.extension() {
                if ext == "log" || ext == "out" || ext == "cc" || ext == "profdata" || ext == "cost"
                {
                    continue;
                }
            }
            if file.is_dir() {
                let _ = std::fs::remove_dir_all(file);
            } else {
                let _ = std::fs::remove_file(file);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_coverage_sanitize() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let executor = Executor::new(&deopt)?;

        // this should pass the sanitization.
        let cov_succ_program_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "sanitize",
            "cjson_cov_succ.cc",
        ]
        .iter()
        .collect();
        let work_path = deopt.get_work_seed_by_id(99999)?;
        std::fs::copy(cov_succ_program_path, &work_path)?;
        let has_err = executor.check_program_is_correct(&work_path)?;
        //println!("{has_err:#?}");
        assert!(has_err.is_none());

        // this should be sanitized by coverage.
        let cov_fail_program_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "sanitize",
            "cjson_cov_fail.cc",
        ]
        .iter()
        .collect();
        let work_path = deopt.get_work_seed_by_id(888888)?;
        std::fs::copy(cov_fail_program_path, &work_path)?;
        let has_err = executor.check_program_is_correct(&work_path)?;
        assert!(has_err.is_some());
        if let Some(err) = has_err {
            match err {
                ProgramError::Coverage(_) => return Ok(()),
                _ => panic!("Should not fail on other sanitization"),
            }
        }
        Ok(())
    }

    #[test]
    fn test_sanitization_for_a_program() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        //let program_path: std::path::PathBuf =
        //    [crate::Deopt::get_crate_dir()?, "testsuites", "new_test.cc"]
        //        .iter()
        //        .collect();
        //let work_path = deopt.get_work_seed_by_id(0)?;
        //std::fs::copy(program_path, &work_path)?;
        let executor = Executor::new(&deopt)?;
        let res = executor.check_program_is_correct(&deopt.get_work_seed_by_id(0)?);
        println!("{res:?}");
        Ok(())
    }

    #[test]
    fn test_corpus_evoluation() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let work_path = deopt.get_work_seed_by_id(61)?;
        let executor = Executor::new(&deopt)?;
        let res = executor.evolve_corpus(&work_path)?;
        println!("{res:?}");
        Ok(())
    }
}
