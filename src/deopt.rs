use crate::{
    analysis::header::get_include_lib_headers,
    config::{self, LibConfig},
    deopt::utils::get_file_dirname,
    execution::{ast::remove_duplicate_definition, logger::ProgramError, Executor},
    feedback::{clang_coverage::CodeCoverage, observer::Observer},
    program::{serde::Serialize, Program},
};
use eyre::{Context, Result};
use once_cell::sync::OnceCell;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    process::Command,
};

use self::utils::create_dir_if_nonexist;

#[derive(Default, Clone)]
pub struct Deopt {
    pub project_name: String,
    pub seed_queue: VecDeque<Program>,
    pub seed_id: usize,
    pub config: LibConfig,
}

impl Deopt {
    pub fn delete_seed_from_queue(&mut self, seed: &Program) {
        self.seed_queue.retain(|x| x.id != seed.id)
    }

    pub fn get_seed_from_queue(&self, seed_id: usize) -> &Program {
        for seed in &self.seed_queue {
            if seed.id == seed_id {
                return seed;
            }
        }
        unreachable!("cannot get seed {seed_id} from seed queue")
    }

    pub fn select_seed_from_queue(&mut self) -> &Program {
        assert!(!self.seed_queue.is_empty());
        let qualities: Vec<f32> = self
            .seed_queue
            .iter()
            .map(|seed| seed.get_weight())
            .collect();
        let choose = crate::program::rand::weighted_choose(qualities);
        self.seed_queue[choose].increase_visited();
        let program = &self.seed_queue[choose];
        self.save_program(program).unwrap();
        program
    }

    pub fn select_seed_exclude<'a>(&'a mut self, seed: &Program) -> &'a Program {
        if self.seed_queue.len() == 1 {
            self.seed_queue[0].increase_visited();
            let program = &self.seed_queue[0];
            self.save_program(program).unwrap();
            return program;
        }
        let mut seed_queue: Vec<&mut Program> = self
            .seed_queue
            .iter_mut()
            .filter(|x| x.id != seed.id)
            .collect();
        let qualities: Vec<f32> = seed_queue.iter().map(|seed| seed.get_weight()).collect();
        let choose = crate::program::rand::weighted_choose(qualities);
        seed_queue[choose].increase_visited();
        let select = seed_queue[choose].id;
        let program = self.get_seed_from_queue(select);
        self.save_program(program).unwrap();
        program
    }

    pub fn update_seed_queue(
        &mut self,
        program: Program,
        coverage: &CodeCoverage,
        has_new: bool,
    ) -> Result<()> {
        if has_new {
            self.update_seed_unique_branches(coverage);
            self.save_program(&program)?;
            self.seed_queue.push_back(program);
        } else {
            self.save_succ_program(&program)?;
        }
        Ok(())
    }

    // Update the quality (especially the unique branches) of seeds in prompt queue according the incoming new code coverage.
    pub fn update_seed_unique_branches(&mut self, coverage: &CodeCoverage) {
        log::debug!("Update prompt queue according the incoming code coverage");
        let coming_branches = Observer::get_program_branches(coverage, self);
        for seed in self.seed_queue.iter_mut() {
            seed.update_unique_branches(&coming_branches);
        }
        for seed in self.seed_queue.iter() {
            self.save_program(seed).unwrap();
        }
    }

    /// get current working directory of this crate.
    pub fn get_crate_dir() -> Result<&'static str> {
        pub static CURRDIR: OnceCell<&str> = OnceCell::new();
        let currdir = CURRDIR.get_or_init(|| env!("CARGO_MANIFEST_DIR"));
        Ok(*currdir)
    }

    /// get the output directory of this crate.
    pub fn get_crate_output_dir() -> Result<PathBuf> {
        let out_dir: PathBuf = [Deopt::get_crate_dir()?, "output"].iter().collect();
        utils::create_dir_if_nonexist(&out_dir)?;
        Ok(out_dir)
    }

    pub fn get_crate_build_dir() -> Result<PathBuf> {
        let build_dir: PathBuf = [Deopt::get_crate_output_dir()?, "build".into()]
            .iter()
            .collect();
        utils::create_dir_if_nonexist(&build_dir)?;
        Ok(build_dir)
    }

    pub fn get_crate_testsuit_dir() -> Result<PathBuf> {
        let testsuit_dir: PathBuf = [Deopt::get_crate_dir()?, "testsuites"].iter().collect();
        Ok(testsuit_dir)
    }

    /// get the internal coverage instrument ignorelist file.
    pub fn get_coverage_bl_file_name() -> Result<String> {
        let bl_file: PathBuf = [Deopt::get_crate_dir()?, "ban_all.txt"].iter().collect();
        let name = bl_file.to_string_lossy().to_string();
        Ok(name)
    }

    pub fn new(project_name: String) -> Result<Self> {
        let mut deopt = Deopt::default();
        deopt.project_name = project_name;
        deopt.config = deopt.parse_lib_config()?;
        Ok(deopt)
    }

    pub fn inc_seed_id(&mut self) -> usize {
        let seed_id = self.seed_id;
        self.seed_id += 1;
        seed_id
    }

    /// parse the custom library config
    fn parse_lib_config(&self) -> Result<LibConfig> {
        let data = self.get_library_data_dir()?;
        let config_path: PathBuf = [data, "config.yaml".into()].iter().collect();
        let content = std::fs::read_to_string(config_path)?;
        let config: LibConfig = serde_yaml::from_str(&content)
            .context("fail to parse yaml config file, please check your syntax")?;
        Ok(config)
    }

    /// get the data directory of the library under test.
    pub fn get_library_data_dir(&self) -> Result<PathBuf> {
        let data_dir: PathBuf = [Deopt::get_crate_dir()?, "libraries", &self.project_name]
            .iter()
            .collect();
        Ok(data_dir)
    }

    /// the the build directory of the library under test.
    pub fn get_library_build_dir(&self) -> Result<PathBuf> {
        let build_dir: PathBuf = [
            Deopt::get_crate_build_dir()?,
            self.config.project_name.clone().into(),
        ]
        .iter()
        .collect();
        utils::create_dir_if_nonexist(&build_dir)?;
        Ok(build_dir)
    }

    /// get the library's gadget path.
    pub fn get_library_gadget_path(&self) -> Result<PathBuf> {
        let mut gadget_path = self.get_library_data_dir()?;
        gadget_path.push(&self.project_name);
        gadget_path.set_extension("gadget");
        Ok(gadget_path)
    }

    pub fn get_library_type_gadget_path(&self) -> Result<PathBuf> {
        let gadget_path: PathBuf = [self.get_library_misc_dir()?, "type_gadgets.txt".into()]
            .iter()
            .collect();
        Ok(gadget_path)
    }

    pub fn get_library_func_gadget_path(&self) -> Result<PathBuf> {
        let gadget_path: PathBuf = [self.get_library_misc_dir()?, "func_gadgets.txt".into()]
            .iter()
            .collect();
        Ok(gadget_path)
    }

    pub fn get_library_branch_dump_path(&self) -> Result<PathBuf> {
        let save_path: PathBuf = [self.get_library_misc_dir()?, "branches.json".into()]
            .iter()
            .collect();
        Ok(save_path)
    }

    pub fn get_library_api_cov_dump_path(&self) -> Result<PathBuf> {
        let save_path: PathBuf = [self.get_library_misc_dir()?, "api_coverages.json".into()]
            .iter()
            .collect();
        Ok(save_path)
    }

    /// get the output directory of the library under test.
    pub fn get_library_output_dir(&self) -> Result<PathBuf> {
        let mut p_out_dir: PathBuf = Self::get_crate_output_dir()?;
        p_out_dir.push(&self.project_name);
        utils::create_dir_if_nonexist(&p_out_dir)?;
        Ok(p_out_dir)
    }

    pub fn get_library_adg_dir(&self) -> Result<PathBuf> {
        let mut outa_dir = self.get_library_output_dir()?;
        outa_dir.push("adgs");
        utils::create_dir_if_nonexist(&outa_dir)?;
        Ok(outa_dir)
    }

    pub fn get_library_succ_seed_dir(&self) -> Result<PathBuf> {
        let mut outs_dir = self.get_library_output_dir()?;
        outs_dir.push("succ_seeds");
        utils::create_dir_if_nonexist(&outs_dir)?;
        Ok(outs_dir)
    }

    pub fn get_library_seed_dir(&self) -> Result<PathBuf> {
        let mut outs_dir = self.get_library_output_dir()?;
        outs_dir.push("seeds");
        utils::create_dir_if_nonexist(&outs_dir)?;
        Ok(outs_dir)
    }

    fn get_library_error_seed_dir(&self) -> Result<PathBuf> {
        let mut outcs_dir = self.get_library_output_dir()?;
        outcs_dir.push("error_seeds");
        utils::create_dir_if_nonexist(&outcs_dir)?;
        Ok(outcs_dir)
    }

    pub fn get_library_driver_dir(&self) -> Result<PathBuf> {
        let mut driver_dir = self.get_library_output_dir()?;
        driver_dir.push("drivers");
        utils::create_dir_if_nonexist(&driver_dir)?;
        Ok(driver_dir)
    }

    pub fn get_library_fuzzer_dir(&self, exploit: bool) -> Result<PathBuf> {
        let mut fuzzer_dir = self.get_library_output_dir()?;
        if exploit {
            fuzzer_dir.push("exploit_fuzzers");
        } else {
            fuzzer_dir.push("fuzzers");
        }
        utils::create_dir_if_nonexist(&fuzzer_dir)?;
        Ok(fuzzer_dir)
    }

    pub fn get_library_misc_dir(&self) -> Result<PathBuf> {
        let mut misc_dir = self.get_library_output_dir()?;
        misc_dir.push("misc");
        utils::create_dir_if_nonexist(&misc_dir)?;
        Ok(misc_dir)
    }

    pub fn get_library_coverage_path(&self) -> Result<PathBuf> {
        let path: PathBuf = [self.get_library_misc_dir()?, "code_coverage.csv".into()]
            .iter()
            .collect();
        Ok(path)
    }

    pub fn get_library_build_header_path(&self) -> Result<PathBuf> {
        let path: PathBuf = [self.get_library_build_dir()?, "include".into()]
            .iter()
            .collect();
        Ok(path)
    }

    pub fn obtain_library_include_headers(&self) -> Result<Vec<PathBuf>> {
        let header_names = get_include_lib_headers(self)?;
        let mut headers: Vec<PathBuf> = Vec::new();
        let header_dir = self.get_library_build_header_path()?;
        for header in header_names {
            let header_path: PathBuf = [header_dir.clone(), header.into()].iter().collect();
            headers.push(header_path);
        }
        Ok(headers)
    }

    pub fn get_library_build_corpus_dir(&self) -> Result<PathBuf> {
        let corpus_dir: PathBuf = [self.get_library_build_dir()?, "corpus".into()]
            .iter()
            .collect();
        Ok(corpus_dir)
    }

    pub fn get_library_landmark_corpus(&self) -> Option<String> {
        if let Some(landmark) = &self.config.landmark {
            if landmark == &true {
                let corpus_files =
                    utils::read_sort_dir(&self.get_library_build_corpus_dir().unwrap()).unwrap();
                let choose = crate::program::rand::random_select(&corpus_files);
                let data = std::fs::read_to_string(choose).unwrap();
                return Some(data);
            }
        }
        None
    }

    pub fn get_asan_options(&self) -> String {
        let mut options = crate::config::ASAN_OPTIONS.join(":");
        if let Some(extra_option) = &self.config.asan_option {
            options.push(':');
            options.push_str(extra_option);
        }
        options
    }

    pub fn copy_library_init_file(&self, dir: &Path) -> Result<()> {
        if let Some(init_file) = &self.config.init_file {
            let file_path: PathBuf = [
                self.get_library_build_dir()?,
                "work".into(),
                init_file.into(),
            ]
            .iter()
            .collect();
            if !file_path.exists() {
                eyre::bail!("Cannot find the library initialize file {init_file:?}")
            }
            let cur_file: PathBuf = [PathBuf::from(dir), init_file.into()].iter().collect();
            std::fs::copy(file_path, cur_file)?;
        }
        Ok(())
    }

    pub fn add_extra_c_flags(&self, cmd: &mut Command) -> Result<()> {
        if let Some(flags) = &self.config.extra_c_flags {
            let ld_path: PathBuf = [self.get_library_build_dir()?, "work".into(), "lib".into()]
                .iter()
                .collect();
            cmd.arg(format!("-L{}", ld_path.to_str().unwrap()));
            let ld_path: PathBuf = [self.get_library_build_dir()?, "work".into(), "lib64".into()]
                .iter()
                .collect();
            cmd.arg(format!("-L{}", ld_path.to_str().unwrap()));
            for flag in flags {
                cmd.arg(flag);
            }
            log::debug!("{cmd:?}");
        }
        Ok(())
    }

    pub fn get_library_shared_corpus_dir(&self) -> Result<PathBuf> {
        let corpus_dir: PathBuf = [self.get_library_output_dir()?, "shared_corpus".into()]
            .iter()
            .collect();
        if !corpus_dir.exists() {
            utils::copy_corpus(&self.get_library_build_corpus_dir()?, &corpus_dir)?;
        }
        Ok(corpus_dir)
    }

    pub fn get_library_global_feature_file(&self) -> Result<PathBuf> {
        let temp_dir = self.get_library_misc_dir()?;
        let profdata = [temp_dir, "global_features".into()].iter().collect();
        Ok(profdata)
    }

    pub fn copy_file_to_shared_corpus(&self, instresting_files: Vec<PathBuf>) -> Result<()> {
        let corpus_dir = self.get_library_shared_corpus_dir()?;
        for file in instresting_files {
            let dst: PathBuf = [
                corpus_dir.clone(),
                file.file_name().unwrap().to_str().unwrap().into(),
            ]
            .iter()
            .collect();
            log::trace!("Find new coverage corpus: {:?}", dst);
            std::fs::copy(file, dst)?;
        }
        Ok(())
    }

    pub fn get_library_build_lib_path(&self) -> Result<PathBuf> {
        let path: PathBuf = [self.get_library_build_dir()?, "lib".into()]
            .iter()
            .collect();
        Ok(path)
    }

    pub fn get_library_build_dict_path(&self) -> Result<PathBuf> {
        let path: PathBuf = [self.get_library_build_dir()?, "fuzzer.dict".into()]
            .iter()
            .collect();
        Ok(path)
    }

    pub fn get_library_work_dir(&self) -> Result<PathBuf> {
        let path: PathBuf = [self.get_library_output_dir()?, "work".into()]
            .iter()
            .collect();
        utils::create_dir_if_nonexist(&path)?;
        Ok(path)
    }

    pub fn get_library_transform_check_dir(&self, driver: &Path) -> Result<PathBuf> {
        let mut path: PathBuf = [self.get_library_work_dir()?, "transform_check".into()]
            .iter()
            .collect();
        utils::create_dir_if_nonexist(&path)?;
        let base_name = driver.file_name().unwrap().to_str().unwrap();
        path.push(base_name.strip_suffix(".cc").unwrap());
        crate::deopt::utils::create_dir_if_nonexist(&path)?;
        Ok(path)
    }

    pub fn get_server_logger_path(&self) -> Result<PathBuf> {
        let path = [self.get_library_output_dir()?, "llm_server.log".into()]
            .iter()
            .collect();
        Ok(path)
    }

    /// tempfile used for cloning programs and performing analysis.
    pub fn get_c_tempfile(&self) -> Result<PathBuf> {
        let path = [self.get_library_output_dir()?, "tempfile.cc".into()]
            .iter()
            .collect();
        Ok(path)
    }

    /// path of source file of FuzzDataProvider
    pub fn get_fdp_path() -> Result<PathBuf> {
        let path = [Deopt::get_crate_dir()?, config::FDP_PATH].iter().collect();
        Ok(path)
    }

    pub fn get_fuzz_wrapper() -> Result<PathBuf> {
        let path = [Deopt::get_crate_dir()?, config::FDP_PATH, "fuzz_wrapper.cc".into()]
            .iter()
            .collect();
        Ok(path)
    }

    pub fn get_seed_path_by_id(&self, id: usize) -> Result<PathBuf> {
        let seed_dir = self.get_library_seed_dir()?;
        let seed_path: PathBuf = [
            seed_dir,
            format!("id_{number:>0width$}.cc", number = id, width = 6).into(),
        ]
        .iter()
        .collect();
        Ok(seed_path)
    }

    pub fn get_succ_seed_path_by_id(&self, id: usize) -> Result<PathBuf> {
        let seed_dir = self.get_library_succ_seed_dir()?;
        let seed_path: PathBuf = [
            seed_dir,
            format!("id_{number:>0width$}.cc", number = id, width = 6).into(),
        ]
        .iter()
        .collect();
        Ok(seed_path)
    }

    pub fn get_seed_work_dir_by_id(&self, id: usize) -> Result<PathBuf> {
        let work_dir = self.get_library_work_dir()?;
        let seed_work_dir: PathBuf = [
            work_dir,
            format!("id_{number:>0width$}", number = id, width = 6).into(),
        ]
        .iter()
        .collect();
        create_dir_if_nonexist(&seed_work_dir)?;
        Ok(seed_work_dir)
    }

    pub fn get_work_seed_by_id(&self, id: usize) -> Result<PathBuf> {
        let seed_work_dir = self.get_seed_work_dir_by_id(id)?;
        let seed_path: PathBuf = [
            seed_work_dir,
            format!("id_{number:>0width$}.cc", number = id, width = 6).into(),
        ]
        .iter()
        .collect();
        Ok(seed_path)
    }

    pub fn get_coverage_file_by_dir(work_dir: &Path) -> PathBuf {
        [work_dir.to_path_buf(), "default.profdata".into()]
            .iter()
            .collect()
    }

    pub fn get_seed_coverage_file(&self, id: usize) -> Result<PathBuf> {
        let seed_work_dir = self.get_seed_work_dir_by_id(id)?;
        Ok(Self::get_coverage_file_by_dir(&seed_work_dir))
    }

    pub fn get_seed_coverage(&self, seed_id: usize) -> Result<CodeCoverage> {
        let profdata = self.get_seed_coverage_file(seed_id)?;
        let executor = Executor::new(self)?;
        let coverage = Executor::obtain_cov_from_profdata(&executor, &profdata)?;
        Ok(coverage)
    }

    // Save the seed programs into disk.
    pub fn save_program(&self, program: &Program) -> Result<PathBuf> {
        let seed_path = self.get_seed_path_by_id(program.id)?;
        let content = [
            utils::format_library_header_strings(self).to_string(),
            program.serialize(),
        ]
        .concat();
        std::fs::write(&seed_path, content)?;
        remove_duplicate_definition(&seed_path)?;
        Ok(seed_path)
    }

    pub fn save_succ_program(&self, program: &Program) -> Result<PathBuf> {
        let seed_path = self.get_succ_seed_path_by_id(program.id)?;
        let content = [
            utils::format_library_header_strings(self).to_string(),
            program.serialize(),
        ]
        .concat();
        std::fs::write(&seed_path, content)?;
        remove_duplicate_definition(&seed_path)?;
        Ok(seed_path)
    }

    pub fn save_err_program(
        &mut self,
        program: &Program,
        err_msg: &ProgramError,
    ) -> Result<PathBuf> {
        let save_dir = self.get_library_error_seed_dir()?;

        let save_dir: PathBuf = match err_msg {
            ProgramError::Syntax(_) => [save_dir.clone(), "syntax".into()].iter().collect(),
            ProgramError::Link(_) => [save_dir.clone(), "link".into()].iter().collect(),
            ProgramError::Execute(_) => [save_dir.clone(), "execute".into()].iter().collect(),
            ProgramError::Fuzzer(_) => [save_dir.clone(), "fuzzer".into()].iter().collect(),
            ProgramError::Coverage(_) => [save_dir.clone(), "coverage".into()].iter().collect(),
            ProgramError::Hang(_) => [save_dir.clone(), "hang".into()].iter().collect(),
        };
        utils::create_dir_if_nonexist(&save_dir)?;
        let seed_path: PathBuf = [
            save_dir,
            format!("id_{number:>0width$}.cc", number = program.id, width = 6).into(),
        ]
        .iter()
        .collect();
        let content = [
            utils::format_library_header_strings(self).to_string(),
            program.serialize(),
            err_msg.get_err_msg(),
        ]
        .concat();
        std::fs::write(&seed_path, content)?;
        Ok(seed_path)
    }

    pub fn load_programs_from_seeds(&mut self) -> Result<()> {
        self.seed_queue.clear();
        let seed_dir = self.get_library_seed_dir()?;
        for entry in utils::read_sort_dir(&seed_dir)? {
            let program = Program::load_from_path(&entry)?;
            self.seed_queue.push_back(program);
        }
        log::trace!("{} programs are load.", self.seed_queue.len());
        Ok(())
    }

    // Prepare a work dir and gadgets for Transformer to dynamically infer the fuzz-ability of a driver.
    // The driver is a program that contains only an argument that was transformed to receive fuzzer's bytes.
    // The infer is performed upon a corpora that is sufficient to cover the program's code.
    // During the infer process, the content of corpora is retain unchanged and only the bytes wiil be passed to the transformed argument are mutated by fuzzer.
    // The workflow is:
    // 1. copy literal corpora collected from program to corpus as the only mutatable corpora.
    // 2. modify the driver's code to read the data directly from the passed corpora.
    pub fn prepare_transform_path_for_driver(&self, driver: &Path, corpora: &Path) -> Result<()> {
        log::trace!("Prepare the work dir for driver: {driver:?}");
        let check_dir = get_file_dirname(driver);

        // copy program literal as seed corpus
        let literal_seed = driver.with_extension("seed");
        if literal_seed.exists() {
            let corpus_dir: PathBuf = [check_dir.clone(), "corpus".into()].iter().collect();
            if corpus_dir.exists() {
                std::fs::remove_dir_all(&corpus_dir)?;
            }
            crate::deopt::utils::create_dir_if_nonexist(&corpus_dir)?;
            let corpus_seed: PathBuf = [corpus_dir, "seed".into()].iter().collect();
            std::fs::copy(literal_seed, corpus_seed)?;
        }

        // copy the highest cov corpora
        let dst_corpora: PathBuf = [check_dir, "highest_cov_corpora".into()].iter().collect();
        std::fs::copy(corpora, dst_corpora)?;

        // Change the raw data read from parameter to read from file.
        let content = std::fs::read_to_string(driver)?;
        let content = content.replace("FDPConsumeRawBytes", "FDPReadRawBytes");
        std::fs::write(driver, content)?;
        Ok(())
    }
}

pub mod utils {
    use std::collections::HashSet;

    use super::*;

    /// create the directory if it does not exist
    pub fn create_dir_if_nonexist(path: &Path) -> Result<()> {
        if !path.exists() {
            std::fs::create_dir(path)?;
        }
        Ok(())
    }

    /// read the directory and sort the entries by the alphabet oder
    pub fn read_sort_dir(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        if !dir.exists() {
            return Ok(entries);
        }
        if !dir.is_dir() {
            eyre::bail!("{dir:?} is not a directory")
        }
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            entries.push(path);
        }
        entries.sort();
        Ok(entries)
    }

    pub fn is_dir_empty(dir: &Path) -> Result<bool> {
        read_sort_dir(dir).map(|entries| entries.is_empty())
    }

    /// format the headers of this library that should include as a single String.
    pub fn format_library_header_strings(deopt: &Deopt) -> &'static str {
        static HEADER: OnceCell<String> = OnceCell::new();
        HEADER.get_or_init(|| {
            let mut content = String::new();
            for header in get_standard_headers() {
                content.push_str(&format!("#include <{header}>\n"));
            }
            for header in get_library_headers(deopt).unwrap() {
                if header.ends_with(".h") {
                    content.push_str("extern \"C\" {\n");
                    content.push_str(&format!("#include <{header}>\n"));            
                    content.push_str("}\n");
                } else {
                    content.push_str(&format!("#include <{header}>\n"));            
                }
            }
            content
        })
    }

    pub fn get_library_headers(deopt: &Deopt) -> Result<Vec<String>> {
        get_include_lib_headers(deopt)
    }

    pub fn get_standard_headers() -> Vec<String> {
        vec![
            "stdlib.h".to_string(),
            "string.h".to_string(),
            "stdint.h".to_string(),
            "vector".to_string(),
            "fstream".to_string(),
            "iostream".to_string(),
            "sstream".to_string(),
        ]
    }

    /// Get the paths of all corpus files in the corpus directory.
    pub fn get_library_corpus_files(deopt: &Deopt) -> &'static Vec<PathBuf> {
        static CORPUS_FILES: OnceCell<Vec<PathBuf>> = OnceCell::new();
        CORPUS_FILES.get_or_init(|| {
            let corpus_dir: PathBuf = deopt
                .get_library_build_corpus_dir()
                .expect("This library has not built with corpus. Please build it first.");
            read_all_files_in_dir(&corpus_dir).unwrap()
        })
    }

    /// Recursively read all files in this dir.
    pub fn read_all_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).context(format!("cannot open dir: {dir:?}"))? {
            let entry = entry?.path();
            if entry.is_file() {
                files.push(entry);
            } else if entry.is_dir() {
                files.extend(read_all_files_in_dir(&entry)?);
            }
        }
        Ok(files)
    }

    /// get the build static library linked with sanitizers
    pub fn get_san_lib_path(deopt: &Deopt) -> &'static PathBuf {
        static PATH: OnceCell<PathBuf> = OnceCell::new();
        PATH.get_or_init(|| {
            let lib_name = deopt.config.static_lib_name.clone();
            let lib_name = lib_name.strip_suffix(".a").unwrap();
            let san_lib = format!("{}_san.a", lib_name);
            let lib_path: PathBuf = [deopt.get_library_build_lib_path().unwrap(), san_lib.into()]
                .iter()
                .collect();
            lib_path
        })
    }

        /// get the build static library linked with sanitizers
    pub fn get_sancov_lib_path(deopt: &Deopt) -> &'static PathBuf {
        static PATH: OnceCell<PathBuf> = OnceCell::new();
        PATH.get_or_init(|| {
            let lib_name = deopt.config.static_lib_name.clone();
            let lib_name = lib_name.strip_suffix(".a").unwrap();
            let san_lib = format!("{}_sancov.a", lib_name);
            let lib_path: PathBuf = [deopt.get_library_build_lib_path().unwrap(), san_lib.into()]
                .iter()
                .collect();
            lib_path
        })
    }

    /// get the build static library linked with fuzzers
    pub fn get_fuzzer_lib_path(deopt: &Deopt) -> &'static PathBuf {
        static PATH: OnceCell<PathBuf> = OnceCell::new();
        PATH.get_or_init(|| {
            let lib_name = deopt.config.static_lib_name.clone();
            let lib_name = lib_name.strip_suffix(".a").unwrap();
            let fuzzer_lib = format!("{}_fuzzer.a", lib_name);
            let lib_path: PathBuf = [
                deopt.get_library_build_lib_path().unwrap(),
                fuzzer_lib.into(),
            ]
            .iter()
            .collect();
            lib_path
        })
    }

    /// get the build static library linked with coverage
    pub fn get_cov_lib_path(deopt: &Deopt, use_shared: bool) -> &'static PathBuf {
        static SHARE_PATH: OnceCell<PathBuf> = OnceCell::new();
        if use_shared {
            return SHARE_PATH.get_or_init(|| {
                let lib_name = deopt.config.dyn_lib_name.clone();
                let lib_name = lib_name.strip_suffix(".so").unwrap();
                let cov_lib = format!("{}_cov.so", lib_name);
                let lib_path: PathBuf =
                    [deopt.get_library_build_lib_path().unwrap(), cov_lib.into()]
                        .iter()
                        .collect();
                lib_path
            });
        }
        static STATIC_PATH: OnceCell<PathBuf> = OnceCell::new();
        STATIC_PATH.get_or_init(|| {
            let lib_name = deopt.config.static_lib_name.clone();
            let lib_name = lib_name.strip_suffix(".a").unwrap();
            let cov_lib = format!("{}_cov.a", lib_name);
            let lib_path: PathBuf = [deopt.get_library_build_lib_path().unwrap(), cov_lib.into()]
                .iter()
                .collect();
            lib_path
        })
    }

    pub fn get_file_dirname(path: &Path) -> PathBuf {
        if path.is_dir() {
            return PathBuf::from(path);
        }
        let dir = path.parent().unwrap();
        PathBuf::from(dir)
    }

    pub fn copy_corpus(from_dir: &Path, to_dir: &Path) -> Result<()> {
        crate::deopt::utils::create_dir_if_nonexist(to_dir)?;
        let lib_corpus_files = read_all_files_in_dir(from_dir)?;
        for file in lib_corpus_files {
            let lib_corpus = std::fs::read(&file)?;
            let to_file: PathBuf = [
                to_dir.to_path_buf(),
                file.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
                    .into(),
            ]
            .iter()
            .collect();
            std::fs::write(to_file, lib_corpus)?;
        }
        Ok(())
    }

    pub fn get_file_hash_set(dir: &Path) -> HashSet<String> {
        let mut sets = HashSet::new();
        for file in std::fs::read_dir(dir).unwrap() {
            let file = file.unwrap().file_name();
            let file = file.to_str().unwrap();
            sets.insert(file.to_string());
        }
        sets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_prompt_queue() -> Result<()> {
        config::Config::init_test("cJSON");
        let mut deopt = Deopt::new("cJSON".to_string())?;

        // load the first seed.
        let seed_id_0 = 29;
        let seed_path_0 = deopt.get_succ_seed_path_by_id(seed_id_0)?;
        let mut seed_0 = Program::load_from_path(&seed_path_0)?;
        let coverage = deopt.get_seed_coverage(seed_id_0)?;
        let unique_branches = Observer::get_program_branches(&coverage, &deopt);
        let mut quality = seed_0.get_quality().clone();
        quality.set_unique_branches(unique_branches);
        seed_0.set_quality(quality);

        deopt.save_program(&seed_0)?;
        deopt.seed_queue.push_back(seed_0);

        // load the second seed
        let seed_id_1 = 55;
        let coverage = deopt.get_seed_coverage(seed_id_1)?;
        deopt.update_seed_unique_branches(&coverage);
        Ok(())
    }
}
