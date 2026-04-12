use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{
    analysis::{adg::ADG, cfg::CFGBuilder},
    config::CONFIG_INSTANCE,
    deopt::utils::read_sort_dir,
    program::{
        gadget::{get_func_gadgets, FuncGadget},
        Program,
    },
    Deopt,
};
use eyre::Result;

use super::{
    branches::{Branch, BranchState, GlobalBranches},
    clang_coverage::CodeCoverage,
};

pub struct Observer {
    pub adg: ADG,
    deopt: Deopt,
    branches: GlobalBranches,
    api_coverage: HashMap<String, f32>,
}

impl Observer {
    pub fn new(deopt: &Deopt) -> Self {
        Self {
            adg: ADG::default(),
            deopt: deopt.clone(),
            branches: GlobalBranches::new(),
            api_coverage: HashMap::new(),
        }
    }

    pub fn get_global_branches(&self) -> &GlobalBranches {
        &self.branches
    }

    pub fn clear_global_branches(&mut self) {
        self.branches.clear();
    }

    pub fn get_adg(&self) -> &ADG {
        &self.adg
    }

    pub fn from_coverage(coverage: &CodeCoverage, deopt: &Deopt) -> Self {
        let mut observer = Observer::new(deopt);
        let new_branches = observer.has_new_branch(coverage);
        if !new_branches.is_empty() {
            observer.merge_new_branch(&new_branches);
        }
        observer
    }

    pub fn add_program_to_adg(&mut self, program_path: &Path) -> Result<()> {
        let ast = crate::execution::Executor::extract_ast(program_path, vec![], &self.deopt)?;
        let cfg = CFGBuilder::build_cfg(ast)?;
        let adg = std::mem::take(&mut self.adg);
        //self.save_program_adg(&adg, program_path)?;
        self.adg = adg.coalesce_from(cfg)?;
        Ok(())
    }

    pub fn save_program_adg(&self, adg: &ADG, program_path: &Path) -> Result<()> {
        let mut adg_path = PathBuf::from(&self.deopt.get_library_adg_dir()?);
        adg_path.push(
            program_path
                .file_name()
                .unwrap_or_else(|| panic!("need a path not dir: {program_path:?}")),
        );
        adg.dump_to_file(&adg_path, true)?;
        adg_path.set_extension("json");
        adg.save_to_file(&adg_path)?;
        Ok(())
    }

    pub fn save_coalesced_adg(&self) -> Result<()> {
        let mut adg_path = PathBuf::from(&self.deopt.get_library_adg_dir()?);
        adg_path.push("coalesced");
        self.adg.dump_to_file(&adg_path, true)?;
        adg_path.set_extension("json");
        self.adg.save_to_file(&adg_path)?;
        Ok(())
    }

    // New branch is the branch triggers a new bucket bitmap of this branch.
    pub fn has_new_branch(&mut self, coverage: &CodeCoverage) -> HashMap<String, Vec<BranchState>> {
        self.branches.has_new(coverage)
    }

    // Unique branch is the branch that have not been triggered before.
    pub fn has_unique_branch(&mut self, coverage: &CodeCoverage) -> HashMap<String, Vec<Branch>> {
        {
            let mut config = CONFIG_INSTANCE.get().unwrap().write().unwrap();
            config.exponent_branch = false;
        }

        let unique_branche_states = self.branches.has_new(coverage);
        {
            let mut config = CONFIG_INSTANCE.get().unwrap().write().unwrap();
            config.exponent_branch = true;
        }
        let mut unique_branches: HashMap<String, Vec<Branch>> = HashMap::new();
        for (func, branch_states) in unique_branche_states {
            let branches: Vec<Branch> = branch_states
                .iter()
                .map(|x: &BranchState| x.get_branch())
                .collect();
            unique_branches.insert(func, branches);
        }
        unique_branches
    }

    pub fn merge_new_branch(&mut self, new_branches: &HashMap<String, Vec<BranchState>>) {
        self.branches.merge(new_branches)
    }

    pub fn merge_coverage(&mut self, coverage: &CodeCoverage) {
        let new_branches = self.has_new_branch(coverage);
        self.merge_new_branch(&new_branches);
    }

    pub fn get_program_branches(
        coverage: &CodeCoverage,
        deopt: &Deopt,
    ) -> HashMap<String, Vec<Branch>> {
        let mut observer = Observer::new(deopt);
        observer.has_unique_branch(coverage)
    }

    pub fn compute_library_api_coverage(&mut self) -> Result<&HashMap<String, f32>> {
        self.api_coverage.clear();
        let mut cov_cache: HashMap<String, (u32, u32)> = HashMap::new();
        for func_name in self.get_global_branches().get_entity().keys() {
            let (covered, total) = self
                .get_global_branches()
                .compute_func_branch_status(func_name);
            cov_cache.insert(func_name.to_string(), (covered, total));
        }
        for gadget in get_func_gadgets() {
            let func = gadget.get_func_name();
            let api_cov = self
                .get_global_branches()
                .compute_recursive_func_coverage(func, &cov_cache)?;
            self.api_coverage.insert(func.to_string(), api_cov);
        }
        Ok(&self.api_coverage)
    }

    pub fn is_library_api_all_covered(&self) -> bool {
        for v in self.api_coverage.values() {
            if v == &0_f32 {
                return false;
            }
        }
        true
    }

    pub fn get_func_coverage(&self, func: &str) -> f32 {
        *self.api_coverage.get(func).unwrap()
    }

    pub fn get_minimal_covered_api(&self, combination: &[&FuncGadget]) -> (String, f32) {
        let mut minimal_cov = 1_f32;
        let mut minimal_api = &String::new();
        for (api, cov) in self.api_coverage.iter() {
            if combination.iter().any(|x| x.get_func_name() == api) {
                continue;
            }
            if cov < &minimal_cov {
                minimal_cov = *cov;
                minimal_api = api;
            }
        }
        (minimal_api.to_string(), minimal_cov)
    }

    pub fn update_quality(
        &self,
        program: &mut Program,
        unique_branches: HashMap<String, Vec<Branch>>,
    ) -> Result<()> {
        let mut quality = program.compute_quality(&self.deopt)?;
        quality.set_unique_branches(unique_branches);
        program.set_quality(quality.clone());
        Ok(())
    }

    pub fn dump_global_states(&self) -> String {
        let branches_dump = serde_json::to_string(&self.branches).unwrap();
        std::fs::write(
            self.deopt.get_library_branch_dump_path().unwrap(),
            branches_dump,
        )
        .unwrap();

        let api_cov_dump = serde_json::to_string(&self.api_coverage).unwrap();
        std::fs::write(
            self.deopt.get_library_api_cov_dump_path().unwrap(),
            api_cov_dump,
        )
        .unwrap();

        let (covered_branch, total_branch) = self.branches.compute_branch_coverage();
        let cover_rate: f32 = covered_branch as f32 / total_branch as f32;
        let api_covs: Vec<&f32> = self.api_coverage.values().collect();
        let dump_str = format!("Covered Branch: {covered_branch}, Total Branch: {total_branch}, Cover Rate: {cover_rate}, \nAPI coverages: {api_covs:?}");
        dump_str
    }

    pub fn get_covered_branch(&self) -> Vec<Branch> {
        self.branches.get_covered_branch()
    }

    pub fn compute_coverage_for_program(program: usize, deopt: &Deopt) -> Result<f32> {
        let mut observer = Observer::new(deopt);
        let coverage = deopt.get_seed_coverage(program)?;
        let new_branches = observer.has_new_branch(&coverage);
        if !new_branches.is_empty() {
            observer.merge_new_branch(&new_branches);
        }
        let (covered_branch, total_branch) = observer.branches.compute_branch_coverage();
        let cover_rate: f32 = covered_branch as f32 / total_branch as f32;
        Ok(cover_rate)
    }

    pub fn sync_from_previous(deopt: &mut Deopt) -> Result<Self> {
        let mut observer = Observer::new(deopt);
        deopt.load_programs_from_seeds()?;
        for program in deopt.seed_queue.iter() {
            let coverage = deopt.get_seed_coverage(program.id)?;
            let new_branches = observer.has_new_branch(&coverage);
            if !new_branches.is_empty() {
                observer.merge_new_branch(&new_branches);
            }
        }
        log::info!("{}", observer.dump_global_states());
        Ok(observer)
    }

    // Recompute the global branch coverage according current seed programs.
    // typicall called after Fuzzer::Executor::recheck_seeds();
    pub fn recompute_global_coverage(&mut self) -> Result<()> {
        log::info!(
            "Recompute the global branch coverage! \n Previous: {}",
            self.dump_global_states()
        );
        self.clear_global_branches();

        let seed_dir = self.deopt.get_library_seed_dir()?;
        for seed in read_sort_dir(&seed_dir)? {
            let mut program = Program::load_from_path(&seed)?;
            let coverage = self.deopt.get_seed_coverage(program.id)?;
            let unique_branches = self.has_unique_branch(&coverage);
            if !unique_branches.is_empty() {
                program.set_unique_branches(unique_branches);
                self.merge_coverage(&coverage);
                // update the quality
                self.deopt.save_program(&program)?;
            }
        }
        log::info!("Recompute finished. Current: {}", self.dump_global_states());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::Executor;

    use super::*;

    #[test]
    fn test_observe_api_coverage() -> Result<()> {
        crate::config::Config::init_test("zlib");
        let deopt = Deopt::new("zlib".to_string())?;
        let seed_id = 974;
        let coverage = deopt.get_seed_coverage(seed_id)?;
        let mut observer = Observer::from_coverage(&coverage, &deopt);
        let _ = observer.compute_library_api_coverage()?;
        Ok(())
    }

    #[test]
    fn test_observe_branch_coverage() -> Result<()> {
        crate::config::Config::init_test("libvpx");
        let mut deopt = Deopt::new("libvpx".to_string())?;
        //let executor = Executor::new(&deopt)?;
        //let programs = deopt.load_programs_from_seeds(true)?;
        //let _ = executor.check_programs_are_correct(&programs, &deopt)?;

        let observer = Observer::sync_from_previous(&mut deopt)?;
        let (covered_branch, total_branch) = observer.branches.compute_branch_coverage();

        deopt.load_programs_from_seeds()?;
        let mut observer = Observer::new(&deopt);
        for program in deopt.seed_queue.iter() {
            let coverage = deopt.get_seed_coverage(program.id)?;
            let new_branches = observer.has_new_branch(&coverage);
            if !new_branches.is_empty() {
                observer.merge_new_branch(&new_branches);
            }
        }
        println!("covered: {covered_branch}, total_branch: {total_branch}");
        let (covered_branch, total_branch) = observer.branches.compute_branch_coverage();
        println!("covered: {covered_branch}, total_branch: {total_branch}");
        Ok(())
    }

    #[test]
    fn test_branch_coverage() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let executor = Executor::new(&deopt)?;

        let profdata: PathBuf = [
            Deopt::get_crate_dir()?,
            "testsuites",
            "corpora",
            "defualt.profdata",
        ]
        .iter()
        .collect();
        let coverage = Executor::obtain_cov_from_profdata(&executor, &profdata)?;
        let clang_branch = coverage.get_total_summary().count_covered_branches();
        let clang_total_branch: usize = coverage.get_total_summary().count_total_branches();
        log::info!("clang coverage: covered: {clang_branch}, total: {clang_total_branch}");

        let mut observer = Observer::new(&deopt);
        observer.merge_coverage(&coverage);
        log::info!("self coverage: {}", observer.dump_global_states());

        let covered_clang_branch = coverage.get_covered_branch();
        let covered_observer_branch = observer.get_covered_branch();
        assert_eq!(covered_clang_branch.len(), covered_observer_branch.len());
        Ok(())
    }
}
