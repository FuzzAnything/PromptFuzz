use crate::{
    analysis::callgraph::get_lib_call_graph, config::get_config, program::get_exec_counter_value,
};
use std::collections::{HashMap, HashSet};

use super::clang_coverage::{CodeCoverage, CovBranch};

type BucketType = u32;
const BUCKET_MASK: BucketType = BucketType::MAX;

/// line_start, col_strat, line_end, col_end, fileid, expand_file_id, kind, True or false branch,
/// those 8 numbers idenitify an unique branch
pub type Branch = [usize; 8];

pub fn parse_branch(clang_branch: &CovBranch) -> (Branch, Branch) {
    let mut branch: Branch = [0; 8];
    branch[..4].copy_from_slice(&clang_branch[..4]);
    branch[4..7].copy_from_slice(&clang_branch[6..9]);
    let true_branch = branch;
    let mut false_branch = branch;
    false_branch[7] = 1;
    (true_branch, false_branch)
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct BranchState {
    branch: Branch,
    // 16 bit map respond for branch hit.
    bucket: BucketType,
}

impl BranchState {
    fn new(branch: Branch, bucket: BucketType) -> Self {
        Self { branch, bucket }
    }

    // count = 200;
    // bucket = 7; The 7-th bit of bucket is 1.
    fn calculate_bucket_count(count: usize) -> BucketType {
        if count == 0 {
            return 0;
        }
        let bucket = usize::ilog2(count);
        if bucket >= 32 {
            1 << 31
        } else {
            1 << bucket
        }
    }

    fn from_llvm_cov(func_state: &CovBranch) -> (Self, Self) {
        let (true_branch, false_branch) = parse_branch(func_state);

        let true_bucket = Self::calculate_bucket_count(func_state[4]);
        let false_bucket = Self::calculate_bucket_count(func_state[5]);

        let true_state = Self::new(true_branch, true_bucket);
        let false_state = Self::new(false_branch, false_bucket);
        (true_state, false_state)
    }

    pub fn clear_bucket(mut self) -> Self {
        self.bucket = BUCKET_MASK;
        self
    }

    pub fn get_branch(&self) -> Branch {
        self.branch
    }

    fn check_exponential_new(&self, bucket: BucketType) -> bool {
        if self.bucket & bucket > 0 {
            return true;
        }
        false
    }

    /// Check there is an absolute new appeared branch.
    fn check_absolute_new(&self, bucket: BucketType) -> bool {
        if self.bucket == BUCKET_MASK && bucket != 0 {
            return true;
        }
        false
    }

    pub fn check_new(&self, func_state: &BranchState) -> bool {
        let bucket = func_state.bucket;
        if get_config().exponent_branch {
            self.check_exponential_new(bucket)
        } else {
            self.check_absolute_new(bucket)
        }
    }

    pub fn merge(&mut self, func_state: &BranchState) {
        self.bucket &= !func_state.bucket;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FuncBranches {
    branches: Vec<BranchState>,
}

impl FuncBranches {
    pub fn new(branches: Vec<BranchState>) -> Self {
        Self { branches }
    }

    pub fn get_branches(&self) -> &Vec<BranchState> {
        &self.branches
    }

    pub fn get_branches_mut(&mut self) -> &mut Vec<BranchState> {
        &mut self.branches
    }

    pub fn get_branch_status(&self) -> (u32, u32) {
        let mut covered = 0_u32;
        let mut total = 0_u32;
        for branch in &self.branches {
            if branch.bucket != BUCKET_MASK {
                covered += 1;
            }
            total += 1;
        }
        (covered, total)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct GlobalBranches {
    branches: HashMap<String, FuncBranches>,
}

impl Default for GlobalBranches {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalBranches {
    pub fn new() -> Self {
        Self {
            branches: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    pub fn get_entity(&self) -> &HashMap<String, FuncBranches> {
        &self.branches
    }

    pub fn clear(&mut self) {
        self.branches.clear();
    }

    fn init(&mut self, coverage: &CodeCoverage) {
        for func_cov in coverage.iter_function_covs() {
            let func_name = func_cov.get_name();
            let func_branches = &func_cov.branches;
            let mut branches = Vec::new();
            for branch_state in func_branches {
                let (true_branch, false_branch) = BranchState::from_llvm_cov(branch_state);
                branches.push(true_branch.clear_bucket());
                branches.push(false_branch.clear_bucket());
            }
            let func_branches = FuncBranches::new(branches);
            if self.branches.contains_key(func_name) {
                continue;
            }
            self.branches.insert(func_name.to_string(), func_branches);
        }
    }

    pub fn has_new(&mut self, coverage: &CodeCoverage) -> HashMap<String, Vec<BranchState>> {
        if self.is_empty() {
            self.init(coverage);
        }
        let mut new_branches: HashMap<String, Vec<BranchState>> = HashMap::new();
        let mut visited = HashSet::new();
        for func in coverage.iter_function_covs() {
            let func_name = func.get_name();
            if visited.contains(func_name) {
                continue;
            }
            visited.insert(func_name);
            let func_states = llvm_branches_to_internal(&func.branches);
            if let Some(global_states) = self.branches.get(func_name) {
                let has_new = Self::check_branch_states(global_states, &func_states);
                if !has_new.is_empty() {
                    new_branches.insert(func_name.to_string(), has_new);
                }
            } else {
                log::error!("cannot found {func_name} in branch tracking, maybe there is name mangling issue");
            }
        }
        new_branches
    }

    pub fn merge(&mut self, new_branches: &HashMap<String, Vec<BranchState>>) {
        for (func, new_branches) in new_branches.iter() {
            if let Some(global_states) = self.branches.get_mut(func) {
                Self::merge_branch_states(global_states, new_branches);
            }
        }
    }

    pub fn check_branch_states(
        global_states: &FuncBranches,
        func_branches: &[BranchState],
    ) -> Vec<BranchState> {
        let global_states = global_states.get_branches();
        assert_eq!(global_states.len(), func_branches.len());

        let mut new_branches: Vec<BranchState> = Vec::new();
        let branch_len = global_states.len();
        for i in 0..branch_len {
            let global_state = &global_states[i];
            let func_state = &func_branches[i];
            let has_new = global_state.check_new(func_state);
            if has_new {
                new_branches.push(func_state.clone());
            }
        }
        new_branches
    }

    pub fn merge_branch_states(global_states: &mut FuncBranches, new_branches: &Vec<BranchState>) {
        for global_state in global_states.get_branches_mut() {
            let global_branch = global_state.get_branch();
            for func_state in new_branches {
                let func_branch = func_state.get_branch();
                if global_branch == func_branch {
                    global_state.merge(func_state)
                }
            }
        }
    }

    pub fn compute_branch_coverage(&self) -> (usize, usize) {
        let mut covered_branch = 0;
        let mut total_branch = 0;
        for func_state in self.branches.values() {
            for branch_state in func_state.get_branches() {
                if branch_state.bucket != BUCKET_MASK {
                    covered_branch += 1;
                }
                total_branch += 1;
            }
        }
        (covered_branch, total_branch)
    }

    pub fn get_covered_branch(&self) -> Vec<Branch> {
        let mut covered = Vec::new();
        for func_state in self.branches.values() {
            for branch_state in func_state.get_branches() {
                if branch_state.bucket != BUCKET_MASK {
                    covered.push(branch_state.branch);
                }
            }
        }
        covered
    }

    pub fn compute_func_branch_status(&self, func: &str) -> (u32, u32) {
        if let Some(func_branch) = self.branches.get(func) {
            return func_branch.get_branch_status();
        }
        (0, 0)
    }

    /// compute the recursive code coverage inside a function
    pub fn compute_recursive_func_coverage(
        &self,
        func: &str,
        cov_cache: &HashMap<String, (u32, u32)>,
    ) -> eyre::Result<f32> {
        if let Some((covered, total)) = cov_cache.get(func) {
            if covered == &0 && total != &0 {
                return Ok(0_f32);
            }
        }
        let mut visited = HashSet::new();
        let (covered_branches, total_branches) =
            self.get_func_branch_coverage(func, cov_cache, &mut visited)?;
        if total_branches == 0 {
            if let Some(exec_count) = get_exec_counter_value(func) {
                if exec_count == 0 {
                    return Ok(0_f32);
                } else {
                    return Ok(1_f32);
                }
            }
            return Ok(0_f32);
        }
        let func_coverage = covered_branches as f32 / total_branches as f32;
        Ok(func_coverage)
    }

    fn get_func_branch_coverage(
        &self,
        func: &str,
        cov_cache: &HashMap<String, (u32, u32)>,
        visited: &mut HashSet<String>,
    ) -> eyre::Result<(u32, u32)> {
        visited.insert(func.to_string());
        if let Some((func_covered, func_total)) = cov_cache.get(func) {
            let callees = get_lib_call_graph().get_direct_callees(func);
            let (callee_covered, callee_total) =
                self.compute_callees_branch_coverage(callees, cov_cache, visited)?;
            let branch = (func_covered + callee_covered, func_total + callee_total);
            return Ok(branch);
        }
        // for standard library apis, directly return zeros.
        Ok((0, 0))
    }

    /// compute the branch coverage for all callees. visited is avoid to count the coverage for duplicated calles, each callee only count once.
    fn compute_callees_branch_coverage(
        &self,
        callees: Vec<&str>,
        cov_cache: &HashMap<String, (u32, u32)>,
        visited: &mut HashSet<String>,
    ) -> eyre::Result<(u32, u32)> {
        let mut covered_branches = 0_u32;
        let mut num_branches = 0_u32;
        for callee in callees {
            if visited.contains(callee) {
                continue;
            }
            let (covered, total) = self.get_func_branch_coverage(callee, cov_cache, visited)?;
            covered_branches += covered;
            num_branches += total;
        }
        let branch = (covered_branches, num_branches);
        Ok(branch)
    }
}

fn llvm_branches_to_internal(llvm_branches: &Vec<CovBranch>) -> Vec<BranchState> {
    let mut func_branches = Vec::new();
    for llvm_branch in llvm_branches {
        let (true_branch, false_branch) = BranchState::from_llvm_cov(llvm_branch);
        func_branches.push(true_branch);
        func_branches.push(false_branch);
    }
    func_branches
}

#[cfg(test)]
mod tests {

    use crate::config::CONFIG_INSTANCE;

    use super::*;

    #[test]
    fn test_absolute_new_branch() {
        crate::config::Config::init_test("cJSON");
        let mut config = CONFIG_INSTANCE.get().unwrap().write().unwrap();
        config.exponent_branch = false;

        let branch: Branch = [0, 0, 0, 0, 0, 0, 0, 0];
        let mut global_branch = BranchState::new(branch, BUCKET_MASK);
        let exec_count = 10;
        let bucket = BranchState::calculate_bucket_count(exec_count);
        let trace_state: BranchState = BranchState::new(branch, bucket);
        let has_new = global_branch.check_new(&trace_state);
        assert!(has_new);

        global_branch.merge(&trace_state);
        let has_new = global_branch.check_new(&trace_state);
        assert!(!has_new);

        let exec_count = 20;
        let bucket = BranchState::calculate_bucket_count(exec_count);
        let trace_state: BranchState = BranchState::new(branch, bucket);
        let has_new = global_branch.check_new(&trace_state);
        assert!(!has_new);
    }

    #[test]
    fn test_exponent_new_branch() {
        crate::config::Config::init_test("cJSON");
        let mut config = CONFIG_INSTANCE.get().unwrap().write().unwrap();
        config.exponent_branch = true;

        let branch: Branch = [0, 0, 0, 0, 0, 0, 0, 0];
        let mut global_branch = BranchState::new(branch, BUCKET_MASK);
        let exec_count = 10;
        let bucket = BranchState::calculate_bucket_count(exec_count);
        let trace_state: BranchState = BranchState::new(branch, bucket);
        let has_new = global_branch.check_new(&trace_state);
        assert!(has_new);

        global_branch.merge(&trace_state);
        let has_new = global_branch.check_new(&trace_state);
        assert!(!has_new);

        let exec_count = 20;
        let bucket = BranchState::calculate_bucket_count(exec_count);
        let trace_state: BranchState = BranchState::new(branch, bucket);
        let has_new = global_branch.check_new(&trace_state);
        assert!(has_new);
    }
}
