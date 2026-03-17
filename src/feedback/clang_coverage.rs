use eyre::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{deopt::utils::{get_file_dirname, is_dir_empty}, feedback::observer::Observer};
use crate::execution::Executor;

use super::branches::{parse_branch, Branch};

#[derive(Debug, Deserialize, Serialize)]
pub struct CodeCoverage {
    data: Vec<CovObject>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CovObject {
    #[serde(skip_deserializing)]
    pub fuzzer_lines: Vec<CovLine>,
    #[serde(default)]
    pub functions: Vec<CovFunction>,
    totals: CovSummary,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CovFunction {
    #[serde(skip_deserializing)]
    pub lines: Vec<CovLine>,
    pub branches: Vec<CovBranch>,
    pub count: usize,
    pub name: String,
}

impl CovFunction {
    pub fn get_name(&self) -> &str {
        if let Some(seq) = self.name.rfind(':') {
            return &self.name[seq + 1..];
        }
        &self.name
    }

    pub fn compute_line_coverage(&self) -> f32 {
        if self.lines.is_empty() {
            return 0_f32;
        }
        let mut covered = 0;
        for line in &self.lines {
            let count = &line[1];
            if count > &0 {
                covered += 1;
            }
        }
        let ratio: f32 = covered as f32 / self.lines.len() as f32;
        ratio
    }

    pub fn compute_branch_coverage(&self) -> f32 {
        if self.branches.is_empty() {
            if self.count == 0 {
                return 0_f32;
            }
            return 1_f32;
        }
        let mut covered = 0;
        for branch in &self.branches {
            if branch.get_true_count() > &0 {
                covered += 1;
            }
            if branch.get_false_count() > &0 {
                covered += 1;
            }
        }
        let ratio: f32 = covered as f32 / (self.branches.len() * 2) as f32;
        ratio
    }

    pub fn get_covered_banch(&self) -> Vec<Branch> {
        let mut covered: Vec<Branch> = Vec::new();
        for branch in &self.branches {
            covered.extend(branch.get_covered_branch());
        }
        covered
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CovSummary {
    branches: CovData,
    functions: CovData,
    lines: CovData,
    regions: CovData,
}

impl CovSummary {
    pub fn count_covered_branches(&self) -> usize {
        self.branches.covered
    }

    pub fn count_total_branches(&self) -> usize {
        self.branches.count
    }

    pub fn count_covered_functions(&self) -> usize {
        self.functions.covered
    }

    pub fn count_covered_lines(&self) -> usize {
        self.lines.covered
    }

    pub fn count_covered_regions(&self) -> usize {
        self.regions.covered
    }

    pub fn has_new_coverage(&self, pre: &Self) -> bool {
        self.count_covered_branches() > pre.count_covered_branches()
            || self.count_covered_functions() > pre.count_covered_functions()
            || self.count_covered_lines() > pre.count_covered_lines()
            || self.count_covered_regions() > pre.count_covered_regions()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CovData {
    count: usize,
    covered: usize,
    _notcovered: Option<usize>,
    percent: f32,
}

// [line_start, col_start, line_end, col_end, exec_count, false_count, fileid, expand_file_id, kind]
pub type CovBranch = [usize; 9];
pub trait BranchCount {
    fn get_true_count(&self) -> &usize;
    fn get_false_count(&self) -> &usize;
    fn get_covered_branch(&self) -> Vec<Branch>;
}

impl BranchCount for CovBranch {
    fn get_true_count(&self) -> &usize {
        &self[4]
    }

    fn get_false_count(&self) -> &usize {
        &self[5]
    }

    fn get_covered_branch(&self) -> Vec<Branch> {
        let (true_branch, false_branch) = parse_branch(self);

        let mut covered = Vec::new();
        if *self.get_true_count() > 0 {
            covered.push(true_branch);
        }
        if *self.get_false_count() > 0 {
            covered.push(false_branch);
        }
        covered
    }
}

// [line, count]
type CovLine = [usize; 2];

impl CodeCoverage {
    pub fn new(file: &Path) -> Result<Self> {
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        let cov: CodeCoverage = serde_json::from_reader(reader)?;
        Ok(cov)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let cov: CodeCoverage = serde_json::from_slice(bytes)?;
        Ok(cov)
    }

    pub fn get_total_summary(&self) -> &CovSummary {
        &self.data[0].totals
    }

    pub fn get_covered_branch(&self) -> Vec<Branch> {
        let mut covered = Vec::new();
        for func_cov in &self.data[0].functions {
            covered.extend(func_cov.get_covered_banch());
        }
        covered
    }

    pub fn get_function_cov(&self, func: &str) -> Option<&CovFunction> {
        self.data[0]
            .functions
            .iter()
            .find(|&func_cov| func_cov.get_name() == func)
    }

    pub fn get_function_cov_mut(&mut self, func: &str) -> Option<&mut CovFunction> {
        self.data[0]
            .functions
            .iter_mut()
            .find(|func_cov| func_cov.get_name() == func)
    }

    pub fn iter_function_covs(&self) -> core::slice::Iter<'_, CovFunction> {
        let iter = self.data[0].functions.iter();
        iter
    }

    pub fn set_fuzzer_lines(mut self, cov_lines: Vec<CovLine>) -> Self {
        self.data[0].fuzzer_lines = cov_lines;
        self
    }

    fn get_count_of_fuzzer_line(&self, line: usize) -> usize {
        for cov_line in &self.data[0].fuzzer_lines {
            if line == cov_line[0] {
                return cov_line[1];
            }
        }
        0
    }

    /// test whether all the provided lines are covered in before executions.
    pub fn are_lines_all_covered(&self, lines: Vec<usize>) -> bool {
        for line in lines {
            let count = self.get_count_of_fuzzer_line(line);
            if count == 0 {
                return false;
            }
        }
        true
    }

    pub fn has_new_coverage(&self, pre_cov: &Self) -> bool {
        self.get_total_summary()
            .has_new_coverage(pre_cov.get_total_summary())
    }

    pub fn display(&self) {
        let summary = self.get_total_summary();
        println!(
            "Covered Regions: {}/{}({})",
            summary.regions.covered, summary.regions.count, summary.regions.percent
        );
        println!(
            "Covered Funtions: {}/{}({})",
            summary.functions.covered, summary.functions.count, summary.functions.percent
        );
        println!(
            "Covered Lines: {}/{}({})",
            summary.lines.covered, summary.lines.count, summary.lines.percent
        );
        println!(
            "Covered Branches: {}/{}({})",
            summary.branches.covered, summary.branches.count, summary.branches.percent
        );
    }

    fn to_csv(&self) -> String {
        let summary = self.get_total_summary();
        format!(
            "{}({}), {}({}), {}({}), {}({})",
            summary.regions.covered,
            summary.regions.percent,
            summary.functions.covered,
            summary.functions.percent,
            summary.lines.covered,
            summary.lines.percent,
            summary.branches.covered,
            summary.branches.percent
        )
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct GlobalFeature {
    features: HashSet<String>,
}

impl GlobalFeature {
    pub fn insert_feature(&mut self, fe: String) -> bool {
        self.features.insert(fe)
    }

    pub fn init_by_corpus(executor: &Executor, fuzzer: &Path) -> Result<Self> {
        let mut gf = Self::default();
        let shared_corpus = executor.deopt.get_library_shared_corpus_dir()?;
        if is_dir_empty(&shared_corpus)? {
            return Ok(gf)
        }

        let sancov_dict = Executor::collect_sancov_from_corpus(fuzzer, &shared_corpus)?;
        for (_, sancov) in sancov_dict {
            for fe in sancov.covered_points {
                if gf.features.contains(&fe) {
                    continue;
                }
                gf.insert_feature(fe);
            }
        }
        Ok(gf)
    }
}

impl Executor {
    pub fn convert_profraw_to_profdata(&self, profraw: &Path, profdata: &Path) -> Result<()> {
        let output = Command::new("llvm-profdata")
            .arg("merge")
            .arg("-sparse")
            .arg(profraw)
            .arg("-o")
            .arg(profdata)
            .output()?;
        if !output.status.success() {
            eyre::bail!("obtain coverage from profraw fail! :{profraw:?}")
        }
        Ok(())
    }

    pub fn merge_profdata(profraw_files: &Vec<PathBuf>, profdata: &Path) -> Result<()> {
        if profraw_files.is_empty() {
            log::warn!("profraw_files is empty, skip merging profdata.");
            return Ok(())
        }
        let mut output = Command::new("llvm-profdata");
        let cmd = output.arg("merge").arg("-sparse");
        for prof_file in profraw_files {
            cmd.arg(prof_file);
        }
        let output = cmd.arg("-o").arg(profdata).output()?;
        if !output.status.success() {
            eyre::bail!("obtain coverage from profraw fail! :{profraw_files:?}")
        }
        Ok(())
    }

    /// report the code coverage for a profile data.
    pub fn obtain_cov_from_profdata(&self, profdata: &Path) -> Result<CodeCoverage> {
        // library so linked with code coverage instrumentation.
        let cov_lib = crate::deopt::utils::get_cov_lib_path(&self.deopt, true);
        // view coverage report
        let output = Command::new("llvm-cov")
            .arg("export")
            .arg(cov_lib)
            .arg("--skip-expansions")
            .arg(format!("--instr-profile={}", profdata.to_string_lossy()))
            .stdout(Stdio::piped())
            .output()?;
        if !output.status.success() {
            eyre::bail!("failed to collect code coverage from {profdata:?}\n cmd: {output:?}")
        }
        let json_output = output.stdout.as_slice();
        let cov: CodeCoverage = CodeCoverage::from_slice(json_output)?;
        Ok(cov)
    }

    pub fn obtain_cov_summary_from_prodata(&self, profdata: &Path) -> Result<CodeCoverage> {
        // library so linked with code coverage instrumentation.
        let cov_lib = crate::deopt::utils::get_cov_lib_path(&self.deopt, true);
        // view coverage report
        let output = Command::new("llvm-cov")
            .arg("export")
            .arg(cov_lib)
            .arg("--skip-expansions")
            .arg("--summary-only")
            .arg(format!("--instr-profile={}", profdata.to_string_lossy()))
            .stdout(Stdio::piped())
            .output()?;
        if !output.status.success() {
            eyre::bail!("failed to collect code coverage from {profdata:?}\n cmd: {output:?}")
        }
        let json_output = output.stdout.as_slice();
        let cov: CodeCoverage = CodeCoverage::from_slice(json_output)?;
        Ok(cov)
    }

    /// Obtain the line coverage of Fuzzer's code
    pub fn obtain_fuzzer_cov_from_profdata(
        &self,
        profdata: &Path,
        program: &Path,
        binary_cov: &Path,
    ) -> Result<Vec<CovLine>> {
        let output = Command::new("llvm-cov")
            .arg("export")
            .arg(binary_cov)
            .arg(format!("--instr-profile={}", profdata.to_string_lossy()))
            .arg("-format=lcov")
            .arg("--ignore-filename-regex=.*output/build/.*")
            .stdout(Stdio::piped())
            .output()?;
        if !output.status.success() {
            eyre::bail!("failed to collect code coverage from {profdata:?}\n cmd: {output:?}")
        }
        let lcov = String::from_utf8_lossy(&output.stdout).to_string();
        let cov_lines = utils::parse_fuzzer_lcov_data(&lcov, program)?;
        Ok(cov_lines)
    }

    pub fn collect_lib_cov_per_fuzzer(&self, fuzzer_dir: &Path) -> Result<()> {
        log::trace!("collect cov for fuzzer: {fuzzer_dir:?}");
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

        let fuzzer_code: PathBuf = [PathBuf::from(fuzzer_dir), "fuzzer.cc".into()]
            .iter()
            .collect();
        let fuzzer_binary: PathBuf = [PathBuf::from(fuzzer_dir), "fuzzer".into()]
            .iter()
            .collect();
        let fuzzer_sancov: PathBuf = [PathBuf::from(fuzzer_dir), "fuzzer_sancov".into()]
            .iter()
            .collect();

        // recover the pruned error branches for collecting coverage
        let content = std::fs::read_to_string(&fuzzer_code)?;
        let content = content.replace("//", "");
        std::fs::write(fuzzer_code, content)?;

        // minimize the corpus
        self.compile_lib_fuzzers(
            fuzzer_dir,
            &fuzzer_binary,
            crate::execution::Compile::FUZZER,
        )?;
        let corpus: PathBuf = [PathBuf::from(fuzzer_dir), "corpus".into()]
            .iter()
            .collect();
        let minimized_corpus: PathBuf = [PathBuf::from(fuzzer_dir), "minimized_corpus".into()]
            .iter()
            .collect();
        if !minimized_corpus.exists() {
            self.minimize_corpus_by_efficient_sancov(&fuzzer_sancov, &minimized_corpus, &corpus)?;
            std::fs::remove_dir_all(corpus)?;
        }

        // compile the fuzzers with coverage and run it on minimized corpus.
        let fuzzer_binary: PathBuf = [PathBuf::from(fuzzer_dir), "fuzzer_cov".into()]
            .iter()
            .collect();
        self.compile_lib_fuzzers(
            fuzzer_dir,
            &fuzzer_binary,
            crate::execution::Compile::COVERAGE,
        )?;

        // run fuzzer with cov on each corpus file.
        let profdata: PathBuf = crate::deopt::Deopt::get_coverage_file_by_dir(fuzzer_dir);
        self.execute_cov_fuzzer_pool(&fuzzer_binary, vec![&minimized_corpus], &profdata)?;
        Ok(())
    }

    pub fn collect_lib_cov_all_fuzzers(&self, fuzzers_dir: &Path) -> Result<()> {
        let mut cov_data = Vec::new();
        for entry in std::fs::read_dir(fuzzers_dir)? {
            let fuzzer_dir = entry?.path();
            let res = self.collect_lib_cov_per_fuzzer(&fuzzer_dir);
            if res.is_ok() {
                let profdata: PathBuf = crate::deopt::Deopt::get_coverage_file_by_dir(&fuzzer_dir);
                log::debug!("collect fuzzer cov finished: {fuzzer_dir:?}");
                cov_data.push(profdata);
            } else {
                log::error!("{:?}", res.err().unwrap());
            }
        }

        let mut binding = Command::new("llvm-profdata");
        let output = binding.current_dir(fuzzers_dir).arg("merge").arg("-sparse");
        for data in cov_data {
            output.arg(data);
        }
        let output = output.arg("-o").arg("default.profdata").output()?;
        if !output.status.success() {
            eyre::bail!("merge cov_data fail!")
        }
        Ok(())
    }

    pub fn report_lib_cov_all_fuzzers(&self, fuzzers_dir: &Path) -> Result<()> {
        let mut coverages: Vec<(CodeCoverage, PathBuf)> = Vec::new();
        let total_profdata: PathBuf = [PathBuf::from(fuzzers_dir), "default.profdata".into()]
            .iter()
            .collect();
        let cov = self.obtain_cov_from_profdata(&total_profdata)?;
        println!("Total library coverage: {total_profdata:?}");
        cov.display();
        coverages.push((cov, PathBuf::from(fuzzers_dir)));

        for fuzzer in crate::deopt::utils::read_sort_dir(fuzzers_dir)? {
            if fuzzer.is_file() {
                continue;
            }
            let fuzzer_profdata: PathBuf =
                [fuzzer.clone(), "default.profdata".into()].iter().collect();
            let cov = self.obtain_cov_from_profdata(&fuzzer_profdata)?;
            println!("Fuzzer library coverage: {fuzzer:?}");
            cov.display();
            coverages.push((cov, fuzzer));
        }
        let csv_save_path = self.deopt.get_library_coverage_path()?;
        utils::save_code_coverage_to_csv(coverages, &csv_save_path)?;
        Ok(())
    }

    pub fn calculate_seed_coverage(&self) -> Result<()> {
        log::info!("Re-calculate the code coverage for seeds");
        let seed_dir = self.deopt.get_library_seed_dir()?;
        let seeds = crate::deopt::utils::read_sort_dir(&seed_dir)?;
        let mut observer = Observer::new(&self.deopt);

        for seed in &seeds {
            let seed_id = crate::program::Program::load_from_path(seed)?.id;
            self.eval_seed_coverage(seed_id)?;
            let coverage = self.deopt.get_seed_coverage(seed_id)?;
            let covered_branch = coverage.get_total_summary().count_covered_branches();
            log::info!("seed: {seed_id}, covered_branch: {covered_branch}");
            observer.merge_coverage(&coverage);
            log::info!("seed: {seed_id}, {}", observer.dump_global_states());
        }
        log::info!(
            "Recompute finished. Current: {}",
            observer.dump_global_states()
        );
        Ok(())
    }
}

pub mod utils {
    use super::*;
    use crate::{analysis::cfg::CFGBuilder, deopt::Deopt};

    /// Sanitize program by checking whether the code of fuzzer are covered enough.
    /// The path in CFG having the maximum calls is considered as the main function routine.
    /// Thus all api calls lies in the path having the maximum calls should be covered,
    ///     otherwise the misuses of uncovererd APIs may be ignored.
    pub fn sanitize_by_fuzzer_coverage(
        fuzzer_path: &Path,
        deopt: &Deopt,
        coverage: &CodeCoverage,
    ) -> Result<bool> {
        let ast =
            Executor::extract_func_ast(fuzzer_path, vec![], deopt, "LLVMFuzzerTestOneInput", true)?;
        let cfg = CFGBuilder::build_cfg(ast)?;
        //cfg.dump_to_file(&fuzzer_path.with_extension("png"), false)?;
        let max_callee_paths = cfg.visit_max_caller_path()?;
        for callee_path in max_callee_paths {
            if coverage.are_lines_all_covered(callee_path) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn dump_fuzzer_coverage(fuzzer_binary: &Path) -> Result<String> {
        let fuzzer_dir = get_file_dirname(fuzzer_binary);
        let profdata: PathBuf = crate::deopt::Deopt::get_coverage_file_by_dir(&fuzzer_dir);
        if !profdata.exists() {
            eyre::bail!(
                "Get coverage sanitizer message failed! profdata does not exist! {profdata:?}"
            )
        }
        let output = Command::new("llvm-cov")
            .current_dir(fuzzer_dir)
            .arg("show")
            .arg(fuzzer_binary)
            .arg(format!("--instr-profile={}", profdata.to_string_lossy()))
            .arg("-name=LLVMFuzzerTestOneInput")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !output.status.success() {
            eyre::bail!(
                "Get coverage sanitizer message failed! {}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
        let msg = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(msg)
    }

    /// parse line coverage of fuzzer (not library) from lcov data
    pub fn parse_fuzzer_lcov_data(lcov: &str, file: &Path) -> Result<Vec<CovLine>> {
        let mut de = crate::program::serde::Deserializer::from_input(lcov);
        de.consume_token_until(file.to_str().unwrap())?;

        let mut cov_lines = Vec::new();
        de.eat_token_until("FNH")?;
        de.eat_token_until("DA:")?;
        while de.is_next_token("DA") {
            de.eat_token("DA:")?;
            let line: usize = de.parse_number()?;
            de.eat_token(",")?;
            let count: usize = de.parse_number()?;
            cov_lines.push([line, count]);
        }
        Ok(cov_lines)
    }

    /// parse line coverage of library from lcov data
    pub fn parse_lcov_data(lcov: &str, coverage: &mut CodeCoverage) -> Result<()> {
        let mut de = crate::program::serde::Deserializer::from_input(lcov);
        // fn: line of function begion, function name;
        while de.is_next_token("SF:") {
            let mut fns: Vec<(usize, &str)> = Vec::new();
            de.eat_token("SF:")?;
            let _sf = de.consume_token_until("\n")?;
            // parse function lines
            while de.is_next_token("FN:") {
                de.eat_token("FN:")?;
                let line: usize = de.parse_number()?;
                de.eat_token(",")?;
                let f_name = de.consume_token_until("\n")?;
                fns.push((line, f_name));
            }
            fns.sort_by(|a, b| a.0.cmp(&b.0));

            let mut line_counts: Vec<(usize, usize)> = Vec::new();
            de.eat_token_until("FNH:")?;
            de.eat_token_until("DA:")?;
            while de.is_next_token("DA:") {
                de.eat_token("DA:")?;
                let line: usize = de.parse_number()?;
                de.eat_token(",")?;
                let count: usize = de.parse_number()?;
                line_counts.push((line, count));
            }

            let mut i = 0;
            let mut j = 0;
            while i < fns.len() && j < line_counts.len() {
                let (cur_begin, f_name) = fns[i];
                let (line, count) = line_counts[j];
                if line < cur_begin {
                    j += 1;
                    continue;
                }
                // if cur fn is the last one
                if i == fns.len() - 1 {
                    let func_cov = coverage.get_function_cov_mut(f_name).unwrap();
                    func_cov.lines.push([line, count]);
                    j += 1;
                } else {
                    let (next_begin, _) = fns[i + 1];
                    // if line still in the range of f_name
                    if line < next_begin {
                        let func_cov = coverage
                            .get_function_cov_mut(f_name)
                            .unwrap_or_else(|| panic!("cannot obtain coverage of :{f_name}"));
                        func_cov.lines.push([line, count]);
                        j += 1;
                    // else get the next fn
                    } else {
                        i += 1;
                    }
                }
            }
            de.consume_token_until("end_of_record")?;
        }
        Ok(())
    }

    pub fn save_code_coverage_to_csv(
        coverages: Vec<(CodeCoverage, PathBuf)>,
        save_file: &Path,
    ) -> Result<()> {
        let mut csv_content = String::new();
        csv_content.push_str("Fuzzer, Regions, Functions, Lines, Branches\n");
        for (cov, fuzzer_name) in coverages {
            let fuzzer_name = fuzzer_name
                .file_name()
                .ok_or_else(|| eyre::eyre!("invalid fuzzer_name: {fuzzer_name:?}"))?
                .to_string_lossy()
                .to_string();
            csv_content.push_str(&format!("{fuzzer_name}, {}\n", cov.to_csv()));
        }
        std::fs::write(save_file, csv_content)?;
        log::info!("Code coverage saved into {save_file:?}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::deopt::Deopt;

    use super::*;

    #[test]
    fn test_parse_coverage_summary() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let profdata: PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "corpora",
            "default.profdata",
        ]
        .iter()
        .collect();
        let executor = Executor::new(&deopt)?;
        let cov = executor.obtain_cov_summary_from_prodata(&profdata)?;
        let summary = cov.get_total_summary();
        assert_eq!(summary.count_covered_branches(), 185);
        assert_eq!(summary.count_covered_functions(), 13);
        assert_eq!(summary.count_covered_lines(), 331);
        assert_eq!(summary.count_covered_regions(), 353);
        Ok(())
    }

    #[test]
    fn test_parse_code_coverage() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let profdata: PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "corpora",
            "default.profdata",
        ]
        .iter()
        .collect();
        let executor = Executor::new(&deopt)?;
        let cov = executor.obtain_cov_from_profdata(&profdata)?;
        let gsv = cov.get_function_cov("cJSON_GetStringValue").unwrap();
        assert_eq!(
            gsv.lines,
            vec![
                [100, 110],
                [101, 110],
                [102, 90],
                [103, 90],
                [104, 90],
                [106, 20],
                [107, 110]
            ]
        );
        assert_eq!(gsv.compute_line_coverage(), 1_f32);
        Ok(())
    }

}
