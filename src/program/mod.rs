pub mod array;
pub mod gadget;
pub mod infer;
pub mod libfuzzer;
pub mod rand;
pub mod serde;
pub mod shim;
pub mod transform;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use self::gadget::FuncGadget;
use self::serde::{Deserialize, Deserializer};
use crate::ast::Visitor;
use crate::deopt::Deopt;
use crate::execution::Executor;
use crate::feedback::branches::Branch;
use eyre::Context;
use eyre::Result;
use once_cell::sync::OnceCell;
use regex::Regex;

static EXEC_COUNTER: OnceCell<RwLock<HashMap<String, u32>>> = OnceCell::new();

pub fn get_exec_counter_value(key: &str) -> Option<u32> {
    let guard = EXEC_COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .read()
        .unwrap();
    guard.get(key).copied()
}

pub fn set_exec_counter_value(key: String, value: u32) {
    let mut guard = EXEC_COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .write()
        .unwrap();
    guard.insert(key, value);
}

pub fn save_exec_counter(deopt: &Deopt) {
    let counter_path: PathBuf = [
        deopt.get_library_misc_dir().unwrap(),
        "exec_counter.json".into(),
    ]
    .iter()
    .collect();
    let guard = EXEC_COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .read()
        .unwrap();
    let json = serde_json::to_string(&*guard).unwrap();
    std::fs::write(counter_path, json).unwrap();
}

pub fn load_exec_counter(deopt: &Deopt) -> HashMap<String, u32> {
    let counter_path: PathBuf = [
        deopt.get_library_misc_dir().unwrap(),
        "exec_counter.json".into(),
    ]
    .iter()
    .collect();
    let content = std::fs::read_to_string(counter_path).unwrap_or_else(|_| {
        log::error!("Detected corrupt state of your last execution, please remove your library output in the `output` directory and restart");
        panic!("Detected corrupt state of your last execution, please remove your library output in the `output` directory and restart")
    });
    let counter: HashMap<String, u32> = serde_json::from_str(&content).unwrap();
    counter
}

#[derive(Default, Debug, Clone, ::serde::Deserialize, ::serde::Serialize)]
pub struct Quality {
    pub density: usize,
    pub unique_branches: HashMap<String, Vec<Branch>>,
    // the library api calls
    pub library_calls: Vec<String>,
    // the calls sequentially called in critical path.
    pub critical_calls: Vec<String>,
    pub visited: usize,
}

impl Quality {
    pub fn new(density: usize, library_calls: Vec<String>, critical_calls: Vec<String>) -> Self {
        Self {
            density,
            unique_branches: HashMap::new(),
            library_calls,
            critical_calls,
            visited: 0,
        }
    }

    pub fn set_unique_branches(&mut self, unique_branches: HashMap<String, Vec<Branch>>) {
        self.unique_branches = unique_branches;
    }

    pub fn get_nr_unique_branches(&self) -> usize {
        let mut nr_branches = 0;
        for branches in self.unique_branches.values() {
            nr_branches += branches.len();
        }
        nr_branches
    }

    pub fn compute_quality_score(&self) -> f32 {
        let top = self.density * (1 + self.unique_branches.len());
        let bottom = 1 + self.visited;
        top as f32 / bottom as f32
    }
}

#[derive(Default, Debug, Clone)]
pub struct Program {
    pub id: usize,
    pub combination: Vec<&'static FuncGadget>,
    pub statements: String,
    quality: Quality,
}

impl Program {
    pub fn new(input: &str) -> Self {
        let mut program = Program {
            statements: input.to_string(),
            ..Default::default()
        };
        // program.replace_return_stmts_with("return 0;").expect("fail to repalce return stmts with return 0;");
        program.strip_include_headers();
        program
    }

    /// load and deserialize program from raw_input.
    pub fn load_from_str(input: &str) -> eyre::Result<Program> {
        let mut de = Deserializer::from_input(input);
        Program::deserialize(&mut de)
    }

    /// load and instantiate program from path.
    pub fn load_from_path(entry: &Path) -> eyre::Result<Program> {
        log::trace!("load program from {entry:?}");
        let program = std::fs::read_to_string(entry).context(format!("{entry:#?}"))?;
        let program = Program::load_from_str(&program)?;
        Ok(program)
    }

    fn strip_include_headers(&mut self) {
        let mut stmts = vec![];
        for line in self.statements.lines() {
            if line.starts_with("#include") {
                continue;
            }
            stmts.push(line);
        }
        self.statements = stmts.join("\n");
    }

    fn _replace_return_stmts_with(&mut self, to: &str) -> eyre::Result<()> {
        let re = Regex::new(r"(return.*);").unwrap();
        if re.is_match(&self.statements) {
            let after = re.replace_all(&self.statements, to).to_string();
            _ = std::mem::replace(&mut self.statements, after);
        }
        Ok(())
    }

    /// Compute the quality of this generated program:
    ///   - Diveristy: number of API calls.
    ///   - Density: number of correlated API calls.
    ///   - Coverage: covered APIs in prompt.
    pub fn compute_quality(&self, deopt: &Deopt) -> eyre::Result<Quality> {
        let seed_path = deopt.get_succ_seed_path_by_id(self.id)?;
        let ast = Executor::extract_ast(&seed_path, vec![], deopt)?;
        let visitor = Visitor::new(ast.clone());

        // compute diversity
        let api_calls = visitor.get_library_call_names();
        for call in api_calls.iter() {
            if let Some(exec_count) = get_exec_counter_value(call) {
                set_exec_counter_value(call.to_string(), exec_count + 1);
            } else {
                set_exec_counter_value(call.to_string(), 1);
            }
        }
        save_exec_counter(deopt);
        // parse critical calls
        let cfg = crate::analysis::cfg::CFGBuilder::build_cfg(ast)?;
        let critical_paths = cfg.visit_max_caller()?;
        let critical_calls = if critical_paths.is_empty() {
            vec![]
        } else {
            critical_paths[0].clone()
        };
        // compute density
        let builder = crate::analysis::adg::ADGBuilder::new();
        let adg = builder.sparse_build(cfg).context(format!(
            "ADG build from program fialed:\n {}",
            self.statements
        ))?;
        let density = adg.compute_density();

        let quality = Quality::new(density, api_calls, critical_calls);
        Ok(quality)
    }

    pub fn update_quality(
        &mut self,
        unique_branches: HashMap<String, Vec<Branch>>,
        deopt: &Deopt,
    ) -> Result<()> {
        let mut quality = self.compute_quality(deopt)?;
        quality.set_unique_branches(unique_branches);
        self.set_quality(quality.clone());
        Ok(())
    }

    // Update the unique branches according the new coverage
    pub fn update_unique_branches(&mut self, coming_branches: &HashMap<String, Vec<Branch>>) {
        for unique_branch in self.quality.unique_branches.iter_mut() {
            let (func, branches) = unique_branch;
            if let Some(coming_func_branches) = coming_branches.get(func) {
                branches.retain(|branch| !coming_func_branches.contains(branch));
            }
        }
        self.quality
            .unique_branches
            .retain(|_, value| !value.is_empty());
    }

    pub fn set_unique_branches(&mut self, unique_branches: HashMap<String, Vec<Branch>>) {
        self.quality.unique_branches = unique_branches
    }

    pub fn set_quality(&mut self, quality: Quality) {
        self.quality = quality;
    }

    pub fn get_quality(&self) -> &Quality {
        &self.quality
    }

    pub fn get_weight(&self) -> f32 {
        self.quality.compute_quality_score()
    }

    pub fn convert_to_prompt(&self) -> Vec<String> {
        let calls: &Vec<String> = &self.get_quality().critical_calls;
        let mut prompt = Vec::new();
        for call in calls {
            if prompt.contains(call) {
                continue;
            }
            prompt.push(call.to_string())
        }
        prompt
    }

    pub fn increase_visited(&mut self) {
        self.quality.visited += 1
    }
}
