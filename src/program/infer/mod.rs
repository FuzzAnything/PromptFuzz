pub mod dynamic_infer;
pub mod static_infer;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use eyre::Result;

use crate::deopt::Deopt;

/// a tuple of relations between args: (array_pos, int_pos)
pub type ArgTuple = (usize, usize);
pub type APIConstraints = HashMap<String, Vec<Constraint>>;

#[derive(Debug, PartialEq, Eq, Hash, Clone, serde::Serialize, serde::Deserialize)]
pub enum Constraint {
    ArrayLen(ArgTuple),
    WeakArrayLen(ArgTuple),
    ArrayIndex(ArgTuple),
    /// argtuple cannot be any constraint
    Format(usize),
    FileName(usize),
    Invalid(ArgTuple),
    // integer constraints
    AllocSize(usize),
    FileDesc(usize),
    LoopCount(usize),
}

impl Constraint {
    pub fn get_array_arg(&self) -> usize {
        match self {
            Constraint::ArrayLen(tuple) => tuple.0,
            Constraint::ArrayIndex(tuple) => tuple.0,
            Constraint::WeakArrayLen(tuple) => tuple.0,
            Constraint::AllocSize(pos) => *pos,
            Constraint::FileName(pos) => *pos,
            Constraint::FileDesc(pos) => *pos,
            Constraint::Format(pos) => *pos,
            Constraint::Invalid(tuple) => tuple.0,
            Constraint::LoopCount(pos) => *pos,
        }
    }

    pub fn get_integer_arg(&self) -> usize {
        match self {
            Constraint::ArrayLen(tuple) => tuple.1,
            Constraint::ArrayIndex(tuple) => tuple.1,
            Constraint::WeakArrayLen(tuple) => tuple.1,
            Constraint::AllocSize(pos) => *pos,
            Constraint::FileName(pos) => *pos,
            Constraint::FileDesc(pos) => *pos,
            Constraint::Format(pos) => *pos,
            Constraint::Invalid(tuple) => tuple.1,
            Constraint::LoopCount(pos) => *pos,
        }
    }

    pub fn get_arg_tuple(&self) -> Option<&ArgTuple> {
        match self {
            Constraint::ArrayLen(tuple) => Some(tuple),
            Constraint::ArrayIndex(tuple) => Some(tuple),
            Constraint::Invalid(tuple) => Some(tuple),
            Constraint::WeakArrayLen(tuple) => Some(tuple),
            Constraint::FileName(_) => None,
            Constraint::FileDesc(_) => None,
            Constraint::Format(_) => None,
            Constraint::AllocSize(_) => None,
            Constraint::LoopCount(_) => None,
        }
    }
}

/// Retrieve the constraint on the arg_pos of the func call.
pub fn get_array_constraint<'a>(
    func: &str,
    arg_pos: &usize,
    constraints: &'a APIConstraints,
) -> Option<&'a Constraint> {
    if let Some(func_constrains) = constraints.get(func) {
        for constraint in func_constrains {
            let (array_pos, _) = match constraint {
                Constraint::ArrayLen(tuple) => tuple,
                Constraint::ArrayIndex(tuple) => tuple,
                Constraint::Invalid(tuple) => tuple,
                _ => continue,
            };
            if array_pos == arg_pos {
                return Some(constraint);
            }
        }
    }
    None
}

pub fn infer_constraints(programs: &Vec<PathBuf>, deopt: &Deopt) -> Result<APIConstraints> {
    let mut constraints: HashMap<String, Vec<Constraint>> = HashMap::new();
    for program in programs {
        if let Err(e) = static_infer::infer_constraints(program, deopt, &mut constraints) {
            log::warn!("Skip program for static constraint infer: {:?} ({})", program, e);
        }
    }
    let mut refined = static_infer::refine_constraints(constraints.clone());
    dynamic_infer::infer(&mut refined, deopt)?;
    save_constraints(&refined, deopt)?;
    Ok(constraints)
}

fn save_constraints(constraints: &APIConstraints, deopt: &Deopt) -> Result<()> {
    let save_path: PathBuf = [deopt.get_library_misc_dir()?, "constraint.json".into()]
        .iter()
        .collect();
    let to_str = serde_json::to_string(constraints)?;
    std::fs::write(save_path, to_str)?;
    Ok(())
}

pub fn load_constraints(deopt: &Deopt) -> Result<APIConstraints> {
    let save_path: PathBuf = [deopt.get_library_misc_dir()?, "constraint.json".into()]
        .iter()
        .collect();
    let from_str = std::fs::read_to_string(save_path)?;
    let constraints: APIConstraints = serde_json::from_str(&from_str)?;
    Ok(constraints)
}
