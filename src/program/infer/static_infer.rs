/// Statically infer the constraints of ArrayLength, ArrayIndex, Format and FileName.
use regex::Regex;

use crate::{
    ast::{loc::is_macro_stmt, Clang, CommomHelper, Node, Visitor},
    config::get_library_name,
    execution::Executor,
    program::gadget::get_func_gadget,
};

use self::utils::is_null_ptr;

use super::*;

pub fn add_function_constraint(
    func: &str,
    constraint: Constraint,
    constraints: &mut HashMap<String, Vec<Constraint>>,
) {
    log::debug!("found constraint: {func}, {constraint:?}");
    // func already has constraints, just add the constraint
    if let Some(func_constraints) = constraints.get_mut(func) {
        func_constraints.push(constraint);
    } else {
        // no constraints found with this func, insert the new constraint.
        let func_constraints = vec![constraint];
        constraints.insert(func.to_string(), func_constraints);
    }
}

pub fn infer_constraints(
    program: &Path,
    deopt: &Deopt,
    constraints: &mut HashMap<String, Vec<Constraint>>,
) -> Result<()> {
    log::trace!("infer constraint for program: {program:?}");
    let ast = Executor::extract_ast(program, vec![], deopt)?;
    let visitor: Visitor = Visitor::new(ast);
    let api_calls = visitor.visit_library_calls();

    for call in api_calls {
        let call_name = call.get_call_name();
        let array_pos = get_func_gadget(&call_name).unwrap().get_array_params_pos();
        for pos in array_pos {
            let array_arg = call.get_call_arg_stmts()[pos];
            if utils::is_file_name(array_arg, &visitor) {
                let constraint = Constraint::FileName(pos);
                add_function_constraint(&call_name, constraint, constraints);
                continue;
            }
            if utils::is_format_string(array_arg, &visitor) {
                let constraint = Constraint::Format(pos);
                add_function_constraint(&call_name, constraint, constraints);
                continue;
            }
        }

        let integer_pos = get_func_gadget(&call_name)
            .unwrap()
            .get_integer_params_pos();
        for pos in integer_pos {
            let integer_arg = call.get_call_arg_stmts()[pos];
            if utils::is_file_descriptor(integer_arg, &visitor) {
                let constraint = Constraint::FileDesc(pos);
                add_function_constraint(&call_name, constraint, constraints);
                continue;
            }
        }

        let arg_tuples = get_arrary_integer_arg_tuples(&call_name);
        for (array_pos, integer_pos) in arg_tuples {
            if array_pos == integer_pos {
                continue;
            }
            let call_arg_stmts = call.get_call_arg_stmts();
            if array_pos >= call_arg_stmts.len() || integer_pos >= call_arg_stmts.len() {
                continue;
            }
            let array_arg = strip_prefix(call.get_call_arg_stmts()[array_pos]);
            let integer_arg = strip_prefix(call.get_call_arg_stmts()[integer_pos]);

            // don't infer null pointer
            if utils::is_null_ptr(array_arg, &visitor) {
                continue;
            }

            // don't infer macro stmts
            if utils::is_macro_literal(integer_arg, &visitor) {
                continue;
            }

            // handle for variable assignment case.
            if let Clang::DeclRefExpr(dre) = &array_arg.kind {
                let array_arg_name = dre.get_name_as_string();

                if utils::is_data_and_size(array_arg, integer_arg, &visitor) {
                    let constraint = Constraint::ArrayLen((array_pos, integer_pos));
                    add_function_constraint(&call_name, constraint, constraints);
                    continue;
                }

                if utils::is_sizeof_expr_of_var(integer_arg, &array_arg_name, &visitor) {
                    let constraint = Constraint::ArrayLen((array_pos, integer_pos));
                    add_function_constraint(&call_name, constraint, constraints);
                    continue;
                }
                if utils::is_alloc_size_of_var(array_arg, integer_arg, &visitor) {
                    let constraint = Constraint::ArrayLen((array_pos, integer_pos));
                    add_function_constraint(&call_name, constraint, constraints);
                    continue;
                }
                if utils::is_strlen_of_var(array_arg, integer_arg, &visitor) {
                    let constraint = Constraint::ArrayLen((array_pos, integer_pos));
                    add_function_constraint(&call_name, constraint, constraints);
                    continue;
                }
            }

            if let Some(array_size) = get_size_of_array_literal(array_arg, &visitor) {
                if let Some(integer_value) = get_integer_concrete_value(integer_arg, &visitor) {
                    if integer_value == 0 {
                        continue;
                    }
                    let arg_tuple = (array_pos, integer_pos);
                    let constraint = match array_size.cmp(&integer_value) {
                        std::cmp::Ordering::Less => Constraint::Invalid(arg_tuple),
                        std::cmp::Ordering::Equal => Constraint::WeakArrayLen(arg_tuple),
                        std::cmp::Ordering::Greater => Constraint::ArrayIndex(arg_tuple),
                    };
                    add_function_constraint(&call_name, constraint, constraints);
                }
            }
        }
    }
    Ok(())
}

/// Refine constraints by dedup and removing conflict.
pub fn refine_constraints(
    constraints: HashMap<String, Vec<Constraint>>,
) -> HashMap<String, Vec<Constraint>> {
    let mut global_constraints: HashMap<String, Vec<Constraint>> = HashMap::new();
    for (func, constraints) in constraints {
        let refined = refine_constraints_for_func(constraints);
        let refined = refine_file_name_constraint(&func, refined);
        if refined.is_empty() {
            continue;
        }
        global_constraints.insert(func, refined);
    }
    global_constraints
}

fn refine_constraints_for_arg_tuple(constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut arr_len = Vec::new();
    let mut weak_arr_len = Vec::new();
    let mut arr_index = Vec::new();
    for constraint in constraints {
        if matches!(constraint, Constraint::Invalid(_)) {
            return Vec::new();
        }
        if matches!(constraint, Constraint::ArrayLen(_)) {
            arr_len.push(constraint);
        } else if matches!(constraint, Constraint::ArrayIndex(_)) {
            arr_index.push(constraint);
        } else if matches!(constraint, Constraint::WeakArrayLen(_)) {
            weak_arr_len.push(constraint);
        }
    }
    if !arr_len.is_empty() {
        return arr_len;
    }
    if weak_arr_len.is_empty() && !arr_index.is_empty() {
        return arr_index;
    }
    if !weak_arr_len.is_empty() && arr_index.is_empty() {
        return weak_arr_len;
    }
    if weak_arr_len.len() > arr_index.len() {
        return weak_arr_len;
    }
    vec![]
}

fn refine_constraints_for_array_arg(constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut arr_len = Vec::new();
    let mut weak_arr_len = Vec::new();
    let mut file_name = Vec::new();
    let mut file_desc = Vec::new();
    let mut arr_index = Vec::new();
    let mut format = Vec::new();
    let mut in_mutate = Vec::new();

    for constraint in constraints {
        match &constraint {
            Constraint::ArrayLen(_) => arr_len.push(constraint),
            Constraint::WeakArrayLen(_) => weak_arr_len.push(constraint),
            Constraint::ArrayIndex(_) => arr_index.push(constraint),
            Constraint::AllocSize(_) => return vec![constraint],
            Constraint::LoopCount(_) => return vec![constraint],
            Constraint::FileName(_) => file_name.push(constraint),
            Constraint::FileDesc(_) => file_desc.push(constraint),
            Constraint::Format(_) => format.push(constraint),
            Constraint::Invalid(_) => return Vec::new(),
        }
    }
    // if different constraint inferred on the same arg
    if !(arr_len.is_empty() && file_name.is_empty() && format.is_empty()) {
        let max_num = usize::max(usize::max(arr_len.len(), file_name.len()), format.len());
        if arr_len.len() == max_num {
            return select_max_array_constraint(arr_len);
        }
        if file_name.len() == max_num {
            return vec![file_name.pop().unwrap()];
        }
        if format.len() == max_num {
            return vec![format.pop().unwrap()];
        }
        return Vec::new();
    }

    if !file_desc.is_empty() {
        return file_desc;
    }

    if weak_arr_len.len() > arr_index.len() {
        return select_max_array_constraint(weak_arr_len);
    }
    if !arr_index.is_empty() {
        let mut cache = HashMap::new();
        for c in &arr_index {
            let tuple = c.get_arg_tuple().unwrap();
            *cache.entry(tuple).or_insert(0) += 1;
        }
        let max_entry = cache.iter().max_by_key(|x| x.1).unwrap();
        let tuple = *max_entry.0;
        let constraint = Constraint::ArrayIndex(*tuple);
        return vec![constraint];
    }
    if !weak_arr_len.is_empty() && weak_arr_len.len() > 1 {
        return select_max_array_constraint(weak_arr_len);
    }
    if !in_mutate.is_empty() {
        in_mutate.dedup();
        return in_mutate;
    }
    vec![]
}

fn refine_constraints_for_integer_arg(constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut arr_len = Vec::new();
    let mut weak_arr_len = Vec::new();
    let mut arr_index = Vec::new();
    let mut file_desc = Vec::new();
    let mut in_mutate = Vec::new();

    for constraint in constraints {
        match &constraint {
            Constraint::ArrayLen(_) => arr_len.push(constraint),
            Constraint::WeakArrayLen(_) => weak_arr_len.push(constraint),
            Constraint::ArrayIndex(_) => arr_index.push(constraint),
            Constraint::AllocSize(_) => return vec![constraint],
            Constraint::LoopCount(_) => return vec![constraint],
            Constraint::FileName(_) => return vec![constraint],
            Constraint::FileDesc(_) => file_desc.push(constraint),
            Constraint::Format(_) => return vec![constraint],
            Constraint::Invalid(_) => return Vec::new(),
        }
    }

    if !(arr_len.is_empty() && file_desc.is_empty())
        && arr_len.len() < file_desc.len()
        && file_desc.len() > 1
    {
        return vec![file_desc.pop().unwrap()];
    }

    arr_len.dedup();
    weak_arr_len.dedup();
    arr_index.dedup();
    in_mutate.dedup();

    if !arr_len.is_empty() {
        if arr_len.len() == 1 {
            return vec![arr_len.pop().unwrap()];
        }
        for constraint in &arr_len {
            if let Constraint::ArrayLen((array_pos, integer_pos)) = constraint {
                if *array_pos == integer_pos + 1 || *array_pos == integer_pos - 1 {
                    return vec![constraint.clone()];
                }
            }
        }
        return vec![arr_len.pop().unwrap()];
    }
    if !weak_arr_len.is_empty() {
        if weak_arr_len.len() == 1 {
            return vec![weak_arr_len.pop().unwrap()];
        }
        for constraint in &weak_arr_len {
            if let Constraint::WeakArrayLen((array_pos, integer_pos)) = constraint {
                if *array_pos == integer_pos + 1
                    || (*integer_pos > 0 && *array_pos == integer_pos - 1)
                {
                    return vec![constraint.clone()];
                }
            }
        }
        return vec![weak_arr_len.pop().unwrap()];
    }
    if !in_mutate.is_empty() {
        return vec![in_mutate.pop().unwrap()];
    }
    if !arr_index.is_empty() {
        return vec![arr_index.pop().unwrap()];
    }
    vec![]
}

/// traversal the constraints and refine the conflic constraints. The remain constraits are creadiable.
fn refine_constraints_for_func(constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut refined = Vec::new();
    // refine for arg_tuple
    let mut tuple_constraints: HashMap<ArgTuple, Vec<Constraint>> = HashMap::new();
    for constraint in constraints {
        if let Some(tuple) = constraint.get_arg_tuple() {
            if let Some(cs) = tuple_constraints.get_mut(tuple) {
                cs.push(constraint);
            } else {
                let cs = vec![constraint.clone()];
                tuple_constraints.insert(*tuple, cs);
            }
        } else {
            refined.push(constraint);
        }
    }

    for (_, constraints) in tuple_constraints {
        let refined_arg_cs = refine_constraints_for_arg_tuple(constraints);
        refined.extend(refined_arg_cs);
    }

    // refine for array arg
    let mut arg_constraints: HashMap<usize, Vec<Constraint>> = HashMap::new();
    for constraint in refined {
        let array_pos = constraint.get_array_arg();
        if let Some(cs) = arg_constraints.get_mut(&array_pos) {
            cs.push(constraint);
        } else {
            let cs = vec![constraint];
            arg_constraints.insert(array_pos, cs);
        }
    }

    let mut refined = Vec::new();
    for (_, constraints) in arg_constraints {
        let refined_arg_cs = refine_constraints_for_array_arg(constraints);
        refined.extend(refined_arg_cs);
    }

    // refine for integer arg
    let mut arg_constraints: HashMap<usize, Vec<Constraint>> = HashMap::new();
    for constraint in refined {
        let integer_pos = constraint.get_integer_arg();
        if let Some(cs) = arg_constraints.get_mut(&integer_pos) {
            cs.push(constraint);
        } else {
            let cs = vec![constraint];
            arg_constraints.insert(integer_pos, cs);
        }
    }

    let mut refined = Vec::new();
    for (_, constraints) in arg_constraints {
        let refined_arg_cs = refine_constraints_for_integer_arg(constraints);
        refined.extend(refined_arg_cs);
    }
    refined
}

fn get_arrary_integer_arg_tuples(func: &str) -> Vec<ArgTuple> {
    let func_gadget = get_func_gadget(func).unwrap();
    let array_pos = func_gadget.get_array_params_pos();
    let mut integer_pos = func_gadget.get_integer_params_pos();
    integer_pos.extend(func_gadget.get_integeral_pointer_pos());
    integer_pos.dedup();
    let mut tuples = Vec::new();
    for array in array_pos {
        for integer in &integer_pos {
            let tuple = (array, *integer);
            tuples.push(tuple);
        }
    }
    tuples
}

fn select_max_array_constraint(constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut counter: HashMap<usize, usize> = HashMap::new();
    for constraint in &constraints {
        let integer_arg = constraint.get_integer_arg();
        *counter.entry(integer_arg).or_default() += 1;
    }
    let max_arg = counter
        .iter()
        .max_by_key(|x| x.1)
        .expect("should not be empty");
    let max_integer_arg = *max_arg.0;
    let mut retained = Vec::new();
    for constraint in constraints {
        let integer_arg = constraint.get_integer_arg();
        if integer_arg == max_integer_arg {
            retained.push(constraint);
        }
    }
    retained
}

/// LLM is possible to assign a string argument with "input_file" name, so check whether this constraint is well inferred
fn refine_file_name_constraint(func: &str, constraints: Vec<Constraint>) -> Vec<Constraint> {
    let mut retained = Vec::new();
    let deopt = Deopt::new(get_library_name()).unwrap();
    for constraint in constraints {
        if let Constraint::FileName(arg_pos) = constraint {
            let res = check_func_arg_is_file_name(func, arg_pos, &deopt);
            if res.is_err() {
                log::error!("Failed to check file name constraint for func: {func}, arg_pos: {arg_pos}, error: {:#?}", res.err());
                continue;
            }
            if !check_func_arg_is_file_name(func, arg_pos, &deopt).unwrap() {
                continue;
            }
        }
        retained.push(constraint);
    }
    retained
}

fn check_func_arg_is_file_name(func: &str, arg_pos: usize, deopt: &Deopt) -> Result<bool> {
    let succ_seeds = deopt.get_library_succ_seed_dir()?;
    let succ_seeds = crate::deopt::utils::read_sort_dir(&succ_seeds)?;

    let mut true_cnt = 0;
    let mut total_cnt = 0;
    for seed in succ_seeds {
        let ast = Executor::extract_ast(&seed, vec![], deopt)?;
        let visitor: Visitor = Visitor::new(ast);
        for call in visitor.find_callexprs(func) {
            let array_arg = call.get_call_arg_stmts()[arg_pos];
            if is_null_ptr(array_arg, &visitor) {
                continue;
            }
            if utils::is_file_name(array_arg, &visitor) {
                true_cnt += 1;
            }
            total_cnt += 1;
        }
    }
    log::debug!(
        "FileName, func: {func}, arg_pos: {arg_pos}, total_cnt: {total_cnt}, true_cnt: {true_cnt}"
    );
    if true_cnt == total_cnt || (true_cnt as f32 / total_cnt as f32) >= 0.8 {
        return Ok(true);
    }
    Ok(false)
}

mod utils {
    use super::*;

    pub fn is_file_name(arg: &Node, visitor: &Visitor) -> bool {
        let arg = strip_prefix(arg);
        let input_re = Regex::new(r"^input_file(\.\w+)?$").unwrap();
        let output_re = Regex::new(r"^output_file(\.\w+)?$").unwrap();
        if let Clang::StringLiteral(sl) = &arg.kind {
            let value = sl.get_eval_value();
            // special case for sqlite3 and libmagic
            if value == ":memory:" || value == "magic" {
                return true;
            }
            if input_re.is_match(&value) || output_re.is_match(&value) {
                return true;
            }
        }
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                return is_file_name(init, visitor);
            }
        }
        false
    }

    pub fn is_file_descriptor(arg: &Node, visitor: &Visitor) -> bool {
        let arg = strip_prefix(arg);
        let fd_producer = ["open", "fileno", "fuzz_fileno"];
        if let Clang::CallExpr(ce) = &arg.kind {
            let name = ce.get_name_as_string(arg);
            if fd_producer.contains(&name.as_str()) {
                return true;
            }
        }
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                return is_file_descriptor(init, visitor);
            }
        }
        false
    }

    pub fn is_format_string(arg: &Node, visitor: &Visitor) -> bool {
        let arg = strip_prefix(arg);
        if let Clang::StringLiteral(sl) = &arg.kind {
            let value = sl.get_eval_value();
            if value.contains('%') {
                return true;
            }
        } else if let Clang::DeclRefExpr(dre) = &arg.kind {
            let var_name = dre.get_name_as_string();
            if let Some(var) = visitor.find_vardecl(&var_name) {
                if let Clang::VarDecl(vd) = &var.kind {
                    if !vd.has_init(var) {
                        return false;
                    }
                    let init = vd.get_init(var);
                    return is_format_string(init, visitor);
                }
            }
        }
        false
    }

    pub fn is_null_ptr(arg: &Node, visitor: &Visitor) -> bool {
        let arg = strip_prefix(arg);
        if let Clang::CXXNullPtrLiteralExpr(_) = &arg.kind {
            return true;
        } else if let Clang::GNUNullExpr(_) = &arg.kind {
            return true;
        } else if let Clang::DeclRefExpr(dre) = &arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                return is_null_ptr(init, visitor);
            }
        }
        false
    }

    /// Whehter this arg is a macro literal
    pub fn is_macro_literal(arg: &Node, visitor: &Visitor) -> bool {
        let arg = strip_prefix(arg);
        if let Clang::IntegerLiteral(il) = &arg.kind {
            if is_macro_stmt(&il.range) {
                return true;
            }
        }
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                return is_macro_literal(init, visitor);
            }
        }
        false
    }

    pub fn is_data_and_size(array_arg: &Node, integer_arg: &Node, visitor: &Visitor) -> bool {
        let array_arg = strip_prefix(array_arg);
        let integer_arg = strip_prefix(integer_arg);
        if let Clang::DeclRefExpr(array_dre) = &array_arg.kind {
            let array_name = array_dre.get_name_as_string();
            if let Clang::DeclRefExpr(integer_dre) = &integer_arg.kind {
                let integer_name = integer_dre.get_name_as_string();
                if array_name == "data" && integer_name == "size" {
                    return true;
                }
                if let Some(integer_init) = integer_dre.get_var_init(visitor) {
                    if is_data_and_size(array_arg, integer_init, visitor) {
                        return true;
                    }
                    if let Some(array_init) = array_dre.get_var_init(visitor) {
                        if is_data_and_size(array_init, integer_init, visitor) {
                            return true;
                        }
                    }
                }
                if let Some(array_init) = array_dre.get_var_init(visitor) {
                    if is_data_and_size(array_init, integer_arg, visitor) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Whether this arg is the sizeof of var_name.
    pub fn is_sizeof_expr_of_var(integer_arg: &Node, array_name: &str, visitor: &Visitor) -> bool {
        let integer_arg = strip_prefix(integer_arg);
        if let Clang::UnaryExprOrTypeTraitExpr(ue) = &integer_arg.kind {
            if !ue.is_sizeof() {
                return false;
            }
            if let Some(inner_name) = ue.get_dre_child_name(integer_arg) {
                if inner_name == array_name {
                    return true;
                }
            }
            if let Some(sizeof_ty) = &ue.arg_type {
                let sizeof_ty_name = sizeof_ty.get_type_name();
                if let Some(var) = visitor.find_vardecl(array_name) {
                    if let Clang::VarDecl(vd) = &var.kind {
                        let array_ty_name = vd.get_type().get_type_name();
                        if array_ty_name == sizeof_ty_name {
                            return true;
                        }
                    }
                }
            }
        } else if let Clang::BinaryOperator(bo) = &integer_arg.kind {
            let left = bo.get_lhs(integer_arg);
            let right = bo.get_rhs(integer_arg);
            return is_sizeof_expr_of_var(left, array_name, visitor)
                || is_sizeof_expr_of_var(right, array_name, visitor);
        } else if let Clang::DeclRefExpr(dre) = &integer_arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                return is_sizeof_expr_of_var(init, array_name, visitor);
            }
        }
        false
    }

    fn is_size_of_var(alloc_arg: &Node, integer_arg: &Node, visitor: &Visitor) -> bool {
        let alloc_arg = strip_prefix(alloc_arg);
        let integer_arg = strip_prefix(integer_arg);
        // if use the same var name
        if let Clang::DeclRefExpr(arg_dre) = &alloc_arg.kind {
            let alloc_arg_name = arg_dre.get_name_as_string();
            if let Clang::DeclRefExpr(integer_arg) = &integer_arg.kind {
                let integer_arg_name = integer_arg.get_name_as_string();
                if alloc_arg_name == integer_arg_name {
                    return true;
                }
                if let Some(init) = integer_arg.get_var_init(visitor) {
                    return is_size_of_var(alloc_arg, init, visitor);
                }
            }
        }
        // if has the same value
        if let Some(integer_value) = get_integer_concrete_value(integer_arg, visitor) {
            if let Some(alloc_size) = get_integer_concrete_value(alloc_arg, visitor) {
                if alloc_size == integer_value {
                    return true;
                }
            }
        }
        false
    }

    /// Whether the array_arg is initialized by malloc/new and the integer_arg is the size.
    pub fn is_alloc_size_of_var(array_arg: &Node, integer_arg: &Node, visitor: &Visitor) -> bool {
        let array_arg = strip_prefix(array_arg);
        if let Clang::DeclRefExpr(dre) = &array_arg.kind {
            // if this array_arg is initialized by a call.
            if let Some(call) = dre.get_var_init_call(visitor) {
                if let Clang::CallExpr(ce) = &call.kind {
                    let call_name = ce.get_name_as_string(call);
                    // if this array_arg is returned by a malloc
                    if call_name != "malloc" {
                        return false;
                    }
                    let malloc_args = ce.get_childs(call);
                    if malloc_args.is_empty() {
                        return false;
                    }
                    return is_size_of_var(malloc_args[0], integer_arg, visitor);
                }
                if let Clang::CXXNewExpr(new_expr) = &call.kind {
                    if let Some(new_arg) = new_expr.get_new_size_var(call) {
                        return is_size_of_var(new_arg, integer_arg, visitor);
                    }
                }
            }
        }
        false
    }

    pub fn is_strlen_of_var(array_arg: &Node, integer_arg: &Node, visitor: &Visitor) -> bool {
        let array_arg = strip_prefix(array_arg);
        let integer_arg = strip_prefix(integer_arg);
        if let Clang::DeclRefExpr(dre) = &array_arg.kind {
            // if this array_arg is initialized by a call.
            let array_name = dre.get_name_as_string();

            // if integer arg is a strlen call
            if let Clang::CallExpr(ce) = &integer_arg.kind {
                let call_name = ce.get_name_as_string(integer_arg);
                if call_name != "strlen" {
                    return false;
                }
                let strlen_arg = ce.get_childs(integer_arg);
                if strlen_arg.is_empty() {
                    return false;
                }
                let strlen_arg = strip_prefix(strlen_arg[0]);
                if let Clang::DeclRefExpr(dre) = &strlen_arg.kind {
                    let strlen_arg_name = dre.get_name_as_string();
                    if array_name == strlen_arg_name {
                        return true;
                    }
                }
            }
            // if integer arg is a declared var
            if let Clang::DeclRefExpr(dre) = &integer_arg.kind {
                if let Some(init) = dre.get_var_init(visitor) {
                    return is_strlen_of_var(array_arg, init, visitor);
                }
            }
        }
        false
    }
}

/// get the size of an InitListExpr
fn get_array_decl_size(ty: &str) -> Option<usize> {
    if let Some(left) = ty.find('[') {
        if let Some(right) = ty.find(']') {
            if left >= right {
                return None;
            }
            let size = &ty[left + 1..right];
            if let Ok(size) = size.parse::<usize>() {
                return Some(size);
            }
        }
    }
    None
}

/// get the array size of the arg in this api call.
fn get_size_of_array_literal(array_arg: &Node, visitor: &Visitor) -> Option<usize> {
    match &array_arg.kind {
        Clang::InitListExpr(ile) => {
            let ty = ile.get_type().get_type_name();
            return get_array_decl_size(&ty);
        }
        Clang::DeclRefExpr(dre) => {
            if let Some(vd) = dre.get_var_decl(visitor) {
                let ty = vd.get_type().get_type_name();
                return get_array_decl_size(&ty);
            }
        }
        _ => return None,
    }
    None
}

/// Get the concrete valut of the integer type arg in this call.
fn get_integer_concrete_value(integer_arg: &Node, visitor: &Visitor) -> Option<usize> {
    match &integer_arg.kind {
        Clang::IntegerLiteral(il) => {
            let value: usize = il
                .get_value()
                .unwrap_or_else(|_| panic!("Cannot get concrete value of IntegerLiteral: {il:#?}"));
            return Some(value);
        }
        Clang::DeclRefExpr(dre) => {
            if let Some(init) = dre.get_var_init(visitor) {
                let init = init.ignore_parent().ignore_cast();
                return get_integer_concrete_value(init, visitor);
            }
        }
        _ => return None,
    }
    None
}

fn strip_prefix(node: &Node) -> &Node {
    node.ignore_parent().ignore_cast().ignore_prefix()
}

#[test]
fn test_static_infer() -> Result<()> {
    crate::config::Config::init_test("c-ares");
    let deopt = Deopt::new("c-ares".to_string())?;
    let mut constraints = APIConstraints::new();

    let programs = crate::deopt::utils::read_sort_dir(&deopt.get_library_succ_seed_dir()?)?;

    for program in programs {
        println!("program: {program:?}");
        infer_constraints(&program, &deopt, &mut constraints)?;
    }
    let refined = refine_constraints(constraints);
    println!("{refined:#?}");
    Ok(())
}
