//! Clang AST Visitor
//! Visit AST nodes and return the source file locations of specific nodes.
//! The returned source file locations typeically is a source code location range: (usize, usize),
//!     which indicates the start and end offsets of this node in source code file.
use std::io::Read;
use std::path::Path;

use crate::analysis::WorkList;
use crate::ast::loc::{get_bare_loc, get_sr_begin_loc, get_sr_end_loc};
use crate::ast::{Clang, CommomHelper, Node, VarDecl};
use crate::program::gadget::get_func_gadget;
use eyre::Result;

use super::CallExpr;

pub struct Visitor {
    pub ast: Node,
}

impl Visitor {
    pub fn new(ast: Node) -> Self {
        Self { ast }
    }

    /// get the loc that suitable to insert code before this stmt. e.g., loc to change call's args.
    fn get_stmt_ins_before_loc(&self, pos: usize, src_file: &Path) -> Result<usize> {
        let mut f = std::fs::OpenOptions::new().read(true).open(src_file)?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;
        let buffer_before = &buffer[..pos];
        let mut idx = 0;
        for c in buffer_before.chars().rev() {
            idx += 1;
            if c == ';' || c == '}' {
                break;
            }
        }
        let loc = pos - idx;
        Ok(loc + 1)
    }

    /// get the loc that suitable to insert code before this stmt. e.g., loc to check call's return value
    fn get_stmt_ins_after_loc(&self, pos: usize, src_file: &Path) -> Result<usize> {
        let mut f = std::fs::OpenOptions::new().read(true).open(src_file)?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;
        let buffer_after = &buffer[pos..];
        let mut idx = 0;
        for c in buffer_after.chars() {
            if c == ';' {
                break;
            }
            idx += 1;
        }
        let loc = pos + idx;
        Ok(loc)
    }

    /// find the FunctionDecl node named with fd_name.
    pub fn find_fd(&self, fd_name: &str) -> Option<&Node> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::FunctionDecl(fd) = &curr.kind {
                let name = fd.get_name();
                if name == fd_name {
                    return Some(curr);
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        None
    }

    /// find the source code location range of the FuntionDecl specified with name of fd_name.
    /// The range starts from type declaration and ends with the end of function name.
    pub fn get_fd_loc(&self, fd_name: &str) -> Result<(usize, usize)> {
        if let Some(fd_node) = self.find_fd(fd_name) {
            if let Clang::FunctionDecl(fd) = &fd_node.kind {
                let loc = fd.loc.clone();
                let range = fd.range.clone();
                if let Some(loc) = get_bare_loc(&loc) {
                    let fd_begin = get_sr_begin_loc(&range)?.offset;
                    let name_end = loc.offset + loc.tok_len;
                    return Ok((fd_begin, name_end));
                }
                eyre::bail!("cannot get BareLocation {loc:?} for this function: {fd_name:?}")
            }
        }
        eyre::bail!("cannot find a fd with name: {fd_name:?}")
    }

    /// find the source code locations range of the ParamVarDecls of function specified with name of fd_name.
    /// The range starts from the declaration of the first Param and ends with the end of the last Param.
    pub fn get_fd_param_loc(&self, fd_name: &str, src_file: &Path) -> Result<(usize, usize)> {
        if let Some(fd_node) = self.find_fd(fd_name) {
            if let Clang::FunctionDecl(fd) = &fd_node.kind {
                if fd.has_params(fd_node) {
                    let params = fd.get_params(fd_node);
                    let first_param = *params.first().unwrap();
                    let last_param = *params.last().unwrap();
                    let begin = get_sr_begin_loc(&first_param.range)?;
                    let end = get_sr_end_loc(&last_param.range)?;
                    let begin_loc = begin.offset;
                    let end_loc = end.offset + end.tok_len;
                    return Ok((begin_loc, end_loc));
                } else {
                    // no params: return locs of "()" or "(void)"
                    let begin = fd.loc.clone();
                    let begin_loc = get_bare_loc(&begin)
                        .ok_or_else(|| eyre::eyre!("cannot get ParamLoction from: {fd:?}"))?;
                    let begin_offset = begin_loc.offset + begin_loc.tok_len;
                    let ty = &std::fs::read_to_string(src_file)?[begin_offset..];
                    let ty_len = ty.find(')').unwrap() - ty.find('(').unwrap() - 1;
                    let begin_loc = begin_offset + 1;
                    let end_loc = begin_loc + ty_len;
                    return Ok((begin_loc, end_loc));
                }
            }
        }
        eyre::bail!("cannot find a fd with name: {fd_name:?}")
    }

    pub fn find_vardecl(&self, var_name: &str) -> Option<&Node> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::VarDecl(vd) = &curr.kind {
                let name = vd.get_name_as_string();
                if name == var_name {
                    return Some(curr);
                }
            }
            if let Clang::ParmVarDecl(pvd) = &curr.kind {
                let name = pvd.get_name_as_string();
                if name == var_name {
                    return Some(curr);
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        None
    }

    pub fn find_binary_operator(&self, var_name: &str) -> Option<&Node> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::BinaryOperator(bo) = &curr.kind {
                let left = bo.get_lhs(curr);
                if let Clang::DeclRefExpr(dre) = &left.kind {
                    let name = dre.get_name_as_string();
                    if var_name == name {
                        let right = bo.get_rhs(curr);
                        return Some(right);
                    }
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        None
    }

    pub fn visit_nth_library_call(&self, nth: usize) -> &Node {
        let calls = self.visit_library_calls();
        let call = calls.get(nth).unwrap();
        call
    }

    /// visit all the callexpr that are library calls.
    pub fn visit_library_calls(&self) -> Vec<&Node> {
        let mut calls = Vec::new();
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let name = ce.get_name_as_string(curr);
                if get_func_gadget(&name).is_some() {
                    calls.push(curr);
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        calls
    }

    pub fn get_library_call_names(&self) -> Vec<String> {
        let mut calls = Vec::new();
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let name = ce.get_name_as_string(curr);
                if get_func_gadget(&name).is_some() {
                    calls.push(name);
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        calls
    }

    /// find the call arg with the specificed name, and return its type name.
    pub fn find_ty_with_arg_name(&self, arg_name: &str) -> Option<String> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let args = ce.get_childs(curr);
                for arg in args {
                    if let Clang::DeclRefExpr(dre) = &arg.kind {
                        let name = dre.get_name_as_string();
                        if name == arg_name {
                            let ty = dre.get_type_name();
                            return Some(ty);
                        }
                    }
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        None
    }

    /// find the callexpr of the i-th call.
    pub fn find_callexpr(&self, call_name: &str, call_i: usize) -> Option<&Node> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        let mut i = 0;
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let name = ce.get_name_as_string(curr);
                if name == call_name {
                    if call_i == i {
                        return Some(curr);
                    } else {
                        i += 1;
                    }
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        None
    }

    pub fn find_callexprs(&self, call_name: &str) -> Vec<&Node> {
        let mut worklist = WorkList::new();
        let mut calls = vec![];
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let name = ce.get_name_as_string(curr);
                if name == call_name {
                    calls.push(curr);
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        calls
    }

    /// get the code insert location before this call.
    pub fn get_call_before_ins_loc(
        &self,
        call_name: &str,
        src_file: &Path,
        call_i: usize,
    ) -> Result<usize> {
        if let Some(node) = self.find_callexpr(call_name, call_i) {
            if let Clang::CallExpr(ce) = &node.kind {
                let ce_begin = get_sr_begin_loc(&ce.range)?.offset;
                let ins_loc = self.get_stmt_ins_before_loc(ce_begin, src_file)?;
                return Ok(ins_loc);
            }
        }
        eyre::bail!("cannot find CallExpr for: {call_name}.")
    }

    /// get the code insert location after this call.
    pub fn get_call_after_ins_loc(
        &self,
        call_name: &str,
        src_file: &Path,
        call_i: usize,
    ) -> Result<usize> {
        if let Some(node) = self.find_callexpr(call_name, call_i) {
            if let Clang::CallExpr(ce) = &node.kind {
                let ce_begin = get_sr_begin_loc(&ce.range)?.offset;
                let ins_loc = self.get_stmt_ins_after_loc(ce_begin, src_file)?;
                return Ok(ins_loc);
            }
        }
        eyre::bail!("cannot find CallExpr for: {call_name}.")
    }

    /// Get begin location of function body, where suitable to insert any VarDecl.
    pub fn get_function_body_begin_loc(&self) -> Result<usize> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CompoundStmt(cs) = &curr.kind {
                let begin = get_sr_begin_loc(&cs.range)?;
                let begin_loc = begin.offset + begin.tok_len;
                return Ok(begin_loc);
            }
            worklist.push_childs(curr.get_childs());
        }
        eyre::bail!("Cannot found suitable location to insert vardecl")
    }

    /// get this var node in the updated ast.
    pub fn get_var_node(&self, node: &Node) -> Result<&Node> {
        if let Clang::VarDecl(vd) = &node.kind {
            let name = vd.get_name_as_string();
            let mut worklist = WorkList::new();
            worklist.push(&self.ast);
            while !worklist.empty() {
                let curr = worklist.pop();
                if let Clang::VarDecl(vd) = &curr.kind {
                    let vd_name = vd.get_name_as_string();
                    if vd_name == name {
                        return Ok(curr);
                    }
                }
                worklist.push_childs(curr.get_childs());
            }
        }
        eyre::bail!("Need VarDecl here: {node:?}")
    }

    pub fn find_api_call_with_arg(&self, arg_name: &str) -> Option<&Node> {
        let calls = self.visit_library_calls();
        for call in calls {
            for arg in call.get_childs() {
                if let Clang::DeclRefExpr(dre) = &arg.kind {
                    let name = dre.get_name_as_string();
                    if arg_name == name {
                        return Some(call);
                    }
                }
            }
        }
        None
    }

    pub fn match_string_pattern(&self, patten: regex::Regex) -> Option<String> {
        let mut work_list = WorkList::new();
        work_list.push(&self.ast);
        while !work_list.empty() {
            let curr = work_list.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let call_name = ce.get_name_as_string(curr);
                if call_name == "fopen" {
                    continue;
                }
            }
            if let Clang::StringLiteral(sl) = &curr.kind {
                let value = sl.get_eval_value();
                if patten.is_match(&value) {
                    return Some(value);
                }
            }
            for child in &curr.inner {
                work_list.push(child);
            }
        }
        None
    }

    pub fn find_nested_call(&self, nested: &[&str]) -> Option<(&CallExpr, &CallExpr, String)> {
        let mut worklist = WorkList::new();
        worklist.push(&self.ast);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                for arg in ce.get_childs(curr).iter() {
                    if let Clang::CallExpr(nested_call) = &arg.kind {
                        let nested_call_name = nested_call.get_name_as_string(arg);
                        if nested.contains(&nested_call_name.as_str()) {
                            return Some((ce, nested_call, nested_call_name));
                        }
                    }
                }
            }
            for child in &curr.inner {
                worklist.push(child);
            }
        }
        None
    }
}

pub mod utils {

    use super::*;

    /// Whether this variable is a fuzzable variable:
    /// 1. has init
    /// 2. is pointer ty
    /// 3. ty is `const`
    /// 4. inited with String or List.
    pub fn is_var_fuzzable(vd: &VarDecl, node: &Node) -> bool {
        if !vd.has_init(node) {
            return false;
        }
        let ty = vd.get_type().get_type_name();

        if !is_pointer_ty(&ty) {
            return false;
        }

        if !ty.starts_with("const") {
            return false;
        }

        let init = vd.get_init(node).ignore_cast().ignore_parent();
        matches!(&init.kind, Clang::StringLiteral(_) | Clang::InitListExpr(_))
    }

    pub fn is_integer_literal(node: &Node) -> bool {
        let node = node.ignore_parenexpr();
        if let Clang::IntegerLiteral(_) = &node.kind {
            return true;
        }
        /* EnumConstant should not be considered as integer literal. Pass the EnumConstant with integer will cause compilation error.
        if let Clang::EnumConstantDecl(_) = &node.kind {
            return true;
        }
        */
        if let Clang::UnaryOperator(uo) = &node.kind {
            if !uo.is_minus() || node.inner.len() != 1 {
                return false;
            }
            if let Clang::IntegerLiteral(_) = &node.inner[0].kind {
                return true;
            }
        }

        false
    }

    /// whether this arg is fuzzable.
    /// 1. should not returned by call
    /// 2. contains code literals
    pub fn is_arg_fuzzable(arg: &Node, visitor: &Visitor) -> bool {
        let arg = arg.ignore_parent().ignore_cast().ignore_prefix();
        if is_integer_literal(arg) {
            return true;
        }
        match &arg.kind {
            Clang::StringLiteral(_) => true,
            Clang::InitListExpr(_) => true,
            Clang::DeclRefExpr(dre) => {
                if let Some(init) = dre.get_var_init(visitor) {
                    return is_arg_fuzzable(init, visitor);
                }
                false
            }
            _ => false,
        }
    }

    fn is_pointer_ty(ty: &str) -> bool {
        ty.find('*').is_some() || ty.find('[').is_some()
    }

    /// get the arg of this call.
    pub fn get_nth_arg(node: &Node, arg_pos: usize) -> Result<&Node> {
        if let Clang::CallExpr(_ce) = &node.kind {
            if let Some(arg) = node.inner.get(arg_pos + 1) {
                return Ok(arg.ignore_cast().ignore_parent());
            }
        }
        eyre::bail!("{node:#?} needs to be a CallExpr")
    }

    pub fn get_arg_ref(arg: &Node) -> Option<String> {
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            let name = dre.get_name_as_string();
            return Some(name);
        }
        None
    }

    pub fn get_call_arg_type(call: &Node, arg_pos: usize) -> String {
        if let Clang::CallExpr(ce) = &call.kind {
            let arg = ce.get_childs_no_ignore(call)[arg_pos];
            let ty = get_call_arg_node_type(arg);
            return ty;
        }
        unreachable!()
    }

    fn get_call_arg_node_type(arg: &Node) -> String {
        match &arg.kind {
            Clang::ImplicitCastExpr(ic) => ic.r#type.get_type_name(),
            Clang::CXXStaticCastExpr(csce) => csce.r#type.get_type_name(),
            Clang::CStyleCastExpr(ce) => ce.r#type.get_type_name(),
            Clang::IntegerLiteral(il) => il.r#type.get_type_name(),
            Clang::StringLiteral(sl) => sl.r#type.get_type_name(),
            Clang::CharacterLiteral(cl) => cl.r#type.get_type_name(),
            Clang::InitListExpr(ile) => ile.r#type.get_type_name(),
            Clang::UnaryExprOrTypeTraitExpr(_) => String::from("size_t"),
            Clang::DeclRefExpr(dre) => dre.get_type_name(),
            Clang::UnaryOperator(ue) => {
                if ue.is_minus() {
                    let inner = ue.get_inner(arg);
                    return get_call_arg_node_type(inner);
                }
                if ue.is_addrof() {
                    let inner = ue.get_inner(arg);
                    let mut ty = get_call_arg_node_type(inner);
                    let last_char = ty.chars().last().unwrap();
                    if last_char == ' ' {
                        ty.push('*')
                    } else {
                        ty.push(' ');
                        ty.push('*');
                    }
                    return ty;
                }
                unreachable!("{arg:#?}")
            }
            Clang::BinaryOperator(bo) => {
                let inner = bo.get_lhs(arg);
                return get_call_arg_node_type(inner);
            }
            _ => unimplemented!("{arg:#?}"),
        }
    }

    pub fn get_func_arg_decl_type(call: &Node, arg_pos: usize) -> String {
        if let Clang::CallExpr(ce) = &call.kind {
            let func_name = ce.get_name_as_string(call);
            if let Some(gadget) = get_func_gadget(&func_name) {
                let ty = gadget.get_alias_arg_types().get(arg_pos).unwrap();
                return ty.to_string();
            }
        }
        unreachable!()
    }

    pub fn is_inner_contain_breakstmt(node: &Node) -> bool {
        let mut worklist = WorkList::new();
        worklist.push(node);
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::BreakStmt = &curr.kind {
                return true;
            }
            worklist.push_childs(curr.get_childs());
        }
        false
    }

    pub fn is_case_or_default_stmt(node: &Node) -> bool {
        if let Clang::CaseStmt = &node.kind {
            return true;
        }
        if let Clang::DefaultStmt = &node.kind {
            return true;
        }
        false
    }

    pub fn is_default_stmt(node: &Node) -> bool {
        if let Clang::DefaultStmt = &node.kind {
            return true;
        }
        false
    }
}
