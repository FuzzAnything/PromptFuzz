use eyre::{Context, Result};
use regex::Regex;
use std::path::Path;

use crate::{
    analysis::adg::{ADGBuilder, TaintData, Taintkind},
    ast::{
        self,
        loc::{
            get_loc_before_stmt, get_source_code_content, get_sr_begin_loc, get_sr_end_loc,
            get_sr_offset,
        },
        Clang, CommomHelper, Node, Visitor,
    },
    deopt::Deopt,
    execution::Executor,
    program::{gadget::is_library_api, transform::Transformer},
};

use super::{
    adg::{TaintDataVec, ADG},
    cfg::CFGBuilder,
    dfa::{CallBack, EnvMgr, StoreMgr, Symbol},
    WorkList,
};
use petgraph::{algo::has_path_connecting, graph::NodeIndex, Direction::Outgoing};

#[derive(Debug)]
pub enum FDError {
    UAC,
    DC,
    LEAK,
    None,
}

/// merge a vec of symbols into one representative symbol.
fn fdsan_merge(syms: Vec<Symbol<TaintDataVec>>) -> Symbol<TaintDataVec> {
    Symbol::union_merge(syms)
}

/// Attach the symbols of this call's args with Arg-taint summary.
fn fdsan_precall(
    store_mgr: &mut StoreMgr<TaintDataVec>,
    env_mgr: &mut EnvMgr<TaintDataVec>,
    call: &ast::Node,
) {
    let call_id = call.id;
    let name = call.get_call_name();

    log::trace!("Visit [Precall]: {}", name);
    for (i, arg_stmt) in call.get_call_arg_stmts().iter().enumerate() {
        let arg = arg_stmt.get_var_name();
        if arg.is_empty() {
            continue;
        }
        // currently do not differ array and array's elements.
        let arg = arg.get_base();
        let data = TaintData::new(call_id, name.clone(), Taintkind::Arg(i as u8));
        // if this arg is a callStmt.
        if arg_stmt.is_call() {
            fdsan_precall(store_mgr, env_mgr, arg_stmt);
            let mut sym = env_mgr.create_object_for_call(call).unwrap();
            fdsan_post_call(store_mgr, arg_stmt, &mut sym);
            sym.get_data_mut().push(data);
            store_mgr.ssa_bind_value(arg, sym).unwrap();
        } else {
            // else, get bind of var.
            let sym = store_mgr.get_bind_mut(&arg);
            if let Ok(sym) = sym {
                sym.get_data_mut().push(data);
            }
            // if bind of var isn't existed. e.g., global var in external libraries.
            else {
                //log::warn!("{sym:?}");
                let mut sym = env_mgr.create_dummy_object();
                sym.get_data_mut().push(data.clone());
                store_mgr.ssa_bind_value(arg, sym).unwrap();
            }
        }
    }
}

/// Attach the symbols of this call's args with Call-taint summary.
fn fdsan_post_call(
    _store_mgr: &mut StoreMgr<TaintDataVec>,
    call: &ast::Node,
    sym: &mut Symbol<TaintDataVec>,
) {
    let call_id = call.id;
    let name = call.get_call_name();

    let data = TaintData::new(call_id, name, Taintkind::Call);
    let sym_data = sym.get_data_mut();
    sym_data.push(data);
}

fn fdsan_create_callback() -> CallBack<TaintDataVec> {
    CallBack {
        merge: Box::new(fdsan_merge),
        precall: Box::new(fdsan_precall),
        postcall: Box::new(fdsan_post_call),
    }
}

impl ADG {
    fn get_node_with_name(&self, name: &str) -> Vec<NodeIndex> {
        let mut nodes = Vec::new();
        for (node, idx) in self.node_map.iter() {
            if node.get_name() == name {
                nodes.push(*idx)
            }
        }
        nodes
    }

    fn get_close_nodes(&self) -> Vec<NodeIndex> {
        let mut nodes = Vec::new();
        let close_funcs = ["close", "fclose"];
        for func in close_funcs {
            nodes.extend(self.get_node_with_name(func));
        }
        nodes
    }

    fn _get_open_nodes(&self) -> Vec<NodeIndex> {
        let mut nodes = Vec::new();
        let open_funcs = ["open", "fopen", "fmemopen"];
        for func in open_funcs {
            nodes.extend(self.get_node_with_name(func));
        }
        nodes
    }

    fn _get_api_nodes(&self) -> Vec<NodeIndex> {
        let mut nodes = Vec::new();
        for (node, idx) in self.node_map.iter() {
            if is_library_api(&node.get_name()) {
                nodes.push(*idx);
            }
        }
        nodes
    }

    fn detect_double_close(&self) -> bool {
        let close_nodes = self.get_close_nodes();
        for node_i in close_nodes.iter() {
            for node_j in close_nodes.iter() {
                if node_i == node_j {
                    continue;
                }
                if has_path_connecting(&self.graph, *node_i, *node_j, None) {
                    return true;
                }
            }
        }
        false
    }

    fn detect_use_after_close(&self) -> bool {
        let close_nodes = self.get_close_nodes();
        for node in close_nodes {
            let neighbors = self.graph.neighbors_directed(node, Outgoing);
            for neighbor in neighbors {
                let node = self.graph.node_weight(neighbor).unwrap();
                if !node.get_name().starts_with("assert") {
                    return true;
                }
            }
        }
        false
    }

    // Note: If the ownership of fd transfered to Library API, it may cause false positive
    fn _detect_leak(&self) -> bool {
        let open_nodes = self._get_open_nodes();
        let close_nodes = self.get_close_nodes();
        for open_node in &open_nodes {
            let mut has_close = false;
            for close_node in &close_nodes {
                if has_path_connecting(&self.graph, *open_node, *close_node, None) {
                    has_close = true;
                }
            }
            for other_open_node in &open_nodes {
                if open_node == other_open_node {
                    continue;
                }
                if has_path_connecting(&self.graph, *open_node, *other_open_node, None) {
                    has_close = true;
                }
            }
            if !has_close {
                return true;
            }
        }
        false
    }

    // Detect leak and consider the ownership transfer. If an ownership transfer occurs, this file descriptor is considerd closed by library APIs.
    fn _detect_leak_ownership(&self) -> bool {
        let open_nodes = self._get_open_nodes();
        let close_nodes = self.get_close_nodes();
        let api_nodes = self._get_api_nodes();
        for open_node in &open_nodes {
            let mut has_close = false;
            for close_node in &close_nodes {
                if has_path_connecting(&self.graph, *open_node, *close_node, None) {
                    has_close = true;
                }
            }
            for other_open_node in &open_nodes {
                if open_node == other_open_node {
                    continue;
                }
                if has_path_connecting(&self.graph, *open_node, *other_open_node, None) {
                    has_close = true;
                }
            }
            for api_node in &api_nodes {
                if has_path_connecting(&self.graph, *open_node, *api_node, None) {
                    has_close = true;
                }
            }
            if !has_close {
                return true;
            }
        }
        false
    }
}

/// File name, use line
type FileLine = Vec<(String, usize, Option<(usize, usize)>)>;

/// begining location of this RetrunStmt.
/// end location of this Return Stmt.
// end location of the current CompoundStmt.
type ReturnLoc = (usize, Option<usize>, Option<(usize, usize)>);

impl Transformer<'_> {
    pub fn add_fd_sanitizer(&mut self) -> Result<()> {
        self.handle_nested_call()?;
        self.add_sanitize_header()?;
        self.handle_fileno()?;
        self.add_sanitize_stmts()?;
        self.handle_set_jump()?;
        self.handle_fclose()?;
        Ok(())
    }

    fn handle_fclose(&mut self) -> Result<()> {
        let content = std::fs::read_to_string(&self.src_file)?;
        let re = Regex::new(r"\bfclose\((?<name>\w+)\)").unwrap();
        let replaced_code = re.replace_all(&content, "assert_file_closed(&$name);");
        std::fs::write(&self.src_file, replaced_code.to_string())?;
        Ok(())
    }

    fn handle_fileno(&self) -> Result<()> {
        let content = std::fs::read_to_string(&self.src_file)?;
        let content = crate::program::transform::utils::relace_pattern_in_content(
            &content,
            "fileno",
            "fuzz_fileno",
        )?;
        std::fs::write(&self.src_file, content)?;
        Ok(())
    }

    fn handle_set_jump(&mut self) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        let mut worklist = WorkList::new();
        worklist.push(&visitor.ast);

        let mut setjum_locs = Vec::new();
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::IfStmt(_) = &curr.kind {
                if let Some(cond) = curr.inner.first() {
                    // if the condition is a setjmp call
                    if is_setjmp_call(cond) {
                        if let Some(body) = curr.inner.get(1) {
                            // save the location of the body stmt.
                            if let Clang::CompoundStmt(cs) = &body.kind {
                                let loc = get_sr_begin_loc(&cs.range)?.offset + 1;
                                setjum_locs.push(loc);
                            }
                        }
                    }
                }
            }
            worklist.push_childs(curr.get_childs());
        }

        if setjum_locs.is_empty() {
            return Ok(());
        }

        for jmp_loc in setjum_locs.iter().rev() {
            let close_stmt = "\n\tFUZZ_FILE_CLOSE();";
            self.seek_and_rewrite(*jmp_loc, 0, close_stmt)?;
        }

        let init_loc = visitor.get_function_body_begin_loc()?;
        let init_stmt = "\n\tFUZZ_FILE_INIT();";
        self.seek_and_rewrite(init_loc, 0, init_stmt)?;

        self.attach_push_after_open()?;

        Ok(())
    }

    fn attach_push_after_open(&mut self) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        let mut worklist = WorkList::new();
        worklist.push(&visitor.ast);

        let mut file_vars = Vec::new();
        let input_re = Regex::new(r"^input_file(\.\w+)?$")?;
        let output_re = Regex::new(r"^output_file(\.\w+)?$")?;

        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::CallExpr(ce) = &curr.kind {
                let name = ce.get_name_as_string(curr);
                if name == "assert_file_name_closed" {
                    continue;
                }
            }
            if let Clang::VarDecl(vd) = &curr.kind {
                if !vd.has_init(curr) {
                    continue;
                }
                let var_name = vd.get_name_as_string();
                let init = vd.get_init(curr).ignore_cast().ignore_parent();
                if let Clang::CallExpr(ce) = &init.kind {
                    let call_name = ce.get_name_as_string(init);
                    let loc = get_sr_offset(&ce.range)?.1 + 1;
                    if call_name == "fuzz_fileno" || call_name == "open" || call_name == "fileno" {
                        file_vars.push((var_name, loc, 0));
                    } else if call_name == "fmemopen" || call_name == "fopen" {
                        file_vars.push((var_name, loc, 1));
                    }
                }
            }
            if let Clang::StringLiteral(sl) = &curr.kind {
                let value = sl.get_eval_value();
                let loc = get_loc_before_stmt(&self.src_file, &sl.range)?;
                if input_re.is_match(&value) || output_re.is_match(&value) {
                    file_vars.push((value, loc, 2));
                }
            }

            worklist.push_childs(curr.get_childs());
        }
        file_vars.dedup_by(|a, b| a.0.eq(&b.0));
        file_vars.sort_by(|a, b| b.1.cmp(&a.1));
        for (var, loc, ty) in file_vars {
            if ty == 0 {
                let push_stmt = format!("\n\tFUZZ_FD_PUSH({var})");
                self.seek_and_rewrite(loc, 0, &push_stmt)?;
            } else if ty == 1 {
                let push_stmt = format!("\n\tFUZZ_FILE_PUSH({var})");
                self.seek_and_rewrite(loc, 0, &push_stmt)?;
            } else {
                let push_stmt = format!("\n\tFUZZ_FILENAME_PUSH(\"{var}\")");
                self.seek_and_rewrite(loc, 0, &push_stmt)?;
            }
        }
        Ok(())
    }

    // Transform the nested call into multi-line calls.
    fn handle_nested_call(&mut self) -> Result<()> {
        let mut global_id = 0;
        let mut visitor = self.get_new_visitor()?;
        let nested_calls = vec!["fuzz_fileno", "open", "fmemopen", "fileno"];

        while let Some((call, arg, nest_name)) = visitor.find_nested_call(&nested_calls) {
            let ins_loc = get_loc_before_stmt(&self.src_file, &call.range)?;
            let (arg_begin, arg_end) = get_sr_offset(&arg.range)?;
            let arg_content = get_source_code_content(&arg.range)?;
            let (var_name, init_stmt) =
                if nest_name == "fuzz_fileno" || nest_name == "open" || nest_name == "fileno" {
                    let var_name = format!("fuzz_fd_{global_id}");
                    let init_stmt = format!("\n\tint {var_name} = {arg_content};\n");
                    (var_name, init_stmt)
                } else {
                    let var_name = format!("fuzz_file_{global_id}");
                    let init_stmt = format!("\n\tFILE* {var_name} = {arg_content};\n");
                    (var_name, init_stmt)
                };
            self.seek_and_rewrite(arg_begin, arg_end - arg_begin, &var_name)?;
            self.seek_and_rewrite(ins_loc, 0, &init_stmt)?;
            global_id += 1;
            visitor = self.get_new_visitor()?;
        }

        Ok(())
    }

    fn add_sanitize_header(&mut self) -> Result<()> {
        let header = "#include \"FDSan.h\"\n";
        let mut content = std::fs::read_to_string(&self.src_file)?;
        content.insert_str(0, header);
        std::fs::write(&self.src_file, content)?;
        Ok(())
    }

    // Add FDSan stmts before each ReturnStmt to sanitize the misuse of files.
    fn add_sanitize_stmts(&mut self) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        let (fds, files, strings) = self.collect_file_identifiers(&visitor)?;
        let return_locs = self.collect_return_stmt_locs(&visitor)?;
        for loc in return_locs.iter().rev() {
            self.add_sanitize_stmt_by_loc(loc, &fds, &files, &strings)?;
        }
        Ok(())
    }

    fn add_sanitize_stmt_by_loc(
        &mut self,
        return_loc: &ReturnLoc,
        fds: &FileLine,
        files: &FileLine,
        strings: &FileLine,
    ) -> Result<()> {
        let (mut begin_loc, end_loc, return_range) = return_loc;
        if let Some(end) = end_loc {
            self.seek_and_rewrite(*end, 0, "\n\t}\n\t")?;
            self.seek_and_rewrite(begin_loc, 0, "{\n\t")?;
            begin_loc += 3;
        }
        for (fd, line, fd_range) in fds {
            if line < &begin_loc && in_compound_range(fd_range, return_range) {
                let stmt = format!("assert_fd_closed({fd});\n\t");
                self.seek_and_rewrite(begin_loc, 0, &stmt)?;
            }
        }
        for (file_name, line, fd_range) in strings {
            if line < &begin_loc && in_compound_range(fd_range, return_range) {
                let stmt = format!("assert_file_name_closed(\"{file_name}\");\n\t");
                self.seek_and_rewrite(begin_loc, 0, &stmt)?;
            }
        }
        for (file, line, fd_range) in files {
            if line < &begin_loc && in_compound_range(fd_range, return_range) {
                let stmt = format!("assert_file_closed(&{file});\n\t");
                self.seek_and_rewrite(begin_loc, 0, &stmt)?;
            }
        }
        Ok(())
    }

    fn collect_file_identifiers(
        &self,
        visitor: &Visitor,
    ) -> Result<(FileLine, FileLine, FileLine)> {
        let mut fds = Vec::new();
        let mut files = Vec::new();
        let mut strings = Vec::new();
        let input_re = Regex::new(r"^input_file(\.\w+)?$")?;
        let output_re = Regex::new(r"^output_file(\.\w+)?$")?;
        let mut cur_comp_range: Option<(usize, usize)> = None;
        let mut comp_stmts: Vec<(&ast::Node, Option<(usize, usize)>)> = vec![];

        let mut worklist = WorkList::new();
        worklist.push(&visitor.ast);

        while !worklist.empty() || !comp_stmts.is_empty() {
            if worklist.empty() {
                let (comp_stmt, comp_range) = comp_stmts.pop().unwrap();
                cur_comp_range = comp_range;
                if comp_stmt.get_childs().is_empty() {
                    continue;
                }
                worklist.push_childs(comp_stmt.get_childs());
            }
            let curr = worklist.pop();
            if let Clang::CompoundStmt(cs) = &curr.kind {
                let begin = get_sr_begin_loc(&cs.range)?.offset;
                let end = get_sr_end_loc(&cs.range)?.offset;
                let comp_range = Some((begin, end));
                comp_stmts.push((curr, comp_range));
                continue;
            }
            if let Clang::VarDecl(vd) = &curr.kind {
                if !vd.has_init(curr) {
                    continue;
                }
                let init = vd.get_init(curr).ignore_cast().ignore_parent();
                if let Clang::CallExpr(ce) = &init.kind {
                    let call = ce.get_name_as_string(init);
                    let line = get_sr_end_loc(&vd.range)?.offset;
                    if call == "fuzz_fileno" || call == "open" || call == "fileno" {
                        fds.push((vd.get_name_as_string(), line, cur_comp_range));
                    }
                    if call == "fmemopen" || call == "fopen" {
                        files.push((vd.get_name_as_string(), line, cur_comp_range));
                    }
                }
            }
            if let Clang::BinaryOperator(bo) = &curr.kind {
                let left = bo.get_lhs(curr).ignore_parent().ignore_cast();
                if let Clang::DeclRefExpr(dre) = &left.kind {
                    let name = dre.get_name_as_string();
                    let right = bo.get_rhs(curr).ignore_cast();
                    let line = get_sr_end_loc(&bo.range)?.offset;
                    if let Clang::CallExpr(ce) = &right.kind {
                        let call = ce.get_name_as_string(right);
                        if call == "fuzz_fileno" || call == "open" || call == "fileno" {
                            fds.push((name.clone(), line, cur_comp_range));
                        }
                        if call == "fmemopen" || call == "fopen" {
                            files.push((name, line, cur_comp_range));
                        }
                    }
                }
            }
            if let Clang::CallExpr(ce) = &curr.kind {
                let call_name = ce.get_name_as_string(curr);
                if call_name == "fopen" {
                    continue;
                }
            }
            if let Clang::StringLiteral(sl) = &curr.kind {
                let value = sl.get_eval_value();
                let line = get_sr_end_loc(&sl.range)?.offset;
                if input_re.is_match(&value) || output_re.is_match(&value) {
                    strings.push((value, line, cur_comp_range));
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        Ok((fds, files, strings))
    }

    // Collect the location information of all ReturnStmts in a program.
    // Return: Vec<begin_loc, Option<end_loc>, Option<Compound_end>>;
    fn collect_return_stmt_locs(&self, visitor: &Visitor) -> Result<Vec<ReturnLoc>> {
        let mut worklist = WorkList::new();
        worklist.push(&visitor.ast);
        let mut locs = Vec::new();
        let mut cur_comp_range: Option<(usize, usize)> = None;
        let mut cur_is_lambda = false;
        let mut comp_stmts: Vec<(&ast::Node, Option<(usize, usize)>, bool)> = vec![];

        while !worklist.empty() || !comp_stmts.is_empty() {
            if worklist.empty() {
                let (comp_stmt, comp_range, is_lambda) = comp_stmts.pop().unwrap();
                cur_comp_range = comp_range;
                cur_is_lambda = is_lambda;
                if comp_stmt.get_childs().is_empty() {
                    continue;
                }
                worklist.push_childs(comp_stmt.get_childs());
            }
            let curr = worklist.pop();
            if let Clang::FunctionDecl(fd) = &curr.kind {
                if fd.get_name() != "LLVMFuzzerTestOneInput" {
                    continue;
                }
            }
            if matches!(&curr.kind, Clang::CXXRecordDecl(_)) {
                continue;
            }
            // skip any body of CallExpr
            if let Clang::CallExpr(_) = &curr.kind {
                continue;
            }
            if let Clang::CXXMemberCallExpr = &curr.kind {
                continue;
            }
            if let Clang::CompoundStmt(cs) = &curr.kind {
                let begin = get_sr_begin_loc(&cs.range)?.offset;
                let end = get_sr_end_loc(&cs.range)?.offset;
                let comp_range = Some((begin, end));
                let is_lambda = cur_is_lambda || self.is_lambda_compound(begin)?;
                comp_stmts.push((curr, comp_range, is_lambda));
                continue;
            }
            if let Clang::ReturnStmt(re) = &curr.kind {
                if cur_is_lambda {
                    continue;
                }
                let loc = get_sr_begin_loc(&re.range)?.offset;
                let end = get_sr_end_loc(&re.range)?.offset;
                if loc == end {
                    continue;
                }
                let content = std::fs::read_to_string(&self.src_file)?;
                let content = content[end..].trim_end();
                let colon = content.find(';').unwrap();
                let mut content = content[colon + 1..].trim_start();
                if content.starts_with("//") {
                    content = content[content.find('\n').unwrap() + 1..].trim_start();
                }
                if content.starts_with('}') {
                    locs.push((loc, None, cur_comp_range));
                } else {
                    locs.push((loc, Some(end + colon + 1), cur_comp_range));
                }
            }
            worklist.push_childs(curr.get_childs());
        }
        locs.dedup();
        locs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(locs)
    }

    fn is_lambda_compound(&self, begin: usize) -> Result<bool> {
        let content = std::fs::read_to_string(&self.src_file)?;
        let line_start = content[..begin].rfind('\n').map_or(0, |idx| idx + 1);
        let prefix = &content[line_start..begin];
        Ok(prefix.contains("[]("))
    }
}

pub fn fd_sanitize(program: &Path, deopt: &Deopt) -> Result<FDError> {
    let ast = Executor::extract_ast(program, vec![], deopt)?;
    let cfg = CFGBuilder::build_cfg(ast)?;
    let adg_builder = ADGBuilder::new_sparse();
    let adg = adg_builder
        .custom_callback_build(cfg, fdsan_create_callback())
        .context(format!("Build ADG fail! {program:?}"))?;
    //adg.dump_to_file(program, true)?;
    if adg.detect_double_close() {
        log::debug!("double close detected");
        Ok(FDError::DC)
    } else if adg.detect_use_after_close() {
        log::debug!("use after close detected");
        Ok(FDError::UAC)
    } else {
        Ok(FDError::None)
    }
}

fn in_compound_range(
    fd_range: &Option<(usize, usize)>,
    return_range: &Option<(usize, usize)>,
) -> bool {
    if let Some((fd_begin, fd_end)) = fd_range {
        if let Some((ret_begin, ret_end)) = return_range {
            if fd_begin == ret_begin && fd_end == ret_end {
                return true;
            }
            if fd_begin < ret_begin && fd_end > ret_end {
                return true;
            }
        }
    }
    false
}

fn is_setjmp_call(node: &Node) -> bool {
    let node = node.ignore_cast();
    if let Clang::CallExpr(_) = &node.kind {
        if node.inner.is_empty() {
            return false;
        }
        let decl = &node.inner[0];
        let decl = decl.ignore_cast();
        if let Clang::DeclRefExpr(dre) = &decl.kind {
            let rd = &dre.referenced_decl;
            if rd.get_name_as_string() == "_setjmp" {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use super::*;

    impl FDError {
        fn is_uac(&self) -> bool {
            if let FDError::UAC = self {
                true
            } else {
                false
            }
        }

        fn is_dc(&self) -> bool {
            if let FDError::DC = self {
                true
            } else {
                false
            }
        }

        fn is_leak(&self) -> bool {
            if let FDError::LEAK = self {
                true
            } else {
                false
            }
        }

        fn is_none(&self) -> bool {
            if let FDError::None = self {
                true
            } else {
                false
            }
        }
    }

    #[test]
    fn test_detect_use_after_close() -> Result<()> {
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "sanitize",
            "fd_san_use_after_close.cc",
        ]
        .iter()
        .collect();
        let res = fd_sanitize(&c_test_path, &deopt)?;
        assert!(res.is_uac());
        Ok(())
    }

    #[test]
    fn test_detect_double_close() -> Result<()> {
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "sanitize",
            "fd_san_double_close.cc",
        ]
        .iter()
        .collect();
        let res = fd_sanitize(&c_test_path, &deopt)?;
        assert!(res.is_dc());
        Ok(())
    }

    #[test]
    fn test_detect_leak() -> Result<()> {
        crate::config::Config::init_test("zlib");
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "sanitize",
            "fd_san_leak.cc",
        ]
        .iter()
        .collect();
        let res = fd_sanitize(&c_test_path, &deopt)?;
        assert!(res.is_leak());
        Ok(())
    }

    #[test]
    fn test_fd_sanitize() -> Result<()> {
        crate::config::Config::init_test("zlib");
        let deopt = Deopt::new("zlib".to_string())?;
        let test_dir: PathBuf = [deopt.get_library_output_dir()?, "seeds_bak".into()]
            .iter()
            .collect();
        for entry in crate::deopt::utils::read_sort_dir(&test_dir)? {
            println!("{entry:#?}");
            let mut transformer = Transformer::new(&entry, &deopt)?;
            transformer.add_fd_sanitizer()?;
            let temp_file = transformer.get_output_file();
            let res = fd_sanitize(&temp_file, &deopt)?;
            println!("{res:#?}");
            assert!(res.is_none());
        }
        Ok(())
    }

    #[test]
    fn test_file_constraint() -> Result<()> {
        crate::config::Config::init_test("libtiff");
        let deopt = Deopt::new("libtiff".to_string())?;
        let seed_id = 1857;
        let work_seed = deopt.get_work_seed_by_id(seed_id)?;

        let mut transformer = Transformer::new(&work_seed, &deopt)?;
        transformer.add_fd_sanitizer()?;
        Ok(())
    }
}
