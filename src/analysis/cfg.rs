//! Build Control-Flow Graph (CFG) for the AST of a function.
//! The CFG is build with CFGBuilder.
//! You can build a CFG of a function by:
//!
//! ```
//! let cfg = CFGBuilder::build_cfg(ast)?;
//! ```
//!
//! Note that, the provided ast must be the body of a FunctionDecl.
//! If you decided to build CFG for arbitary part of an AST,
//!     you can use this to build the partial CFG:
//! ```
//!  let mut builder = CFGBuilder::default();
//!  let (entry, exit) = builder.build_from_ast(ast.clone())?;
//! ```
//! These will reutrn the Entry and Exit block for this CFG.

use crate::{
    analysis::WorkList,
    ast::{
        self,
        utils::{is_case_or_default_stmt, is_default_stmt, is_inner_contain_breakstmt},
        Clang, CommomHelper,
    },
    program::gadget::is_library_api,
};
use eyre::Result;
use petgraph::{
    dot::{Config, Dot},
    graph::{EdgeIndex, NodeIndex},
    Directed, Graph,
};
use std::{cell::RefCell, path::PathBuf};
use std::{collections::HashMap, process::Command};
use std::{collections::HashSet, path::Path, rc::Rc, slice::Iter};

type RcBasicBlock = Rc<RefCell<BasicBlock>>;

/// the basic block used for building CFG.
#[derive(Default)]
pub struct BasicBlock {
    pub ident: String,
    pub id: usize,
    pub stmts: Vec<Rc<ast::Node>>,
    pub succ: Vec<RcBasicBlock>,
}

/// the basic block used for building CFG.
impl BasicBlock {
    /// build with an block id.
    pub fn new(block_id: usize) -> Self {
        log::trace!("create a new block: [B{block_id}]");
        Self {
            id: block_id,
            ..Default::default()
        }
    }

    /// create the entry block.
    pub fn create_entry(block_id: usize) -> Self {
        let mut entry = Self::new(block_id);
        entry.ident = format!("[B{block_id} (Entry)]");
        entry
    }

    /// create the exit block.
    pub fn create_exit(block_id: usize) -> Self {
        let mut entry = Self::new(block_id);
        entry.ident = format!("[B{block_id} (Exit)]");
        entry
    }

    /// create an empty block with no stmts.
    pub fn create_empty(block_id: usize) -> Self {
        let mut entry = Self::new(block_id);
        entry.ident = format!("[B{block_id}]");
        entry
    }

    /// append stmt to this block.
    pub fn append_stmt(&mut self, stmt: Rc<ast::Node>) {
        self.stmts.push(stmt);
    }

    /// add a successor of this block.
    pub fn add_succ(&mut self, succ: RcBasicBlock) {
        self.succ.push(succ)
    }

    /// get the successors of this blcok.
    pub fn get_succ(&self) -> Vec<RcBasicBlock> {
        self.succ.clone()
    }

    /// pop the specific node from successors.
    pub fn pop_succ(&mut self, node: RcBasicBlock) {
        let mut index: usize = usize::MAX;
        for (id, child) in self.succ.iter().enumerate() {
            if child.borrow().get_ident() == node.borrow().get_ident() {
                index = id;
                break;
            }
        }
        // This node must in self.succ.
        assert_ne!(index, usize::MAX);
        self.succ.remove(index);
    }

    /// clear successors of this block.
    pub fn clear_succ(&mut self) {
        self.succ.clear();
    }

    /// get the single successor of this block.
    pub fn get_signle_succ(&self) -> RcBasicBlock {
        // only can used when is block has only one child.
        assert_eq!(self.succ.len(), 1);
        self.succ[0].clone()
    }

    /// get the identifier of this block.
    pub fn get_ident(&self) -> String {
        self.ident.clone()
    }

    /// clone self to CFGBlock
    pub fn to_cfg_block(&self) -> CFGBlock {
        CFGBlock {
            ident: self.ident.clone(),
            stmts: self.stmts.clone(),
        }
    }

    /// If this block is started with LabelStmt, return label_id.
    pub fn is_label_block(&self) -> Option<clang_ast::Id> {
        if self.stmts.is_empty() {
            return None;
        }
        let first = self.stmts.first().unwrap();
        if let ast::Clang::LabelStmt(label) = &first.kind {
            return Some(label.decl_id);
        }
        None
    }

    /// If this block ends with GotoStmt, return goto_id.
    pub fn is_goto_block(&self) -> Option<clang_ast::Id> {
        if self.stmts.is_empty() {
            return None;
        }
        let last = self.stmts.last().unwrap();
        if let ast::Clang::GotoStmt(goto) = &last.kind {
            return Some(goto.target_label_decl_id);
        }
        None
    }

    /// Is this block ends with ReturnStmt.
    pub fn is_return_block(&self) -> bool {
        if self.stmts.is_empty() {
            return false;
        }
        let last = self.stmts.last().unwrap();
        if let ast::Clang::ReturnStmt(_) = &last.kind {
            return true;
        }
        false
    }
}

#[derive(Clone)]
/// The block stored in CFG, which only include necessary attributes.
pub struct CFGBlock {
    ident: String,
    stmts: Vec<Rc<ast::Node>>,
}

/// Default deubg display all node information which is unreadable. We should only verbose the useful stmt information.
impl std::fmt::Debug for CFGBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut stmt_kinds: Vec<String> = Vec::new();
        for stmt in &self.stmts {
            let dump_str = stmt.dump();
            stmt_kinds.push(dump_str);
        }
        let stmts = stmt_kinds.join("\n");
        write!(f, "{}\n {}", self.ident, stmts)
    }
}

impl CFGBlock {
    pub fn is_entry(&self) -> bool {
        self.ident == "[B0 (Entry)]"
    }

    pub fn is_exit(&self) -> bool {
        self.ident.contains("Exit")
    }

    pub fn iter_stmts(&self) -> Iter<'_, Rc<ast::Node>> {
        self.stmts.iter()
    }

    pub fn get_ident(&self) -> String {
        self.ident.clone()
    }

    /// get the line number of API calls inside this block
    pub fn get_call_lines(&self) -> Vec<usize> {
        let mut line_locs = Vec::new();
        for stmt in &self.stmts {
            let mut worklist = WorkList::new();
            worklist.push(stmt.as_ref());
            while !worklist.empty() {
                let cur = worklist.pop();
                if let Clang::CallExpr(ce) = &cur.kind {
                    let call_name = ce.get_name_as_string(cur);
                    if is_library_api(&call_name) {
                        let line = ce.get_souce_line();
                        line_locs.push(line);
                    }
                }
                for child in &cur.inner {
                    worklist.push(child);
                }
            }
        }
        line_locs
    }

    pub fn get_caller(&self) -> Vec<String> {
        let mut callers = Vec::new();
        for stmt in &self.stmts {
            let mut worklist = WorkList::new();
            worklist.push(stmt.as_ref());
            while !worklist.empty() {
                let cur = worklist.pop();
                if let Clang::CallExpr(ce) = &cur.kind {
                    let call_name = ce.get_name_as_string(cur);
                    if is_library_api(&call_name) {
                        callers.push(call_name);
                    }
                }
                for child in &cur.inner {
                    worklist.push(child);
                }
            }
        }
        callers
    }
}

pub type EdgeWeight = usize;
#[derive(Clone)]
pub struct CFG {
    graph: Graph<CFGBlock, EdgeWeight, Directed>,
    node_map: HashMap<String, NodeIndex>,
    edge_map: HashMap<(NodeIndex, NodeIndex), EdgeIndex>,
}

impl Default for CFG {
    fn default() -> Self {
        Self::new()
    }
}

impl CFG {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
            node_map: HashMap::new(),
            edge_map: HashMap::new(),
        }
    }

    /// get the Entry node index.
    pub fn get_entry_node(&self) -> Result<NodeIndex> {
        let node = self
            .graph
            .node_indices()
            .next()
            .ok_or_else(|| eyre::eyre!("Empty CFG."))?;
        let entry = self
            .graph
            .node_weight(node)
            .ok_or_else(|| eyre::eyre!("No weight attaced with {node:?}"))?;
        if entry.is_entry() {
            Ok(node)
        } else {
            eyre::bail!("{entry:?} is not the Entry.")
        }
    }

    /// get the Exit node index.
    pub fn get_exit_node(&self) -> Result<NodeIndex> {
        let node = self
            .graph
            .node_indices()
            .next_back()
            .ok_or_else(|| eyre::eyre!("Empty CFG."))?;
        let exit = self
            .graph
            .node_weight(node)
            .ok_or_else(|| eyre::eyre!("No weight with {node:?}"))?;
        if exit.is_exit() {
            Ok(node)
        } else {
            eyre::bail!("{exit:?} is not the Exit.")
        }
    }

    /// get the node weight (CFGBlock) of the given node index.
    pub fn get_node_weight(&self, node: NodeIndex) -> Result<CFGBlock> {
        Ok(self
            .graph
            .node_weight(node)
            .ok_or_else(|| eyre::eyre!("no weight with {node:?}"))?
            .clone())
    }

    pub fn get_node(&self, bb: &CFGBlock) -> NodeIndex {
        let ident = &bb.ident;
        if self.node_map.contains_key(ident) {
            return *self.node_map.get(ident).unwrap();
        }
        unreachable!("{bb:#?} not in CFG")
    }

    pub fn get_edge(&self, src: &CFGBlock, dest: &CFGBlock) -> Option<EdgeIndex> {
        let src_node = self.get_node(src);
        let dest_node = self.get_node(dest);
        let edge = (src_node, dest_node);
        if self.edge_map.contains_key(&edge) {
            return self.edge_map.get(&edge).copied();
        }
        None
    }

    /// get edge weight
    pub fn get_edge_weight(&self, src: &CFGBlock, dest: &CFGBlock) -> Option<&EdgeWeight> {
        if let Some(edge) = self.get_edge(src, dest) {
            return self.graph.edge_weight(edge);
        }
        None
    }

    /// get mutable edge weight
    pub fn get_edge_weigth_mut(
        &mut self,
        src: &CFGBlock,
        dest: &CFGBlock,
    ) -> Option<&mut EdgeWeight> {
        if let Some(edge) = self.get_edge(src, dest) {
            return self.graph.edge_weight_mut(edge);
        }
        None
    }

    /// update edge weight
    pub fn update_edge_weight(
        &mut self,
        src: &CFGBlock,
        dest: &CFGBlock,
        weight: EdgeWeight,
    ) -> Result<()> {
        if let Some(old_weight) = self.get_edge_weigth_mut(src, dest) {
            *old_weight = weight;
            return Ok(());
        }
        eyre::bail!("Edge from {src:?} to {dest:?} does not exist")
    }

    // get the node index from graph. if not exist, add this node beforehand.
    pub fn get_or_add_node(&mut self, bb: CFGBlock) -> NodeIndex {
        let ident = bb.ident.clone();
        if self.node_map.contains_key(&ident) {
            return *self.node_map.get(&ident).unwrap();
        }
        let curr_node = self.graph.add_node(bb);
        self.node_map.insert(ident, curr_node);
        curr_node
    }

    // add edge if not exist
    pub fn add_edge(&mut self, src: NodeIndex, dest: NodeIndex) -> EdgeIndex {
        let edge = (src, dest);
        if self.edge_map.contains_key(&edge) {
            return *self.edge_map.get(&edge).unwrap();
        }
        //log::trace!("add edge from {src:?} to {dest:?}");
        let edge_idx = self.graph.add_edge(src, dest, 0);
        self.edge_map.insert(edge, edge_idx);
        edge_idx
    }

    /// get all incoming nodes to this block.
    pub fn get_predecessors(&self, block: &CFGBlock) -> Vec<CFGBlock> {
        let node = self.get_node(block);
        let idxs = self
            .graph
            .neighbors_directed(node, petgraph::Direction::Incoming);
        let mut predecessors = vec![];
        for idx in idxs {
            let block = self.get_node_weight(idx).unwrap();
            predecessors.push(block);
        }
        predecessors
    }

    /// get all outgoing nodes from this block
    pub fn get_successors(&self, block: &CFGBlock) -> Vec<CFGBlock> {
        let node = self.get_node(block);
        let idxs = self
            .graph
            .neighbors_directed(node, petgraph::Direction::Outgoing);
        let mut predecessors = vec![];
        for idx in idxs {
            let block = self.get_node_weight(idx).unwrap();
            predecessors.push(block);
        }
        predecessors
    }

    /// Return the line nubmer of the library API calls lie in the path owns the max callees.
    pub fn visit_max_caller_path(&self) -> Result<Vec<Vec<usize>>> {
        let mut max_callee_path: Vec<usize> = Vec::new();
        let mut equ_max_len_callee_paths: Vec<Vec<usize>> = Vec::new();

        let mut worklist: WorkList<(CFGBlock, Vec<usize>)> = WorkList::new();
        let entry = self.get_entry_node()?;
        let entry_block = self.get_node_weight(entry)?;
        worklist.push((entry_block, vec![]));

        while !worklist.empty() {
            let (cur_block, cur_calls) = worklist.pop();
            if cur_block.is_exit() {
                match cur_calls.len().cmp(&max_callee_path.len()) {
                    std::cmp::Ordering::Less => continue,
                    std::cmp::Ordering::Equal => equ_max_len_callee_paths.push(cur_calls),
                    std::cmp::Ordering::Greater => {
                        equ_max_len_callee_paths.clear();
                        equ_max_len_callee_paths.push(cur_calls.clone());
                        max_callee_path = cur_calls;
                    }
                }
                continue;
            }
            let lines = [cur_calls, cur_block.get_call_lines()].concat();
            let childs = self.get_successors(&cur_block);
            for child in childs {
                worklist.push((child, lines.clone()));
            }
        }
        equ_max_len_callee_paths.dedup();
        Ok(equ_max_len_callee_paths)
    }

    // Visit the CFG and find the paths that called maximal APIs.
    pub fn visit_max_caller(&self) -> Result<Vec<Vec<String>>> {
        let mut max_caller: Vec<String> = Vec::new();
        let mut equ_max_len_caller: Vec<Vec<String>> = Vec::new();

        let mut worklist: WorkList<(CFGBlock, Vec<String>)> = WorkList::new();
        let entry = self.get_entry_node()?;
        let entry_block = self.get_node_weight(entry)?;
        worklist.push((entry_block, vec![]));

        while !worklist.empty() {
            let (cur_block, cur_calls) = worklist.pop();
            if cur_block.is_exit() {
                match cur_calls.len().cmp(&max_caller.len()) {
                    std::cmp::Ordering::Less => continue,
                    std::cmp::Ordering::Equal => equ_max_len_caller.push(cur_calls),
                    std::cmp::Ordering::Greater => {
                        equ_max_len_caller.clear();
                        equ_max_len_caller.push(cur_calls.clone());
                        max_caller = cur_calls;
                    }
                }
                continue;
            }
            let lines = [cur_calls, cur_block.get_caller()].concat();
            let childs = self.get_successors(&cur_block);
            for child in childs {
                worklist.push((child, lines.clone()));
            }
        }
        equ_max_len_caller.dedup();
        Ok(equ_max_len_caller)
    }

    /// Dump this cfg to a Graphviz format file and translate it to PNG.
    pub fn dump_to_file(&self, file: &Path, verbose_edge: bool) -> Result<()> {
        let config = if verbose_edge {
            vec![]
        } else {
            vec![Config::EdgeNoLabel]
        };
        let raw_str = format!("{:?}", Dot::with_config(&self.graph, &config));
        let mut dot_path = PathBuf::from(file);
        dot_path.set_extension("dot");
        std::fs::write(&dot_path, raw_str)?;
        let mut cfg_path = dot_path.clone();
        cfg_path.set_extension("cfg.png");
        let output = Command::new("dot")
            .arg("-Tpng")
            .arg(&dot_path)
            .arg("-o")
            .arg(cfg_path)
            .output()?;
        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
            eyre::bail!("{err_msg}");
        }
        std::fs::remove_file(dot_path)?;
        Ok(())
    }
}

/// Build CFG from the given statements.
#[derive(Default)]
pub struct CFGBuilder {
    /// current block
    pub block: Option<Rc<BasicBlock>>,
    /// id of current block
    pub block_id: usize,
    /// stored basicblocks
    pub bbs: Vec<RcBasicBlock>,
    /// Function name of this CFG
    pub name: Option<String>,
}

impl CFGBuilder {
    /// init the function name for this cfg builder.
    pub fn init_from_ast(&mut self, ast: &ast::Node) -> Result<()> {
        if let ast::Clang::FunctionDecl(fd) = &ast.kind {
            self.name = Some(fd.get_name());
            return Ok(());
        }
        eyre::bail!("expect FunctionDecl, receive: {ast:?}");
    }

    /// get a builder starts with block_id.
    pub fn from_block_id(block_id: usize) -> Self {
        CFGBuilder {
            block_id,
            ..Default::default()
        }
    }

    /// create the entry basic blcok
    fn create_entry_bb(&mut self) -> RcBasicBlock {
        let entry = Rc::new(RefCell::new(BasicBlock::create_entry(self.block_id)));
        self.block_id += 1;
        entry
    }

    /// create the exit basic blcok
    fn create_exit_bb(&mut self) -> RcBasicBlock {
        let exit = Rc::new(RefCell::new(BasicBlock::create_exit(self.block_id)));
        self.block_id += 1;
        exit
    }

    /// create an empty basic blcok
    fn create_empty_bb(&mut self) -> RcBasicBlock {
        let bb = Rc::new(RefCell::new(BasicBlock::create_empty(self.block_id)));
        self.block_id += 1;
        bb
    }

    /// connect edge from src to dest blocks.
    fn connect_bb(&self, src: RcBasicBlock, dest: RcBasicBlock) {
        log::trace!(
            "Add edge from {} to {}",
            src.borrow().get_ident(),
            dest.borrow().get_ident()
        );
        src.borrow_mut().add_succ(dest);
    }

    /// build a cfg from the given AST.
    pub fn build_cfg(ast: ast::Node) -> Result<CFG> {
        let mut builder = CFGBuilder::default();
        builder.init_from_ast(&ast)?;
        log::trace!("Build CFG for function : {:?}", builder.name);
        let ast = Rc::new(ast);
        let (entry, exit) = builder.build_from_ast(ast.clone())?;
        let entry = CFGBuilder::refine_blocks(entry, exit);

        let mut cfg = CFG::new();

        let mut worklist = WorkList::new();
        let mut visited = HashSet::new();
        worklist.push(entry);
        // Bread-first traversal to build graph.
        while !worklist.empty() {
            let curr = worklist.pop_front();
            if visited.contains(&curr.borrow().get_ident()) {
                continue;
            }
            let curr_node = cfg.get_or_add_node(curr.borrow().to_cfg_block());
            for child in curr.borrow().get_succ() {
                let child_node = cfg.get_or_add_node(child.borrow().to_cfg_block());
                cfg.add_edge(curr_node, child_node);
                worklist.push(child.clone());
            }
            visited.insert(curr.borrow().get_ident());
        }
        Ok(cfg)
    }

    /// build the basic blocks for the given partial AST.
    pub fn build_block_for_ast(
        &mut self,
        ast: Rc<ast::Node>,
    ) -> eyre::Result<(RcBasicBlock, RcBasicBlock)> {
        let mut builder = CFGBuilder::from_block_id(self.block_id);
        let (entry, exit) = builder.build_from_ast(ast)?;
        self.block_id = builder.block_id;
        Ok((entry, exit))
    }

    /// build basic blocks for the given ast.
    pub fn build_from_ast(
        &mut self,
        ast: Rc<ast::Node>,
    ) -> eyre::Result<(RcBasicBlock, RcBasicBlock)> {
        let entry = self.create_entry_bb();
        // current working blcok.
        let mut block = self.create_empty_bb();
        self.connect_bb(entry.clone(), block.clone());

        let mut worklist = WorkList::new();
        worklist.push(ast.clone());
        while !worklist.empty() {
            let curr = worklist.pop();
            match &curr.kind {
                // just skip these stmts.
                ast::Clang::TranslationUnitDecl
                | ast::Clang::ExprWithCleanups
                | ast::Clang::CompoundStmt(_)
                | ast::Clang::CaseStmt
                | ast::Clang::DefaultStmt
                | ast::Clang::FunctionDecl(_)
                | ast::Clang::ImplicitCastExpr(_)
                | ast::Clang::CStyleCastExpr(_)
                | ast::Clang::ParenExpr(_) => {
                    let mut childs = Vec::new();
                    for child in &curr.inner {
                        let inner = Rc::new(child.clone());
                        childs.push(inner);
                    }
                    worklist.push_childs(childs);
                }
                // just push thest stmts.
                ast::Clang::DeclStmt(_)
                | ast::Clang::ReturnStmt(_)
                | ast::Clang::Other
                | ast::Clang::BinaryOperator(_)
                | ast::Clang::CallExpr(_)
                | ast::Clang::CXXMemberCallExpr
                | ast::Clang::UnaryOperator(_)
                | ast::Clang::BreakStmt
                | ast::Clang::ContinueStmt
                | ast::Clang::ParmVarDecl(_)
                | ast::Clang::DeclRefExpr(_)
                | ast::Clang::ConstantExpr(_)
                | ast::Clang::IntegerLiteral(_)
                | ast::Clang::FloatingLiteral(_)
                | ast::Clang::CharacterLiteral(_)
                | ast::Clang::StringLiteral(_)
                | ast::Clang::GNUNullExpr(_)
                | ast::Clang::MemberExpr(_)
                | ast::Clang::CXXNullPtrLiteralExpr(_) => {
                    block.borrow_mut().append_stmt(curr.clone());
                }
                ast::Clang::IfStmt(ifstmt) => {
                    let has_else = ifstmt.has_else;
                    if has_else {
                        // Three childs: Condition, Then, Else
                        assert_eq!(
                            curr.inner.len(),
                            3,
                            "The if stmt should has three child stmts."
                        );
                    } else {
                        // Three childs: Condition, Then
                        assert_eq!(
                            curr.inner.len(),
                            2,
                            "The if stmt should has two child stmts."
                        );
                    }

                    let cond = Rc::new(curr.inner[0].clone());
                    let then = Rc::new(curr.inner[1].clone());
                    // push cond child to current block.
                    block.borrow_mut().append_stmt(cond.clone());
                    // build basic blocks for the Then child.
                    let (then_entry, then_exit) = self.build_block_for_ast(then)?;
                    // build next wroking block.
                    let new_block = self.create_empty_bb();
                    // add cfg edges: block->then_block->new_block
                    self.connect_bb(block.clone(), then_entry.clone());
                    self.connect_bb(then_exit, new_block.clone());
                    // build and add the else block.
                    if has_else {
                        let else_block = Rc::new(curr.inner[2].clone());
                        let (else_entry, else_exit) = self.build_block_for_ast(else_block)?;
                        // has eles, connect block->else_block->new_block;
                        self.connect_bb(block.clone(), else_entry.clone());
                        self.connect_bb(else_exit, new_block.clone());
                    } else {
                        // hasn't else, connect block->new_block
                        self.connect_bb(block.clone(), new_block.clone());
                    }
                    block = new_block;
                }
                ast::Clang::ForStmt => {
                    // forstmt has 4 childs: init, NULL, cond, body, inc
                    assert_eq!(curr.inner.len(), 5);
                    let init = Rc::new(curr.inner[0].clone());
                    let cond = Rc::new(curr.inner[2].clone());
                    let inc = Rc::new(curr.inner[3].clone());
                    let body = Rc::new(curr.inner[4].clone());

                    // build basic blocks for the Init child.
                    let (init_entry, init_exit) = self.build_block_for_ast(init)?;

                    // build basic blocks for the Cond child.
                    let (cond_entry, cond_exit) = self.build_block_for_ast(cond)?;

                    // build basic blocks for the Body child.
                    let (body_entry, body_exit) = self.build_block_for_ast(body)?;

                    // build basic blocks for the Inc child.
                    let (inc_entry, inc_exit) = self.build_block_for_ast(inc)?;

                    // build next wroking block.
                    let new_block = self.create_empty_bb();
                    // connect cfg edges
                    self.connect_bb(block.clone(), init_entry.clone());
                    self.connect_bb(init_exit.clone(), cond_entry.clone());
                    self.connect_bb(cond_exit.clone(), new_block.clone());
                    self.connect_bb(cond_exit.clone(), body_entry.clone());
                    self.connect_bb(body_exit.clone(), inc_entry.clone());
                    self.connect_bb(inc_exit.clone(), new_block.clone());
                    // set new_block as the working blcok;
                    block = new_block;
                }
                ast::Clang::WhileStmt => {
                    // WhileStmt has two nodes: Cond, Body
                    let (cond, body) = if curr.inner.len() == 2 {
                        (
                            Rc::new(curr.inner[0].clone()),
                            Rc::new(curr.inner[1].clone()),
                        )
                    } else if curr.inner.len() == 3 {
                        (
                            Rc::new(curr.inner[0].clone()),
                            Rc::new(curr.inner[2].clone()),
                        )
                    } else {
                        unreachable!("{curr:#?}")
                    };

                    // build basic blocks for the Cond child.
                    let (cond_entry, cond_exit) = self.build_block_for_ast(cond)?;

                    // build basic blocks for the Body child.
                    let (body_entry, body_exit) = self.build_block_for_ast(body)?;

                    // build next wroking block.
                    let new_block = self.create_empty_bb();

                    // connect cfg edges.
                    self.connect_bb(block.clone(), cond_entry.clone());
                    self.connect_bb(cond_exit.clone(), body_entry.clone());
                    self.connect_bb(cond_exit.clone(), new_block.clone());
                    self.connect_bb(body_exit.clone(), new_block.clone());

                    block = new_block;
                }
                ast::Clang::DoStmt => {
                    // DoStmt has two nodes: Body, Cond
                    assert_eq!(curr.inner.len(), 2, "{curr:#?}");
                    let body = Rc::new(curr.inner[0].clone());
                    let cond = Rc::new(curr.inner[1].clone());

                    // build basic blocks for the Cond child.
                    let (cond_entry, cond_exit) = self.build_block_for_ast(cond)?;

                    // build basic blocks for the Body child.
                    let (body_entry, body_exit) = self.build_block_for_ast(body)?;

                    // build next wroking block.
                    let new_block = self.create_empty_bb();

                    // connect cfg edges.
                    self.connect_bb(block.clone(), body_entry.clone());
                    self.connect_bb(body_exit.clone(), cond_entry.clone());
                    self.connect_bb(cond_exit.clone(), new_block.clone());

                    block = new_block;
                }
                ast::Clang::GotoStmt(_) => {
                    block.borrow_mut().append_stmt(curr.clone());
                    let new_block = self.create_empty_bb();
                    // The edge from block-> new_block shouldn't exist. The edge to next block is delayed.
                    block = new_block;
                }
                ast::Clang::LabelStmt(_) => {
                    let new_block = self.create_empty_bb();
                    // The edge from gotoStmt is delayed.
                    self.connect_bb(block.clone(), new_block.clone());
                    block = new_block;
                    block.borrow_mut().append_stmt(curr.clone());
                }
                ast::Clang::SwitchStmt => {
                    // SwitchStmt has two nodes: Cond, Body
                    assert_eq!(curr.inner.len(), 2, "{curr:#?}");
                    let cond = Rc::new(curr.inner[0].clone());
                    let body = Rc::new(curr.inner[1].clone());

                    block.borrow_mut().append_stmt(cond.clone());
                    let new_block = self.create_empty_bb();
                    let mut previous = None;
                    for child in &body.inner {
                        let child_block = Rc::new(child.clone());
                        let (block_entry, block_exit) = self.build_block_for_ast(child_block)?;
                        if is_case_or_default_stmt(child) {
                            self.connect_bb(block.clone(), block_entry.clone());
                        }
                        if let Some(previous) = previous {
                            self.connect_bb(previous, block_entry);
                        }
                        if is_inner_contain_breakstmt(child) {
                            previous = None;
                            self.connect_bb(block_exit.clone(), new_block.clone());
                        } else if is_default_stmt(child) {
                            self.connect_bb(block_exit.clone(), new_block.clone());
                            break;
                        } else {
                            previous = Some(block_exit);
                        }
                    }
                    block = new_block;
                }
                _ => todo!("{:#?} is unimplemented", curr),
            }
        }

        let exit = self.create_exit_bb();
        block.borrow_mut().add_succ(exit.clone());
        Ok((entry, exit))
    }

    /// Refine the initial build blocks:
    /// 1. remove the redundant edge and nodes.
    /// 2. add correct Return to Exit edges.
    /// 3. add correct Goto to Label edges.
    pub fn refine_blocks(entry: RcBasicBlock, exit: RcBasicBlock) -> RcBasicBlock {
        let entry = CFGBuilder::remove_dup(entry, exit.clone());
        let entry = CFGBuilder::add_return_connect(entry, exit);
        CFGBuilder::add_goto_connection(entry)
    }

    /// Remove the redundant nodes and edges from the build entry.
    pub fn remove_dup(entry: RcBasicBlock, exit: RcBasicBlock) -> RcBasicBlock {
        let entry_ident = entry.borrow().get_ident();
        let exit_ident = exit.borrow().get_ident();

        let mut worklist = WorkList::new();
        let mut visited = HashSet::new();
        worklist.push(entry.clone());
        while !worklist.empty() {
            let curr = worklist.pop();
            if visited.contains(&curr.borrow().get_ident()) {
                continue;
            }

            let mut need_to_pop = Vec::new();
            let mut need_to_push: Vec<RcBasicBlock> = Vec::new();
            let mut push_curr = false;
            // find the child that need to be removed or pushed.
            for child in &curr.borrow().get_succ() {
                // if find redundant "Entry" and "Exit" nodes, drop them.
                if Self::block_should_delete(child.clone(), &entry_ident, &exit_ident) {
                    let next_nodes = child.borrow().get_succ();
                    need_to_pop.push(child.clone());
                    need_to_push.extend(next_nodes.clone());
                    // remove the edge from child->next_node.
                    if Rc::strong_count(child) == 1 {
                        for next in next_nodes {
                            child.borrow_mut().pop_succ(next);
                        }
                    }
                    push_curr = true;
                    break;
                }
            }
            if push_curr {
                worklist.push(curr.clone());
                // remove the edge from curr->child
                for node in need_to_pop {
                    curr.borrow_mut().pop_succ(node);
                }
                // add the edge to curr->next_node
                for node in need_to_push {
                    curr.borrow_mut().add_succ(node);
                }
            } else {
                visited.insert(curr.borrow().get_ident());
                for child in &curr.borrow().get_succ() {
                    worklist.push(child.clone());
                }
            }
        }
        entry
    }

    /// Goto jump cannot add during building. Connect goto jump to label blocks as a post-process step.
    pub fn add_goto_connection(entry: RcBasicBlock) -> RcBasicBlock {
        let mut label_blocks: HashMap<clang_ast::Id, RcBasicBlock> = HashMap::new();

        // first traversal to collect labeled block;
        let mut worklist = WorkList::new();
        worklist.push(entry.clone());
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Some(label_id) = curr.borrow().is_label_block() {
                label_blocks.insert(label_id, curr.clone());
            }
            for child in curr.borrow().get_succ() {
                worklist.push(child);
            }
        }

        // second traversal to connect the blocks from goto to label.
        let mut worklist = WorkList::new();
        worklist.push(entry.clone());
        while !worklist.empty() {
            let curr = worklist.pop();
            let block = if let Some(goto_id) = curr.borrow().is_goto_block() {
                label_blocks.get(&goto_id)
            } else {
                None
            };
            if let Some(block) = block {
                curr.borrow_mut().add_succ(block.clone());
            }
            for child in curr.borrow().get_succ() {
                worklist.push(child);
            }
        }
        entry
    }

    /// Some return jump cannnot connect during building. Connect Return jump to Exit blocks as a post-process step.
    pub fn add_return_connect(entry: RcBasicBlock, exit: RcBasicBlock) -> RcBasicBlock {
        let mut worklist = WorkList::new();
        worklist.push(entry.clone());

        while !worklist.empty() {
            let curr = worklist.pop_front();
            let curr_ref = curr.borrow();
            if curr_ref.is_return_block() {
                drop(curr_ref);
                curr.borrow_mut().clear_succ();
                curr.borrow_mut().add_succ(exit.clone());
            }
            for child in curr.borrow().get_succ() {
                worklist.push(child);
            }
        }
        entry
    }

    // The redundant "Entry" and "Exit" shoud be removed.
    pub fn block_should_delete(block: RcBasicBlock, entry_ident: &str, exit_ident: &str) -> bool {
        let child_ident = block.borrow().get_ident();
        if child_ident != entry_ident
            && child_ident != exit_ident
            && (child_ident.contains("Entry") || child_ident.contains("Exit"))
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::Deopt;

    use super::*;

    #[test]
    fn test_cfg_builder() -> Result<()> {
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf =
            [crate::Deopt::get_crate_dir()?, "testsuites", "test_cfg.cc"]
                .iter()
                .collect();
        let ast = crate::execution::Executor::extract_func_ast(
            &c_test_path,
            vec![],
            &deopt,
            "LLVMFuzzerTestOneInput",
            true,
        )?;
        let cfg = CFGBuilder::build_cfg(ast)?;
        let out = c_test_path.with_extension("cfg");
        cfg.dump_to_file(&out, false)?;
        // TODO: verify the generated CFG is correct.
        Ok(())
    }

    #[test]
    fn test_cfg_max_call_path() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf =
            [crate::Deopt::get_crate_dir()?, "testsuites", "test_cfg.cc"]
                .iter()
                .collect();
        let ast = crate::execution::Executor::extract_func_ast(
            &c_test_path,
            vec![],
            &deopt,
            "LLVMFuzzerTestOneInput",
            true,
        )?;
        let cfg = CFGBuilder::build_cfg(ast)?;
        let path = cfg.visit_max_caller_path()?;
        assert_eq!(path.len(), 2);
        let path_0 = &path[0];
        let path_1 = &path[1];
        assert_eq!(
            path_0,
            &vec![
                61, 68, 76, 85, 85, 89, 89, 97, 106, 107, 108, 113, 115, 120, 128, 129, 130, 135,
                143, 144
            ]
        );
        assert_eq!(
            path_1,
            &vec![
                61, 68, 76, 85, 85, 89, 89, 97, 106, 107, 108, 113, 115, 120, 128, 129, 130, 135,
                137, 138
            ]
        );
        Ok(())
    }

    #[test]
    fn test_cfg_max_caller() -> Result<()> {
        crate::config::Config::init_test("cJSON");
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf =
            [crate::Deopt::get_crate_dir()?, "testsuites", "test_cfg.cc"]
                .iter()
                .collect();
        let ast = crate::execution::Executor::extract_func_ast(
            &c_test_path,
            vec![],
            &deopt,
            "LLVMFuzzerTestOneInput",
            true,
        )?;
        let cfg = CFGBuilder::build_cfg(ast)?;
        let callers = cfg.visit_max_caller()?;
        assert_eq!(callers[0].len(), 20);
        Ok(())
    }

    /// test CFGBuilder whther successfully run on all correct seeds.
    #[test]
    fn test_cfg_builder_on_seeds() -> Result<()> {
        let deopt = crate::Deopt::new("cJSON".to_string())?;
        let mut out_dir = deopt.get_library_output_dir()?;
        out_dir.push("cfgs");
        crate::deopt::utils::create_dir_if_nonexist(&out_dir)?;

        let correct_seed_dir = deopt.get_library_seed_dir()?;
        for seed in std::fs::read_dir(correct_seed_dir)? {
            let entry = seed?.path();
            log::trace!("seed to test cfg: {entry:?}");

            let ast = crate::execution::Executor::extract_ast(&entry, vec![], &deopt)?;
            let cfg = CFGBuilder::build_cfg(ast)?;
            let mut cfg_path = PathBuf::from(out_dir.clone());
            cfg_path.push(entry.file_name().unwrap());
            cfg.dump_to_file(&cfg_path, false)?;
        }
        Ok(())
    }
}
