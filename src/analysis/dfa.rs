//! Context-Sensitive and Control-flow Sensitive data flow analysis engine
//!
//! The data flow engine is achieved by traversing CFG (build from AST) and abstractly evaluating the value transfers between the code statements,
//!     as it handles each callsite unique and differs object conditionally,
//!     the engine achieves a context-sensitive and control-flow sensitive analysis.
//!
//! The engine is highly customized for collecting API dependency or other usefull relation,
//!     especially for building API Dependency Graph (ADG),
//!     and thus is not an gneneral engine for travial analysis work.
//!
//! Note:
//! 1. field-insensitive, e.g., does not differ array[i] with array.
//! 2. value abstraction, e.g., record where the variable obtained from or passed to and attach it with an abstract symbol value.
//!    But it does not evaluate the variable with exact compution.
//!
//! Inter-procedural analysis is expensive,
//!     as its goal of design is to build ADG,
//!     and intra-procedural analysis is enough.
//!
//! The DFA engine is equipped with serveral callbacks which are able to inject or collect data flow on Symbols by intercepting the DFA execution.
//! You can implement your callbacks to customize your DFA tasks.
//! ```
//! pub struct CallBack {
//! merge: Box<dyn Fn(&Symbol, &Symbol) -> Symbol>,
//! /// invoked before CallStmt, so is able to access the arguments.
//! precall: Box<dyn Fn(&mut StoreMgr, &ast::Node) -> ()>,
//! /// invokded after CallStmt, so is able to access the returned symbol.
//! postcall: Box<dyn Fn(&mut StoreMgr, &ast::Node, &mut Symbol) -> ()>
//! }
//! ```
//! With the default CallBacks,
//!     this DFA engine does not perform any redundant works except for the control-flow sensitive data flow simulation and value abstraction.
//!

use crate::ast::{self, CommomHelper};
use std::collections::{HashMap, HashSet};

use super::{
    cfg::{CFGBlock, EdgeWeight, CFG},
    WorkList,
};
use clang_ast::Id;
use eyre::Result;

/// Path-based symbol storage.
pub type Storage<T> = HashMap<VarName, Symbol<T>>;

pub struct Analyzer<T: SymbolData> {
    store_mgr: StoreMgr<T>,
    env_mgr: EnvMgr<T>,
    analy_mgr: AnalysisMgr,
    callback: CallBack<T>,
}

impl<T: SymbolData> Analyzer<T> {
    pub fn new(cfg: CFG) -> Self {
        Self {
            store_mgr: StoreMgr::new(),
            env_mgr: EnvMgr::default(),
            analy_mgr: AnalysisMgr::new(cfg),
            callback: CallBack::default(),
        }
    }

    pub fn set_callback(mut self, callback: CallBack<T>) -> Self {
        self.callback = callback;
        self
    }

    pub fn execute(&mut self) -> eyre::Result<()> {
        let entry = self.analy_mgr.get_entry_block()?;
        self.handle_block_in(&entry)?;
        self.process_block(&entry)?;
        self.handle_block_out(&entry)?;
        while !self.analy_mgr.worklist.empty() {
            let block = self.analy_mgr.get_next_work();
            self.handle_block_in(&block)?;
            self.process_block(&block)?;
            self.handle_block_out(&block)?
        }
        Ok(())
    }

    fn handle_block_in(&mut self, block: &CFGBlock) -> Result<()> {
        if self.analy_mgr.is_block_ready(block)? {
            self.analy_mgr
                .handle_path_join(block, &mut self.store_mgr, &self.callback.merge)?;
            Ok(())
        } else {
            eyre::bail!("The block is not ready: {block:#?}")
        }
    }

    fn process_block(&mut self, block: &CFGBlock) -> Result<()> {
        for stmt in block.iter_stmts() {
            self.visit_stmt(stmt)?;
        }
        Ok(())
    }

    fn handle_block_out(&mut self, block: &CFGBlock) -> Result<()> {
        self.analy_mgr.add_visited(block)?;
        self.analy_mgr.update_worklist(block)?;
        self.analy_mgr
            .handle_path_split(block, &mut self.store_mgr)?;
        Ok(())
    }

    fn visit_stmt(&mut self, stmt: &ast::Node) -> Result<()> {
        let stmt = stmt.ignore_cast().ignore_parent();
        log::trace!("visit stmt: {:?}", stmt.kind);
        match stmt.kind {
            // This kinds of stmts only act as a dummy to declear the stmt kind, we skip evaluate these stmts.
            ast::Clang::TranslationUnitDecl
            | ast::Clang::CompoundStmt(_)
            | ast::Clang::ReturnStmt(_)
            | ast::Clang::Other
            | ast::Clang::BreakStmt
            | ast::Clang::ContinueStmt
            | ast::Clang::CXXMemberCallExpr
            | ast::Clang::LabelStmt(_)
            | ast::Clang::GotoStmt(_)
            | ast::Clang::FunctionDecl(_)
            | ast::Clang::DeclRefExpr(_)
            | ast::Clang::IntegerLiteral(_)
            | ast::Clang::StringLiteral(_)
            | ast::Clang::CharacterLiteral(_)
            | ast::Clang::FloatingLiteral(_)
            | ast::Clang::CXXNullPtrLiteralExpr(_)
            | ast::Clang::MemberExpr(_)
            | ast::Clang::GNUNullExpr(_) => self.visit_dummy_stmt(stmt),
            ast::Clang::DeclStmt(_) => self.visit_decl_stmt(stmt),
            ast::Clang::ParmVarDecl(_) | ast::Clang::VarDecl(_) => self.visit_var_decl(stmt),
            ast::Clang::BinaryOperator(_) => self.visit_binary_operator(stmt),
            ast::Clang::CallExpr(_) => self.visit_call_expr(stmt),
            ast::Clang::UnaryOperator(_)
            | ast::Clang::ImplicitCastExpr(_)
            | ast::Clang::CStyleCastExpr(_)
            | ast::Clang::CXXReinterpretCastExpr
            | ast::Clang::ParenExpr(_) => {
                for child in stmt.get_childs() {
                    self.visit_stmt(child)?;
                }
                Ok(())
            }
            _ => {
                //log::warn!("stmt {stmt:?} is unimplemented in DFA");
                self.visit_dummy_stmt(stmt)
            }
        }
    }

    /// This kinds of stmts only act as a dummy to declear the stmt kind, we skip evaluate these stmts.
    fn visit_dummy_stmt(&self, _stmt: &ast::Node) -> Result<()> {
        Ok(())
    }

    fn visit_decl_stmt(&mut self, stmt: &ast::Node) -> Result<()> {
        if let ast::Clang::DeclStmt(_) = &stmt.kind {
            for child in &stmt.inner {
                self.visit_var_decl(child)?;
            }
            return Ok(());
        }
        eyre::bail!("Visit DeclStmt, but visited {stmt:?}")
    }

    fn visit_var_decl(&mut self, stmt: &ast::Node) -> Result<()> {
        if let ast::Clang::VarDecl(vd) = &stmt.kind {
            let var = vd.get_name(stmt);
            let ty = vd.get_type();
            // if has init, init an object for this var.
            let sym = if vd.has_init(stmt) {
                let init = vd.get_init(stmt);
                self.get_rvalue(init)?
            } else {
                self.env_mgr.create_uninit_object(ty)
            };
            self.store_mgr.bind_value(var, sym)?;
            return Ok(());
        } else if let ast::Clang::ParmVarDecl(pvd) = &stmt.kind {
            let var = pvd.get_name(stmt);
            let ty = pvd.get_type();
            let sym = self.env_mgr.create_uninit_object(ty);
            self.store_mgr.bind_value(var, sym)?;
            return Ok(());
        } else if let ast::Clang::FunctionDecl(_) = &stmt.kind {
            return Ok(());
        } else if let ast::Clang::CXXRecordDecl(_) = &stmt.kind {
            return Ok(());
        } else if let ast::Clang::RecordDecl(_) = &stmt.kind {
            return Ok(());
        }
        eyre::bail!("Visit VarDecl, but visited {stmt:?}")
    }

    fn visit_binary_operator(&mut self, stmt: &ast::Node) -> Result<()> {
        if let ast::Clang::BinaryOperator(bo) = &stmt.kind {
            let left = bo.get_lhs(stmt);
            let right = bo.get_rhs(stmt);
            if bo.is_assignment() {
                let var = left.get_var_name();
                let sym = self.get_rvalue(right)?;
                self.store_mgr.ssa_bind_value(var, sym)?;
            } else {
                self.visit_stmt(left)?;
                self.visit_stmt(right)?;
            }
            // do not evalute other kinds of binary operator.
            return Ok(());
        }
        eyre::bail!("Visit BinaryOperator, but visited {stmt:?}")
    }

    fn visit_call_expr(&mut self, stmt: &ast::Node) -> Result<()> {
        // TODO: here to add callback
        (self.callback.precall)(&mut self.store_mgr, &mut self.env_mgr, stmt);
        Ok(())
    }

    /// get the value of the Right Hand Expression
    fn get_rvalue(&mut self, stmt: &ast::Node) -> Result<Symbol<T>> {
        let stmt = stmt.ignore_cast().ignore_parent().ignore_cast();
        let sym = match &stmt.kind {
            ast::Clang::CallExpr(_) => {
                (self.callback.precall)(&mut self.store_mgr, &mut self.env_mgr, stmt);
                let mut sym = self.env_mgr.create_object_for_call(stmt)?;
                (self.callback.postcall)(&mut self.store_mgr, stmt, &mut sym);
                sym
            }
            ast::Clang::CharacterLiteral(_)
            | ast::Clang::StringLiteral(_)
            | ast::Clang::IntegerLiteral(_)
            | ast::Clang::FloatingLiteral(_) => self.env_mgr.create_object_from_literal(stmt)?,
            ast::Clang::ParenExpr(_) => {
                assert!(!stmt.inner.is_empty());
                if stmt.inner.len() == 1 {
                    let child = stmt.inner.first().unwrap();
                    self.get_rvalue(child)?
                } else {
                    self.env_mgr.create_dummy_object()
                }
            }
            ast::Clang::DeclRefExpr(_) => {
                let var = stmt.get_var_name();
                if let Ok(sym) = self.store_mgr.get_bind(&var) {
                    sym
                } else {
                    self.env_mgr.create_dummy_object()
                }
            }
            ast::Clang::InitListExpr(il) => {
                let ty = il.get_type();
                self.env_mgr.create_list_object(ty)
            }
            ast::Clang::BinaryOperator(bo) => {
                if bo.is_assignment() {
                    let left = bo.get_lhs(stmt);
                    let right = bo.get_rhs(stmt);
                    let var = left.get_var_name();
                    let sym = self.get_rvalue(right)?;
                    self.store_mgr.ssa_bind_value(var, sym.clone())?;
                    sym
                } else {
                    self.env_mgr.create_dummy_object()
                }
            }
            ast::Clang::ArraySubscriptExpr(ase) => {
                let lhs = ase.get_lhs(stmt).ignore_cast().ignore_parent();
                if let ast::Clang::DeclRefExpr(_) = &lhs.kind {
                    self.get_rvalue(lhs)?
                } else if let ast::Clang::CallExpr(_) = &lhs.kind {
                    self.get_rvalue(lhs)?
                } else {
                    //log::warn!("getRValue is unimplemented for : {stmt:#?}");
                    self.env_mgr.create_dummy_object()
                }
            }
            ast::Clang::MemberExpr(me) => {
                let base_expr = me.get_base_expr(stmt).ignore_cast().ignore_parent();
                if let ast::Clang::DeclRefExpr(_) = &base_expr.kind {
                    self.get_rvalue(base_expr)?
                } else if let ast::Clang::CallExpr(_) = &base_expr.kind {
                    self.get_rvalue(base_expr)?
                } else {
                    //log::warn!("getRValue is unimplemented for : {stmt:#?}");
                    self.env_mgr.create_dummy_object()
                }
            }
            ast::Clang::CXXConstructExpr(_)
            | ast::Clang::CXXMemberCallExpr
            | ast::Clang::CXXNullPtrLiteralExpr(_)
            | ast::Clang::GNUNullExpr(_)
            | ast::Clang::UnaryOperator(_)
            | ast::Clang::UnaryExprOrTypeTraitExpr(_)
            | ast::Clang::Other => self.env_mgr.create_dummy_object(),
            _ => {
                //log::warn!("getRValue is unimplemented for : {stmt:#?}");
                self.env_mgr.create_dummy_object()
            }
        };
        Ok(sym)
    }

    pub fn dump_analysis_result(&self) -> Result<Storage<T>> {
        let path_id = self.store_mgr.get_path_id();
        if path_id == 0 {
            eyre::bail!("No DFA works executed!")
        }
        let store = self.store_mgr.get_storage_from_path(path_id);
        let store = store.ok_or_else(|| eyre::eyre!("No storage for path :{path_id:?}."))?;
        for (var, sym) in store {
            log::trace!("\nvar: {var:?}, symbol: {:?}", sym.get_data());
        }
        Ok(store.clone())
    }
}

/// Analysis Manager: Maintain the analysis status
pub struct AnalysisMgr {
    cfg: CFG,
    worklist: WorkList<CFGBlock>,
    visited: HashSet<String>,
}

impl AnalysisMgr {
    fn new(cfg: CFG) -> Self {
        Self {
            cfg,
            worklist: WorkList::new(),
            visited: HashSet::new(),
        }
    }

    fn get_entry_block(&self) -> Result<CFGBlock> {
        let entry_node = self.cfg.get_entry_node()?;
        let entry_block = self.cfg.get_node_weight(entry_node)?;
        Ok(entry_block)
    }

    fn add_visited(&mut self, block: &CFGBlock) -> Result<()> {
        if self.visited.insert(block.get_ident()) {
            Ok(())
        } else {
            eyre::bail!("Insert failed. The block is already visited: {block:#?}")
        }
    }

    /// Whether this block is ready to be processed. The ready block should meet these standards:
    /// 1. The block self should have not been visited.
    /// 2. All predecessor nodes should have been visited.
    fn is_block_ready(&self, block: &CFGBlock) -> Result<bool> {
        // block should not be visited
        let ident = block.get_ident();
        if self.visited.contains(&ident) {
            return Ok(false);
        }
        // all predecessors should be visited before
        for predecessor in self.cfg.get_predecessors(block) {
            let ident = predecessor.get_ident();
            if !self.visited.contains(&ident) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// push the ready successors to worklist
    fn update_worklist(&mut self, curr: &CFGBlock) -> Result<()> {
        for child in self.cfg.get_successors(curr) {
            if self.is_block_ready(&child)? {
                self.worklist.push(child);
            }
        }
        Ok(())
    }

    /// get the next block to work. If curr has only one child, the child is selected as the next block.
    /// If curr has more than one childs,
    fn get_next_work(&mut self) -> CFGBlock {
        self.worklist.pop()
    }

    /// Wether the edge is labeled with path_id?
    fn is_edge_labeled(&self, src: &CFGBlock, dest: &CFGBlock) -> bool {
        !self
            .cfg
            .get_edge_weight(src, dest)
            .unwrap()
            .eq(&EdgeWeight::default())
    }

    /// label the path_id of the edge as current path_id.
    fn set_path_for_edge<T: SymbolData>(
        &mut self,
        src: &CFGBlock,
        dest: &CFGBlock,
        store_mgr: &StoreMgr<T>,
    ) -> Result<()> {
        if self.is_edge_labeled(src, dest) {
            eyre::bail!("The edge from {src:?} to {dest:?} is already labeled.")
        }
        self.cfg
            .update_edge_weight(src, dest, store_mgr.get_path_id())?;
        Ok(())
    }

    /// create and label new path_id for the edge that discovers new path.
    fn create_new_path_for_edge<T: SymbolData>(
        &mut self,
        src: &CFGBlock,
        dest: &CFGBlock,
        store_mgr: &mut StoreMgr<T>,
    ) -> Result<usize> {
        if self.is_edge_labeled(src, dest) {
            eyre::bail!("The edge from {src:?} to {dest:?} is already labeled.")
        }
        let new_path = store_mgr.new_path_id();
        self.cfg.update_edge_weight(src, dest, new_path)?;
        Ok(new_path)
    }

    /// clone the storage of current path to a given path.
    fn clone_current_storage_to_path<T: SymbolData>(
        &self,
        new_path: usize,
        store_mgr: &mut StoreMgr<T>,
    ) -> Result<()> {
        let store = store_mgr.get_current_storage();
        store_mgr.set_storage_for_path(new_path, store.clone())?;
        Ok(())
    }

    /// control-flow sensitive function. If path split happens after this block, create new paths and storages.
    fn handle_path_split<T: SymbolData>(
        &mut self,
        block: &CFGBlock,
        store_mgr: &mut StoreMgr<T>,
    ) -> Result<()> {
        if block.is_exit() {
            return Ok(());
        }
        let childs = self.cfg.get_successors(block);
        if childs.is_empty() {
            eyre::bail!("block {block:?} should has at least one successor.")
        }
        // choose one child to continue evaluating the same path.
        let left_child = &childs[0];
        self.set_path_for_edge(block, left_child, store_mgr)?;

        //let should_split = childs.len() > 1;
        //if should_split {
        //    store_mgr.path_split()?;
        //}

        // if the nr of childs greater than 1, means a path split should happen. create new path and clone storage for them.
        for child in &childs[1..] {
            let new_path = self.create_new_path_for_edge(block, child, store_mgr)?;
            self.clone_current_storage_to_path(new_path, store_mgr)?;
        }
        Ok(())
    }

    fn handle_path_join<T: SymbolData, F: Fn(Vec<Symbol<T>>) -> Symbol<T>>(
        &mut self,
        block: &CFGBlock,
        store_mgr: &mut StoreMgr<T>,
        merge: &F,
    ) -> Result<()> {
        if block.is_entry() {
            return Ok(());
        }
        let predecessors = self.cfg.get_predecessors(block);
        let should_join = predecessors.len() > 1;
        if should_join {
            let mut path_vec = vec![];
            for predecessor in predecessors {
                let path_id = self.cfg.get_edge_weight(&predecessor, block).unwrap();
                path_vec.push(*path_id);
            }
            log::trace!(
                "block: {} meet path join with: {path_vec:?}.",
                block.get_ident()
            );
            store_mgr.path_join(path_vec, merge)?;
        } else {
            let only_predecessor = &predecessors[0];
            let path_id = self.cfg.get_edge_weight(only_predecessor, block).unwrap();
            store_mgr.swith_to_path(*path_id);
            log::trace!("block: {} set path to {path_id}.", block.get_ident());
        }
        Ok(())
    }
}

#[derive(Default)]
/// Storage Manager: Maintain the program evaluation storage that had evalated before.
pub struct StoreMgr<T: SymbolData> {
    /// id of current path
    path_id: usize,
    path_count: usize,
    /// vars storage in different paths
    path_storage: HashMap<usize, Storage<T>>,
}

impl<T: SymbolData> StoreMgr<T> {
    pub fn new() -> Self {
        Self {
            path_id: 1,
            path_count: 1,
            path_storage: {
                let mut map = HashMap::new();
                map.insert(1, HashMap::new());
                map
            },
        }
    }

    fn get_path_id(&self) -> EdgeWeight {
        self.path_id as EdgeWeight
    }

    fn new_path_id(&mut self) -> EdgeWeight {
        self.path_count += 1;
        self.path_count as EdgeWeight
    }

    fn swith_to_path(&mut self, path_id: usize) {
        self.path_id = path_id;
    }

    /// get the reference of vars storage in currrent path.
    fn get_current_storage(&self) -> &Storage<T> {
        self.path_storage.get(&self.path_id).unwrap()
    }

    /// get mutable reference var stores in currrent path.
    fn get_current_storage_mut(&mut self) -> &mut HashMap<VarName, Symbol<T>> {
        self.path_storage.get_mut(&self.path_id).unwrap()
    }

    /// get the storage of a specific path.
    fn get_storage_from_path(&self, path_id: usize) -> Option<&Storage<T>> {
        self.path_storage.get(&path_id)
    }

    fn set_storage_for_path(&mut self, path_id: usize, store: Storage<T>) -> Result<()> {
        self.path_storage.insert(path_id, store).map_or_else(
            || Ok(()),
            |_| eyre::bail!("set storage for existing path {path_id:?}"),
        )
    }

    /// insert a new create variable
    /// Warning: Currently, the DFA engine doesn't differ two variable declarations between different scopes.
    /// That means, the old declaration will be overwriten by the new declaration.
    fn _insert_new_var(&mut self, var: VarName, sym: Symbol<T>) -> Result<()> {
        if self.get_current_storage().contains_key(&var) {
            log::warn!("var {var:?} is already created");
        }
        self.get_current_storage_mut().insert(var, sym);
        Ok(())
    }

    /// bind the value to this var. Old value is overwrited.
    fn bind_value(&mut self, var: VarName, sym: Symbol<T>) -> Result<()> {
        self.get_current_storage_mut().insert(var, sym);
        Ok(())
    }

    /// bind the value into var with Static-Single-Assignment (SSA) form.
    /// The old var is renamed and the new value stores in the new var.
    pub fn ssa_bind_value(&mut self, var: VarName, sym: Symbol<T>) -> Result<()> {
        let old_var = self.new_ssa_var(&var)?;
        let old_value = self.get_bind(&var).unwrap_or(sym.clone());
        self.bind_value(old_var, old_value)?;
        self.bind_value(var, sym)?;
        Ok(())
    }

    /// the ssa_id of old var is increased, the var is used as new var.
    pub fn new_ssa_var(&self, var: &VarName) -> Result<VarName> {
        let mut ssa_id = 0;
        // loop until find a suitable ssa_id for this var.
        loop {
            let mut old_var = var.clone();
            old_var.ssa = ssa_id;
            if self.get_current_storage().contains_key(&old_var) {
                ssa_id += 1;
            } else {
                return Ok(old_var);
            }
        }
    }

    /// get the bind vaule of this var
    pub fn get_bind(&self, var: &VarName) -> Result<Symbol<T>> {
        let bind = self
            .get_current_storage()
            .get(var)
            .ok_or_else(|| eyre::eyre!("get bind of var {var:?} failed"));
        bind.cloned()
    }

    pub fn get_bind_mut(&mut self, var: &VarName) -> Result<&mut Symbol<T>> {
        self.get_current_storage_mut()
            .get_mut(var)
            .ok_or_else(|| eyre::eyre!("get bind of var {var:?} failed"))
    }

    /// Merge var storage of different paths when meet path join. The default merge operation is Union.
    fn path_join<F: Fn(Vec<Symbol<T>>) -> Symbol<T>>(
        &mut self,
        path_vec: Vec<usize>,
        merge_callback: F,
    ) -> Result<()> {
        let mut merge_store: Storage<T> = HashMap::new();
        let mut changed_var: HashSet<&VarName> = HashSet::new();
        // find the same vars but have different symbols in paths.
        for path_id in &path_vec {
            let path_store = self
                .path_storage
                .get(path_id)
                .ok_or_else(|| eyre::eyre!("path id {path_id} not found."))?;
            for (var_name, sym) in path_store.iter() {
                if merge_store.contains_key(var_name) {
                    //log::trace!("The merge store already contains {var_name:?}");
                    let exist_sym = merge_store.get(var_name).unwrap();
                    // find different symbols
                    if !exist_sym.eq(sym) {
                        changed_var.insert(var_name);
                    }
                } else {
                    merge_store.insert(var_name.clone(), sym.clone());
                }
            }
        }
        // merge the symbols from different paths to a single symbol
        for var in changed_var {
            let mut wait_to_merge = vec![];
            for path_id in &path_vec {
                let path_store = self
                    .path_storage
                    .get(path_id)
                    .ok_or_else(|| eyre::eyre!("path id {path_id} not found."))?;
                if path_store.contains_key(var) {
                    let value = path_store.get(var).unwrap();
                    wait_to_merge.push(value.clone());
                }
            }
            log::trace!("merge symbol for var: {var:?}");
            let new_sym = (merge_callback)(wait_to_merge);
            merge_store.insert(var.clone(), new_sym);
        }

        for (_var, sym) in merge_store.iter_mut() {
            sym.get_data_mut().refine()?;
        }
        // create new path id.
        self.path_id = self.new_path_id();
        // initial the storage for the new path
        self.path_storage.insert(self.path_id, merge_store);
        Ok(())
    }
}

#[derive(Default)]
/// Environment Manager: Create astract object from the run-time environment.
pub struct EnvMgr<T: SymbolData> {
    ctx: usize,
    data: std::marker::PhantomData<T>,
}

impl<T: SymbolData> EnvMgr<T> {
    fn create_uninit_object(&mut self, ty: ast::Type) -> Symbol<T> {
        let ctx = self.get_current_ctx();
        Symbol {
            r#type: Some(ty),
            state: ObjectState::Uninit,
            id: ctx,
            data: T::default(),
        }
    }

    pub fn create_dummy_object(&mut self) -> Symbol<T> {
        let ctx = self.get_current_ctx();
        Symbol {
            r#type: None,
            state: ObjectState::Other,
            id: ctx,
            data: T::default(),
        }
    }

    fn create_list_object(&mut self, ty: ast::Type) -> Symbol<T> {
        let ctx = self.get_current_ctx();
        Symbol {
            r#type: Some(ty),
            state: ObjectState::List,
            id: ctx,
            data: T::default(),
        }
    }

    fn create_object_from_literal(&mut self, literal: &ast::Node) -> Result<Symbol<T>> {
        let ctx = self.get_current_ctx();
        let sym = match &literal.kind {
            ast::Clang::CharacterLiteral(cl) => {
                let ty = cl.r#type.clone();
                Symbol::new(ty, ObjectState::Literal(Literal::Char(cl.clone())), ctx)
            }
            ast::Clang::StringLiteral(sl) => {
                let ty = sl.r#type.clone();
                Symbol::new(ty, ObjectState::Literal(Literal::String(sl.clone())), ctx)
            }
            ast::Clang::IntegerLiteral(il) => {
                let ty = il.r#type.clone();
                Symbol::new(ty, ObjectState::Literal(Literal::Int(il.clone())), ctx)
            }
            ast::Clang::FloatingLiteral(fl) => {
                let ty = fl.r#type.clone();
                Symbol::new(ty, ObjectState::Literal(Literal::Float(fl.clone())), ctx)
            }
            _ => unreachable!("require Literal stmt, received: {literal:#?}"),
        };
        Ok(sym)
    }

    pub fn create_object_for_call(&mut self, call: &ast::Node) -> Result<Symbol<T>> {
        if let ast::Clang::CallExpr(ce) = &call.kind {
            let ty = ce.get_type();
            let state = ObjectState::Call;
            let ctx = self.get_current_ctx();
            let symbol = Symbol::new(ty, state, ctx);
            return Ok(symbol);
        }
        eyre::bail!("create var for call, but receive: {call:#?}")
    }

    fn get_current_ctx(&mut self) -> usize {
        self.ctx += 1;
        self.ctx
    }
}

#[derive(Default, Clone, Debug)]
/// Symbol Manager: Maintain the symbol evaluated before.
pub struct Symbol<T: SymbolData> {
    pub r#type: Option<ast::Type>,
    pub state: ObjectState,
    // id of ctx when create this symbol
    pub id: usize,
    /// the attribute data you what to collect from data flow.
    data: T,
}

impl<T: SymbolData> PartialEq for Symbol<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data == other.data
    }
}

impl<T: SymbolData> Symbol<T> {
    pub fn new(ty: ast::Type, state: ObjectState, id: usize) -> Self {
        Self {
            r#type: Some(ty),
            state,
            id,
            data: T::default(),
        }
    }

    /// Merge symbol when meet path join by unioning their new symbol data.
    /// In general, the specific merge operation needs to be determined based on the application scenario,
    ///     and it should be achieved by implementing T::data_merge() functions.
    pub fn union_merge(syms: Vec<Self>) -> Self {
        let mut data_vec = vec![];
        for sym in &syms {
            let data = sym.get_data();
            if !data.is_empty() {
                data_vec.push(data.clone());
            }
        }
        let mut new_sym = syms.first().unwrap().clone();
        let new_data = T::data_merge(data_vec);
        new_sym.data = new_data;
        new_sym
    }

    pub fn get_data(&self) -> &T {
        &self.data
    }

    pub fn get_data_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

#[derive(Default, Clone, Debug)]
pub enum ObjectState {
    #[default]
    Uninit,
    /// Object returned by call
    Call,
    /// Initialized by List
    List,
    /// Parent, element
    Element(usize, usize),
    /// Parent, region
    Region(usize, String),
    /// exact value literal.
    Literal(Literal),
    /// like compound compution
    Other,
}

impl ObjectState {
    pub fn is_uninit(&self) -> bool {
        matches!(self, ObjectState::Uninit)
    }
}

#[derive(Default, Clone, Debug)]
pub enum Literal {
    Char(ast::CharacterLiteral),
    String(ast::StringLiteral),
    Int(ast::IntegerLiteral),
    Float(ast::FloatingLiteral),
    #[default]
    Other,
}

/// SSA form Variables
#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct VarName {
    pub id: Vec<Id>,
    pub name: Vec<String>,
    pub kind: Vec<VarKind>,
    pub ssa: usize,
}

#[derive(Default, Debug, Eq, PartialEq, Hash, Clone)]
pub enum VarKind {
    Arrary,
    Member,
    #[default]
    Base,
    Call,
}

impl VarName {
    pub fn new(name: String, id: Id) -> Self {
        Self {
            id: vec![id],
            name: vec![name],
            kind: vec![VarKind::Base],
            ssa: 0,
        }
    }

    pub fn from_vec(names: Vec<String>, kinds: Vec<VarKind>, ids: Vec<Id>) -> Self {
        Self {
            id: ids,
            name: names,
            kind: kinds,
            ssa: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
    }

    pub fn get_base(&self) -> Self {
        let id = self.id.last().unwrap();
        let name = self.name.last().unwrap();
        let kind = self.kind.last().unwrap();
        Self {
            id: vec![*id],
            name: vec![name.clone()],
            kind: vec![kind.clone()],
            ssa: 0,
        }
    }
}

type MergeCall<T> = dyn Fn(Vec<Symbol<T>>) -> Symbol<T>;
type PreCall<T> = dyn Fn(&mut StoreMgr<T>, &mut EnvMgr<T>, &ast::Node);
type PostCall<T> = dyn Fn(&mut StoreMgr<T>, &ast::Node, &mut Symbol<T>);
/// CallBacks intercepted in DFA workflow to manipulate symbols and gather program data flow information.
pub struct CallBack<T: SymbolData> {
    /// The merge function is the phi function used in DFA SSA to aggregate value abstration from different paths.
    pub merge: Box<MergeCall<T>>,
    /// invoked before CallStmt, so is able to access the arguments.
    pub precall: Box<PreCall<T>>,
    /// invokded after CallStmt, so is able to access the returned symbol.
    pub postcall: Box<PostCall<T>>,
}

fn default_merge<T: SymbolData>(_syms: Vec<Symbol<T>>) -> Symbol<T> {
    unimplemented!()
}

fn default_precall<T: SymbolData>(
    _store_mgr: &mut StoreMgr<T>,
    _env_mgr: &mut EnvMgr<T>,
    _call: &ast::Node,
) {
}

fn default_postcall<T: SymbolData>(
    _store_mgr: &mut StoreMgr<T>,
    _call: &ast::Node,
    _sym: &mut Symbol<T>,
) {
}

impl<T: SymbolData> Default for CallBack<T> {
    fn default() -> Self {
        Self {
            merge: Box::new(|syms| default_merge(syms)),
            precall: Box::new(|store_mgr, env_mgr, call| default_precall(store_mgr, env_mgr, call)),
            postcall: Box::new(|store_mgr, call, sym| default_postcall(store_mgr, call, sym)),
        }
    }
}

pub trait SymbolData: Default + Clone + Eq + PartialEq + std::fmt::Debug {
    fn append_split(&mut self);
    fn has_split(&self) -> bool;
    fn data_merge(data_vec: Vec<Self>) -> Self;
    fn refine(&mut self) -> Result<()>;
    fn is_empty(&self) -> bool;
}
