//! This module provides functionality to build an API Dependency Graph (ADG) for a program.
//!
//! The ADG is built on top of the Control Flow Graph (CFG) and is constructed by performing a data flow analysis.
//! To utilize our DFA engine to build an ADG,
//!     a core step is to carefully design callbacks that intercept DFA workflow to collect taint information.
//! For convenience, the CFGBuilder is provided, which implements the DFA callbacks internally.
//!
//! Given a CFG, the ADG can be obtained directly by:
//!
//! ```
//!  let mut builder = ADGBuilder::new(cfg);
//!  let adg = builder.build()?;
//! ```
//!
//! If you want to visualize the ADG that you generated, you can dump it to Graphviz format using the following code:
//!
//! ```
//! adg.dump_to_file(&c_test_path, true)?;
//! ```
//!
//! We have defined an important concept with the ADG,
//!     which is that it can be categorized into two kinds: Sparse ADG and Dense ADG.
//! The "sparse" ADG represents each "API call" as a unique node,
//!     while the "dense" ADG represents each "API" as a unique node.
//! The sparse ADG records almost all detailed dependency relationships (data flow & control flow) between APIs,
//!     but it is hard to do graph merge due to node explosion.
//! ```
//! let mut builder = ADGBuilder::new(cfg);
//! let adg = builder.sparse_build()?;
//! ```
//! The dense ADG records the compressed API dependency relationships,
//!     where the knowledge is dense in the graph and is suitable for graph merging.
//! ```
//! let mut builder = ADGBuilder::new(cfg);
//! let adg = builder.dense_build()?;
//! ```
//!
//! Build Dense ADG is the default option.
//!
//!
//! ADG coalesce: coalesce the ADG with new ADG (built from the new cfg).
//! ```
//!  let adg = builder.coalesce_from_new_cfg(cfg)?;
//! ```
//!
//!

use crate::{
    ast::{self, CommomHelper},
    program::gadget::{get_func_gadget, is_library_api},
};
use clang_ast::Id;
use eyre::Result;
use petgraph::{
    dot::{Config, Dot},
    graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
    Directed, Graph, Undirected,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

use super::{
    cfg::CFG,
    dfa::{Analyzer, CallBack, EnvMgr, Storage, StoreMgr, Symbol, SymbolData},
};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Node {
    name: String,
    id: Id,
}

impl Node {
    /// Dense node
    pub fn new(data: &TaintData) -> Self {
        Self {
            name: data.name.clone(),
            id: Id::default(),
        }
    }

    /// Sparse node
    pub fn from(data: &TaintData) -> Self {
        Self {
            name: data.name.clone(),
            id: data.id,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EdgeWeight {
    pub score: f64,
    pub count: usize,
    pub deps: HashSet<Dependency>,
}

impl EdgeWeight {
    pub fn from(dep: Dependency) -> Self {
        let mut weight = EdgeWeight::default();
        weight.deps.insert(dep);
        weight
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Dependency {
    CallRet(u8),
    ArgShare(u8, u8),
    #[default]
    Other,
}

impl Dependency {
    pub fn from(src_kind: &Taintkind, dest_kind: &Taintkind) -> Result<Self> {
        if src_kind == &Taintkind::Call {
            match dest_kind {
                Taintkind::Arg(arg) => {
                    return Ok(Dependency::CallRet(*arg));
                }
                _ => return Ok(Dependency::Other),
            }
        } else if let Taintkind::Arg(from_arg) = src_kind {
            match dest_kind {
                Taintkind::Arg(to_arg) => {
                    return Ok(Dependency::ArgShare(*from_arg, *to_arg));
                }
                _ => return Ok(Dependency::Other),
            }
        }
        Ok(Dependency::Other)
    }
}

#[serde_as]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ADG {
    pub graph: Graph<Node, EdgeWeight, Directed>,
    #[serde_as(as = "HashMap<serde_with::json::JsonString, _>")]
    pub node_map: HashMap<Node, NodeIndex>,
    #[serde_as(as = "HashMap<serde_with::json::JsonString, _>")]
    pub edge_map: HashMap<(NodeIndex, NodeIndex), EdgeIndex>,
    pub dense: bool,
}

impl ADG {
    pub fn coalesce_from(self, cfg: CFG) -> Result<Self> {
        let new_adg = ADGBuilder::from(self).coalesce_from_new_cfg(cfg)?;
        Ok(new_adg)
    }

    pub fn get_node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn get_edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn get_node(&self, node: &Node) -> NodeIndex {
        *self
            .node_map
            .get(node)
            .unwrap_or_else(|| panic!("{node:?} not exist in ADG."))
    }

    pub fn get_or_add_node(&mut self, node: Node) -> NodeIndex {
        *self
            .node_map
            .entry(node.clone())
            .or_insert_with(|| self.graph.add_node(node.clone()))
    }

    pub fn add_dependency(&mut self, edge: &EdgeIndex, dep: Dependency) {
        let edge_weight = self.graph.edge_weight_mut(*edge).unwrap();
        edge_weight.deps.insert(dep);
    }

    pub fn get_edge(&self, src: &Node, dest: &Node) -> &EdgeWeight {
        let src_idx = self.get_node(src);
        let dest_idx = self.get_node(dest);
        let edge_idx = self
            .edge_map
            .get(&(src_idx, dest_idx))
            .unwrap_or_else(|| panic!("Edge {src:?} to {dest:?} not exist!"));
        self.graph.edge_weight(*edge_idx).unwrap()
    }

    pub fn add_edge(&mut self, src: Node, dest: Node, dep: Dependency) -> EdgeIndex {
        let src_node = self.get_or_add_node(src);
        let dest_node = self.get_or_add_node(dest);
        let edge = (src_node, dest_node);
        if self.edge_map.contains_key(&edge) {
            let edge_idx = *self.edge_map.get(&edge).unwrap();
            if self.dense {
                self.increase_edge_count(&edge_idx);
                self.add_dependency(&edge_idx, dep);
            }
            return edge_idx;
        }
        let edge_idx = self
            .graph
            .add_edge(src_node, dest_node, EdgeWeight::from(dep));
        self.edge_map.insert(edge, edge_idx);
        edge_idx
    }

    pub fn increase_edge_count(&mut self, edge: &EdgeIndex) {
        let edge_weight = self.graph.edge_weight_mut(*edge).unwrap();
        edge_weight.count += 1;
    }

    /// Visualize this ADG to a Graphviz format file and translate it to PNG.
    /// verbose_edge: whether dump the edge weights.
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
        let mut adg_path = dot_path.clone();
        adg_path.set_extension("adg.png");
        let _output = Command::new("dot")
            .arg("-Tpng")
            .arg(&dot_path)
            .arg("-o")
            .arg(adg_path)
            .output()?;
        std::fs::remove_file(dot_path)?;
        Ok(())
    }

    pub fn serialize_to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn deserialize_from_json(input: &str) -> Result<Self> {
        Ok(serde_json::from_str(input)?)
    }

    pub fn save_to_file(&self, file: &Path) -> Result<()> {
        Ok(std::fs::write(file, self.serialize_to_json()?)?)
    }

    pub fn load_from_file(file: &Path) -> Result<Self> {
        let input = std::fs::read_to_string(file)?;
        Self::deserialize_from_json(&input)
    }

    pub fn compute_density(&self) -> usize {
        let mut undigraph: Graph<Node, (), Undirected> = Graph::default();
        for node in self.graph.node_indices() {
            undigraph.add_node(self.graph[node].clone());
        }

        for edge in self.graph.edge_references() {
            let (a, b) = (edge.source(), edge.target());
            if !undigraph.contains_edge(a, b) && !undigraph.contains_edge(b, a) {
                undigraph.add_edge(a, b, ());
            }
        }
        let scc = petgraph::algo::kosaraju_scc(&undigraph);
        // compute the number of nodes in the largest connected component.
        let density = scc
            .iter()
            .map(|subgraph| {
                let mut api_calls = Vec::new();
                // count number of api calls in each subgraph
                for node in subgraph {
                    let node_weight = undigraph.node_weight(*node).unwrap();
                    let node_name = node_weight.get_name();
                    if get_func_gadget(&node_name).is_some() {
                        api_calls.push(node);
                    }
                }
                api_calls.len()
            })
            .max()
            .unwrap_or(1);
        density
    }
}

/// Taint structure attached with each symbol.
/// It records each function the symbol has encountered.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct TaintData {
    /// Unique id of this Call
    id: Id,
    /// Function name of this Call
    name: String,
    /// Kind of this taint.
    kind: Taintkind,
}

impl TaintData {
    pub fn new(id: Id, name: String, kind: Taintkind) -> Self {
        Self { id, name, kind }
    }

    pub fn new_split() -> Self {
        Self {
            id: Id::default(),
            name: String::from("Split"),
            kind: Taintkind::Split,
        }
    }

    pub fn new_sep() -> Self {
        Self {
            id: Id::default(),
            name: String::from("Sep"),
            kind: Taintkind::Sep,
        }
    }

    pub fn new_join() -> Self {
        Self {
            id: Id::default(),
            name: String::from("Join"),
            kind: Taintkind::Join,
        }
    }

    pub fn new_merge() -> Self {
        Self {
            id: Id::default(),
            name: String::from("Merge"),
            kind: Taintkind::Merge,
        }
    }

    pub fn new_holder() -> Self {
        Self {
            id: Id::default(),
            name: String::from("Holder"),
            kind: Taintkind::Holder,
        }
    }

    pub fn is_split(&self) -> bool {
        matches!(self.kind, Taintkind::Split)
    }

    pub fn is_join(&self) -> bool {
        matches!(self.kind, Taintkind::Join)
    }

    pub fn is_merge(&self) -> bool {
        matches!(self.kind, Taintkind::Merge)
    }

    pub fn is_seq(&self) -> bool {
        matches!(self.kind, Taintkind::Sep)
    }

    pub fn is_default(&self) -> bool {
        matches!(self.kind, Taintkind::Default)
    }

    pub fn is_holder(&self) -> bool {
        matches!(self.kind, Taintkind::Holder)
    }
}

fn find_first_join_idx(sym_data: &TaintDataVec, merge_idx: Option<usize>) -> Option<usize> {
    if let Some(merge_idx) = merge_idx {
        if let Some(join_idx) = sym_data[merge_idx..].iter().position(|data| data.is_join()) {
            return Some(join_idx + merge_idx);
        }
    }
    None
}

fn find_last_merge_idx(sym_data: &[TaintData]) -> Option<usize> {
    let mut merge_idx = 0;
    for data in sym_data.iter().rev() {
        if data.is_merge() {
            break;
        }
        merge_idx += 1;
    }
    if merge_idx == sym_data.len() {
        return None;
    }
    let idx = sym_data.len() - 1 - merge_idx;
    Some(idx)
}

fn merge_at_pos(data_vec: &Vec<TaintDataVec>, pos: usize) -> TaintDataVec {
    let mut merge_data = TaintDataVec::default();
    merge_data.push(TaintData::new_merge());
    for data in data_vec {
        if data.len() == pos {
            merge_data.push(TaintData::new_holder());
        } else {
            let remain = &data[pos..];
            merge_data.extend_from_slice(remain);
        }
        merge_data.push(TaintData::new_sep());
    }
    merge_data.push(TaintData::new_join());
    merge_data
}

fn get_merge(data_vec: Vec<TaintDataVec>) -> TaintDataVec {
    if data_vec.len() == 1 {
        return data_vec[0].clone();
    }
    let mut position = 0;
    loop {
        let mut pos_data = TaintData::default();
        let mut pos_merge_subseq: Vec<&TaintData> = Vec::new();
        let mut should_break = false;
        for data in &data_vec {
            if let Some(taint) = data.get(position) {
                if taint.is_merge() {
                    if pos_merge_subseq.is_empty() {
                        pos_merge_subseq = get_merge_subseq(data, position);
                    } else {
                        let subseq = get_merge_subseq(data, position);
                        if !subseq.eq(&pos_merge_subseq) {
                            should_break = true;
                            break;
                        }
                    }
                }
                if pos_data.is_default() {
                    pos_data = taint.clone();
                    continue;
                }
                if !taint.eq(&pos_data) {
                    should_break = true;
                    break;
                }
            } else {
                should_break = true;
                break;
            }
        }
        if should_break {
            break;
        }
        position += 1;
    }
    let prefix_data = data_vec[0][..position].to_vec();
    let merge_data = merge_at_pos(&data_vec, position);
    [prefix_data, merge_data].concat()
}

fn get_merge_subseq(data: &[TaintData], merge_idx: usize) -> Vec<&TaintData> {
    let mut subseq = Vec::new();
    for entry in data[merge_idx..].iter() {
        subseq.push(entry);
        if entry.is_join() {
            break;
        }
    }
    subseq
}

/// Record the API dependency or control flow events.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub enum Taintkind {
    /// symbol is returned by a Call
    Call,
    /// symbol is used in nth arg of a Call
    Arg(u8),
    #[default]
    Default,
    /// Path split happens with this symbol
    Split,
    /// indicate there performed a merge operation.
    Merge,
    /// separate different control flows.
    Sep,
    /// Path join happens with this symbol
    Join,
    Holder,
}

pub type TaintDataVec = Vec<TaintData>;

impl SymbolData for TaintDataVec {
    fn append_split(&mut self) {
        self.push(TaintData::new_split())
    }

    fn refine(&mut self) -> Result<()> {
        if self.last().is_none() {
            return Ok(());
        }
        if self.last().unwrap().is_split() {
            self.pop();
            return Ok(());
        }
        Ok(())
    }

    fn has_split(&self) -> bool {
        for data in self {
            if data.is_split() {
                return true;
            }
        }
        false
    }

    /// merge a vec of taint data to one tiant data.
    fn data_merge(data_vec: Vec<Self>) -> Self {
        if data_vec.is_empty() {
            return Self::default();
        }
        log::trace!("data to merge: {data_vec:?}");
        get_merge(data_vec)
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

pub struct ADGBuilder {
    adg: ADG,
    dense: bool,
}

impl Default for ADGBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ADGBuilder {
    pub fn new() -> Self {
        Self {
            adg: ADG::default(),
            dense: true,
        }
    }

    pub fn new_sparse() -> Self {
        Self {
            adg: ADG::default(),
            dense: false,
        }
    }

    fn from(adg: ADG) -> Self {
        Self { adg, dense: true }
    }

    /// merge a vec of symbols into one representative symbol.
    fn adg_merge(syms: Vec<Symbol<TaintDataVec>>) -> Symbol<TaintDataVec> {
        Symbol::union_merge(syms)
    }

    /// Attach the symbols of this call's args with Arg-taint summary.
    fn adg_precall(
        store_mgr: &mut StoreMgr<TaintDataVec>,
        env_mgr: &mut EnvMgr<TaintDataVec>,
        call: &ast::Node,
    ) {
        let call_id = call.id;
        let name = call.get_call_name();
        if !is_library_api(&name) {
            return;
        }
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
                Self::adg_precall(store_mgr, env_mgr, arg_stmt);
                let mut sym = env_mgr.create_object_for_call(call).unwrap();
                Self::adg_post_call(store_mgr, arg_stmt, &mut sym);
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
    fn adg_post_call(
        _store_mgr: &mut StoreMgr<TaintDataVec>,
        call: &ast::Node,
        sym: &mut Symbol<TaintDataVec>,
    ) {
        let call_id = call.id;
        let name = call.get_call_name();
        if !is_library_api(&name) {
            return;
        }
        let data = TaintData::new(call_id, name, Taintkind::Call);
        let sym_data = sym.get_data_mut();
        sym_data.push(data);
    }

    fn create_callback() -> CallBack<TaintDataVec> {
        CallBack {
            merge: Box::new(Self::adg_merge),
            precall: Box::new(Self::adg_precall),
            postcall: Box::new(Self::adg_post_call),
        }
    }

    /// Add an edge between two API node (Sparse or Dense).
    /// If building Dense ADG, each API is a node; if building Sparse ADG, each API call is a node.
    fn add_edge(&mut self, src: &TaintData, dest: &TaintData) -> Result<()> {
        // if building dense graph.
        let (src_node, dest_node) = if self.dense {
            let src_node = Node::new(src);
            let dest_node = Node::new(dest);
            (src_node, dest_node)
        } else {
            let src_node = Node::from(src);
            let dest_node = Node::from(dest);
            (src_node, dest_node)
        };
        let dependency = Dependency::from(&src.kind, &dest.kind)?;
        if dependency == Dependency::Other {
            return Ok(());
        }
        self.adg.add_edge(src_node, dest_node, dependency);
        Ok(())
    }

    fn add_node(&mut self, data: &TaintData) {
        let node = if self.dense {
            Node::new(data)
        } else {
            Node::from(data)
        };
        self.adg.get_or_add_node(node);
    }

    /// the minimal subseq in symbol data that begin with [Merge] token and ends with [Join] token.
    /// A merge_idx is additional returned, which is the previous one token before the [Merge] token.
    /// Return: Option<(merge_idx, subseq)>
    fn find_minimal_subseq(&self, sym_data: &mut TaintDataVec) -> Option<(usize, Vec<TaintData>)> {
        let merge_idx = find_last_merge_idx(sym_data);
        let join_idx = find_first_join_idx(sym_data, merge_idx);
        if merge_idx.is_none() && join_idx.is_none() {
            return None;
        } else if merge_idx.is_none() || join_idx.is_none() {
            unreachable!("The [Merge] and [Join] in symbol data must be paired: {sym_data:?}")
        }
        let merge_idx = merge_idx.unwrap();
        let join_idx = join_idx.unwrap();
        let is_next_sep = if sym_data.len() > join_idx + 1 {
            sym_data[join_idx + 1].is_seq()
        } else {
            false
        };
        let subtree: Vec<TaintData> = sym_data.drain(merge_idx..join_idx + 1).collect();
        if is_next_sep {
            sym_data.insert(merge_idx, TaintData::new_holder());
        }
        Some((merge_idx, subtree))
    }

    /// return the previous one data before the [Merge] token.
    fn get_merge_previous_data(sym_data: &[TaintData], merge_idx: usize) -> Option<&TaintData> {
        if merge_idx == 0 {
            return None;
        }
        let previous_data = sym_data.get(merge_idx - 1).unwrap();
        match previous_data.kind {
            Taintkind::Call | Taintkind::Arg(_) => Some(previous_data),
            Taintkind::Merge => Self::get_merge_previous_data(sym_data, merge_idx - 1),
            Taintkind::Sep => {
                let merge_idx = find_last_merge_idx(sym_data);
                if let Some(merge_idx) = merge_idx {
                    Self::get_merge_previous_data(&sym_data[..merge_idx], merge_idx)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn get_join_subsequent_data(sym_data: &[TaintData], merge_idx: usize) -> Option<&TaintData> {
        if merge_idx >= sym_data.len() {
            return None;
        }
        let previous_data = sym_data.get(merge_idx).unwrap();
        match previous_data.kind {
            Taintkind::Call | Taintkind::Arg(_) => Some(previous_data),
            Taintkind::Sep => {
                let mut join_idx = 0;
                for (idx, data) in sym_data[merge_idx..].iter().enumerate() {
                    if data.kind == Taintkind::Join {
                        join_idx = idx;
                        break;
                    }
                }
                if join_idx == 0 {
                    return None;
                }
                join_idx += merge_idx + 1;
                Self::get_join_subsequent_data(sym_data, join_idx + 1)
            }
            _ => None,
        }
    }

    /// split the subseq to path subseq by [Sep] token. Each path subseq is the data collected from a single path.
    fn split_subseq_by_sep(subseq: &TaintDataVec) -> Vec<Vec<&TaintData>> {
        let mut path_subseqs = vec![];
        let mut path_subeseq = vec![];
        for data in subseq {
            if data.is_merge() || data.is_join() || data.is_holder() {
                continue;
            }
            if data.is_seq() {
                path_subseqs.push(path_subeseq);
                path_subeseq = vec![];
                continue;
            }
            path_subeseq.push(data);
        }
        //path_subseqs.p
        path_subseqs
    }

    fn build_from_single_path_subseq(
        &mut self,
        seq: Vec<&TaintData>,
        previous_data: &Option<&TaintData>,
        subsequent_data: &Option<&TaintData>,
    ) -> Result<()> {
        if seq.is_empty() {
            return Ok(());
        }
        let mut first = seq.first().unwrap();
        self.add_node(first);
        if let Some(previous) = previous_data {
            self.add_edge(previous, first)?;
        }
        for next in &seq[1..] {
            self.add_edge(first, next)?;
            first = next;
        }
        let last = seq.last().unwrap();
        if let Some(subsequent) = subsequent_data {
            self.add_edge(last, subsequent)?;
        }
        Ok(())
    }

    /// build the graph with subseq. Subseq is strated with [Merge] and ended with [Join], where data of control flows are separated by [Sep].
    fn build_from_subseq(
        &mut self,
        subseq: TaintDataVec,
        previous_data: Option<&TaintData>,
        subsequent_data: Option<&TaintData>,
    ) -> Result<()> {
        log::trace!("build ADG from subseq: {subseq:?}, previous: {previous_data:?}, subsequent: {subsequent_data:?}");
        let path_subseqs = Self::split_subseq_by_sep(&subseq);
        for path_subseq in path_subseqs {
            self.build_from_single_path_subseq(path_subseq, &previous_data, &subsequent_data)?;
        }
        Ok(())
    }

    /// build the graph with a sequence of taint data.
    fn build_from_seq(&mut self, sym_data_seq: &mut TaintDataVec) -> Result<()> {
        log::trace!("build ADG from seq: {sym_data_seq:?}");
        loop {
            if let Some((merge_idx, subseq)) = self.find_minimal_subseq(sym_data_seq) {
                let previous = Self::get_merge_previous_data(sym_data_seq.as_slice(), merge_idx);
                let subsequent = Self::get_join_subsequent_data(sym_data_seq, merge_idx);
                self.build_from_subseq(subseq, previous, subsequent)?;
            } else {
                let seq = Vec::from_iter(sym_data_seq.iter());
                self.build_from_single_path_subseq(seq, &None, &None)?;
                break;
            }
        }
        Ok(())
    }

    /// Build the ADG from the analysis result of DFA. The input result is evaluated symbols and their taint data during DFA.
    pub fn build_from_analysis_result(&mut self, mut result: Storage<TaintDataVec>) -> Result<()> {
        for (_var, sym) in result.iter_mut() {
            log::trace!("\nbuild ADG from var: {_var:?}");
            let sym_data_seq = sym.get_data_mut();
            if sym_data_seq.is_empty() {
                continue;
            }
            self.build_from_seq(sym_data_seq)?;
        }
        Ok(())
    }

    /// build a ADG, the dense is specified by self.dense.
    pub fn build(mut self, cfg: CFG) -> Result<ADG> {
        let mut analyzer = Analyzer::<TaintDataVec>::new(cfg).set_callback(Self::create_callback());
        analyzer.execute()?;
        let result = analyzer.dump_analysis_result()?;
        self.build_from_analysis_result(result)?;
        Ok(self.adg)
    }

    /// build a sparse ADG, where each API is a unique node.
    pub fn dense_build(mut self, cfg: CFG) -> Result<ADG> {
        self.dense = true;
        self.build(cfg)
    }

    /// build a sparse ADG, where each API call is a unique node.
    pub fn sparse_build(mut self, cfg: CFG) -> Result<ADG> {
        self.dense = false;
        self.build(cfg)
    }

    pub fn custom_callback_build(
        mut self,
        cfg: CFG,
        callback: CallBack<TaintDataVec>,
    ) -> Result<ADG> {
        let mut analyzer = Analyzer::<TaintDataVec>::new(cfg).set_callback(callback);
        analyzer.execute()?;
        let result = analyzer.dump_analysis_result()?;
        self.build_from_analysis_result(result)?;
        Ok(self.adg)
    }

    /// coalesce ADG with a new ADG build from the given cfg.
    pub fn coalesce_from_new_cfg(mut self, cfg: CFG) -> Result<ADG> {
        assert!(self.dense, "coalesce only used for dense graph.");
        let mut analyzer = Analyzer::<TaintDataVec>::new(cfg).set_callback(Self::create_callback());
        analyzer.execute()?;
        let result = analyzer.dump_analysis_result()?;
        self.build_from_analysis_result(result)?;
        Ok(self.adg)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::Deopt;

    use super::*;
    #[test]
    fn test_dfa_build_adg() -> Result<()> {
        let c_test_path: std::path::PathBuf =
            [crate::Deopt::get_crate_dir()?, "testsuites", "new_test.cc"]
                .iter()
                .collect();
        crate::config::Config::init_test("c-ares");
        let deopt = Deopt::new("c-ares".to_string())?;
        let ast = crate::execution::Executor::extract_ast(&c_test_path, vec![], &deopt)?;
        let cfg = crate::analysis::cfg::CFGBuilder::build_cfg(ast)?;
        cfg.dump_to_file(&c_test_path, true)?;

        // test sparse ADG
        let builder = ADGBuilder::new();
        let adg = builder.sparse_build(cfg.clone())?;
        adg.dump_to_file(&c_test_path, true)?;
        Ok(())
    }

    #[test]
    fn test_build_sparse_dense_and_coalesce_adg() -> Result<()> {
        let deopt = Deopt::new("cJSON".to_string())?;
        let c_test_path: std::path::PathBuf =
            [crate::Deopt::get_crate_dir()?, "testsuites", "test_adg.c"]
                .iter()
                .collect();
        let ast = crate::execution::Executor::extract_ast(&c_test_path, vec![], &deopt)?;
        let cfg = crate::analysis::cfg::CFGBuilder::build_cfg(ast)?;
        cfg.dump_to_file(&c_test_path, true)?;

        // test sparse ADG
        let builder = ADGBuilder::new();
        let adg = builder.sparse_build(cfg.clone())?;
        adg.dump_to_file(&c_test_path, true)?;

        assert_eq!(adg.get_node_count(), 18);
        assert_eq!(adg.get_edge_count(), 18);

        // test dense ADG
        let builder = ADGBuilder::new();
        let adg = builder.dense_build(cfg)?;
        adg.dump_to_file(&c_test_path, true)?;
        assert_eq!(adg.get_node_count(), 12);
        assert_eq!(adg.get_edge_count(), 15);

        // test ADG coalesce
        let c_test_path: std::path::PathBuf = [
            crate::Deopt::get_crate_dir()?,
            "testsuites",
            "test_coalesce.c",
        ]
        .iter()
        .collect();
        let ast = crate::execution::Executor::extract_ast(&c_test_path, vec![], &deopt)?;
        let cfg = crate::analysis::cfg::CFGBuilder::build_cfg(ast)?;
        cfg.dump_to_file(&c_test_path, true)?;
        let adg = adg.coalesce_from(cfg)?;
        adg.dump_to_file(&c_test_path, true)?;
        Ok(())
    }
}
