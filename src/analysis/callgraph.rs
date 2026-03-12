use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{config::get_library_name, deopt::Deopt};
use eyre::Context;
use once_cell::sync::OnceCell;
use petgraph::{graph::NodeIndex, Directed, Graph};
use regex::Regex;

struct DotNode {
    id: u64,
    label: String,
}

impl DotNode {
    pub fn new(id: &str, label: &str) -> Self {
        Self {
            id: u64::from_str_radix(&id[2..], 16).unwrap(),
            label: label.to_string(),
        }
    }
}

struct DotEdge {
    src: u64,
    dst: u64,
}

impl DotEdge {
    pub fn new(src: &str, dst: &str) -> Self {
        Self {
            src: u64::from_str_radix(&src[2..], 16).unwrap(),
            dst: u64::from_str_radix(&dst[2..], 16).unwrap(),
        }
    }
}

fn dot_parser(dot_file: &Path) -> eyre::Result<(Vec<DotNode>, Vec<DotEdge>)> {
    let content =
        std::fs::read_to_string(dot_file).context(format!("dot file open error: {dot_file:?}"))?;
    let node_re =
        Regex::new(r###"Node(0x[0-9a-fA-F]+) \[shape=record,label="\{(.+?)\}"];"###).unwrap();
    let mut nodes = Vec::new();
    for captures in node_re.captures_iter(&content) {
        let id = &captures[1];
        let label = &captures[2];
        let node = DotNode::new(id, label);
        nodes.push(node);
    }

    let mut edges: Vec<DotEdge> = Vec::new();
    let edge_re = Regex::new(r###"Node(0x[0-9a-fA-F]+) -> Node(0x[0-9a-fA-F]+);"###).unwrap();
    for captures in edge_re.captures_iter(&content) {
        let src = &captures[1];
        let dst = &captures[2];
        let edge = DotEdge::new(src, dst);
        edges.push(edge)
    }
    Ok((nodes, edges))
}

pub struct CallGraph {
    graph: Graph<String, u8, Directed>,
    node_map: HashMap<String, NodeIndex>,
}

impl CallGraph {
    fn new() -> Self {
        Self {
            graph: Graph::new(),
            node_map: HashMap::new(),
        }
    }

    fn construct(&mut self, nodes: Vec<DotNode>, edges: Vec<DotEdge>) {
        self.construct_nodes(&nodes);
        self.construct_edges(nodes, edges);
    }

    fn construct_nodes(&mut self, nodes: &Vec<DotNode>) {
        for node in nodes {
            let idx = self.graph.add_node(node.label.clone());
            self.node_map.insert(node.label.clone(), idx);
        }
    }

    fn construct_edges(&mut self, nodes: Vec<DotNode>, edges: Vec<DotEdge>) {
        for edge in edges {
            let from = edge.src;
            let to = edge.dst;
            let src = nodes.iter().find(|x| x.id == from).unwrap();
            let dst = nodes.iter().find(|x| x.id == to).unwrap();
            let src_node = self.node_map.get(&src.label).unwrap();
            let dst_node = self.node_map.get(&dst.label).unwrap();

            self.graph.add_edge(*src_node, *dst_node, 0);
        }
    }

    pub fn get_direct_callees(&self, func: &str) -> Vec<&str> {
        let node = self
            .node_map
            .get(func);
        if node.is_none() {
            return Vec::new();
        }
        let mut callees = Vec::new();
        for neighbor in self
            .graph
            .neighbors_directed(*node.unwrap(), petgraph::Direction::Outgoing)
        {
            let callee = self.graph.node_weight(neighbor).unwrap();
            callees.push(callee.as_str());
        }
        callees
    }

    /// Dump this cfg to a Graphviz format file and translate it to PNG.
    pub fn dump_to_file(&self, deopt: &Deopt) -> eyre::Result<()> {
        let config = vec![petgraph::dot::Config::EdgeNoLabel];
        let raw_str = format!(
            "{:?}",
            petgraph::dot::Dot::with_config(&self.graph, &config)
        );
        let file: PathBuf = [deopt.get_library_misc_dir()?, "callgraph".into()]
            .iter()
            .collect();

        let mut dot_path = file.clone();
        dot_path.set_extension("dot");
        std::fs::write(&dot_path, raw_str)?;
        let mut cfg_path = file.clone();
        cfg_path.set_extension("pdf");
        let output = std::process::Command::new("dot")
            .arg("-Tpdf")
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

pub fn get_lib_call_graph() -> &'static CallGraph {
    static GRAPH: OnceCell<CallGraph> = OnceCell::new();
    GRAPH.get_or_init(|| {
        let deopt = Deopt::new(get_library_name()).unwrap();
        let dot_path: PathBuf = [
            deopt.get_library_build_dir().unwrap(),
            "work".into(),
            "callgraph.dot".into(),
        ]
        .iter()
        .collect();
        let (nodes, edges) = dot_parser(&dot_path).unwrap();
        let mut call_graph = CallGraph::new();
        call_graph.construct(nodes, edges);
        call_graph
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_call_graph() -> eyre::Result<()> {
        crate::config::Config::init_test("libvpx");
        let deopt = Deopt::new("libvpx".to_string())?;
        let call_graph = get_lib_call_graph();
        call_graph.dump_to_file(&deopt)?;
        Ok(())
    }
}
