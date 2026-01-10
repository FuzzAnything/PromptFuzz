//! Parse the header dependency
//! For header files of a library, typically there are the dependency between them.
//! For example, libpng, the header file "pnglibconf.h" record the configuration of the library and "png.h" rely on it.
//! Such config-like files should be include by other headers and should not be included directly, otherwise the gadgets (apis, types and macros) parsed from headers files might be inconsisent with the built binary library.
//! The get_include_lib_headers() returns the top-level header files that a program should include.
//! The get_include_sys_headers() returns the system header files used in this library.

use crate::{config::get_library_name, deopt::Deopt, execution::Executor};
use eyre::Result;
use once_cell::sync::OnceCell;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    process::{Command, Stdio},
};

use super::WorkList;

#[derive(Debug)]
struct TreeNode {
    name: String,
    children: Vec<TreeNode>,
}

impl TreeNode {
    fn new(name: String) -> Self {
        let name = name.replace("./", "");
        Self {
            name,
            children: Vec::new(),
        }
    }

    fn new_invalid() -> Self {
        Self {
            name: "invalid".to_string(),
            children: Vec::new(),
        }
    }

    fn is_invalid(&self) -> bool {
        self.name == "invalid"
    }

    fn set_name(&mut self, name: String) {
        self.name = name;
    }

    fn add_child(&mut self, child: TreeNode) {
        self.children.push(child)
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_clean_root(&mut self, deopt: &Deopt) {
        let binding = deopt.get_library_build_header_path().unwrap();
        let include_path = binding.to_str().unwrap();
        let mut work_list = WorkList::new();
        work_list.push(self);
        while !work_list.empty() {
            let node = work_list.pop();
            let name = node.get_name();
            if name.starts_with(include_path) {
                let name = name.strip_prefix(include_path).unwrap();
                let name = name.strip_prefix('/').unwrap();
                node.set_name(name.to_string());
            }
            for child in &mut node.children {
                work_list.push(child);
            }
        }
    }
}

impl Executor {
    fn extract_header_dependency(&self, header: &Path) -> Result<TreeNode> {
        let header_path = self.deopt.get_library_build_header_path()?;
        let output = Command::new("clang++")
            .current_dir(&header_path)
            .arg("-fsyntax-only")
            .arg("-H")
            .arg("-I.")
            .arg(header)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("fail to extract header dependency");
        if !output.status.success() {
            log::trace!("{}", String::from_utf8_lossy(&output.stderr));
            return Ok(TreeNode::new_invalid());
        }
        let base_name = header
            .to_str()
            .unwrap()
            .strip_prefix(header_path.to_str().unwrap())
            .unwrap();
        let base_name = [".", base_name].concat();
        let output = String::from_utf8_lossy(&output.stderr).to_string();
        let mut tree = parse_dependency_tree(&output, &base_name, &header_path)?;
        tree.get_clean_root(&self.deopt);
        Ok(tree)
    }
}

fn get_layer_child(layered_nodes: Vec<(usize, &str)>, depth: usize) -> Vec<TreeNode> {
    let mut seq_each_layer = Vec::new();
    let mut layer_seqs = Vec::new();
    for (layer, node) in layered_nodes {
        if layer == depth {
            seq_each_layer.push(layer_seqs);
            layer_seqs = Vec::new();
        }
        layer_seqs.push((layer, node));
    }
    seq_each_layer.push(layer_seqs);
    seq_each_layer.retain(|x| !x.is_empty());

    let mut childs = Vec::new();
    for seq in seq_each_layer {
        let root = seq[0];
        let mut root = TreeNode::new(root.1.to_string());
        for child in get_layer_child(seq[1..].to_vec(), depth + 1) {
            root.add_child(child);
        }
        childs.push(root);
    }
    childs
}

fn parse_dependency_tree(output: &str, base_name: &str, header_path: &Path) -> Result<TreeNode> {
    let mut node_layer: Vec<(usize, &str)> = Vec::new();
    for line in output.lines() {
        let sep = line
            .find(' ')
            .ok_or_else(|| eyre::eyre!("Expect an spece in line: {line}"))?;
        let layer = sep;
        let header = line[sep..].trim();
        if !header.starts_with(header_path.to_str().unwrap()) {
            continue;
        }
        if header.ends_with(".h") || header.ends_with(".hpp") || header.ends_with(".hxx") {
            node_layer.push((layer, header));
        }
    }
    let mut tree = TreeNode::new(base_name.to_owned());
    for child in get_layer_child(node_layer, 1) {
        tree.add_child(child);
    }
    Ok(tree)
}


fn get_independent_headers(trees: &[TreeNode]) -> Result<Vec<&str>> {
    use std::collections::{HashMap, HashSet};
    
    // Collect all nodes and their inclusion relationships
    let mut all_nodes: HashMap<&str, &TreeNode> = HashMap::new();
    let mut included_by_others: HashSet<&str> = HashSet::new();
    let mut includes_map: HashMap<&str, HashSet<&str>> = HashMap::new();
    
    // Recursively collect all nodes and dependency relationships
    fn collect_nodes<'a>(
        node: &'a TreeNode, 
        all_nodes: &mut HashMap<&'a str, &'a TreeNode>,
        included_by_others: &mut HashSet<&'a str>,
        includes_map: &mut HashMap<&'a str, HashSet<&'a str>>
    ) {
        let name = node.get_name();
        all_nodes.insert(name, node);
        
        let mut children_set = HashSet::new();
        
        // Collect all child nodes, which are included by the current node
        for child in &node.children {
            let child_name = child.get_name();
            included_by_others.insert(child_name);
            children_set.insert(child_name);
            collect_nodes(child, all_nodes, included_by_others, includes_map);
        }
        
        includes_map.insert(name, children_set);
    }
    
    // Collect nodes for each tree
    for tree in trees {
        collect_nodes(tree, &mut all_nodes, &mut included_by_others, &mut includes_map);
    }
    
    // Find all root nodes (nodes not included by any other nodes)
    let mut independent_headers: Vec<&str> = Vec::new();
    
    for name in all_nodes.keys() {
        if !included_by_others.contains(name) {
            independent_headers.push(name);
        }
    }
    
    // If independent headers are found, return them directly
    if !independent_headers.is_empty() {
        independent_headers.sort();
        independent_headers.dedup();
        return Ok(independent_headers);
    }
    
    // No independent headers found, possible circular dependencies exist
    // Use greedy algorithm to find minimum coverage set
    let mut result = Vec::new();
    let mut covered: HashSet<&str> = HashSet::new();
    let mut remaining_nodes: HashSet<&str> = all_nodes.keys().cloned().collect();
    
    while !remaining_nodes.is_empty() {
        // Find the node that can cover the most uncovered nodes
        let mut best_node: Option<&str> = None;
        let mut best_coverage = 0;
        
        for &node in &remaining_nodes {
            // Calculate how many uncovered nodes this node can cover
            let mut coverage = 0;
            
            // The node itself
            if !covered.contains(node) {
                coverage += 1;
            }
            
            // Calculate the number of nodes reachable through inclusion relationships
            let reachable = get_reachable_nodes(node, &includes_map);
            for &reachable_node in &reachable {
                if !covered.contains(reachable_node) {
                    coverage += 1;
                }
            }
            
            if coverage > best_coverage {
                best_coverage = coverage;
                best_node = Some(node);
            }
        }
        
        if let Some(selected) = best_node {
            result.push(selected);
            remaining_nodes.remove(selected);
            
            // Mark all reachable nodes as covered
            covered.insert(selected);
            let reachable = get_reachable_nodes(selected, &includes_map);
            for &reachable_node in &reachable {
                covered.insert(reachable_node);
                remaining_nodes.remove(reachable_node);
            }
        } else {
            // If no best node is found, select any remaining node
            if let Some(&first) = remaining_nodes.iter().next() {
                result.push(first);
                remaining_nodes.remove(first);
                covered.insert(first);
            }
        }
    }
    
    result.sort();
    result.dedup();
    
    Ok(result)
}

// Helper function: get all nodes reachable from a given node
fn get_reachable_nodes<'a>(
    start: &'a str, 
    includes_map: &HashMap<&'a str, HashSet<&'a str>>
) -> HashSet<&'a str> {
    let mut reachable = HashSet::new();
    let mut stack = vec![start];
    let mut visited = HashSet::new();
    
    while let Some(current) = stack.pop() {
        if visited.contains(current) {
            continue;
        }
        visited.insert(current);
        reachable.insert(current);
        
        if let Some(children) = includes_map.get(current) {
            for &child in children {
                if !visited.contains(child) {
                    stack.push(child);
                }
            }
        }
    }
    
    reachable
}


fn is_a_lib_header(name: &str) -> bool {
    !name.starts_with('/')
}

fn get_included_sys_header(tree: &TreeNode) -> Vec<&str> {
    let mut worklist = WorkList::new();
    worklist.push(tree);
    let mut sys_headers = Vec::new();
    while !worklist.empty() {
        let node = worklist.pop();
        let name = node.get_name();
        // the names not start with '/' are lib headers
        if is_a_lib_header(name) {
            for child in &node.children {
                let child_name = child.get_name();
                if is_a_lib_header(child_name) {
                    continue;
                }
                sys_headers.push(child_name);
            }
        }
        for child in &node.children {
            worklist.push(child);
        }
    }
    sys_headers
}

fn get_library_dep_trees(deopt: &Deopt) -> &'static Vec<TreeNode> {
    static TREES: OnceCell<Vec<TreeNode>> = OnceCell::new();
    TREES.get_or_init(|| {
        let executor = Executor::new(deopt).unwrap();
        let header_dir = deopt.get_library_build_header_path().unwrap();
        let headers = crate::deopt::utils::read_all_files_in_dir(&header_dir).unwrap();
        let mut header_trees = Vec::new();
        for header in headers {
            let ext = header.extension();
            if ext.is_none() {
                continue;
            }
            let ext = ext.unwrap().to_string_lossy().to_string();
            if ext != "h" && ext != "hpp" && ext != "hxx" {
                continue;
            }
            let tree = executor.extract_header_dependency(&header).unwrap();
            if tree.is_invalid() {
                continue;
            }
            header_trees.push(tree);
        }
        header_trees
    })
}

pub fn get_include_lib_headers(deopt: &Deopt) -> Result<Vec<String>> {
    let header_trees = get_library_dep_trees(deopt);
    let header_strs: Vec<String> = get_independent_headers(header_trees)?
        .iter()
        .map(|x| x.to_string())
        .collect();
    Ok(header_strs)
}

pub fn get_include_sys_headers(deopt: &Deopt) -> &'static Vec<String> {
    static SYS_HEADERS: OnceCell<Vec<String>> = OnceCell::new();
    SYS_HEADERS.get_or_init(|| {
        let header_trees = get_library_dep_trees(deopt);
        let header_strs: Vec<String> = get_independent_headers(header_trees)
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect();
        let mut sys_headers = Vec::new();
        for tree in header_trees {
            let name = tree.get_name();
            if header_strs.contains(&name.to_string()) {
                let headers = get_included_sys_header(tree);
                // remove the prefix of sys headers
                for header in headers {
                    if let Some(idx) = header.rfind("/include/") {
                        let header = header[idx + "/include/".len()..].to_string();
                        if !sys_headers.contains(&header) {
                            sys_headers.push(header);
                        }
                    }
                }
            }
        }
        sys_headers
    })
}

pub fn get_include_sys_headers_str() -> String {
    let deopt = Deopt::new(get_library_name()).unwrap();
    let headers = get_include_sys_headers(&deopt);
    headers.join("\n")
}

#[test]
fn test_library_headers() {
    let deopt = Deopt::new("c-ares".to_string()).unwrap();
    let headers = get_include_lib_headers(&deopt).unwrap();
    let sys_headers = get_include_sys_headers(&deopt);
    assert_eq!(
        headers,
        vec!["aom/aomdx.h", "aom/aom_decoder.h", "aom/aomcx.h"]
    );
    assert_eq!(sys_headers, &vec!["stddef.h", "stdint.h", "inttypes.h"]);
}

#[test]
fn test_library_header() {
    crate::config::Config::init_test("cJSON");
    let deopt = Deopt::new("cJSON".to_string()).unwrap();
    let headers = get_include_lib_headers(&deopt).unwrap();
    println!("{headers:?}");
}

#[test]
fn test_get_independent_headers() {
    // Create test data
    let mut root1 = TreeNode::new("header1.h".to_string());
    let mut child1 = TreeNode::new("child1.h".to_string());
    let child2 = TreeNode::new("child2.h".to_string());
    child1.add_child(child2);
    root1.add_child(child1);
    
    let mut root2 = TreeNode::new("header2.h".to_string());
    let child3 = TreeNode::new("child3.h".to_string());
    root2.add_child(child3);
    
    let trees = vec![root1, root2];
    
    // Test the function
    let result = get_independent_headers(&trees).unwrap();
    
    // Verify results - should return root nodes since they are not included by others
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"header1.h"));
    assert!(result.contains(&"header2.h"));
    assert!(!result.contains(&"child1.h"));
    assert!(!result.contains(&"child2.h"));
    assert!(!result.contains(&"child3.h"));
}

#[test]
fn test_get_independent_headers_complex() {
    // Create more complex test data, simulating cross-reference scenarios
    let mut root1 = TreeNode::new("main.h".to_string());
    let mut common = TreeNode::new("common.h".to_string());
    let util1 = TreeNode::new("util1.h".to_string());
    let util2 = TreeNode::new("util2.h".to_string());
    common.add_child(util1);
    common.add_child(util2);
    root1.add_child(common);
    
    let mut root2 = TreeNode::new("secondary.h".to_string());
    let mut helper = TreeNode::new("helper.h".to_string());
    let base = TreeNode::new("base.h".to_string());
    helper.add_child(base);
    root2.add_child(helper);
    
    let trees = vec![root1, root2];
    
    // Test the function
    let result = get_independent_headers(&trees).unwrap();
    
    // Verify results - should only return top-level independent headers
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"main.h"));
    assert!(result.contains(&"secondary.h"));
    
    // These should not be in the results since they are included by other headers
    assert!(!result.contains(&"common.h"));
    assert!(!result.contains(&"util1.h"));
    assert!(!result.contains(&"util2.h"));
    assert!(!result.contains(&"helper.h"));
    assert!(!result.contains(&"base.h"));
}

#[test]
fn test_get_independent_headers_circular() {
    // Create circular dependency test data
    // A -> B -> C -> A (circular dependency)
    // D -> E (independent chain)
    
    let mut node_a = TreeNode::new("A.h".to_string());
    let mut node_b = TreeNode::new("B.h".to_string());
    let mut node_c = TreeNode::new("C.h".to_string());
    
    // Simulate cycle: A includes B, B includes C, C includes A
    // Note: Due to TreeNode structure limitations, we cannot directly create true circular references
    // But we can create a scenario where all nodes are included by other nodes
    node_c.add_child(TreeNode::new("A.h".to_string())); // C includes A
    node_b.add_child(node_c); // B includes C  
    node_a.add_child(node_b); // A includes B
    
    // Add an independent chain to verify mixed scenarios
    let mut node_d = TreeNode::new("D.h".to_string());
    let node_e = TreeNode::new("E.h".to_string());
    node_d.add_child(node_e);
    
    let trees = vec![node_a, node_d];
    
    // Test the function
    let result = get_independent_headers(&trees).unwrap();
    
    // In this case, should find results containing at least A.h and D.h
    // D.h is independent, A.h is a representative from the cycle
    assert!(!result.is_empty());
    
    // D.h should be in the results since it's independent
    assert!(result.contains(&"D.h"));
    
    // Results should contain the minimum set that covers all nodes
    println!("Circular dependency test result: {:?}", result);
}

#[test]
fn test_get_independent_headers_all_circular() {
    // Create complete circular dependency test data, all nodes are included by others
    // Tree1: X -> Y -> Z -> X
    // Tree2: P -> Q -> P
    
    let mut node_x = TreeNode::new("X.h".to_string());
    let mut node_y = TreeNode::new("Y.h".to_string());
    let mut node_z = TreeNode::new("Z.h".to_string());
    
    // X includes Y, Y includes Z, Z includes X (simulated by creating another X node)
    node_z.add_child(TreeNode::new("X.h".to_string()));
    node_y.add_child(node_z);
    node_x.add_child(node_y);
    
    let mut node_p = TreeNode::new("P.h".to_string());
    let mut node_q = TreeNode::new("Q.h".to_string());
    
    // P includes Q, Q includes P (simulated by creating another P node)
    node_q.add_child(TreeNode::new("P.h".to_string()));
    node_p.add_child(node_q);
    
    let trees = vec![node_x, node_p];
    
    // Test the function
    let result = get_independent_headers(&trees).unwrap();
    
    // Should find minimum set that covers all nodes
    assert!(!result.is_empty());
    
    // Result count should be reasonable (not exceeding total node count)
    assert!(result.len() <= 2); // At most two representative nodes
    
    println!("All circular dependency test result: {:?}", result);
    
    // Verify that selected nodes can indeed cover the main dependency trees
    // Due to cycles, should include at least one of the main tree's root nodes
    let has_main_tree_coverage = result.contains(&"X.h") || result.contains(&"Y.h") || result.contains(&"Z.h");
    let has_second_tree_coverage = result.contains(&"P.h") || result.contains(&"Q.h");
    
    assert!(has_main_tree_coverage, "Should cover the main dependency tree");
    assert!(has_second_tree_coverage, "Should cover the second dependency tree");
}
