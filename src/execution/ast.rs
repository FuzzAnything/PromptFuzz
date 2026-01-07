//! Execute clang to extract AST from program:
//! Command:
//!     $ clang++ -Xclang -ast-dump=json -fsyntax-only path/to/source.cc

use crate::ast::loc::get_source_code_range;
use crate::program::gadget::get_func_gadget;
use crate::Deopt;
use clang_ast::SourceLocation;
use eyre::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Executor;
use crate::ast::{Clang, Node};

impl Executor {
    /// Extract ast for main
    pub fn extract_ast(program: &Path, pch_list: Vec<PathBuf>, deopt: &Deopt) -> Result<Node> {
        Self::extract_func_ast(program, pch_list, deopt, "LLVMFuzzerTestOneInput", true)
    }

    /// Extract ast for function.
    pub fn extract_func_ast(
        program: &Path,
        pch_list: Vec<PathBuf>,
        deopt: &Deopt,
        func: &str,
        use_fdp: bool,
    ) -> Result<Node> {
        let ast_filter = format!("-ast-dump-filter={func}");
        let include_path =
            "-I".to_owned() + deopt.get_library_build_header_path()?.to_str().unwrap();

        let mut binding = Command::new("clang++");
        let mut cmd = binding
            .arg("-fsyntax-only")
            .arg("-Xclang")
            .arg("-ast-dump=json")
            .arg("-Xclang")
            .arg(ast_filter)
            .arg(include_path)
            .arg(program);

        for pch in pch_list {
            cmd = cmd.arg("-include-pch").arg(pch);
        }

        if use_fdp {
            let include_fdp = "-I".to_owned() + Deopt::get_fdp_path()?.to_str().unwrap();
            cmd = cmd.arg(include_fdp);
        }

        //log::trace!("extract ast from {program:?}, cmd: {cmd:?}");

        let output = cmd
            .stdout(Stdio::piped())
            .output()
            .expect("failed to execute cmd.");
        if output.status.success() {
            let json_output = output.stdout.as_slice();
            let node: Node = ast_dump_filter(json_output, func)?;
            return Ok(node);
        }
        eyre::bail!(
            "fail to extract from {program:?}\n, {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn extract_program_ast(program: &Path) -> Result<Node> {
        let mut binding = Command::new("clang++");
        let output = binding
            .arg("-cc1")
            .arg("-fsyntax-only")
            .arg("-ast-dump=json")
            .arg(program)
            .stdout(Stdio::piped())
            .output()
            .expect("failed to execute cmd.");

        let json_output = output.stdout.as_slice();
        let node: Node = serde_json::from_slice(json_output)?;
        Ok(node)
    }

    pub fn parse_header_ast(header: &Path, deopt: &Deopt) -> eyre::Result<Node> {
        let mut ast = Executor::extract_header_ast(header, deopt)?;
        let headers =
            crate::deopt::utils::read_all_files_in_dir(&deopt.get_library_build_header_path()?)?;
        let _ = eliminate_irrelative_ast(&mut ast, &headers);
        log::info!("Parsed header for: {header:?}");
        Ok(ast)
    }

    pub fn extract_header_ast(header: &Path, deopt: &Deopt) -> Result<Node> {
        let include_path =
            "-I".to_owned() + deopt.get_library_build_header_path()?.to_str().unwrap();
        let mut binding = Command::new("clang++");
        let binding = binding
            .arg("-fsyntax-only")
            .arg("-Xclang")
            .arg("-ast-dump=json")
            .arg(include_path)
            .arg(header);
        let output = binding
            .stdout(Stdio::piped())
            .output()
            .expect("failed to execute cmd.");
        if output.status.success() {
            let json_output = output.stdout.as_slice();
            let node: Node = serde_json::from_slice(json_output)
                .with_context(|| eyre::eyre!("fail to extract ast from {header:?}"))?;
            return Ok(node);
        }
        eyre::bail!(
            "fail to extract ast from {header:?}\n cmd:{binding:?}\n {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Filter the ast and only retain the node with function name as `func`.
fn ast_dump_filter(data: &[u8], func: &str) -> Result<Node> {
    let it = data.iter();
    let mut json: Vec<u8> = Vec::new();
    let mut last: u8 = 0_u8;
    for cur in it {
        json.push(*cur);
        if *cur == b'}' && last == b'\n' {
            let ast: Node = serde_json::from_slice(json.as_slice())?;
            if let Clang::FunctionDecl(fd) = &ast.kind {
                let name = fd.get_name();
                if func == name {
                    return Ok(ast);
                }
            }
            json.clear();
        }
        last = *cur;
    }
    unreachable!()
}

/// elimitate the irrelative asts that included in this file.
fn eliminate_irrelative_ast<'a>(ast: &'a mut Node, headers: &Vec<PathBuf>) -> &'a Node {
    ast.inner.retain_mut(|child| match &child.kind {
        Clang::EnumDecl(el) => is_defined_in_headers(&el.loc, headers),
        Clang::FunctionDecl(fd) => is_defined_in_headers(&fd.loc, headers),
        Clang::RecordDecl(rd) => is_defined_in_headers(&rd.loc, headers),
        Clang::CXXRecordDecl(crd) => is_defined_in_headers(&crd.loc, headers),
        Clang::TypedefDecl(td) => is_defined_in_headers(&td.loc, headers),
        Clang::LinkageSpecDecl(lsd) => {
            if is_defined_in_headers(&lsd.loc, headers) {
                eliminate_irrelative_ast(child, headers);
                return true;
            }
            false
        }
        _ => false,
    });
    ast
}

/// whether the ast element is definied inside the header file
fn is_defined_in_headers(loc: &SourceLocation, headers: &Vec<PathBuf>) -> bool {
    for header in headers {
        if let Some(loc) = &loc.spelling_loc {
            let file_path = PathBuf::from(loc.file.to_string());
            if file_path.eq(header) {
                return true;
            }
        }
        if let Some(loc) = &loc.expansion_loc {
            let file_path = PathBuf::from(loc.file.to_string());
            if file_path.eq(header) {
                return true;
            }
        }
    }
    false
}

/// LLMs tends to re-declare the provided API in code.
/// Those duplicate definitions cause link error, thus those duplicated definitions need to be removed.
pub fn remove_duplicate_definition(program: &Path) -> Result<()> {
    let ast = Executor::extract_program_ast(program)?;
    let mut del_ranges = vec![];
    for child in &ast.inner {
        if let Clang::FunctionDecl(fd) = &child.kind {
            let name = fd.get_name();
            if get_func_gadget(&name).is_some() {
                del_ranges.push(fd.range.clone());
            }
        }
    }
    let mut content = std::fs::read_to_string(program)?;
    for sr in del_ranges.iter().rev() {
        let (begin, end) = get_source_code_range(sr)?;
        content.replace_range(begin..end + 1, "");
    }
    std::fs::write(program, content)?;
    Ok(())
}

#[test]
fn test_ast_dump_filter() -> Result<()> {
    let c_test_path: std::path::PathBuf =
        [crate::Deopt::get_crate_dir()?, "testsuites", "test_dfa.cc"]
            .iter()
            .collect();
    let deopt = Deopt::new("cJSON".to_string())?;
    let func = "main";
    let ast_filter = format!("-ast-dump-filter={func}");
    let include_path = "-I".to_owned() + deopt.get_library_build_header_path()?.to_str().unwrap();

    let mut binding = Command::new("clang++");
    let output = binding
        .arg("-fsyntax-only")
        .arg("-Xclang")
        .arg("-ast-dump=json")
        .arg("-Xclang")
        .arg(ast_filter)
        .arg(include_path)
        .arg(c_test_path)
        .stdout(Stdio::piped())
        .output()
        .expect("failed to execute cmd.");

    //log::trace!("extract ast from {program:?}, cmd: {cmd:?}");
    if output.status.success() {
        let json_output = output.stdout.as_slice();
        let node = ast_dump_filter(json_output, func)?;
        if let Clang::FunctionDecl(fd) = &node.kind {
            assert_eq!(func, &fd.get_name());
            return Ok(());
        }
        eyre::bail!("Target ast is not FunctionDecl")
    }

    eyre::bail!("Unable to extract the ast")
}
