use super::*;
use clang_ast::{BareSourceLocation, SourceLocation, SourceRange};
use eyre::Result;
use std::{
    cmp::min,
    io::{Read, Seek},
    path::Path,
};

/// Get the absolute location
pub fn get_bare_loc(loc: &SourceLocation) -> Option<&BareSourceLocation> {
    loc.spelling_loc.as_ref()
}

/// Get the bigin location of this range.
pub fn get_sr_begin_loc(sr: &SourceRange) -> Result<&BareSourceLocation> {
    if let Some(begin) = &sr.begin.spelling_loc {
        if begin.file.ends_with(".cc") {
            return Ok(begin);
        }
    }
    if let Some(begin) = &sr.begin.expansion_loc {
        if begin.file.ends_with(".cc") {
            return Ok(begin);
        }
    }
    eyre::bail!("cannot get begin from SourceRange: {sr:?}")
}

/// Get the end location of this range.
pub fn get_sr_end_loc(sr: &SourceRange) -> Result<&BareSourceLocation> {
    if let Some(end) = &sr.end.spelling_loc {
        if end.file.ends_with(".cc") {
            return Ok(end);
        }
    }
    if let Some(end) = &sr.end.expansion_loc {
        if end.file.ends_with(".cc") {
            return Ok(end);
        }
    }
    eyre::bail!("cannot get end from SourceRange: {sr:?}")
}

/// Get the source file offsets of this range.
pub fn get_sr_offset(sr: &SourceRange) -> Result<(usize, usize)> {
    let begin = get_sr_begin_loc(sr)?.offset;
    let end = get_sr_end_loc(sr)?;
    let end = end.offset + end.tok_len;
    Ok((begin, end))
}

/// Get the beginning offset of the previous one VarDecl;
fn get_pre_vd_begin(vd_begin: &BareSourceLocation, src_file: &Path) -> Result<usize> {
    let begin_loc = vd_begin.offset;
    let buffer = std::fs::read_to_string(src_file)?;
    let buf = &buffer[..begin_loc];
    let comma = buf
        .rfind(',')
        .ok_or_else(|| eyre::eyre!("a prefix vd should be separated by ',' : {buf}"))?;
    Ok(comma)
}

pub fn get_loc_before_stmt(src_file: &Path, range: &SourceRange) -> Result<usize> {
    let begin_loc = get_sr_begin_loc(range)?.offset;
    let buffer = std::fs::read_to_string(src_file)?;
    let buf = &buffer[..begin_loc];
    let mut end_locs = Vec::new();
    if let Some(idx) = buf.rfind(';') {
        end_locs.push(idx);
    }
    if let Some(idx) = buf.rfind('}') {
        end_locs.push(idx);
    }
    if let Some(idx) = buf.rfind('{') {
        end_locs.push(idx)
    }
    let end_loc = end_locs.iter().max().unwrap();
    Ok(end_loc + 1)
}

fn get_post_vd_begin(vd_begin: &BareSourceLocation, src_file: &Path) -> Result<usize> {
    let begin_loc = vd_begin.offset;
    let buffer = std::fs::read_to_string(src_file)?;
    let last_char = buffer.chars().nth(begin_loc - 1).unwrap();
    if last_char == '*' {
        Ok(begin_loc - 1)
    } else {
        Ok(begin_loc)
    }
}

fn get_vd_end_offset(vd_end: &BareSourceLocation, src_file: &Path) -> Result<usize> {
    let buffer = std::fs::read_to_string(src_file).unwrap();
    let end_loc = vd_end.offset + vd_end.tok_len;
    let buf = &buffer[end_loc..];
    let comma_offset = buf.find(',');
    let semicolon_offset = buf.find(';');
    if comma_offset.is_none() {
        return Ok(end_loc + semicolon_offset.unwrap());
    }
    if comma_offset.unwrap() < semicolon_offset.unwrap() {
        return Ok(end_loc + comma_offset.unwrap());
    }
    Ok(end_loc + semicolon_offset.unwrap())
}

/// if there is other vd in this range.
fn has_other_before_vd(
    begin: &BareSourceLocation,
    end: &BareSourceLocation,
    src_file: &Path,
) -> bool {
    let begin_loc = begin.offset;
    let end_loc = end.offset;
    let buffer = std::fs::read_to_string(src_file).unwrap();
    let buf = &buffer[begin_loc..end_loc];
    buf.find('=').is_some()
}

fn has_other_after_vd(end: &BareSourceLocation, src_file: &Path) -> bool {
    let buffer = std::fs::read_to_string(src_file).unwrap();
    let buf = &buffer[end.offset + end.tok_len..];
    let comma_offset = buf.find(',');
    let semicolon_offset = buf.find(';');
    if comma_offset.is_none() {
        return false;
    }
    if comma_offset.unwrap() < semicolon_offset.unwrap() {
        return true;
    }
    false
}

/// Get the source file offset of the begin and the end of this VarDecl.
/// This source file range is used to delete a VarDecl.
pub fn get_var_uninit_loc(vd: &VarDecl, src_file: &Path) -> Result<(usize, usize)> {
    if let Some(vd_loc) = get_bare_loc(&vd.loc) {
        let vd_begin = get_sr_begin_loc(&vd.range)?;
        let vd_end = get_sr_end_loc(&vd.range)?;
        // if var before has other vd
        if has_other_before_vd(vd_begin, vd_loc, src_file) {
            let begin = get_pre_vd_begin(vd_loc, src_file)?;
            let end = vd_end.offset + vd_end.tok_len;
            return Ok((begin, end));
        } else {
            // if var after has other vd
            if has_other_after_vd(vd_end, src_file) {
                let begin = get_post_vd_begin(vd_loc, src_file)?;
                let end = get_vd_end_offset(vd_end, src_file)? + 1;
                return Ok((begin, end));
            } else {
                let begin = vd_begin.offset;
                let end = get_vd_end_offset(vd_end, src_file)? + 1;
                return Ok((begin, end));
            }
        }
    }
    eyre::bail!("cannot get loction for variable: {vd:?}")
}

pub fn get_source_code_range(sr: &SourceRange) -> Result<(usize, usize)> {
    let begin = get_sr_begin_loc(sr)?;
    let end = get_sr_end_loc(sr)?;
    let begin_loc = begin.offset;
    let end_loc = end.offset + end.tok_len;
    Ok((begin_loc, end_loc))
}

pub fn get_header_code_range(sr: &SourceRange) -> Result<(usize, usize)> {
    let begin = sr.begin.spelling_loc.as_ref().unwrap();
    let end = sr.end.spelling_loc.as_ref().unwrap();
    let begin_loc = begin.offset;
    let end_loc = end.offset + end.tok_len;
    Ok((begin_loc, end_loc))
}

pub fn get_source_code_content(sr: &SourceRange) -> Result<String> {
    if let Some(loc) = &sr.begin.spelling_loc {
        let file = std::path::PathBuf::from(loc.file.clone().to_string());
        let (begin, end) = get_source_code_range(sr)?;
        let mut f = std::fs::File::options().read(true).open(file)?;
        f.seek(std::io::SeekFrom::Start(begin as u64))?;
        if end <= begin {
            eyre::bail!("unable to get the source code range")
        }
        let count = end - begin;
        let count = min(count, 100);
        let mut buf = vec![0; count];
        f.read_exact(buf.as_mut_slice())?;
        return Ok(String::from_utf8_lossy(&buf).to_string());
    }
    eyre::bail!("unable to get the file name of this sr")
}

pub fn get_header_code_content(sr: &SourceRange) -> Result<String> {
    if let Some(begin_loc) = &sr.begin.spelling_loc {
        if let Some(end_loc) = &sr.end.spelling_loc {
            if begin_loc.file.as_ref() != end_loc.file.as_ref() {
                eyre::bail!("unable to get the source code range: {sr:?}")
            }
            let src_file = std::path::PathBuf::from(begin_loc.file.clone().to_string());
            let (begin, end) = get_header_code_range(sr)?;
            let mut f = std::fs::File::options().read(true).open(src_file)?;
            f.seek(std::io::SeekFrom::Start(begin as u64))?;
            if end <= begin {
                eyre::bail!("unable to get the source code range: {sr:?}")
            }
            if end_loc.line < begin_loc.line {
                eyre::bail!("unable to get the source code range: {sr:?}")
            }
            if end_loc.line - begin_loc.line >= 10 {
                eyre::bail!("unable to get the source code range: {sr:?}")
            }
            let count = end - begin;
            let count = min(count, 100);
            let mut buf = vec![0; count];
            f.read_exact(buf.as_mut_slice())?;
            return Ok(String::from_utf8_lossy(&buf).to_string());
        }
    }
    eyre::bail!("unable to get the file name of this sr")
}

/// Get the end source file location of inserted fuzzer shim.
/// Any fuzzzer variables should be initialized before this loc (inside the fuzzer shim).
pub fn get_fuzzer_shim_end_loc(src_file: &Path) -> Result<usize> {
    let mut f = std::fs::OpenOptions::new().read(true).open(src_file)?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;
    let shim_end = "//fuzzer shim end}";
    let loc = buffer
        .find(shim_end)
        .ok_or_else(|| eyre::eyre!("cannot find `fuzzer shim end`"))?;
    Ok(loc)
}

pub fn get_fuzzer_shim_after_loc(src_file: &Path) -> Result<Option<usize>> {
    let mut f = std::fs::OpenOptions::new().read(true).open(src_file)?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;
    let shim_end = "//fuzzer shim end}";
    if let Some(loc) = buffer.find(shim_end) {
        let loc = loc + shim_end.len();
        return Ok(Some(loc));
    }
    Ok(None)
}

/// Get the source file range of the fuzzer shim
pub fn get_fuzzer_shim_range(src_file: &Path) -> Result<(usize, usize)> {
    let mut f = std::fs::OpenOptions::new().read(true).open(src_file)?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;
    let shim_begin = "//fuzzer vars shim";
    let shim_end = "//fuzzer shim end}";
    let begin_loc = buffer
        .find(shim_begin)
        .ok_or_else(|| eyre::eyre!("cannot find `fuzzer vars shim`"))?;
    let end_loc = buffer
        .find(shim_end)
        .ok_or_else(|| eyre::eyre!("cannot find `fuzzer shim end`"))?;
    let end_loc = end_loc + shim_end.len();
    Ok((begin_loc, end_loc))
}

pub fn is_valid_range(range: &SourceRange) -> bool {
    if range.begin.spelling_loc.is_some() {
        return true;
    }
    if range.begin.expansion_loc.is_some() {
        return true;
    }
    false
}

/// Whether this range is in some header files.
pub fn is_macro_stmt(range: &SourceRange) -> bool {
    if let Some(loc) = &range.begin.spelling_loc {
        return loc.file.as_ref().ends_with(".h");
    }
    if let Some(loc) = &range.end.spelling_loc {
        return loc.file.as_ref().ends_with(".h");
    }
    false
}

pub fn is_macro_expansion(range: &SourceRange) -> bool {
    range.begin.expansion_loc.is_some() || range.end.expansion_loc.is_some()
}
