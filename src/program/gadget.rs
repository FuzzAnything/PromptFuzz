use crate::{
    config,
    program::gadget::{
        func_gadget::{load_func_gadgets, parse_func_gadgets},
        typed_gadget::{dump_type_gadgets, load_type_gadgets},
    },
    Deopt,
};
use ctype::*;
use eyre::{Context, Result};
use once_cell::sync::OnceCell;
use regex::Regex;
use std::collections::HashMap;

use super::{rand::random_sample, Deserialize, Deserializer};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuncGadget {
    pub name: String,
    arg_idents: Vec<String>,
    arg_types: Vec<String>,
    alias_arg_types: Vec<String>,
    ret_type: String,
    alias_ret_type: String,
}

pub fn get_func_gadgets() -> &'static Vec<FuncGadget> {
    static GADGETS: OnceCell<Vec<FuncGadget>> = OnceCell::new();
    GADGETS.get_or_init(|| {
        let deopt = Deopt::new(config::get_library_name()).unwrap();
        if let Ok(gadgets) = load_func_gadgets(&deopt) {
            return gadgets;
        }
        let mut gadgets = parse_func_gadgets(&deopt).unwrap();
        if let Some(ban_funcs) = &deopt.config.ban {
            gadgets.retain(|x| {
                for ban_func in ban_funcs {
                    let re = Regex::new(ban_func)
                        .unwrap_or_else(|_| panic!("Error regex in config.yaml: {ban_func}"));
                    if re.is_match(x.get_func_name()) {
                        return false;
                    }
                }
                true
            })
        }
        func_gadget::dump_func_gadgets(&gadgets, &deopt).unwrap();
        log::debug!("Parsed {} function gadgets.", gadgets.len());
        if gadgets.is_empty() {
            panic!("Cannot extract function gadgets! Please check whether your library building was sucessful!")
        }
        gadgets
    })
}

#[derive(Eq, PartialEq, Hash, Clone, serde::Deserialize, serde::Serialize)]
pub struct TypeGadget {
    /// type name
    pub name: String,
    /// class of type: enum or struct
    pub class: TypeClass,
    /// type soruce code definition
    pub def: String,
    /// underlying type of typedef
    pub underly_ty: Option<String>,
}

#[derive(Eq, PartialEq, Hash, Clone, serde::Deserialize, serde::Serialize)]
pub enum TypeClass {
    Typedef,
    Enum,
    Struct,
}

pub fn get_type_gadgets() -> &'static Vec<TypeGadget> {
    static GADGETS: OnceCell<Vec<TypeGadget>> = OnceCell::new();
    GADGETS.get_or_init(|| {
        let deopt = Deopt::new(config::get_library_name()).unwrap();
        if let Ok(gadgets) = load_type_gadgets(&deopt) {
            return gadgets;
        }
        let gadgets = typed_gadget::parse_type_gadgets(&deopt).unwrap();
        let gadgets = typed_gadget::add_custom_type_gadgets(gadgets);
        dump_type_gadgets(&gadgets, &deopt)
            .context("Error to dump type gadgets")
            .unwrap();
        gadgets
    })
}

pub fn get_type_gadget(ty: &str) -> Option<&'static TypeGadget> {
    get_type_gadgets().iter().find(|&gadget| gadget.name == ty)
}

impl TypeGadget {
    pub fn new(name: String, def: String, class: TypeClass, ty: Option<String>) -> Self {
        //make sure the last char is ';'
        Self {
            name,
            def,
            class,
            underly_ty: ty,
        }
    }

    pub fn is_type(&self, ty: &str) -> bool {
        if self.name == ty {
            return true;
        }
        false
    }
}

pub mod typed_gadget {
    use std::collections::HashSet;

    use super::{TypeClass, TypeGadget};
    use crate::{
        ast::{Clang, Node},
        execution::Executor,
        program::gadget::{
            ctype::{self, get_unsugared_unqualified_type},
            get_type_gadget,
        },
        Deopt,
    };
    use eyre::Result;

    /// get the source code definition of this type name.
    pub fn get_type_definition(ty: &str, visited: &mut HashSet<String>) -> Option<String> {
        log::trace!("get definition of type: {ty}");
        let ty = get_unsugared_unqualified_type(ty);
        if ctype::is_primitive_type(&ty) {
            return None;
        }
        if visited.contains(&ty) {
            return None;
        }
        visited.insert(ty.clone());
        if let Some(gadget) = get_type_gadget(&ty) {
            if let TypeClass::Typedef = &gadget.class {
                let mut type_def = gadget.def.clone();
                if let Some(underly_ty) = &gadget.underly_ty {
                    let query = get_type_definition(underly_ty, visited);
                    if let Some(def) = query {
                        type_def.insert(0, '\n');
                        type_def.insert_str(0, &def);
                    }
                }
                return Some(type_def);
            }
            if let TypeClass::Struct = &gadget.class {
                let def = gadget.def.clone();
                return Some(def);
            }
            if let TypeClass::Enum = &gadget.class {
                let def = gadget.def.clone();
                return Some(def);
            }
        }
        // the type "FILE" may not be recognized by GPT, we should explicitly tell what it is.
        if ty == "FILE" {
            return Some(String::from("FILE: it is the type in stdio.h, e.g., FILE *fopen(const char *filename, const char *mode)"));
        }
        log::warn!("Unable to get the definition of the type: {ty}");
        None
    }

    pub fn parse_type_gadgets(deopt: &Deopt) -> Result<Vec<TypeGadget>> {
        let headers = deopt.obtain_library_include_headers()?;
        let mut gadgets = Vec::new();
        for header in headers {
            if let Some(ext) = header.extension() {
                if ext != "h" && ext != "hpp" && ext != "hxx" {
                    continue;
                }
            }
            let ast_res = Executor::parse_header_ast(&header, deopt);
            if let Err(err) = ast_res {
                log::error!("{}", err.to_string());
                log::error!("Meet a error during parse header's ast. Some headers are prevent to be included. IF that is the case, please just ignore it.");
                continue;
            }
            let ast = ast_res.unwrap();
            let header_gadgets: Vec<TypeGadget> = parse_type_gadget_from_ast(&ast)?;
            gadgets.extend(header_gadgets);
        }
        let mut visited: HashSet<TypeGadget> = HashSet::new();
        gadgets.retain(|x| {
            if visited.contains(x) {
                false
            } else {
                visited.insert(x.clone());
                true
            }
        });
        log::debug!("Parsed {} typed gadgets", gadgets.len());
        Ok(gadgets)
    }

    fn parse_type_gadget_from_ast(ast: &Node) -> Result<Vec<TypeGadget>> {
        let mut gadgets: Vec<TypeGadget> = Vec::new();
        let mut last_child = None;
        for child in ast.inner.iter() {
            match &child.kind {
                Clang::EnumDecl(el) => {
                    if let Some(name) = &el.name {
                        let name = name.to_string();
                        let def = el.get_definition(child);
                        let def = format!("enum {name} {{\n{def}\n}};");
                        let gadget = TypeGadget::new(name, def, TypeClass::Enum, None);
                        gadgets.push(gadget);
                    }
                }
                Clang::RecordDecl(rd) => {
                    if let Some(name) = rd.get_name() {
                        let def = rd.get_definition(child);
                        let def = if def.len() > 1 {
                            format!("struct {name} {{\n{def}\n}};")
                        } else {
                            format!("struct {name};")
                        };
                        let gadget = TypeGadget::new(name, def, TypeClass::Struct, None);
                        gadgets.push(gadget);
                        last_child = None;
                    } else {
                        last_child = Some(child);
                    }
                }
                Clang::CXXRecordDecl(crd) => {
                    if let Some(name) = &crd.name {
                        let name = name.to_string();
                        let def = crd.get_definition(child);
                        let def = if def.len() > 1 {
                            format!("struct {name} {{\n{def}\n}};")
                        } else {
                            format!("struct {name};")
                        };
                        let gadget = TypeGadget::new(name, def, TypeClass::Struct, None);
                        gadgets.push(gadget);
                        last_child = None;
                    } else {
                        last_child = Some(child);
                    }
                }
                Clang::TypedefDecl(td) => {
                    let name = td.name.to_string();
                    let ty = td.r#type.get_type_name();
                    let underly_ty = get_unsugared_unqualified_type(&ty);
                    let gadget = if let Some(gadget) = handle_unamed_typedef(child, last_child) {
                        gadget
                    } else if underly_ty == name {
                        let def = String::new();
                        TypeGadget::new(name, def, TypeClass::Typedef, None)
                    } else {
                        let def = format!("typedef {ty} {name};");
                        TypeGadget::new(name, def, TypeClass::Typedef, Some(ty))
                    };

                    gadgets.push(gadget);
                }
                Clang::LinkageSpecDecl(_) => {
                    gadgets.extend(parse_type_gadget_from_ast(child)?);
                }
                _ => {
                    continue;
                }
            }
        }
        Ok(gadgets)
    }

    /// Some libraries could use some types from external.
    /// Instead supporting all types that might be used in system headers which incur heavy works,
    ///      we direct adding typedef for those types to avoid huge works.
    pub fn add_custom_type_gadgets(mut gadgets: Vec<TypeGadget>) -> Vec<TypeGadget> {
        let uint_gadget = TypeGadget::new(
            "u_int".into(),
            "typedef unsigned int u_int".into(),
            TypeClass::Typedef,
            Some(String::from("unsigned int")),
        );
        let uchar_gadgget = TypeGadget::new(
            "u_char".into(),
            "typedef unsigned char u_char".into(),
            TypeClass::Typedef,
            Some(String::from("unsigned char")),
        );
        let ushort_gadget = TypeGadget::new(
            "u_short".into(),
            "typedef unsigned short".into(),
            TypeClass::Typedef,
            Some(String::from("unsigned short")),
        );
        gadgets.push(uint_gadget);
        gadgets.push(uchar_gadgget);
        gadgets.push(ushort_gadget);
        gadgets
    }

    pub fn dump_type_gadgets(gadgets: &Vec<TypeGadget>, deopt: &Deopt) -> Result<()> {
        let dump_file = deopt.get_library_type_gadget_path()?;
        let mut content = Vec::new();
        for gadget in gadgets {
            content.push(gadget.def.clone());
        }
        let contents = content.join("\n\n");
        std::fs::write(&dump_file, contents)?;
        let dump_file = dump_file.with_extension("json");
        let dump_str = serde_json::to_string(gadgets)?;
        std::fs::write(dump_file, dump_str)?;
        Ok(())
    }

    pub fn load_type_gadgets(deopt: &Deopt) -> Result<Vec<TypeGadget>> {
        let dump_file = deopt.get_library_type_gadget_path()?;
        let content = std::fs::read_to_string(dump_file)?;
        let gadgets: Vec<TypeGadget> = serde_json::from_str(&content)?;
        Ok(gadgets)
    }

    fn handle_unamed_typedef(td_node: &Node, record_node: Option<&Node>) -> Option<TypeGadget> {
        if td_node.inner.is_empty() {
            return None;
        }
        let record_node = record_node?;
        if let Clang::TypedefDecl(td) = &td_node.kind {
            let name = td.name.clone().to_string();
            if let Clang::ElaboratedType(et) = &td_node.inner[0].kind {
                if let Some(otd) = &et.owned_tag_decl {
                    if otd.id == record_node.id {
                        let def = if let Clang::RecordDecl(rd) = &record_node.kind {
                            rd.get_definition(record_node)
                        } else if let Clang::CXXRecordDecl(crd) = &record_node.kind {
                            crd.get_definition(record_node)
                        } else {
                            unreachable!()
                        };
                        let def = format!("typedef struct {{\n{def}\n}} {name};");
                        let gadget = TypeGadget::new(name, def, TypeClass::Typedef, None);
                        return Some(gadget);
                    }
                }
            }
        }
        None
    }
}

pub mod func_gadget {
    use std::collections::HashSet;

    use crate::ast::{Clang, Node};
    use crate::execution::Executor;

    use super::FuncGadget;
    use super::*;

    pub fn parse_func_gadgets(deopt: &Deopt) -> Result<Vec<FuncGadget>> {
        let headers = deopt.obtain_library_include_headers()?;
        let mut gadgets = Vec::new();
        for header in headers {
            if let Some(ext) = header.extension() {
                if ext != "h" && ext != "hpp" && ext != "hxx" {
                    continue;
                }
            }
            let ast_res = Executor::parse_header_ast(&header, deopt);
            if let Err(err) = ast_res {
                log::error!("{}", err.to_string());
                log::error!("Meet a error during parse header's ast. Some headers are prevent to be included. IF that is the case, please just ignore it.");
                continue;
            }
            let ast = ast_res.unwrap();
            let header_gadgets: Vec<FuncGadget> = parse_func_gadgets_from_ast(&ast, deopt)?;
            gadgets.extend(header_gadgets);
        }
        let mut visited: HashSet<String> = HashSet::new();
        gadgets.retain(|x| {
            if visited.contains(&x.name) {
                false
            } else {
                visited.insert(x.name.clone());
                true
            }
        });
        Ok(gadgets)
    }

    fn parse_func_gadgets_from_ast(ast: &Node, deopt: &Deopt) -> Result<Vec<FuncGadget>> {
        let mut gadgets = Vec::new();
        for child in ast.inner.iter() {
            if let Clang::LinkageSpecDecl(_) = &child.kind {
                gadgets.extend(parse_func_gadgets_from_ast(child, deopt)?);
            }
            if let Clang::FunctionDecl(fd) = &child.kind {
                let name = fd.get_name();
                log::trace!("parse gadget: {name}");
                if let Some(ban) = &deopt.config.ban {
                    if ban.contains(&name) {
                        continue;
                    }
                }
                let params = fd.get_params(child);
                let alias_ret_type = fd.get_ret_type();
                let ret_type = to_gadget_type(&alias_ret_type)?;
                let mut idents = vec![];
                let mut alias_types = vec![];
                let mut types = vec![];

                for param in params {
                    let ident = param.get_name_as_string();
                    let alias_type = param.get_sized_ty_name(deopt);
                    let ty = to_gadget_type(&alias_type)?;
                    idents.push(ident);
                    alias_types.push(alias_type);
                    types.push(ty);
                }
                let gadget =
                    FuncGadget::new(name, idents, types, alias_types, ret_type, alias_ret_type);
                gadgets.push(gadget);
            }
        }
        Ok(gadgets)
    }

    pub fn dump_func_gadgets(gadgets: &Vec<FuncGadget>, deopt: &Deopt) -> Result<()> {
        let save_path = deopt.get_library_func_gadget_path()?;
        let mut dump_str = String::new();
        dump_str.push_str("Raw Func Gadgets:\n");
        for gadget in gadgets {
            dump_str.push_str(&gadget.gen_raw_type_signature());
            dump_str.push('\n');
        }
        dump_str.push_str("\n\nAlias Func Gadget:\n");
        for gadget in gadgets {
            dump_str.push_str(&gadget.gen_signature());
            dump_str.push('\n');
        }
        std::fs::write(&save_path, dump_str)?;
        let dump_str = serde_json::to_string(gadgets)?;
        let save_path = save_path.with_extension("json");
        std::fs::write(save_path, dump_str)?;
        Ok(())
    }

    pub fn load_func_gadgets(deopt: &Deopt) -> Result<Vec<FuncGadget>> {
        let save_path = deopt.get_library_func_gadget_path()?.with_extension("json");
        let content = std::fs::read_to_string(save_path)?;
        let gadgets: Vec<FuncGadget> = serde_json::from_str(&content)?;
        Ok(gadgets)
    }
}

impl Deserialize for FuncGadget {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("(")?;
        let name = de.parse_string()?;
        // parse arg idents
        de.consume_token_until("arg_idents: [")?;
        let mut arg_idents = vec![];
        while de.peek_char()? == '\"' {
            let ident = de.parse_string()?;
            arg_idents.push(ident.to_owned());
            if de.peek_char()? == ',' {
                de.eat_token(",")?;
            }
        }
        // parse arg types
        de.consume_token_until("arg_types: [")?;
        let mut arg_types = vec![];
        while de.peek_char()? == '\"' {
            let arg_type = de.parse_string()?;
            arg_types.push(arg_type.to_owned());
            if de.peek_char()? == ',' {
                de.eat_token(",")?;
            }
        }
        // parse ret type
        de.consume_token_until("ret_type: ")?;
        let ret_type = if de.is_next_token("Some(") {
            de.eat_token("Some(")?;
            de.parse_string()?
        } else {
            "void"
        };
        // parse alias arg types.
        de.consume_token_until("alias_arg_types: [")?;
        let mut alias_arg_types = vec![];
        while de.peek_char()? == '\"' {
            let arg_type = de.parse_string()?;
            alias_arg_types.push(arg_type.to_owned());
            if de.peek_char()? == ',' {
                de.eat_token(",")?;
            }
        }
        // parse alias ret type
        de.consume_token_until("alias_ret_type: ")?;
        let alias_ret_type = if de.is_next_token("Some(") {
            de.eat_token("Some(")?;
            de.parse_string()?
        } else {
            "void"
        };
        Ok(Self {
            name: name.to_owned(),
            arg_idents,
            arg_types,
            alias_arg_types,
            ret_type: ret_type.to_owned(),
            alias_ret_type: alias_ret_type.to_owned(),
        })
    }
}

impl FuncGadget {
    pub fn new(
        name: String,
        arg_idents: Vec<String>,
        arg_types: Vec<String>,
        alias_arg_types: Vec<String>,
        ret_type: String,
        alias_ret_type: String,
    ) -> Self {
        Self {
            name,
            arg_idents,
            arg_types,
            alias_arg_types,
            ret_type,
            alias_ret_type,
        }
    }

    pub fn get_func_name(&self) -> &str {
        &self.name
    }

    pub fn gen_raw_type_signature(&self) -> String {
        let ret_type = &self.ret_type;
        let name = &self.name;
        let mut args = String::new();
        for (index, ty) in self.arg_types.iter().enumerate() {
            let ident = &self.arg_idents[index];
            let arg = format!("{ty} {ident}");
            args.push_str(&arg);
            if index != self.arg_types.len() - 1 {
                args.push_str(", ");
            }
        }
        let sig = format!("{ret_type} {name}({args})");
        sig
    }

    /// get the function signature.
    pub fn gen_signature(&self) -> String {
        let ret_type = &self.alias_ret_type;
        let name = &self.name;
        let mut args = String::new();
        for (index, ty) in self.alias_arg_types.iter().enumerate() {
            let ident = &self.arg_idents[index];
            let (ty, size) = split_ty_with_size(ty);
            let arg = if let Some(size) = size {
                format!("{ty} {ident}{size}")
            } else {
                format!("{ty} {ident}")
            };
            args.push_str(&arg);
            if index != self.alias_arg_types.len() - 1 {
                args.push_str(", ");
            }
        }
        let sig = format!("{ret_type}{name}({args})");
        sig
    }

    pub fn get_alias_arg_types(&self) -> &Vec<String> {
        &self.alias_arg_types
    }

    pub fn get_alias_ret_type(&self) -> &str {
        &self.alias_ret_type
    }

    pub fn is_fuzzable(&self) -> bool {
        for param in &self.arg_types {
            if is_fuzzable_array_ty(param) {
                return true;
            }
        }
        false
    }

    /// get the fuzzable parameters of this API call. The parameter should be immutable array.
    pub fn get_fuzzable_params(&self) -> Vec<usize> {
        let mut params = Vec::new();
        for (i, param) in self.arg_types.iter().enumerate() {
            if is_fuzzable_array_ty(param) {
                params.push(i);
            }
        }
        params
    }

    pub fn get_array_params_pos(&self) -> Vec<usize> {
        let mut params = Vec::new();
        for (i, param) in self.arg_types.iter().enumerate() {
            if is_array_ty(param) {
                params.push(i);
            }
        }
        params
    }

    /// get the positiions of integer parameters of this API call.
    pub fn get_integer_params_pos(&self) -> Vec<usize> {
        let mut pos = Vec::new();
        for (i, param) in self.arg_types.iter().enumerate() {
            if is_integer_ty(param) {
                pos.push(i);
            }
        }
        pos
    }

    pub fn get_integeral_pointer_pos(&self) -> Vec<usize> {
        let mut pos = Vec::new();
        for (i, param) in self.arg_types.iter().enumerate() {
            if is_integeral_pointer(param) {
                pos.push(i);
            }
        }
        pos
    }

    /// get the positiions of integer parameters of this API call.
    pub fn get_floating_params(&self) -> Vec<usize> {
        let mut pos = Vec::new();
        for (i, param) in self.arg_types.iter().enumerate() {
            if is_floating_ty(param) {
                pos.push(i);
            }
        }
        pos
    }

    pub fn get_canonical_arg_type(&self, arg_pos: usize) -> Option<&String> {
        self.arg_types.get(arg_pos)
    }

    pub fn is_signle_layer_pointer(&self, arg_pos: usize) -> bool {
        let ty = &self.arg_types[arg_pos];
        if let Some(inner) = get_const_pointer_inner(ty) {
            if is_primitive_type(inner) {
                return true;
            }
        }
        false
    }
}

pub mod ctype {

    use regex::Regex;

    use crate::{deopt::Deopt, program::serde::Deserializer};

    use super::{get_type_gadget, TypeClass};

    pub fn to_gadget_type(input: &str) -> eyre::Result<String> {
        let unalias_ty = retrieve_canonical_type(input);
        let mut de = Deserializer::from_input(&unalias_ty);
        let mut is_const = false;
        let mut ty_name = vec![];
        let mut pointer_layers = vec![];

        if unalias_ty.contains("(") || unalias_ty.contains(")") {
            return Ok(format!("FnPointer<{unalias_ty}>"));
        }

        while !de.is_empty() {
            if de.peek_char()? == '*' || de.peek_char()? == '[' {
                if is_const {
                    pointer_layers.push("FuzzConstPointer<".to_string());
                    is_const = false;
                } else {
                    pointer_layers.push("FuzzMutPointer<".to_string());
                }
                if de.peek_char()? == '*' {
                    de.eat_token("*")?;
                } else {
                    de.eat_token("[")?;
                    let size: usize = de.parse_number()?;
                    de.eat_token("]")?;
                    let sized_layer = format!("Sized<{size}>");
                    pointer_layers.push(sized_layer);
                }
                continue;
            }
            if de.is_next_token("const") {
                is_const = true;
                de.eat_token("const")?;
                continue;
            }
            if de.is_next_token("__restrict") {
                de.eat_token("__restrict")?;
                continue;
            }
            let next_token = de.next_token()?;
            ty_name.push(next_token);
        }
        let mut ty_name = ty_name.join(" ");
        for pointer in pointer_layers.iter().rev() {
            ty_name.insert_str(0, pointer);
            if pointer.starts_with("Sized") {
                continue;
            }
            ty_name.push('>');
        }
        Ok(ty_name)
    }

    pub fn is_primitive_type(ty: &str) -> bool {
        static PRIMITVE_TYPS: [&str; 26] = [
            "char",
            "signed char",
            "unsigned char",
            "double",
            "float",
            "int",
            "unsigned int",
            "long",
            "unsigned long",
            "long long",
            "unsigned long long",
            "short",
            "unsigned short",
            "void",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "uint128_t",
            "bool",
            "int8_t",
            "int16_t",
            "size_t",
            "int32_t",
            "int64_t",
            "int128_t",
        ];
        if PRIMITVE_TYPS.contains(&ty) {
            return true;
        }
        false
    }

    pub fn is_floating_ty(ty: &str) -> bool {
        matches!(ty, "float" | "double")
    }

    pub fn is_integer_ty(ty: &str) -> bool {
        matches!(
            ty,
            "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "int"
                | "unsigned int"
                | "short"
                | "long"
                | "unsigned short"
                | "unsigned long"
                | "long long"
                | "unsigned long long"
                | "size_t"
        )
    }

    pub fn is_unsigned_integer_ty(ty: &str) -> bool {
        matches!(
            ty,
            "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "unsigned short"
                | "unsigned int"
                | "unsigned long"
                | "unsigned long long"
        )
    }

    pub fn is_mut_pointer_ty(ty: &str) -> bool {
        ty.starts_with("FuzzMutPointer")
    }

    pub fn is_const_pointer_ty(ty: &str) -> bool {
        ty.starts_with("FuzzConstPointer")
    }

    pub fn is_sized_layer(ty: &str) -> bool {
        ty.starts_with("Sized")
    }

    fn strip_const_pointer(ty: &str) -> &str {
        let ty = ty
            .strip_prefix("FuzzConstPointer<")
            .unwrap_or_else(|| panic!("expect a const pointer, but get: {ty}"));
        ty.strip_suffix('>')
            .unwrap_or_else(|| panic!("const pointer should end with '>', get: {ty}"))
    }

    fn strip_mut_pointer(ty: &str) -> &str {
        let ty = ty
            .strip_prefix("FuzzMutPointer<")
            .unwrap_or_else(|| panic!("expect mut pointer, but get: {ty}"));
        ty.strip_suffix('>')
            .unwrap_or_else(|| panic!("mut pointer should end with '>', but get: {ty}"))
    }

    fn strip_sized_layer(ty: &str) -> &str {
        let ty = ty
            .strip_prefix("Sized<")
            .unwrap_or_else(|| panic!("expect a sized layer, but get: {ty}"));
        let idx = ty
            .find('>')
            .unwrap_or_else(|| panic!("sized layer should contain a '>', but get: {ty}"));
        &ty[idx + 1..]
    }

    pub fn is_array_ty(ty: &str) -> bool {
        if is_const_pointer_ty(ty) || is_mut_pointer_ty(ty) {
            return true;
        }
        false
    }

    pub fn is_sized_array_ty(ty: &str) -> bool {
        if let Some(inner) = get_sized_pointer_inner(ty) {
            return is_sized_layer(inner);
        }
        false
    }

    pub fn is_integeral_pointer(ty: &str) -> bool {
        if let Some(inner) = get_pointer_inner(ty) {
            if is_integer_ty(inner) {
                return true;
            }
        }
        false
    }

    /// Whether this ty is array and is able to receive fuzzer's mutable bytes (considered as fuzzable).
    /// 1. must be const qualified array.
    /// 2. the array elements must be primitive types.
    pub fn is_fuzzable_array_ty(ty: &str) -> bool {
        if is_const_pointer_ty(ty) {
            let inner = get_pointer_inner(ty).expect("expect not fail.");
            if is_primitive_type(inner) {
                return true;
            }
            if !is_const_pointer_ty(inner) {
                return false;
            }
            // only consider a maximal depth of 2.
            let inner = get_pointer_inner(inner).expect("expect not fail.");
            if is_primitive_type(inner) {
                return true;
            }
        }
        false
    }

    fn get_integer_ty_identifier(ty: &str) -> &str {
        match ty {
            "uint8_t" => "UINT8",
            "uint16_t" | "unsigned short" => "UINT16",
            "uint32_t" | "unsigned int" => "UINT32",
            "uint64_t" | "unsigned long" | "unsigned long long" | "size_t" => "UINT64",
            "int8_t" => "INT8",
            "int16_t" | "short" => "INT16",
            "int32_t" | "int" => "INT32",
            "int64_t" | "long" | "long long" => "INT64",
            _ => unreachable!(),
        }
    }

    pub fn get_integer_ty_max(ty: &str) -> String {
        let identifier = get_integer_ty_identifier(ty);
        [identifier, "_MAX"].concat()
    }

    pub fn get_integer_ty_min(ty: &str) -> String {
        let identifier = get_integer_ty_identifier(ty);
        if identifier.starts_with('U') {
            String::from("0")
        } else {
            [identifier, "_MIN"].concat()
        }
    }

    /// get pointer' inner, but retain the sized layer.
    pub fn get_sized_pointer_inner(ty: &str) -> Option<&str> {
        if is_const_pointer_ty(ty) {
            Some(strip_const_pointer(ty))
        } else if is_mut_pointer_ty(ty) {
            Some(strip_mut_pointer(ty))
        } else {
            None
        }
    }

    /// get pointer's inner with sized layer stripped
    pub fn get_pointer_inner(ty: &str) -> Option<&str> {
        if let Some(inner) = get_sized_pointer_inner(ty) {
            if is_sized_layer(inner) {
                return Some(strip_sized_layer(inner));
            }
            return Some(inner);
        }
        None
    }

    pub fn get_const_pointer_inner(ty: &str) -> Option<&str> {
        if is_const_pointer_ty(ty) {
            return get_pointer_inner(ty);
        }
        None
    }

    /// Strip all sugars or qualifiers in type declaration. e.g, const aom_codec_iter_t ** => aom_codec_iter_t
    pub fn get_unsugared_unqualified_type(c_type: &str) -> String {
        let re = Regex::new(r"\b(const|volatile|restrict|struct|enum|__restrict)\b").unwrap();
        let output_str = re.replace_all(c_type, "").to_string();
        let re = Regex::new(r"\[\d+\]").unwrap();
        let output_str = re.replace_all(&output_str, "").to_string();
        let stripped_type = output_str.replace('*', "").trim().to_string();
        stripped_type
    }

    /// Recover the canonical type for a human wrappered type.
    pub fn retrieve_canonical_type(ty: &str) -> String {
        let mut full_type = String::from(ty);
        let mut ty_name = get_unsugared_unqualified_type(ty);
        while let Some(ty_gadget) = get_type_gadget(&ty_name) {
            if matches!(&ty_gadget.class, TypeClass::Typedef) {
                if let Some(underly_ty) = &ty_gadget.underly_ty {
                    let re = Regex::new(&format!(r"\b{ty_name}\b")).unwrap();
                    full_type = re.replace(&full_type, underly_ty).to_string();
                    ty_name = get_unsugared_unqualified_type(underly_ty);
                    continue;
                }
            }
            break;
        }
        full_type
    }

    pub fn split_ty_with_size(ty: &str) -> (&str, Option<&str>) {
        if let Some(size_start) = ty.find('[') {
            return (&ty[..size_start], Some(&ty[size_start..]));
        }
        (ty, None)
    }

    pub fn get_exact_value_of_macro(
        deopt: &Deopt,
        macro_name: &str,
    ) -> eyre::Result<Option<usize>> {
        let header_path = deopt.get_library_build_header_path()?;
        let re = Regex::new(&format!(r"#define\s+{macro_name}\s+(\d+)\s+"))?;
        for entry in std::fs::read_dir(header_path)? {
            let entry = entry?.path();
            if entry.extension().is_some() && entry.extension().unwrap() == "h" {
                let content = std::fs::read_to_string(entry)?;
                if let Some(capture) = re.captures(&content) {
                    if let Some(value) = capture.get(1) {
                        return Ok(Some(value.as_str().parse::<usize>()?));
                    }
                }
            }
        }
        Ok(None)
    }
}

pub fn is_library_api(func: &str) -> bool {
    get_func_gadget(func).is_some()
}

pub fn get_func_gadget(func: &str) -> Option<&'static FuncGadget> {
    get_func_gadgets().iter().find(|x| x.name == func)
}

pub fn dump_func_gadgets_tostr() -> String {
    let gadgets = get_func_gadgets();
    let gadgets = random_sample(gadgets, crate::config::MAX_CONTEXT_APIS);
    let mut dump_str = vec![];
    for gadget in gadgets {
        dump_str.push(gadget.gen_signature());
    }
    dump_str.join("\n")
}

/// Get the functions with their fuzzable parameters.
/// Returned with the map of Function names and vectors of fuzzable parameters' positions.
pub fn get_fuzzable_funcs() -> &'static HashMap<String, Vec<usize>> {
    static FUNCS: OnceCell<HashMap<String, Vec<usize>>> = OnceCell::new();
    FUNCS.get_or_init(|| {
        let mut funcs: HashMap<String, Vec<usize>> = HashMap::new();
        for gadget in get_func_gadgets() {
            let name = gadget.name.clone();
            let param_pos = gadget.get_fuzzable_params();
            funcs.insert(name, param_pos);
        }
        funcs
    })
}

#[cfg(test)]
mod tests {
    use super::{typed_gadget::parse_type_gadgets, *};
    use crate::config::Config;

    #[test]
    fn test_fuzzable_funcs() {
        Config::init_test("c-ares");
        let funcs = get_fuzzable_funcs();
        println!("{funcs:?}");
    }

    #[test]
    fn test_parse_func_gadgets() -> Result<()> {
        crate::config::Config::init_test("libavc");
        let gadgets = get_func_gadgets();
        for gadget in gadgets {
            println!("{}", gadget.gen_signature())
        }
        Ok(())
    }

    #[test]
    fn test_parse_type_gadgets() -> Result<()> {
        crate::config::Config::init_test("curl");
        let deopt = Deopt::new("curl".to_string())?;
        let gadgets = parse_type_gadgets(&deopt)?;
        for gadget in gadgets {
            println!("{}", gadget.def)
        }
        Ok(())
    }

    #[test]
    fn test_recover_canonical_type() -> Result<()> {
        crate::config::Config::init_test("libpng");
        let ty = "png_const_structrp";
        let unalias_ty = retrieve_canonical_type(ty);
        assert_eq!(unalias_ty, "const struct png_struct_def *__restrict");

        let ty = "png_const_inforp";
        let unalias_ty = retrieve_canonical_type(ty);
        assert_eq!(unalias_ty, "const struct png_info_def *__restrict");
        Ok(())
    }

    #[test]
    fn test_recover_canonical_type_lcms() -> Result<()> {
        crate::config::Config::init_test("lcms");
        let ty = "cmsHPROFILE";
        let unalias_ty = retrieve_canonical_type(ty);
        println!("{unalias_ty}");
        Ok(())
    }

    #[test]
    fn test_to_gagdet_type() -> Result<()> {
        crate::config::Config::init_test("libpng");
        let test_ty = "const char **";
        let gty = to_gadget_type(test_ty)?;
        assert_eq!("FuzzConstPointer<FuzzMutPointer<char>>", gty);

        let test_ty = "const char * const *";
        let gty = to_gadget_type(test_ty)?;
        assert_eq!("FuzzConstPointer<FuzzConstPointer<char>>", gty);

        let ty = "png_const_structrp";
        let gty = to_gadget_type(ty)?;
        assert_eq!(gty, "FuzzConstPointer<struct png_struct_def>");

        let ty = "png_error_ptr";
        let gty = to_gadget_type(ty)?;
        assert_eq!(gty, "FnPointer<void (*)(png_structp, png_const_charp)>");

        Ok(())
    }
}
