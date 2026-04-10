use crate::{
    analysis::{dfa::VarName, WorkList},
    program::gadget::ctype::get_exact_value_of_macro,
};
use clang_ast::{Id, Kind, SourceLocation, SourceRange};
use serde::Deserialize;

use super::*;

#[derive(Deserialize, Debug, Clone)]
pub struct FunctionDecl {
    pub name: Option<String>,
    #[serde(default)]
    pub loc: SourceLocation,
    #[serde(default)]
    pub range: SourceRange,
    pub r#type: Type,
}

impl FunctionDecl {
    pub fn get_name(&self) -> String {
        self.name.clone().unwrap_or_default()
    }

    pub fn get_type(&self) -> Type {
        self.r#type.clone()
    }

    pub fn has_params(&self, node: &Node) -> bool {
        if node.inner.is_empty() {
            return false;
        }
        let first_child = &node.inner[0];
        if let Clang::ParmVarDecl(_) = &first_child.kind {
            return true;
        }
        false
    }

    pub fn get_params<'a>(&self, node: &'a Node) -> Vec<&'a ParmVarDecl> {
        let mut params = Vec::new();
        for child in &node.inner {
            if let Clang::ParmVarDecl(pvd) = &child.kind {
                params.push(pvd);
            }
        }
        params
    }

    pub fn get_ret_type(&self) -> String {
        let ret_ty_str = if let Some(ty) = self.r#type.get_desugared_type() {
            ty
        } else {
            self.r#type.get_type_name()
        };
        let idx = ret_ty_str.find('(').unwrap();
        ret_ty_str[..idx].to_string()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct VarDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    name: Option<Box<str>>,
    r#type: Type,
    #[serde(default)]
    _init: InitStyle,
}

impl<'a> VarDecl {
    pub fn get_name(&self, node: &Node) -> VarName {
        VarName::new(self.get_name_as_string(), node.id)
    }

    pub fn get_name_as_string(&self) -> String {
        self.name
            .clone()
            .unwrap_or("dummy_var".into())
            .into_string().trim().to_string()
    }

    pub fn get_type(&self) -> Type {
        self.r#type.clone()
    }

    pub fn has_init(&self, node: &Node) -> bool {
        !node.inner.is_empty()
    }

    pub fn get_init(&self, node: &'a Node) -> &'a Node {
        assert!(self.has_init(node));
        assert_eq!(node.inner.len(), 1);
        node.inner.first().unwrap()
    }

    /// get the var declaration of this var, e.g., const char* name.
    pub fn get_var_decl_name(&self) -> String {
        let mut ty = self.get_type().get_type_name();
        let name = self.get_name_as_string();
        if let Some(pos) = ty.find('[') {
            ty.insert(pos, ' ');
            ty.insert_str(pos + 1, &name);
            return ty;
        }
        ty.push(' ');
        ty.push_str(&name);
        ty
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct QualType {
    pub r#type: Type,
    pub qualifiers: Box<str>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CallExpr {
    pub range: SourceRange,
    pub r#type: Type,
}

impl CallExpr {
    pub fn get_name_as_string(&self, node: &Node) -> String {
        assert!(!node.inner.is_empty());
        let fd = node.inner.first().unwrap().ignore_cast();
        if let Clang::DeclRefExpr(dre) = &fd.kind {
            return dre.get_name_as_string();
        }
        String::from("FunctionPointers")
    }

    pub fn get_type(&self) -> Type {
        self.r#type.clone()
    }

    pub fn get_childs<'a>(&self, node: &'a Node) -> Vec<&'a Node> {
        assert!(!node.inner.is_empty());
        let mut childs = vec![];
        for child in node.inner[1..].iter() {
            if let Clang::BinaryOperator(bo) = &child.kind {
                if bo.is_assignment() {
                    childs.push(bo.get_rhs(child));
                } else {
                    childs.push(child)
                }
            } else {
                childs.push(child.ignore_cast().ignore_parent());
            }
        }
        childs
    }

    pub fn get_childs_no_ignore<'a>(&self, node: &'a Node) -> Vec<&'a Node> {
        assert!(!node.inner.is_empty());
        let mut childs = vec![];
        for child in node.inner[1..].iter() {
            if let Clang::BinaryOperator(bo) = &child.kind {
                if bo.is_assignment() {
                    childs.push(bo.get_rhs(child));
                } else {
                    childs.push(child);
                }
            } else {
                childs.push(child);
            }
        }
        childs
    }

    pub fn get_souce_line(&self) -> usize {
        if let Some(loc) = &self.range.begin.expansion_loc {
            loc.line
        } else {
            0
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ImplicitCastExpr {
    pub range: SourceRange,
    pub r#type: Type,
    //#[serde(rename = "castKind")]
    //pub cast_kind: CastKind,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CStyleCastExpr {
    pub range: SourceRange,
    pub r#type: Type,
    //#[serde(rename = "castKind")]
    //pub cast_kind: CastKind,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeclRefExpr {
    pub range: SourceRange,
    pub r#type: Type,
    #[serde(rename = "referencedDecl")]
    pub referenced_decl: Decl,
    #[serde(rename = "foundReferencedDecl")]
    pub found_referenced_decl: Option<Decl>,
}

impl DeclRefExpr {
    pub fn get_name_as_string(&self) -> String {
        self.referenced_decl.get_name_as_string()
    }

    pub fn get_type_name(&self) -> String {
        self.r#type.get_type_name()
    }

    pub fn get_var_decl<'a>(&self, visitor: &'a Visitor) -> Option<&'a VarDecl> {
        let var_name = self.get_name_as_string();
        if let Some(var) = visitor.find_vardecl(&var_name) {
            if let Clang::VarDecl(vd) = &var.kind {
                return Some(vd);
            }
        }
        None
    }

    pub fn get_var_init<'a>(&self, visitor: &'a Visitor) -> Option<&'a Node> {
        let var_name = self.get_name_as_string();
        if let Some(var) = visitor.find_vardecl(&var_name) {
            if let Clang::VarDecl(vd) = &var.kind {
                if !vd.has_init(var) {
                    return None;
                }
                let init = vd.get_init(var).ignore_parent().ignore_cast();
                return Some(init);
            }
        }
        None
    }

    // if this variable is initialized by a call, return this call.
    pub fn get_var_init_call<'a>(&self, visitor: &'a Visitor) -> Option<&'a Node> {
        if let Some(init) = self.get_var_init(visitor) {
            let init = init.ignore_parent().ignore_cast();
            if matches!(&init.kind, Clang::CallExpr(_) | Clang::CXXNewExpr(_)) {
                return Some(init);
            }
        }
        let var_name = self.get_name_as_string();
        if let Some(bo_right) = visitor.find_binary_operator(&var_name) {
            let init = bo_right.ignore_parent().ignore_cast();
            if matches!(&init.kind, Clang::CallExpr(_)) {
                return Some(init);
            }
        }
        None
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct StringLiteral {
    pub range: SourceRange,
    pub r#type: Type,
    pub value: Box<str>,
}

fn unescape_string(s: &str) -> Option<String> {
    let mut res = String::new();
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(delim) => match delim {
                    '"' => res.push('"'),
                    '\\' => res.push('\\'),
                    '/' => res.push('/'),
                    'b' => res.push('\x08'),
                    'f' => res.push('\x0c'),
                    'n' => res.push('\n'),
                    'r' => res.push('\r'),
                    't' => res.push('\t'),
                    'u' => {
                        let codepoint = chars
                            .by_ref()
                            .take(4)
                            .collect::<String>()
                            .parse::<u32>()
                            .ok()?;
                        match std::char::from_u32(codepoint) {
                            Some(c) => res.push(c),
                            None => return None, // invalid unicode codepoint
                        }
                    }
                    _ => return None,
                },
                None => return None,
            }
        } else {
            res.push(ch);
        }
    }
    Some(res)
}

impl StringLiteral {
    pub fn get_value(&self) -> String {
        self.value.to_string()
    }

    pub fn get_eval_value(&self) -> String {
        let value = self.get_value();
        let value =
            unescape_string(&value).unwrap_or_else(|| panic!("invalid escape string: {value}"));
        if let Some(value) = value.strip_prefix('\"') {
            if let Some(value) = value.strip_suffix('\"') {
                return value.to_string();
            }
            return value.to_string();
        }
        value.to_string()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CharacterLiteral {
    pub range: SourceRange,
    pub r#type: Type,
    pub value: u32,
}

impl CharacterLiteral {
    pub fn get_value<T: std::str::FromStr>(&self) -> eyre::Result<T>
    where
        <T as std::str::FromStr>::Err: std::fmt::Debug,
    {
        let value: T = self.value.to_string().parse::<T>().unwrap();
        Ok(value)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct FloatingLiteral {
    pub range: SourceRange,
    pub r#type: Type,
    pub value: Box<str>,
}

impl FloatingLiteral {
    pub fn get_value<T: std::str::FromStr>(&self) -> eyre::Result<T>
    where
        <T as std::str::FromStr>::Err: std::fmt::Debug,
    {
        let value: T = self.value.parse::<T>().unwrap();
        Ok(value)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct IntegerLiteral {
    pub range: SourceRange,
    pub r#type: Type,
    pub value: Box<str>,
}

impl IntegerLiteral {
    pub fn get_value<T: std::str::FromStr + Default>(&self) -> eyre::Result<T> {
        let value: T = self.value.parse::<T>().unwrap_or_default();
        Ok(value)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct GotoStmt {
    #[serde(rename = "targetLabelDeclId")]
    pub target_label_decl_id: Id,
}

#[derive(Deserialize, Debug, Clone)]
pub struct IfStmt {
    pub range: SourceRange,
    #[serde(rename = "hasInit", default)]
    pub has_init: bool,
    #[serde(rename = "hasVar", default)]
    pub has_var: bool,
    #[serde(rename = "hasElse", default)]
    pub has_else: bool,
    #[serde(rename = "isConstexpr", default)]
    pub is_constexpr: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ParmVarDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    pub name: Option<Box<str>>,
    pub r#type: Type,
}

impl ParmVarDecl {
    pub fn get_name(&self, node: &Node) -> VarName {
        VarName::new(self.get_name_as_string(), node.id)
    }

    pub fn get_name_as_string(&self) -> String {
        self.name.clone().unwrap_or("".into()).into_string()
    }

    pub fn get_type(&self) -> Type {
        self.r#type.clone()
    }

    /// get the ty name with sized constraint: const int[size].
    pub fn get_sized_ty_name(&self, deopt: &crate::deopt::Deopt) -> String {
        let raw_ty = self.get_type().get_type_name();
        if !raw_ty.contains('*') {
            return raw_ty;
        }
        let src_content = loc::get_header_code_content(&self.range);
        if src_content.is_err() {
            return raw_ty;
        }
        let src_content = src_content.unwrap();
        let sized_ty = if let Some(left) = src_content.find('[') {
            if let Some(right) = src_content.find(']') {
                &src_content[left + 1..right]
            } else {
                return raw_ty;
            }
        } else {
            return raw_ty;
        };

        if sized_ty.is_empty() {
            return raw_ty;
        }
        if let Some(size) = Self::get_number(sized_ty) {
            let raw_ty = raw_ty.trim_end_matches('*');
            let raw_ty = raw_ty.trim_end();
            let sized_ty: String = [raw_ty, "[", &size.to_string(), "]"].concat();
            return sized_ty;
        } else if let Ok(Some(value)) = get_exact_value_of_macro(deopt, sized_ty) {
            let raw_ty = raw_ty.trim_end_matches('*');
            let raw_ty = raw_ty.trim_end();
            let sized_ty: String = [raw_ty, "[", &value.to_string(), "]"].concat();
            return sized_ty;
        }
        unreachable!("Meet a sized ParamDecl but fail to get its exact value, please ban this function. Extracted src_content: {src_content}, ty: {raw_ty}, range: {0:#?}", self.range)
    }

    fn get_number(s: &str) -> Option<usize> {
        if let Ok(value) = s.parse::<usize>() {
            return Some(value);
        }
        None
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct PointerType {
    pub r#type: Type,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RecordDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    pub name: Option<Box<str>>,
    #[serde(rename = "previousDecl")]
    pub previous_decl: Option<Id>,
    #[serde(rename = "completeDefinition", default)]
    pub complete_definition: bool,
    #[serde(rename = "tagUsed")]
    pub tag_used: TagTypeKind,
}

impl RecordDecl {
    pub fn get_name(&self) -> Option<String> {
        if let Some(name) = &self.name {
            return Some(name.to_string());
        }
        None
    }

    pub fn get_definition(&self, node: &Node) -> String {
        let mut fields = vec![];
        let mut nested_record = None;
        for child in node.inner.iter() {
            if let Clang::FieldDecl(fd) = &child.kind {
                let name = fd.get_name();
                let ty = fd.r#type.get_type_name();
                if ty.contains("(unnamed") {
                    if let Some(nested) = &nested_record {
                        let field = format!("{nested} {name};");
                        fields.push(field);
                        continue;
                    }
                }
                let field = format!("\t{ty} {name}");
                fields.push(field);
            }
            if let Clang::RecordDecl(crd) = &child.kind {
                if !crd.complete_definition {
                    continue;
                }
                let raw_def = crd.get_definition(child);
                let mut def = String::new();
                for line in raw_def.lines() {
                    def.push('\t');
                    def.push_str(line);
                    def.push('\n');
                }
                def.pop();
                if let Some(name) = crd.get_name() {
                    let field = if let TagTypeKind::Union = &crd.tag_used {
                        format!("\tunion {name} {{\n{def}\n\t}}")
                    } else if let TagTypeKind::Struct = &crd.tag_used {
                        format!("\tstruct {name} {{\n{def}\n\t}}")
                    } else {
                        unreachable!("{child:#?}")
                    };
                    fields.push(field);
                    nested_record = None;
                } else {
                    let field = if let TagTypeKind::Union = &crd.tag_used {
                        format!("\tunion {{\n{def}\n\t}}")
                    } else if let TagTypeKind::Struct = &crd.tag_used {
                        format!("\tstruct {{\n{def}\n\t}}")
                    } else {
                        unreachable!("{child:#?}")
                    };
                    nested_record = Some(field);
                }
            }
        }
        let mut fields = fields.join(";\n");
        fields.push(';');
        fields
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct RecordType {
    pub r#type: Type,
    pub decl: Decl,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BinaryOperator {
    pub range: SourceRange,
    pub r#type: Type,
    pub opcode: BinaryOpcode,
}

impl<'a> BinaryOperator {
    pub fn is_assignment(&self) -> bool {
        self.opcode == BinaryOpcode::Assign
    }

    pub fn is_compound_assignment(&self) -> bool {
        matches!(
            &self.opcode,
            BinaryOpcode::MulAssign
                | BinaryOpcode::DivAssign
                | BinaryOpcode::RemAssign
                | BinaryOpcode::AddAssign
                | BinaryOpcode::SubAssign
                | BinaryOpcode::ShlAssign
                | BinaryOpcode::ShrAssign
                | BinaryOpcode::AndAssign
                | BinaryOpcode::XorAssign
                | BinaryOpcode::OrAssign
        )
    }

    pub fn is_relation_op(&self) -> bool {
        matches!(&self.opcode, BinaryOpcode::PtrMemD | BinaryOpcode::PtrMemI)
    }

    pub fn is_arithmetic_op(&self) -> bool {
        matches!(
            &self.opcode,
            BinaryOpcode::Mul
                | BinaryOpcode::Div
                | BinaryOpcode::Rem
                | BinaryOpcode::Add
                | BinaryOpcode::Sub
        )
    }

    pub fn is_logic_op(&self) -> bool {
        matches!(
            &self.opcode,
            BinaryOpcode::Cmp
                | BinaryOpcode::LT
                | BinaryOpcode::GT
                | BinaryOpcode::LE
                | BinaryOpcode::GE
                | BinaryOpcode::EQ
                | BinaryOpcode::NE
        )
    }

    pub fn is_bitwise_op(&self) -> bool {
        matches!(
            &self.opcode,
            BinaryOpcode::Shl
                | BinaryOpcode::Shr
                | BinaryOpcode::And
                | BinaryOpcode::Xor
                | BinaryOpcode::Or
                | BinaryOpcode::LAnd
                | BinaryOpcode::LOr
        )
    }

    pub fn get_lhs(&self, node: &'a Node) -> &'a Node {
        node.inner.first().unwrap()
    }

    pub fn get_rhs(&self, node: &'a Node) -> &'a Node {
        node.inner.get(1).unwrap()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct UnaryOperator {
    pub range: SourceRange,
    pub r#type: Type,
    #[serde(rename = "isPostfix")]
    pub is_postfix: bool,
    pub opcode: UnaryOpcode,
}

impl UnaryOperator {
    pub fn is_minus(&self) -> bool {
        matches!(self.opcode, UnaryOpcode::Minus)
    }

    pub fn is_addrof(&self) -> bool {
        matches!(self.opcode, UnaryOpcode::AddrOf)
    }

    pub fn get_inner<'a>(&self, node: &'a Node) -> &'a Node {
        &node.inner[0]
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeclStmt {
    pub range: SourceRange,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ReturnStmt {
    pub range: SourceRange,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ArraySubscriptExpr {
    pub r#type: Type,
}

impl<'a> ArraySubscriptExpr {
    pub fn get_lhs(&self, node: &'a Node) -> &'a Node {
        node.inner.first().unwrap()
    }

    pub fn get_rhs(&self, node: &'a Node) -> &'a Node {
        node.inner.get(1).unwrap()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CompoundStmt {
    pub range: SourceRange,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ParenExpr {
    pub r#type: Type,
    pub range: SourceRange,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LabelStmt {
    pub name: Box<str>,
    #[serde(rename = "declId")]
    pub decl_id: Id,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MemberExpr {
    pub r#type: Type,
    pub name: Box<str>,
    #[serde(rename = "isArrow")]
    pub is_arrow: bool,
    #[serde(rename = "referencedMemberDecl")]
    pub referenced_member_decl: Id,
}

impl MemberExpr {
    pub fn get_name_as_string(&self) -> String {
        self.name.clone().into_string()
    }

    pub fn get_base_expr<'a>(&self, node: &'a Node) -> &'a Node {
        node.inner[0].ignore_cast().ignore_parent()
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct InitListExpr {
    pub r#type: Type,
    #[serde(default)]
    pub array_filler: Vec<Node>,
    pub field: Option<Decl>,
    pub range: SourceRange,
}

impl InitListExpr {
    pub fn get_type(&self) -> Type {
        self.r#type.clone()
    }

    pub fn get_decl_name(&self, var_name: &str) -> String {
        let mut ty = self.get_type().get_type_name();
        if let Some(pos) = ty.find('[') {
            ty.insert(pos, ' ');
            ty.insert_str(pos + 1, var_name);
            return ty;
        }
        ty.push(' ');
        ty.push_str(var_name);
        ty
    }

    pub fn get_len(&self) -> usize {
        self.array_filler.len()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct UnaryExprOrTypeTraitExpr {
    pub range: SourceRange,
    pub name: Box<str>,
    #[serde(rename = "argType")]
    pub arg_type: Option<Type>,
}

impl UnaryExprOrTypeTraitExpr {
    pub fn is_sizeof(&self) -> bool {
        self.name == "sizeof".into()
    }

    pub fn get_dre_child_name(&self, node: &Node) -> Option<String> {
        let mut worklist = WorkList::new();
        worklist.push(node);
        while !worklist.empty() {
            let cur_node = worklist.pop();
            if let Clang::DeclRefExpr(dre) = &cur_node.kind {
                return Some(dre.get_name_as_string());
            }
            for child in cur_node.get_childs() {
                worklist.push(child);
            }
        }
        None
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CXXNullPtrLiteralExpr {
    pub range: SourceRange,
    pub r#type: Type,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CXXConstructExpr {
    pub range: SourceRange,
    pub r#type: Type,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GNUNullExpr {
    pub range: SourceRange,
    pub r#type: Type,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CXXNewExpr {
    pub range: SourceRange,
    pub r#type: Type,
    #[serde(rename = "isArray", default)]
    pub is_array: bool,
}

impl CXXNewExpr {
    pub fn get_new_size_var<'a>(&self, node: &'a Node) -> Option<&'a Node> {
        if !self.is_array {
            return None;
        }
        if node.inner.len() != 1 {
            return None;
        }
        let inner = node.inner[0].ignore_parent().ignore_cast();
        Some(inner)
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Type {
    #[serde(rename = "qualType")]
    pub qual_type: Box<str>,
    #[serde(rename = "desugaredQualType")]
    pub desugared_qual_type: Option<Box<str>>,
    #[serde(rename = "typeAliasDeclId")]
    pub type_alias_decl_id: Option<Id>,
}

impl Type {
    pub fn get_type_name(&self) -> String {
        self.qual_type.to_string()
    }

    pub fn get_unqualified_type(&self) -> String {
        let ty = self.get_type_name();
        let ty = if ty.starts_with("const ") {
            ty.strip_prefix("const ").unwrap()
        } else {
            &ty
        };
        ty.to_string()
    }

    pub fn get_desugared_type(&self) -> Option<String> {
        if let Some(ty) = &self.desugared_qual_type {
            return Some(ty.to_string());
        }
        None
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Decl {
    pub id: Id,
    #[serde(default)]
    pub kind: Kind,
    pub name: Option<Box<str>>,
    pub r#type: Option<Type>,
}

impl Decl {
    pub fn get_name_as_string(&self) -> String {
        self.name
            .clone()
            .unwrap_or("dummy_name".into())
            .into_string()
    }
}

#[derive(Deserialize, Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum InitStyle {
    #[serde(skip_deserializing)]
    #[default]
    NoInit,
    #[serde(rename = "c")]
    CInit,
    #[serde(rename = "call")]
    CallInit,
    #[serde(rename = "list")]
    ListInit,
}

#[derive(Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
pub enum BinaryOpcode {
    #[serde(rename = ".*")]
    PtrMemD,
    #[serde(rename = "->*")]
    PtrMemI,
    #[serde(rename = "*")]
    Mul,
    #[serde(rename = "/")]
    Div,
    #[serde(rename = "%")]
    Rem,
    #[serde(rename = "+")]
    Add,
    #[serde(rename = "-")]
    Sub,
    #[serde(rename = "<<")]
    Shl,
    #[serde(rename = ">>")]
    Shr,
    #[serde(rename = "<=>")]
    Cmp,
    #[serde(rename = "<")]
    LT,
    #[serde(rename = ">")]
    GT,
    #[serde(rename = "<=")]
    LE,
    #[serde(rename = ">=")]
    GE,
    #[serde(rename = "==")]
    EQ,
    #[serde(rename = "!=")]
    NE,
    #[serde(rename = "&")]
    And,
    #[serde(rename = "^")]
    Xor,
    #[serde(rename = "|")]
    Or,
    #[serde(rename = "&&")]
    LAnd,
    #[serde(rename = "||")]
    LOr,
    #[serde(rename = "=")]
    Assign,
    #[serde(rename = "*=")]
    MulAssign,
    #[serde(rename = "/=")]
    DivAssign,
    #[serde(rename = "%=")]
    RemAssign,
    #[serde(rename = "+=")]
    AddAssign,
    #[serde(rename = "-=")]
    SubAssign,
    #[serde(rename = "<<=")]
    ShlAssign,
    #[serde(rename = ">>=")]
    ShrAssign,
    #[serde(rename = "&=")]
    AndAssign,
    #[serde(rename = "^=")]
    XorAssign,
    #[serde(rename = "|=")]
    OrAssign,
    #[serde(rename = ",")]
    Comma,
}

#[derive(Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
pub enum UnaryOpcode {
    #[serde(rename = "++")]
    Inc,
    #[serde(rename = "--")]
    Dec,
    #[serde(rename = "&")]
    AddrOf,
    #[serde(rename = "*")]
    Deref,
    #[serde(rename = "+")]
    Plus,
    #[serde(rename = "-")]
    Minus,
    #[serde(rename = "~")]
    Not,
    #[serde(rename = "!")]
    LNot,
    #[serde(rename = "__real")]
    Real,
    #[serde(rename = "__imag")]
    Imag,
    #[serde(rename = "__extension__")]
    Extension,
    #[serde(rename = "co_await")]
    Coawait,
}

/// Type definition
#[derive(Deserialize, Debug, Clone)]
pub struct TypedefDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    #[serde(rename = "isImplicit", default)]
    pub is_implicit: bool,
    #[serde(rename = "isReferenced", default)]
    pub is_referenced: bool,
    #[serde(rename = "previousDecl")]
    pub previous_decl: Option<Id>,
    pub name: Box<str>,
    pub r#type: Type,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EnumDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    #[serde(rename = "isReferenced", default)]
    pub is_referenced: bool,
    #[serde(rename = "previousDecl")]
    pub previous_decl: Option<Id>,
    pub name: Option<Box<str>>,
}

impl EnumDecl {
    pub fn get_definition(&self, node: &Node) -> String {
        let mut fields = vec![];
        for child in node.inner.iter() {
            if let Clang::EnumConstantDecl(ecd) = &child.kind {
                let mut field = ecd.get_name();
                field.insert(0, '\t');
                if let Some(value) = ecd.get_const_value(child) {
                    field.push_str(&format!(" = {value}"));
                }
                fields.push(field);
            }
        }
        fields.join(",\n")
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct EnumConstantDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    pub name: Box<str>,
    pub r#type: Type,
}

impl EnumConstantDecl {
    pub fn get_name(&self) -> String {
        self.name.clone().into_string()
    }

    pub fn get_const_value(&self, node: &Node) -> Option<i32> {
        if let Some(child) = node.inner.first() {
            if let Clang::ConstantExpr(ce) = &child.kind {
                return Some(ce.parse_int());
            }
        }
        None
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConstantExpr {
    pub range: SourceRange,
    pub r#type: Type,
    pub value: Box<str>,
}

impl ConstantExpr {
    pub fn parse_int(&self) -> i32 {
        self.value
            .parse()
            .unwrap_or_else(|_| panic!("fail to parse int from : {self:#?}"))
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct FieldDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    pub name: Option<Box<str>>,
    pub r#type: Type,
}

impl FieldDecl {
    pub fn get_name(&self) -> String {
        if let Some(name) = &self.name {
            name.clone().into_string()
        } else {
            String::from("Dummy")
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct LinkageSpecDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CXXRecordDecl {
    pub loc: SourceLocation,
    pub range: SourceRange,
    #[serde(rename = "isReferenced", default)]
    pub is_referenced: bool,
    pub name: Option<Box<str>>,
    #[serde(rename = "tagUsed")]
    pub tag_used: TagTypeKind,
    #[serde(rename = "completeDefinition", default)]
    pub complete_definition: bool,
}

#[derive(Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
pub enum TagTypeKind {
    #[serde(rename = "struct")]
    Struct,
    #[serde(rename = "union")]
    Union,
    #[serde(rename = "class")]
    Class,
    #[serde(rename = "enum")]
    Enum,
}

impl CXXRecordDecl {
    pub fn get_name(&self) -> Option<String> {
        if let Some(name) = &self.name {
            return Some(name.to_string());
        }
        None
    }

    pub fn get_definition(&self, node: &Node) -> String {
        let mut fields = vec![];
        let mut nested_record = None;
        for child in node.inner.iter() {
            if let Clang::FieldDecl(fd) = &child.kind {
                let name = fd.get_name();
                let ty = fd.r#type.get_type_name();
                if ty.contains("(unnamed") {
                    if let Some(nested) = &nested_record {
                        let field = format!("{nested} {name}");
                        fields.push(field);
                        continue;
                    }
                }
                let field = format!("\t{ty} {name}");
                fields.push(field);
            }
            if let Clang::CXXRecordDecl(crd) = &child.kind {
                if !crd.complete_definition {
                    continue;
                }
                let raw_def = crd.get_definition(child);
                let mut def = String::new();
                for line in raw_def.lines() {
                    def.push('\t');
                    def.push_str(line);
                    def.push('\n');
                }
                def.pop();
                if let Some(name) = crd.get_name() {
                    let field = if let TagTypeKind::Union = &crd.tag_used {
                        format!("\tunion {name} {{\n{def}\n\t}}")
                    } else if let TagTypeKind::Struct = &crd.tag_used {
                        format!("\tstruct {name} {{\n{def}\n\t}}")
                    } else {
                        unreachable!("{child:#?}")
                    };
                    fields.push(field);
                    nested_record = None;
                } else {
                    let field = if let TagTypeKind::Union = &crd.tag_used {
                        format!("\tunion {{\n{def}\n\t}}")
                    } else if let TagTypeKind::Struct = &crd.tag_used {
                        format!("\tstruct {{\n{def}\n\t}}")
                    } else {
                        unreachable!("{child:#?}")
                    };
                    nested_record = Some(field);
                }
            }
        }
        let mut fields = fields.join(";\n");
        fields.push(';');
        fields
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ElaboratedType {
    pub r#type: Type,
    #[serde(rename = "ownedTagDecl")]
    pub owned_tag_decl: Option<Decl>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CXXStaticCastExpr {
    pub range: SourceRange,
    pub r#type: Type,
}
