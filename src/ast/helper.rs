use super::{
    loc::{get_source_code_content, get_source_code_range},
    *,
};
use crate::analysis::{
    dfa::{VarKind, VarName},
    WorkList,
};

/// Common helper function to strip or ignore some useless parents.
pub trait CommomHelper {
    fn ignore_parent(&self) -> &Self;
    fn ignore_cast(&self) -> &Self;
    fn ignore_parenexpr(&self) -> &Self;
    fn ignore_prefix(&self) -> &Self;
    fn get_child(&self) -> &Self;
    fn get_child_mut(&mut self) -> &mut Self;
    fn get_childs(&self) -> Vec<&Self>;
    fn get_var_name(&self) -> VarName;
    fn is_call(&self) -> bool;
    fn get_call_name(&self) -> String;
    fn get_call_arg_stmts(&self) -> Vec<&Node>;
    fn get_source_range(&self) -> eyre::Result<(usize, usize)>;
    fn dump(&self) -> String;
    fn is_macro_expansion(&self) -> bool;
}

impl CommomHelper for Node {
    /// Ignore useless parent node
    fn ignore_parent(&self) -> &Self {
        match &self.kind {
            Clang::TranslationUnitDecl
            | Clang::CompoundLiteralExpr
            | Clang::MaterializeTemporaryExpr
            | Clang::ExprWithCleanups => self.inner.first().unwrap().ignore_parent(),
            _ => self,
        }
    }

    /// Ignore the cast-style stmt.
    fn ignore_cast(&self) -> &Self {
        match &self.kind {
            Clang::CStyleCastExpr(_)
            | Clang::ImplicitCastExpr(_)
            | Clang::CXXReinterpretCastExpr => self.get_child().ignore_cast(),
            _ => self,
        }
    }

    fn ignore_parenexpr(&self) -> &Self {
        if let Clang::ParenExpr(_) = &self.kind {
            if self.inner.len() == 1 {
                return self.inner[0].ignore_parenexpr();
            }
        }

        self
    }

    fn ignore_prefix(&self) -> &Self {
        if let Clang::UnaryOperator(_) = &self.kind {
            if self.inner.len() == 1 {
                return self.inner[0].ignore_parenexpr();
            }
        }
        self
    }

    /// Get the signle child. You must make sure this kind of stmt only has a single child.
    fn get_child(&self) -> &Self {
        assert_eq!(self.inner.len(), 1);
        self.inner.first().unwrap()
    }

    fn get_child_mut(&mut self) -> &mut Self {
        self.inner.get_mut(0).unwrap()
    }

    fn get_childs(&self) -> Vec<&Self> {
        let mut childs = Vec::new();
        for child in &self.inner {
            childs.push(child);
        }
        childs
    }

    /// Get the varialbe name of the given stmt.
    fn get_var_name(&self) -> VarName {
        let mut worklist = WorkList::new();
        worklist.push(self);
        let mut names = vec![];
        let mut kinds = vec![];
        let mut ids = vec![];
        while !worklist.empty() {
            let curr = worklist.pop();
            if let Clang::DeclRefExpr(dre) = &curr.kind {
                if let clang_ast::Kind::EnumConstantDecl = dre.referenced_decl.kind {
                    continue;
                }
                names.push(dre.get_name_as_string());
                kinds.push(VarKind::Base);
                ids.push(dre.referenced_decl.id);
            }
            if let Clang::ArraySubscriptExpr(ase) = &curr.kind {
                names.push("i".to_owned());
                kinds.push(VarKind::Arrary);
                ids.push(curr.id);
                worklist.push(ase.get_lhs(curr));
                continue;
            }
            if let Clang::MemberExpr(me) = &curr.kind {
                let name = me.get_name_as_string();
                names.push(name);
                // Currently only retain the member relationship, ignore the "is_arrow" attribute.
                kinds.push(VarKind::Member);
                ids.push(curr.id);
            }
            for child in &curr.inner {
                worklist.push(child);
            }
        }
        VarName::from_vec(names, kinds, ids)
    }

    fn is_call(&self) -> bool {
        matches!(&self.ignore_cast().kind, Clang::CallExpr(_))
    }

    fn get_call_name(&self) -> String {
        if let Clang::CallExpr(ce) = &self.kind {
            ce.get_name_as_string(self)
        } else {
            panic!("using get_call_name() on not CallExpr: {self:#?}")
        }
    }

    fn get_call_arg_stmts(&self) -> Vec<&Node> {
        if let Clang::CallExpr(ce) = &self.kind {
            ce.get_childs(self)
        } else {
            panic!("using get_call_name() on not CallExpr: {self:#?}")
        }
    }

    fn get_source_range(&self) -> eyre::Result<(usize, usize)> {
        match &self.kind {
            Clang::ImplicitCastExpr(ce) => get_source_code_range(&ce.range),
            Clang::CStyleCastExpr(ce) => get_source_code_range(&ce.range),
            Clang::StringLiteral(sl) => get_source_code_range(&sl.range),
            Clang::IntegerLiteral(il) => get_source_code_range(&il.range),
            Clang::CharacterLiteral(cl) => get_source_code_range(&cl.range),
            Clang::FloatingLiteral(fl) => get_source_code_range(&fl.range),
            Clang::IfStmt(is) => get_source_code_range(&is.range),
            Clang::DeclStmt(ds) => get_source_code_range(&ds.range),
            Clang::BinaryOperator(bo) => get_source_code_range(&bo.range),
            Clang::UnaryOperator(uo) => get_source_code_range(&uo.range),
            Clang::ReturnStmt(rs) => get_source_code_range(&rs.range),
            Clang::CallExpr(ce) => get_source_code_range(&ce.range),
            Clang::UnaryExprOrTypeTraitExpr(ue) => get_source_code_range(&ue.range),
            Clang::CXXStaticCastExpr(cce) => get_source_code_range(&cce.range),
            Clang::ParenExpr(pe) => get_source_code_range(&pe.range),
            Clang::Other => {
                if let Some(first) = self.inner.first() {
                    let start = first.get_source_range()?.0;
                    let end = self.inner.last().unwrap().get_source_range()?.1;
                    Ok((start, end))
                } else {
                    eyre::bail!("Other node has no children: {self:#?}")
                }
            },
            _ => {
                if let Some(first) = self.inner.first() {
                    let start = first.get_source_range()?.0;
                    let end = self.inner.last().unwrap().get_source_range()?.1;
                    Ok((start, end))
                } else {
                    eyre::bail!("Other node has no children: {self:#?}")
                }
            }
        }
    }

    fn dump(&self) -> String {
        let dump_str = match &self.kind {
            Clang::ImplicitCastExpr(ce) => get_source_code_content(&ce.range),
            Clang::CStyleCastExpr(ce) => get_source_code_content(&ce.range),
            Clang::StringLiteral(sl) => get_source_code_content(&sl.range),
            Clang::IntegerLiteral(il) => get_source_code_content(&il.range),
            Clang::CharacterLiteral(cl) => get_source_code_content(&cl.range),
            Clang::FloatingLiteral(fl) => get_source_code_content(&fl.range),
            //Clang::IfStmt(is) => {
            //    get_source_code_content(&is.range)
            //},
            Clang::DeclStmt(ds) => get_source_code_content(&ds.range),
            Clang::BinaryOperator(bo) => get_source_code_content(&bo.range),
            Clang::ReturnStmt(rs) => get_source_code_content(&rs.range),
            Clang::CallExpr(ce) => get_source_code_content(&ce.range),
            Clang::ParmVarDecl(pvd) => get_source_code_content(&pvd.range),
            Clang::UnaryOperator(uo) => get_source_code_content(&uo.range),
            Clang::ConstantExpr(ue) => get_source_code_content(&ue.range),
            _ => Ok(format!("{:?}", self.kind)),
        };
        dump_str.unwrap_or_else(|_| format!("{:?}", self.kind))
    }

    fn is_macro_expansion(&self) -> bool {
        match &self.kind {
            Clang::ImplicitCastExpr(ce) => crate::ast::loc::is_macro_expansion(&ce.range),
            Clang::CStyleCastExpr(ce) => crate::ast::loc::is_macro_expansion(&ce.range),
            Clang::StringLiteral(sl) => crate::ast::loc::is_macro_expansion(&sl.range),
            Clang::IntegerLiteral(il) => crate::ast::loc::is_macro_expansion(&il.range),
            Clang::CharacterLiteral(cl) => crate::ast::loc::is_macro_expansion(&cl.range),
            Clang::FloatingLiteral(fl) => crate::ast::loc::is_macro_expansion(&fl.range),
            Clang::IfStmt(is) => crate::ast::loc::is_macro_expansion(&is.range),
            Clang::DeclStmt(ds) => crate::ast::loc::is_macro_expansion(&ds.range),
            Clang::BinaryOperator(bo) => crate::ast::loc::is_macro_expansion(&bo.range),
            Clang::UnaryOperator(uo) => crate::ast::loc::is_macro_expansion(&uo.range),
            Clang::ReturnStmt(rs) => crate::ast::loc::is_macro_expansion(&rs.range),
            Clang::CallExpr(ce) => crate::ast::loc::is_macro_expansion(&ce.range),
            Clang::UnaryExprOrTypeTraitExpr(ue) => crate::ast::loc::is_macro_expansion(&ue.range),
            Clang::CXXStaticCastExpr(cce) => crate::ast::loc::is_macro_expansion(&cce.range),
            Clang::ParenExpr(pe) => crate::ast::loc::is_macro_expansion(&pe.range),
            Clang::DeclRefExpr(dre) => crate::ast::loc::is_macro_expansion(&dre.range),
            Clang::CompoundStmt(cs) => crate::ast::loc::is_macro_expansion(&cs.range),
            Clang::ConstantExpr(ce) => crate::ast::loc::is_macro_expansion(&ce.range),
            Clang::EnumConstantDecl(ecd) => crate::ast::loc::is_macro_expansion(&ecd.range),
            Clang::InitListExpr(ile) => crate::ast::loc::is_macro_expansion(&ile.range),
            _ => {
                // For other unhandled nodes, check if any of their children are macro expansions
                self.inner.iter().any(|child| child.is_macro_expansion())
            }
        }
    }
}
