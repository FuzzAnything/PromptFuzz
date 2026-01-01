/// Perform source-to-source transformation on C source code file.
/// The transformation is performed based on the source code location on AST.
use crate::{
    ast::{
        loc::is_macro_stmt,
        utils::{get_nth_arg, is_arg_fuzzable},
    },
    program::{
        array::InitListType,
        gadget::ctype::{is_fuzzable_array_ty, is_unsigned_integer_ty},
    },
};
use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use crate::{
    ast::{
        loc::{get_fuzzer_shim_end_loc, get_fuzzer_shim_range},
        utils::{get_call_arg_type, get_func_arg_decl_type},
        Clang, CommomHelper, InitListExpr, IntegerLiteral, Node, VarDecl, Visitor,
    },
    execution::Executor,
    program::gadget::ctype::{get_pointer_inner, is_integer_ty, is_sized_array_ty},
    Deopt,
};

use eyre::{ContextCompat, Result};
use regex::Regex;

use self::utils::{is_read_from_file, is_ret_by_call, replace_string_in_file};

use super::{
    gadget::get_func_gadget,
    infer::{APIConstraints, Constraint},
    shim::FuzzerShim,
};

pub struct Transformer<'a> {
    pub src_file: PathBuf,
    deopt: &'a Deopt,
    /// main function of this file.
    main: String,
    /// fuzzer fields
    pub fuzzer_shim: FuzzerShim,
}

impl<'a> Transformer<'a> {
    /// directly edit on the passed src_file.
    pub fn new(src_file: &Path, deopt: &'a Deopt) -> Result<Self> {
        let mut out_file = PathBuf::from(src_file);
        out_file.set_extension("cc");
        let transformer = Self {
            src_file: out_file,
            deopt,
            main: "LLVMFuzzerTestOneInput".to_string(),
            fuzzer_shim: FuzzerShim::new(),
        };
        Ok(transformer)
    }

    /// create a copy and without change self code.
    pub fn without_self_change(mut self) -> Self {
        let out_file = self.src_file.with_extension("transform.cc");
        std::fs::copy(&self.src_file, &out_file)
            .unwrap_or_else(|_| panic!("unable to copy {:?} to {:?}", self.src_file, out_file));
        self.src_file = out_file;
        self
    }

    pub fn get_output_file(&self) -> &Path {
        &self.src_file
    }

    pub fn new_check(src_file: &Path, deopt: &'a Deopt) -> Result<Self> {
        let mut out_file = deopt.get_library_transform_check_dir(src_file)?;
        let base_name = src_file
            .file_name()
            .ok_or_else(|| eyre::eyre!("{src_file:?} should be a path of source code"))?;
        out_file.push(base_name);
        out_file.set_extension("cc");
        if src_file.ne(&out_file) {
            std::fs::copy(src_file, &out_file)?;
        }
        let transformer = Self {
            src_file: out_file,
            deopt,
            main: "LLVMFuzzerTestOneInput".to_string(),
            fuzzer_shim: FuzzerShim::new(),
        };
        Ok(transformer)
    }

    pub fn get_fuzzer_offset(&self) -> usize {
        self.fuzzer_shim.get_offset()
    }

    pub fn get_fuzzer_bytes(&self) -> &[u8] {
        self.fuzzer_shim.get_seeds()
    }

    fn update_ast(&mut self) -> Result<Node> {
        let ast = Executor::extract_func_ast(&self.src_file, vec![], self.deopt, &self.main, true)?;
        Ok(ast)
    }

    /// Given the sequence numbers of fuzzable arguments, transform those arguments to receive fuzzer engine's bytes.
    /// The transformation satisfies th passed constraints.
    /// nths: the sequence numbers of the arguments you want to transform.
    pub fn transform_to_fuzzer(
        &mut self,
        constraints: &APIConstraints,
        nths: Vec<usize>,
    ) -> Result<()> {
        log::debug!("Change {:?} to fuzzer, {nths:?}", self.src_file.file_name());
        // change to fuzzer function declaration
        let fuzzer_ty = "int";
        let fuzzer_name = "LLVMFuzzerTestOneInput".to_string();

        let fuzzer_params = "const uint8_t* f_data, size_t f_size";
        self.change_fd_to_fuzzer(fuzzer_ty, &fuzzer_name, fuzzer_params)?;
        self.change_input_data_fuzzable()?;

        // change fuzzable args of calls to receive fuzzer input
        self.change_calls_to_fuzzer(constraints, nths)?;
        // ignore to change vardecl, because it is useless as all fuzzable args are already changed.

        self.write_fuzzer_seeds()?;
        self.add_fd_sanitizer()?;
        self.handle_file_constraint("data", "size")?;
        self.add_fuzzer_size_constraint("f_size")?;

        Ok(())
    }

    pub fn transform_with_execution_check(
        &mut self,
        constraints: &APIConstraints,
        corpora: &Path,
    ) -> Result<Vec<usize>> {
        let transform_len: usize = self.get_transform_len(constraints)?;
        let mut changable_args = Vec::new();
        let mut executor = Executor::new(self.deopt)?;
        for nth in 0..transform_len {
            let mut transformer = Self::new(&self.src_file, self.deopt)?.without_self_change();
            transformer.transform_to_fuzzer(constraints, vec![nth])?;
            let out_driver = transformer.get_output_file();
            if let Some(err) = executor.transform_check(out_driver, corpora)? {
                let err_msg = err.get_err_msg();
                log::warn!(
                    "program: {:?} at nth_fuzzable_arg: {nth} cannot be fuzzable.\n {err_msg}",
                    self.src_file
                );
            } else {
                changable_args.push(nth);
            }
        }
        Ok(changable_args)
    }

    /// get the number of fuzzable arguments wait to be transformed to receive fuzzer's bytes in this program.
    pub fn get_transform_len(&mut self, constraints: &APIConstraints) -> Result<usize> {
        let visitor = self.get_new_visitor()?;
        let fuzz_variants = visitor.collect_fuzzable_variants(&visitor, constraints);
        Ok(fuzz_variants.len())
    }

    pub fn preprocess(&mut self) -> Result<()> {
        self.handle_file_constraint("data", "size")?;
        self.add_fuzzer_size_constraint("size")?;
        Ok(())
    }

    // write the raw bytes to the "intput_file";
    fn handle_file_constraint(&mut self, data: &str, size: &str) -> Result<()> {
        let re = Regex::new(r"^input_file(\.\w+)?$")?;
        let visitor = self.get_new_visitor()?;
        if let Some(file_name) = visitor.match_string_pattern(re) {
            let ins_loc =
                if let Some(loc) = crate::ast::loc::get_fuzzer_shim_after_loc(&self.src_file)? {
                    loc
                } else {
                    visitor.get_function_body_begin_loc()?
                };
            let init_stmt = format!("\n\tFILE *input_file_ptr = fopen(\"{file_name}\", \"wb\");\n\tif (input_file_ptr == NULL) {{return 0;}}\n\tfwrite({data}, sizeof(uint8_t), {size}, input_file_ptr);\n\tfclose(input_file_ptr);\n");
            self.seek_and_rewrite(ins_loc, 0, &init_stmt)?;
        }
        Ok(())
    }

    /// change the 'main' function to fuzzable and receive fuzzer input
    fn change_fd_to_fuzzer(
        &mut self,
        fuzzer_ty: &str,
        fuzzer_name: &str,
        fuzzer_params: &str,
    ) -> Result<()> {
        self.change_fd_name(fuzzer_name, fuzzer_ty)?;
        self.change_fd_params(fuzzer_name, fuzzer_params)?;
        Ok(())
    }

    /// change the data input read from file to read from fuzzer.
    fn change_input_data_fuzzable(&mut self) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        // whether needs to cast the type of bytes.
        let init_stmt = if let Some(ty_name) = visitor.find_ty_with_arg_name("data") {
            // whether append a null terminator at the end of bytes.
            if self.deopt.config.should_terminate_with_null() {
                format!("FDPConsumeRawBytesWithNullTerm({ty_name}, data, size, fdp)")
            } else {
                format!("FDPConsumeRawBytes({ty_name}, data, size, fdp)")
            }
        } else if self.deopt.config.should_terminate_with_null() {
            "FDPConsumeRawBytesWithNullTerm(const uint8_t *, data, size, fdp)".to_string()
        } else {
            "FDPConsumeRawBytes(const uint8_t *, data, size, fdp)".to_string()
        };
        self.fuzzer_shim.append_fuzzer_stmt(init_stmt);
        self.write_fuzzer_vars_stmts()?;
        replace_string_in_file(&self.src_file, "const uint8_t *data; size_t size;", "")?;
        Ok(())
    }

    /// make up a variable for this call's string arg.
    fn makeup_call_string_arg(
        &mut self,
        call: &Node,
        array_pos: usize,
        constraint: &Option<Constraint>,
    ) -> Result<()> {
        let init_id = self.fuzzer_shim.get_init_id_inc();
        let fuzz_str = format!("fuzz_str_{}", init_id);
        if let Some(constraint) = constraint {
            match constraint {
                Constraint::ArrayLen((array_pos, integer_pos)) => {
                    // format the declaration name and type of this array var.
                    let arg_ty = get_func_arg_decl_type(call, *integer_pos);
                    let fuzz_size = if arg_ty.contains('*') {
                        format!("static_cast<{arg_ty}>(&fuzz_str_sz_{init_id})")
                    } else {
                        format!("static_cast<{arg_ty}>(fuzz_str_sz_{init_id})")
                    };

                    if integer_pos > array_pos {
                        self.change_call_arg(call, *integer_pos, &fuzz_size)?;
                        self.change_call_arg(call, *array_pos, &fuzz_str)?;
                    } else {
                        self.change_call_arg(call, *array_pos, &fuzz_str)?;
                        self.change_call_arg(call, *integer_pos, &fuzz_size)?;
                    }
                }
                Constraint::ArrayIndex((array_pos, integer_pos)) => {
                    // format the declaration name and type of this array var.
                    let arg_ty = get_func_arg_decl_type(call, *integer_pos);
                    let index_stmt = format!("\n\tFDPGetRandomInteger({arg_ty}, fuzz_str_idx_{init_id}, fuzz_str_sz_{init_id});");
                    let fuzz_size = if arg_ty.contains('*') {
                        format!("static_cast<{arg_ty}>(&fuzz_str_idx_{init_id})")
                    } else {
                        format!("static_cast<{arg_ty}>(fuzz_str_idx_{init_id})")
                    };

                    if integer_pos > array_pos {
                        self.change_call_arg(call, *integer_pos, &fuzz_size)?;
                        self.change_call_arg(call, *array_pos, &fuzz_str)?;
                    } else {
                        self.change_call_arg(call, *array_pos, &fuzz_str)?;
                        self.change_call_arg(call, *integer_pos, &fuzz_size)?;
                    }
                    let ins_pos = get_fuzzer_shim_end_loc(&self.src_file)?;
                    self.seek_and_rewrite(ins_pos, 0, &index_stmt)?;
                }
                _ => unreachable!(),
            }
        } else {
            self.change_call_arg(call, array_pos, &fuzz_str)?;
        }
        Ok(())
    }

    fn makeup_call_integer_arg(&mut self, call: &Node, arg_pos: usize, ty: &str) -> Result<()> {
        let c_ty_name = match ty {
            "int8_t" => "int8_t",
            "uint8_t" => "uint8_t",
            "int16_t" | "short" => "int16_t",
            "uint16_t" | "unsigned short" => "uint16_t",
            "int32_t" | "int" => "int32_t",
            "uint32_t" | "unsigned int" => "uint32_t",
            "int64_t" | "long" | "long long" => "int64_t",
            "uint64_t" | "unsigned long" | "unsigned long long" | "size_t" => "uint64_t",
            _ => unimplemented!("{ty} unimplemented type"),
        };
        let fuzz_var = format!("fuzz_{c_ty_name}_{}", self.fuzzer_shim.get_init_id_inc());
        self.change_call_arg(call, arg_pos, &fuzz_var)?;
        Ok(())
    }

    pub fn seek_and_rewrite(&self, pos: usize, len: usize, str: &str) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.src_file)?;
        f.seek(std::io::SeekFrom::Start((pos + len) as u64))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let mut str = str.as_bytes().to_vec();
        str.extend(buf);
        f.set_len((pos + str.len()) as u64)?;
        f.seek(std::io::SeekFrom::Start(pos as u64))?;
        f.write_all(&str)?;
        Ok(())
    }

    pub fn get_new_visitor(&mut self) -> Result<Visitor> {
        let ast = self.update_ast()?;
        let visitor = Visitor::new(ast);
        Ok(visitor)
    }

    fn change_fd_name(&mut self, change_to_name: &str, change_to_ty: &str) -> Result<()> {
        let fd_name = self.main.clone();
        let visitor = self.get_new_visitor()?;
        let (begin, end) = visitor.get_fd_loc(&fd_name)?;
        let len = end - begin;
        let change_to = [change_to_ty, change_to_name].join(" ");
        self.main = change_to_name.to_string();
        self.seek_and_rewrite(begin, len, &change_to)
    }

    fn change_fd_params(&mut self, fd_name: &str, change_to: &str) -> Result<()> {
        let src_file = self.src_file.clone();
        let visitor = self.get_new_visitor()?;
        let ins_loc = visitor.get_function_body_begin_loc()?;
        self.seek_and_rewrite(ins_loc, 0, "const uint8_t *data; size_t size;")?;
        let (begin, end) = visitor.get_fd_param_loc(fd_name, &src_file)?;
        let len = end - begin;
        self.seek_and_rewrite(begin, len, change_to)?;
        Ok(())
    }

    pub fn change_call_arg(&mut self, call: &Node, arg_pos: usize, change_to: &str) -> Result<()> {
        if let Clang::CallExpr(ce) = &call.kind {
            // Cannot proceed macro on AST.
            if is_macro_stmt(&ce.range) {
                return Ok(());
            }
            let args = ce.get_childs_no_ignore(call);
            if let Some(arg) = args.get(arg_pos) {
                if let Clang::CXXDefaultArgExpr = &arg.kind {
                    return Ok(());
                }
                let (begin, end) = arg.get_source_range()?;
                let len = end - begin;
                self.seek_and_rewrite(begin, len, change_to)?;
                return Ok(());
            }
            eyre::bail!("access arg_pos `{arg_pos}` out of bound: `{}`", args.len())
        }
        eyre::bail!("cannot change args for not CallExpr")
    }

    fn create_string_fuzzer_var(&mut self, str_var: String, ty: &str) -> Result<()> {
        if ty == "void" {
            self.fuzzer_shim.append_string_var(str_var, "unsigned char");
            return Ok(());
        }
        self.fuzzer_shim.append_string_var(str_var, ty);
        Ok(())
    }

    fn create_integer_fuzzer_var(&mut self, int_var: &IntegerLiteral, ty: &str) -> Result<()> {
        match ty {
            "int8_t" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<i8>()?),
            "uint8_t" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<u8>()?),
            "int16_t" | "short" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<i16>()?),
            "uint16_t" | "unsigned short" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<u16>()?),
            "int32_t" | "int" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<i32>()?),
            "uint32_t" | "unsigned int" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<u32>()?),
            "int64_t" | "long" | "long long" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<i64>()?),
            "uint64_t" | "size_t" | "unsigned long" | "unsigned long long" => self
                .fuzzer_shim
                .append_integer_var(int_var.get_value::<u64>()?),
            _ => unimplemented!("{ty} unimplemented type"),
        }
        Ok(())
    }

    fn init_fuzzable_list_var(
        &mut self,
        decl_name: &str,
        ty: &str,
        shape: (usize, usize),
        ins_pos: usize,
        should_cast: bool,
    ) -> Result<()> {
        let (row, col) = shape;
        //let name = vd.get_var_decl_name();
        // if is one dimensional array.
        if col == 0 {
            let mut array_init_stmts = format!("\n\t\t{decl_name} = {{");
            let mut stmts = Vec::new();
            for _i in 0..row {
                let stmt = format!("fuzz_{ty}_{}", self.fuzzer_shim.get_init_id_inc());
                stmts.push(stmt);
            }
            array_init_stmts.push_str(&stmts.join(","));
            array_init_stmts.push_str("};");
            self.fuzzer_shim
                .append_fuzzer_stmt(array_init_stmts.clone());
            self.seek_and_rewrite(ins_pos, 0, &array_init_stmts)?;
            Ok(())
        // else if two dimensional array.
        } else {
            let mut matrix_init_stmts = format!("\n\t\t{decl_name} = {{");
            let mut row_stmts = Vec::new();
            for _i in 0..row {
                let mut col_stmts = Vec::new();
                for _j in 0..col {
                    let stmt = format!("fuzz_{ty}_{}", self.fuzzer_shim.get_init_id_inc());
                    col_stmts.push(stmt)
                }
                let mut col_init = String::new();
                if ty != "char" && should_cast {
                    let cast_stmt = format!("(const {ty} *)({ty} [{col}])");
                    col_init.push_str(&cast_stmt);
                }
                col_init.push('{');
                col_init.push_str(&col_stmts.join(","));
                col_init.push('}');
                row_stmts.push(col_init);
            }
            matrix_init_stmts.push_str(&row_stmts.join(","));
            matrix_init_stmts.push_str("};");
            self.fuzzer_shim
                .append_fuzzer_stmt(matrix_init_stmts.clone());
            self.seek_and_rewrite(ins_pos, 0, &matrix_init_stmts)?;
            Ok(())
        }
    }

    /// Add the size_t constriant for the fuzzer input.
    pub fn add_fuzzer_size_constraint(&mut self, size_stmt: &str) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        let ins_loc = visitor.get_function_body_begin_loc()?;
        let constraint = format!(
            "\n\tif({size_stmt}<{}) return 0;\n",
            self.fuzzer_shim.get_offset()
        );
        self.seek_and_rewrite(ins_loc, 0, &constraint)?;
        Ok(())
    }

    fn write_fuzzer_vars_stmts(&mut self) -> Result<()> {
        let fuzzer_stmts = self.fuzzer_shim.serialize_fuzzer_stmts();
        let visitor = self.get_new_visitor()?;
        let ins_loc = visitor.get_function_body_begin_loc()?;
        self.seek_and_rewrite(ins_loc, 0, &fuzzer_stmts)?;
        self.seek_and_rewrite(0, 0, "#include \"FuzzedDataProvider.h\"\n")?;
        Ok(())
    }

    fn update_fuzzer_shim(&mut self) -> Result<()> {
        let (begin, end) = get_fuzzer_shim_range(&self.src_file)?;
        let fuzzer_stmts = self.fuzzer_shim.serialize_fuzzer_stmts();
        self.seek_and_rewrite(begin, end - begin, &fuzzer_stmts)?;
        Ok(())
    }

    fn write_fuzzer_seeds(&mut self) -> Result<()> {
        let mut path = self.src_file.clone();
        path.set_extension("seed");
        std::fs::write(path, self.fuzzer_shim.get_seeds())?;
        Ok(())
    }

    fn change_calls_to_fuzzer(
        &mut self,
        constraints: &APIConstraints,
        nths: Vec<usize>,
    ) -> Result<()> {
        let mut cur_nth = 0;

        let visitor = self.get_new_visitor()?;
        let fuzz_variants = visitor.collect_fuzzable_variants(&visitor, constraints);
        for fuzz_varaint in &fuzz_variants {
            // only transform the specificed arguments
            if !nths.contains(&cur_nth) {
                cur_nth += 1;
                continue;
            }
            self.create_unlimit_call_fuzzer_var(fuzz_varaint, &visitor)?;
            cur_nth += 1;
        }
        cur_nth = 0;
        self.update_fuzzer_shim()?;
        for fuzz_varaint in &fuzz_variants {
            if !nths.contains(&cur_nth) {
                cur_nth += 1;
                continue;
            }
            self.change_call_arg_fuzzable(fuzz_varaint)?;
            cur_nth += 1;
        }
        Ok(())
    }

    fn _create_unlimit_call_fuzzer_var(
        &mut self,
        arg_ty: &str,
        arg: &Node,
        visitor: &Visitor,
    ) -> Result<()> {
        let arg = arg.ignore_parenexpr();
        if is_fuzzable_array_ty(arg_ty) {
            if let Clang::StringLiteral(sl) = &arg.kind {
                let value = sl.get_eval_value();
                let ty = get_pointer_inner(arg_ty).expect("array ty should not faild");
                self.create_string_fuzzer_var(value, ty)?;
            } else if let Clang::InitListExpr(ile) = &arg.kind {
                if !ile.is_mutable_list(arg) {
                    return Ok(());
                }
                if is_sized_array_ty(arg_ty) {
                    self.create_list_fuzzer_var(ile, arg)?;
                } else {
                    self.create_unlimit_list_fuzzer_var(ile, arg)?;
                }
            }
        }

        if is_integer_ty(arg_ty) {
            if let Clang::IntegerLiteral(il) = &arg.kind {
                self.create_integer_fuzzer_var(il, arg_ty)?;
                return Ok(());
            } else if let Clang::EnumConstantDecl(ecd) = &arg.kind {
                if let Some(value) = ecd.get_const_value(arg) {
                    self.fuzzer_shim.append_integer_var(value);
                    return Ok(());
                }
            } else if let Clang::UnaryOperator(uo) = &arg.kind {
                // negative value
                if !uo.is_minus() || arg.inner.len() != 1 {
                    return Ok(());
                }
                if let Clang::IntegerLiteral(il) = &arg.inner[0].kind {
                    let mut il = il.clone();
                    if !is_unsigned_integer_ty(arg_ty) {
                        let mut value = il.value.to_string();
                        value.insert(0, '-');
                        il.value = value.into();
                    }
                    self.create_integer_fuzzer_var(&il, arg_ty)?;
                }
                return Ok(());
            }
        }
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                self._create_unlimit_call_fuzzer_var(arg_ty, init, visitor)?;
            }
        }
        Ok(())
    }

    fn create_unlimit_call_fuzzer_var(
        &mut self,
        fuzz_varaint: &FuzzVariant,
        visitor: &Visitor,
    ) -> Result<()> {
        let arg_pos = fuzz_varaint.get_arg_pos();
        let call_name = fuzz_varaint.get_call_name();
        let call_node = fuzz_varaint.get_call_node();
        log::trace!("change {arg_pos}-th arg of {call_name} be fuzzable");

        let arg = get_nth_arg(call_node, *arg_pos)?.ignore_parenexpr();
        let arg_ty = get_func_gadget(call_name)
            .unwrap()
            .get_canonical_arg_type(*arg_pos)
            .context(format!(
                "cannot get canonical ty for arg :{arg_pos}-th {call_name}."
            ))?;
        self._create_unlimit_call_fuzzer_var(arg_ty, arg, visitor)?;
        Ok(())
    }

    fn change_arg_by_constraint(
        &mut self,
        call: (&Node, &str, usize),
        arg_pos: usize,
        arg_node: &Node,
        constraint: &Option<Constraint>,
        ty: &str,
        visitor: &Visitor,
    ) -> Result<()> {
        let (call_node, call_name, n_call) = call;
        let arg_node = arg_node.ignore_parenexpr();
        if is_fuzzable_array_ty(ty) {
            if let Clang::StringLiteral(_) = &arg_node.kind {
                self.makeup_call_string_arg(call_node, arg_pos, constraint)?;
                return Ok(());
            } else if let Clang::InitListExpr(ile) = &arg_node.kind {
                if !ile.is_mutable_list(arg_node) {
                    return Ok(());
                }
                if is_sized_array_ty(ty) {
                    self.makeup_sized_call_list_arg(ile, call_node, call_name, n_call, arg_pos)?;
                } else {
                    self.makeup_call_list_arg(
                        ile, call_node, call_name, n_call, arg_pos, constraint,
                    )?;
                }
                return Ok(());
            }
        }

        if is_integer_ty(ty) {
            if let Clang::IntegerLiteral(_) = &arg_node.kind {
                self.makeup_call_integer_arg(call_node, arg_pos, ty)?;
                return Ok(());
            } else if let Clang::EnumConstantDecl(ecd) = &arg_node.kind {
                if ecd.get_const_value(arg_node).is_some() {
                    self.makeup_call_integer_arg(call_node, arg_pos, ty)?;
                }
                return Ok(());
            } else if let Clang::UnaryOperator(uo) = &arg_node.kind {
                if !uo.is_minus() || arg_node.inner.len() != 1 {
                    return Ok(());
                }
                if let Clang::IntegerLiteral(_) = &arg_node.inner[0].kind {
                    self.makeup_call_integer_arg(call_node, arg_pos, ty)?;
                }
                return Ok(());
            }
        }

        if let Clang::DeclRefExpr(dre) = &arg_node.kind {
            if let Some(init) = dre.get_var_init(visitor) {
                self.change_arg_by_constraint(
                    (call_node, call_name, n_call),
                    arg_pos,
                    init,
                    constraint,
                    ty,
                    visitor,
                )?;
            }
        }
        Ok(())
    }

    fn change_call_arg_fuzzable(&mut self, fuzz_varaint: &FuzzVariant) -> Result<()> {
        let visitor = self.get_new_visitor()?;
        let n_call = fuzz_varaint.get_n_th_call();
        let arg_pos = fuzz_varaint.get_arg_pos();
        let call_name = fuzz_varaint.get_call_name();
        let call = visitor.visit_nth_library_call(*n_call);
        let constraint = fuzz_varaint.get_constraint();

        let arg = crate::ast::utils::get_nth_arg(call, *arg_pos)?;
        let ty = get_func_gadget(call_name)
            .unwrap()
            .get_canonical_arg_type(*arg_pos)
            .unwrap();

        self.change_arg_by_constraint(
            (call, call_name, *n_call),
            *arg_pos,
            arg,
            constraint,
            ty,
            &visitor,
        )?;
        Ok(())
    }

    /// make up a variable for this call's list arg.
    fn makeup_sized_call_list_arg(
        &mut self,
        ile: &InitListExpr,
        call: &Node,
        call_name: &str,
        n_call: usize,
        arg_pos: usize,
    ) -> Result<()> {
        let new_var_name = format!("fuzzer_var_{call_name}_{n_call}_{arg_pos}");
        let decl_name = ile.get_decl_name(&new_var_name);
        self.change_call_arg(call, arg_pos, &new_var_name)?;
        self.make_sized_list_expr_fuzzable(&decl_name, ile)?;
        Ok(())
    }

    fn makeup_call_list_arg(
        &mut self,
        ile: &InitListExpr,
        call: &Node,
        call_name: &str,
        n_call: usize,
        arg_pos: usize,
        constraint: &Option<Constraint>,
    ) -> Result<()> {
        // format the declaration name and type of this array var.
        let array_var_name = format!("fuzzer_var_{call_name}_{n_call}_{arg_pos}");
        let array_decl_type = get_call_arg_type(call, arg_pos);
        let mut array_decl_name: String = format!("{array_decl_type} {array_var_name}");

        // current, only handle constraint for the single layer poitner.
        let constraint = if get_func_gadget(call_name)
            .unwrap()
            .is_signle_layer_pointer(arg_pos)
        {
            constraint
        } else {
            let decl_type = ile.get_decl_name(&array_var_name);
            array_decl_name = decl_type;
            if !array_decl_name.starts_with("const") {
                array_decl_name.insert_str(0, "const ");
            }
            &None
        };

        if let Some(constraint) = constraint {
            match &constraint {
                Constraint::ArrayLen((array_pos, integer_pos)) => {
                    // format the declaration name and type of this array var.
                    let size_decl_type = get_call_arg_type(call, *integer_pos);
                    let size_decl_name = format!("fuzzer_size_{call_name}_{n_call}_{arg_pos}");

                    let size_arg = Some((size_decl_name.as_str(), size_decl_type.as_str(), 0));

                    if integer_pos > array_pos {
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                    } else {
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                    }
                    self.make_unlimit_list_expr_fuzzable(&array_decl_name, ile, size_arg)?;
                }
                Constraint::WeakArrayLen((array_pos, integer_pos)) => {
                    // format the declaration name and type of this array var.
                    let size_decl_type = get_call_arg_type(call, *integer_pos);
                    let size_decl_name = format!("fuzzer_size_{call_name}_{n_call}_{arg_pos}");

                    let size_arg = Some((size_decl_name.as_str(), size_decl_type.as_str(), 0));

                    if integer_pos > array_pos {
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                    } else {
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                    }
                    self.make_unlimit_list_expr_fuzzable(&array_decl_name, ile, size_arg)?;
                }
                Constraint::ArrayIndex((array_pos, integer_pos)) => {
                    // format the declaration name and type of this array var.
                    let size_decl_name = format!("fuzzer_index_{call_name}_{n_call}_{arg_pos}");
                    let size_decl_type = get_call_arg_type(call, *integer_pos);
                    let size_arg = Some((size_decl_name.as_str(), size_decl_type.as_str(), 1));

                    if integer_pos > array_pos {
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                    } else {
                        self.change_call_arg(call, arg_pos, &array_var_name)?;
                        self.change_call_arg(call, *integer_pos, &size_decl_name)?;
                    }
                    self.make_unlimit_list_expr_fuzzable(&array_decl_name, ile, size_arg)?;
                }
                _ => unreachable!(),
            }
        } else {
            self.change_call_arg(call, arg_pos, &array_var_name)?;
            self.make_unlimit_list_expr_fuzzable(&array_decl_name, ile, None)?;
        }
        Ok(())
    }

    fn create_list_fuzzer_var(&mut self, ile: &InitListExpr, node: &Node) -> Result<()> {
        let ty = ile.get_type().get_type_name();
        let ty = InitListType::new(&ty);
        match ty {
            InitListType::CharList(row, col) => {
                self.create_char_list_fuzzer_var(ile, node, row, col)?;
            }
            InitListType::CharStarList(row, _col) => {
                let strings = ile.get_char_star_array_literal(node, Some(row))?;
                for string in strings {
                    self.fuzzer_shim.append_string_var(string, "char");
                }
            }
            InitListType::UCharList(row, col) => {
                self.create_uchar_list_fuzzer_var(ile, node, row, col)?;
            }
            InitListType::UCharStarList(row, _col) => {
                let strings = ile.get_char_star_array_literal(node, Some(row))?;
                for string in strings {
                    self.fuzzer_shim.append_string_var(string, "unsigned char");
                }
            }
            InitListType::FloatList(row, col) => {
                self.create_float_list_fuzzer_var(ile, node, row, col)?;
            }
            InitListType::FloatStarList(row, _col) => {
                let matrix = ile.get_floating_matrix_literal::<f32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_float_vars(literals);
                }
            }
            InitListType::DoubleList(row, col) => {
                self.create_double_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::DoubleStarList(row, _col) => {
                let matrix = ile.get_floating_matrix_literal::<f64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_double_vars(literals);
                }
            }
            InitListType::I8List(row, col) => {
                self.create_int8_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::I8StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i8>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I16List(row, col) => {
                self.create_int16_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::I16StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i16>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I32List(row, col) => {
                self.create_int32_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::I32StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I64List(row, col) => {
                self.create_int64_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::I64StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U8List(row, col) => {
                self.create_uint8_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::U8StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u8>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U16List(row, col) => {
                self.create_uint16_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::U16StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u16>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U32List(row, col) => {
                self.create_uint32_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::U32StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U64List(row, col) => {
                self.create_uint64_t_list_fuzzer_var(ile, node, row, col)?
            }
            InitListType::U64StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::Others => unreachable!(),
            InitListType::PointerList => return Ok(()),
        };
        Ok(())
    }

    fn create_unlimit_list_fuzzer_var(&mut self, ile: &InitListExpr, node: &Node) -> Result<()> {
        let ty = ile.get_type().get_type_name();
        let ty = InitListType::new(&ty);
        match ty {
            InitListType::CharList(row, _) => {
                self.create_unlimit_char_list_fuzzer_var(ile, node, row)?;
            }
            InitListType::CharStarList(row, _col) => {
                let strings = ile.get_char_star_array_literal(node, Some(row))?;
                for string in strings {
                    self.fuzzer_shim.append_string_var(string, "char");
                }
            }
            InitListType::UCharList(row, _) => {
                self.create_unlimit_uchar_list_fuzzer_var(ile, node, row)?;
            }
            InitListType::UCharStarList(row, _col) => {
                let strings = ile.get_char_star_array_literal(node, Some(row))?;
                for string in strings {
                    self.fuzzer_shim.append_string_var(string, "unsigned char");
                }
            }
            InitListType::FloatList(row, _) => {
                self.create_unlimit_float_list_fuzzer_var(ile, node, row)?;
            }
            InitListType::FloatStarList(row, _col) => {
                let matrix = ile.get_floating_matrix_literal::<f32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_float_vars(literals);
                }
            }
            InitListType::DoubleList(row, _) => {
                self.create_unlimit_double_list_fuzzer_var(ile, node, row)?
            }
            InitListType::DoubleStarList(row, _col) => {
                let matrix = ile.get_floating_matrix_literal::<f64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_double_vars(literals);
                }
            }
            InitListType::I8List(row, _) => {
                self.create_unlimit_int8_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::I8StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i8>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I16List(row, _) => {
                self.create_unlimit_int16_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::I16StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i16>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I32List(row, _) => {
                self.create_unlimit_int32_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::I32StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::I64List(row, _) => {
                self.create_unlimit_int64_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::I64StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<i64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U8List(row, _) => {
                self.create_unlimit_uint8_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::U8StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u8>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U16List(row, _) => {
                self.create_unlimit_uint16_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::U16StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u16>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U32List(row, _) => {
                self.create_unlimit_uint32_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::U32StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u32>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::U64List(row, _) => {
                self.create_unlimit_uint64_t_list_fuzzer_var(ile, node, row)?
            }
            InitListType::U64StarList(row, _col) => {
                let matrix = ile.get_integer_matrix_literal::<u64>(node, Some(row), None)?;
                for literals in matrix {
                    self.fuzzer_shim.append_integer_vars(literals);
                }
            }
            InitListType::Others => unreachable!(),
            InitListType::PointerList => return Ok(()),
        };
        Ok(())
    }

    fn make_sized_list_expr_fuzzable(&mut self, decl_name: &str, ile: &InitListExpr) -> Result<()> {
        let ty = ile.get_type().get_type_name();
        let ty = InitListType::new(&ty);
        let ins_pos = get_fuzzer_shim_end_loc(&self.src_file)?;
        match ty {
            InitListType::CharList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "char", (row, col), ins_pos, false)?;
            }
            InitListType::CharStarList(row, _col) => {
                self.init_fuzzable_list_var(decl_name, "str", (row, 0), ins_pos, true)?
            }
            InitListType::UCharList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uchar", (row, col), ins_pos, false)?;
            }
            InitListType::UCharStarList(row, _col) => {
                self.init_fuzzable_list_var(decl_name, "str", (row, 0), ins_pos, true)?
            }
            InitListType::FloatList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "float", (row, col), ins_pos, false)?;
            }
            InitListType::FloatStarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "float", (row, col), ins_pos, true)?
            }
            InitListType::DoubleList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "double", (row, col), ins_pos, false)?;
            }
            InitListType::DoubleStarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "double", (row, col), ins_pos, true)?
            }
            InitListType::I8List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int8_t", (row, col), ins_pos, false)?;
            }
            InitListType::I8StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int8_t", (row, col), ins_pos, true)?
            }
            InitListType::I16List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int16_t", (row, col), ins_pos, false)?;
            }
            InitListType::I16StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int16_t", (row, col), ins_pos, true)?
            }
            InitListType::I32List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int32_t", (row, col), ins_pos, false)?;
            }
            InitListType::I32StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int32_t", (row, col), ins_pos, true)?
            }
            InitListType::I64List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int64_t", (row, col), ins_pos, false)?;
            }
            InitListType::I64StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int64_t", (row, col), ins_pos, true)?
            }
            InitListType::U8List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint8_t", (row, col), ins_pos, false)?;
            }
            InitListType::U8StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint8_t", (row, col), ins_pos, true)?
            }
            InitListType::U16List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint16_t", (row, col), ins_pos, false)?;
            }
            InitListType::U16StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint16_t", (row, col), ins_pos, true)?
            }
            InitListType::U32List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint32_t", (row, col), ins_pos, false)?;
            }
            InitListType::U32StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint32_t", (row, col), ins_pos, true)?
            }
            InitListType::U64List(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint64_t", (row, col), ins_pos, false)?;
            }
            InitListType::U64StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint64_t", (row, col), ins_pos, true)?
            }
            InitListType::Others => unimplemented!(),
            InitListType::PointerList => return Ok(()),
        }
        Ok(())
    }

    fn make_unlimit_list_expr_fuzzable(
        &mut self,
        decl_name: &str,
        ile: &InitListExpr,
        size_arg: Option<(&str, &str, u32)>,
    ) -> Result<()> {
        let ty = ile.get_type().get_type_name();
        let ty = InitListType::new(&ty);
        let ins_pos = get_fuzzer_shim_end_loc(&self.src_file)?;
        match ty {
            InitListType::CharList(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "char", ins_pos, size_arg)?;
            }
            InitListType::CharStarList(row, _col) => {
                self.init_fuzzable_list_var(decl_name, "str", (row, 0), ins_pos, true)?
            }
            InitListType::UCharList(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "char", ins_pos, size_arg)?;
            }
            InitListType::UCharStarList(row, _col) => {
                self.init_fuzzable_list_var(decl_name, "str", (row, 0), ins_pos, true)?
            }
            InitListType::FloatList(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "float", ins_pos, size_arg)?;
            }
            InitListType::FloatStarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "float", (row, col), ins_pos, true)?
            }
            InitListType::DoubleList(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "double", ins_pos, size_arg)?;
            }
            InitListType::DoubleStarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "double", (row, col), ins_pos, true)?
            }
            InitListType::I8List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "int8_t", ins_pos, size_arg)?;
            }
            InitListType::I8StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int8_t", (row, col), ins_pos, true)?
            }
            InitListType::I16List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "int16_t", ins_pos, size_arg)?;
            }
            InitListType::I16StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int16_t", (row, col), ins_pos, true)?
            }
            InitListType::I32List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "int32_t", ins_pos, size_arg)?;
            }
            InitListType::I32StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int32_t", (row, col), ins_pos, true)?
            }
            InitListType::I64List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "int64_t", ins_pos, size_arg)?;
            }
            InitListType::I64StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "int64_t", (row, col), ins_pos, true)?
            }
            InitListType::U8List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "uint8_t", ins_pos, size_arg)?;
            }
            InitListType::U8StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint8_t", (row, col), ins_pos, true)?
            }
            InitListType::U16List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "uint16_t", ins_pos, size_arg)?;
            }
            InitListType::U16StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint16_t", (row, col), ins_pos, true)?
            }
            InitListType::U32List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "uint32_t", ins_pos, size_arg)?;
            }
            InitListType::U32StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint32_t", (row, col), ins_pos, true)?
            }
            InitListType::U64List(_, _) => {
                self.init_unlimit_fuzzable_list_var(decl_name, "uint64_t", ins_pos, size_arg)?;
            }
            InitListType::U64StarList(row, col) => {
                self.init_fuzzable_list_var(decl_name, "uint64_t", (row, col), ins_pos, true)?
            }
            InitListType::Others => unimplemented!(),
            InitListType::PointerList => return Ok(()),
        }
        Ok(())
    }

    fn init_unlimit_fuzzable_list_var(
        &mut self,
        decl_name: &str,
        ty: &str,
        ins_pos: usize,
        size_arg: Option<(&str, &str, u32)>,
    ) -> Result<()> {
        let init_id = self.fuzzer_shim.get_init_id_inc();
        let mut array_init_stmts = format!("\n\t\t{decl_name} = fuzz_{ty}_array_{};", init_id);
        if let Some((integer_name, integer_type, c_type)) = size_arg {
            let fuzzer_size_var = format!("fuzz_{ty}_array_size_{init_id}");
            // ctype: 0 for ArrayLen and 1 for ArrayIndex
            let init_stmt = if c_type == 0 {
                if integer_type.contains('*') {
                    format!("\n\t\t{integer_type} {integer_name} = static_cast<{integer_type}>(&{fuzzer_size_var});")
                } else {
                    format!("\n\t\t{integer_type} {integer_name} = static_cast<{integer_type}>({fuzzer_size_var});")
                }
            } else {
                format!(
                    "\n\t\tFDPGetRandomInteger({integer_type}, {integer_name}, {fuzzer_size_var})"
                )
            };
            array_init_stmts.push_str(&init_stmt);
        }
        self.fuzzer_shim
            .append_fuzzer_stmt(array_init_stmts.clone());
        self.seek_and_rewrite(ins_pos, 0, &array_init_stmts)?;
        Ok(())
    }
}

#[derive(Clone)]
struct FuzzVariant {
    call_name: String,
    call_node: Node,
    n_call: usize,
    arg_pos: usize,
    constraint: Option<Constraint>,
}

impl FuzzVariant {
    fn get_arg_pos(&self) -> &usize {
        &self.arg_pos
    }

    fn get_call_node(&self) -> &Node {
        &self.call_node
    }

    fn get_call_name(&self) -> &str {
        &self.call_name
    }

    fn get_n_th_call(&self) -> &usize {
        &self.n_call
    }

    fn get_constraint(&self) -> &Option<Constraint> {
        &self.constraint
    }
}

impl FuzzVariant {
    fn new(
        call_name: String,
        call_node: Node,
        n_call: usize,
        arg_pos: usize,
        constraint: Option<Constraint>,
    ) -> Self {
        Self {
            call_name,
            call_node,
            n_call,
            arg_pos,
            constraint,
        }
    }
}

fn collect_fuzzable_array_args(
    call_name: &str,
    call: &Node,
    n_call: usize,
    constraints: &APIConstraints,
    visitor: &Visitor,
) -> Vec<FuzzVariant> {
    // get the positions of constant array parameters of this API call.
    let const_array_pos = super::gadget::get_fuzzable_funcs()
        .get(call_name)
        .unwrap()
        .to_vec();
    let const_array_pos: Vec<&usize> = const_array_pos
        .iter()
        .filter(|array_pos| !filter_constrained_array_args(constraints, call_name, array_pos))
        .collect();
    let mut fuzz_args = Vec::new();
    for arg_pos in const_array_pos {
        let arg = get_nth_arg(call, *arg_pos).unwrap();
        if is_read_from_file(arg, visitor) || !is_arg_fuzzable(arg, visitor) {
            continue;
        }
        // read from file, needn't transform
        let constraint = get_array_arg_constraint(constraints, call_name, arg_pos);
        let variant = FuzzVariant::new(
            call_name.to_string(),
            call.clone(),
            n_call,
            *arg_pos,
            constraint,
        );
        fuzz_args.push(variant);
    }
    fuzz_args
}

fn collect_fuzzable_integer_args(
    call_name: &str,
    call: &Node,
    n_call: usize,
    constraints: &APIConstraints,
    visitor: &Visitor,
) -> Vec<FuzzVariant> {
    // get the positions of integer (scalar) type parameters of this API call.
    let integeral_pos = get_func_gadget(call_name).unwrap().get_integer_params_pos();
    // filter out the positions inferred with constraints.
    let integeral_pos: Vec<&usize> = integeral_pos
        .iter()
        .filter(|x| !filter_constrained_integer_args(constraints, call_name, x))
        .collect();
    let mut fuzz_args = Vec::new();
    for arg_pos in integeral_pos {
        let arg = get_nth_arg(call, *arg_pos).unwrap();
        if is_ret_by_call(call_name, *arg_pos, visitor) || !is_arg_fuzzable(arg, visitor) {
            continue;
        }
        // read from file, needn't transform
        let variant = FuzzVariant::new(call_name.to_string(), call.clone(), n_call, *arg_pos, None);
        fuzz_args.push(variant);
    }
    fuzz_args
}

impl Visitor {
    /// Analyze the AST of the program. Collect the API calls that contained the fuzzable arguments.
    fn collect_fuzzable_variants(
        &self,
        visitor: &Visitor,
        constraints: &APIConstraints,
    ) -> Vec<FuzzVariant> {
        let mut fuzz_variants = Vec::new();
        let calls = self.visit_library_calls();
        for (n_th_call, call) in calls.iter().enumerate() {
            // cannot locate code elements in macro expansion, skip it.
            if let Clang::CallExpr(ce) = &call.kind {
                if is_macro_stmt(&ce.range) {
                    continue;
                }
            }

            let call_name = call.get_call_name();
            // get the positions of constant array parameters of this API call.
            let fuzz_arrays =
                collect_fuzzable_array_args(&call_name, call, n_th_call, constraints, visitor);
            // get the positions of integer (scalar) type parameters of this API call.
            let fuzz_integers =
                collect_fuzzable_integer_args(&call_name, call, n_th_call, constraints, visitor);

            fuzz_variants.extend(fuzz_arrays);
            fuzz_variants.extend(fuzz_integers);
        }
        fuzz_variants
    }
}

/// those array args are not fuzzable arrays, they should not be transformed to receive fuzz bytes.
fn filter_constrained_array_args(constraints: &APIConstraints, call_name: &str, x: &usize) -> bool {
    if let Some(func_constraints) = constraints.get(call_name) {
        for constraint in func_constraints {
            if let crate::program::infer::Constraint::FileName(file_pos) = constraint {
                if file_pos == x {
                    return true;
                }
            }
            if let crate::program::infer::Constraint::Format(format_pos) = constraint {
                if format_pos == x {
                    return true;
                }
            }
            // integeral pointer
            if let crate::program::infer::Constraint::ArrayLen((_, size_pos)) = constraint {
                if size_pos == x {
                    return true;
                }
            }
            if let crate::program::infer::Constraint::WeakArrayLen((_, size_pos)) = constraint {
                if size_pos == x {
                    return true;
                }
            }
            if let crate::program::infer::Constraint::ArrayIndex((_, idx_pos)) = constraint {
                if idx_pos == x {
                    return true;
                }
            }
        }
    }
    false
}

fn get_array_arg_constraint(
    constraints: &APIConstraints,
    call_name: &str,
    arg_pos: &usize,
) -> Option<Constraint> {
    if let Some(func_constraints) = constraints.get(call_name) {
        for constraint in func_constraints {
            if let crate::program::infer::Constraint::ArrayLen((array_pos, _)) = constraint {
                if array_pos == arg_pos {
                    return Some(constraint.clone());
                }
            }
            if let crate::program::infer::Constraint::WeakArrayLen((array_pos, _)) = constraint {
                if array_pos == arg_pos {
                    return Some(constraint.clone());
                }
            }
            if let crate::program::infer::Constraint::ArrayIndex((array_pos, _)) = constraint {
                if array_pos == arg_pos {
                    return Some(constraint.clone());
                }
            }
        }
    }
    None
}

// those args are constrained, we don't rand mutate those args.
fn filter_constrained_integer_args(
    constraints: &APIConstraints,
    call_name: &str,
    x: &usize,
) -> bool {
    if let Some(func_constraints) = constraints.get(call_name) {
        for constraint in func_constraints {
            match constraint {
                crate::program::infer::Constraint::ArrayLen((_, int_pos)) => {
                    if int_pos == x {
                        return true;
                    }
                }
                crate::program::infer::Constraint::WeakArrayLen((_, int_pos)) => {
                    if int_pos == x {
                        return true;
                    }
                }
                crate::program::infer::Constraint::ArrayIndex((_, int_pos)) => {
                    if int_pos == x {
                        return true;
                    }
                }
                crate::program::infer::Constraint::AllocSize(int_pos) => {
                    if int_pos == x {
                        return true;
                    }
                }
                crate::program::infer::Constraint::FileDesc(int_pos) => {
                    if int_pos == x {
                        return true;
                    }
                }
                crate::program::infer::Constraint::FileName(_)
                | crate::program::infer::Constraint::Format(_) => {
                    continue;
                }
                crate::program::infer::Constraint::Invalid(_) => return true,
                crate::program::infer::Constraint::LoopCount(int_pos) => {
                    if int_pos == x {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub mod utils {
    use std::path::Path;

    use super::*;
    pub fn fuzzable_var_get_vd(node: &Node) -> &VarDecl {
        if let Clang::VarDecl(vd) = &node.kind {
            return vd;
        }
        unreachable!("node must be fuzzable! node: {node:?}")
    }

    pub fn fuzzable_var_get_init(node: &Node) -> &Node {
        if let Clang::VarDecl(vd) = &node.kind {
            return vd.get_init(node).ignore_cast().ignore_parent();
        }
        unreachable!("node must be fuzzable! node: {node:?}")
    }

    /// replace a pattern to a str in a file.
    pub fn replace_string_in_file(file: &Path, pat: &str, to: &str) -> eyre::Result<()> {
        let content = std::fs::read_to_string(file)?;
        let content = content.replace(pat, to);
        std::fs::write(file, content)?;
        Ok(())
    }

    pub fn relace_pattern_in_content(content: &str, pat: &str, to: &str) -> eyre::Result<String> {
        let pattern = format!(r"\b{pat}\b");
        let re = Regex::new(&pattern)?;
        let content = re.replace_all(content, to).to_string();
        Ok(content)
    }

    /// Whether hte arg is the a buf read from in_file.
    /// fread(buf, data, 1, size, in_file);
    pub fn is_read_from_file(arg: &Node, visitor: &Visitor) -> bool {
        if let Clang::DeclRefExpr(dre) = &arg.kind {
            let arg_name = dre.get_name_as_string();
            let calls = visitor.find_callexprs("fread");
            if calls.is_empty() {
                return false;
            }
            for call in calls {
                if let Clang::CallExpr(ce) = &call.kind {
                    let mut arg_match = false;
                    let args = ce.get_childs(call);
                    if let Some(array_arg) = args.first() {
                        if let Clang::DeclRefExpr(dre) = &array_arg.kind {
                            let fread_buf_name = dre.get_name_as_string();
                            if arg_name == fread_buf_name {
                                arg_match = true;
                            }
                        }
                    }
                    if !arg_match {
                        continue;
                    }
                    if let Some(file_arg) = args.get(3) {
                        if let Clang::DeclRefExpr(dre) = &file_arg.kind {
                            let fread_file_name = dre.get_name_as_string();
                            if fread_file_name == "in_file" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    // Is this arg returned by calls
    pub fn is_ret_by_call(func: &str, arg_pos: usize, visitor: &Visitor) -> bool {
        if let Some(call) = visitor.find_callexpr(func, 0) {
            if let Clang::CallExpr(ce) = &call.kind {
                let call_args = ce.get_childs(call);
                if arg_pos >= call_args.len() {
                    return false;
                }
                let arg = ce.get_childs(call)[arg_pos];
                if crate::ast::utils::is_integer_literal(arg) {
                    return false;
                }
                if matches!(
                    &arg.kind,
                    Clang::CallExpr(_) | Clang::CXXNewExpr(_) | Clang::CXXMemberCallExpr
                ) {
                    return true;
                }

                if let Clang::DeclRefExpr(dre) = &arg.kind {
                    if let Some(init) = dre.get_var_init(visitor) {
                        if matches!(
                            &init.kind,
                            Clang::CallExpr(_) | Clang::CXXNewExpr(_) | Clang::CXXMemberCallExpr
                        ) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

pub fn transform(
    deopt: &Deopt,
    program_path: &Path,
    use_cons: bool,
    corpora: Option<PathBuf>,
) -> Result<()> {
    let constraints = super::infer::load_constraints(deopt)?;
    if use_cons {
        let corpora = corpora.expect("a corpora must be passed when transform with constraints");
        let mut transformer = Transformer::new_check(program_path, deopt)?;
        let changable_args = transformer.transform_with_execution_check(&constraints, &corpora)?;
        let mut transformer = Transformer::new(program_path, deopt)?;
        transformer.transform_to_fuzzer(&constraints, changable_args)?;
    } else {
        let mut transformer = Transformer::new_check(program_path, deopt)?;
        let changable_args = Vec::from_iter(0..transformer.get_transform_len(&constraints)?);
        let mut transformer = Transformer::new(program_path, deopt)?;
        transformer.transform_to_fuzzer(&constraints, changable_args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_without_constraint() -> Result<()> {
        crate::config::Config::init_test("libjpeg-turbo");
        let deopt = Deopt::new("libjpeg-turbo".to_string())?;
        let test_file: PathBuf = [
            Deopt::get_crate_dir()?,
            "testsuites".into(),
            "new_test.cc".into(),
        ]
        .iter()
        .collect();

        //let constraints = crate::program::infer::load_constraints(&deopt)?;
        let constraints = APIConstraints::new();
        let changable_args = Vec::from_iter(0..100);
        let mut transformer = Transformer::new(&test_file, &deopt)?;
        transformer.transform_to_fuzzer(&constraints, changable_args)?;

        Ok(())
    }

    #[test]
    fn test_transform_with_constraint() -> Result<()> {
        crate::config::Config::init_test("zlib");
        let deopt = Deopt::new("zlib".to_string())?;
        let test_file: PathBuf = [
            Deopt::get_crate_dir()?,
            "testsuites".into(),
            "new_test.cc".into(),
        ]
        .iter()
        .collect();

        let constraints = crate::program::infer::load_constraints(&deopt)?;
        let corpora: PathBuf = [
            deopt.get_library_shared_corpus_dir()?,
            "vp80-00-comprehensive-014.ivf".into(),
        ]
        .iter()
        .collect();
        let mut transformer = Transformer::new_check(&test_file, &deopt)?;
        let changable_args = transformer.transform_with_execution_check(&constraints, &corpora)?;
        let mut transformer = Transformer::new(&test_file, &deopt)?;
        transformer.transform_to_fuzzer(&constraints, changable_args)?;

        Ok(())
    }
}
