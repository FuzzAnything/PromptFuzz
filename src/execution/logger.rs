use std::{
    path::PathBuf,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{self, Instant},
};

use eyre::Result;
use once_cell::sync::OnceCell;
use regex::{Captures, Regex};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum ProgramError {
    Syntax(String),
    Link(String),
    Execute(String),
    Fuzzer(String),
    Coverage(String),
    Hang(String),
}

impl ProgramError {
    pub fn get_err_msg(&self) -> String {
        match self {
            ProgramError::Syntax(msg) => format!("\nSyntax Error: \n{msg}"),
            ProgramError::Link(msg) => format!("\nLink Error: \n{msg}"),
            ProgramError::Execute(msg) => format!("\nExecute Error: \n{msg}"),
            ProgramError::Fuzzer(msg) => format!("\nFuzzer Error: \n{msg}"),
            ProgramError::Coverage(msg) => format!("\nCoverage Error: \n{msg}"),
            ProgramError::Hang(msg) => format!("\nExecuted Hang!: \n{msg}"),
        }
    }
}

pub enum AsanError {
    DoubleFree,
    UAF,
    HeapOverflow,
    StackOverflow,
    Leak,
    Segv,
    Undefined,
    //attempting free on address which was not malloc
    ErrFree,
    //e.g.,  stack-overflow on address 0x7ffd44bd4719
    FDSan,
    Others(String),
}

impl AsanError {
    pub fn from(msg: &str) -> Self {
        if msg.contains("stack-buffer-overflow") || msg.contains("AddressSanitizer: stack-overflow")
        {
            Self::StackOverflow
        } else if msg.contains("heap-buffer-overflow") {
            Self::HeapOverflow
        } else if msg.contains("LeakSanitizer") {
            Self::Leak
        } else if msg.contains("double-free") {
            Self::DoubleFree
        } else if msg.contains("heap-use-after-free") {
            Self::UAF
        } else if msg.contains("SEGV") {
            Self::Segv
        } else if msg.contains("attempting free on address which was not malloc") {
            Self::ErrFree
        } else if msg.contains("is_file_name_closed(char const*)") || msg.contains("fd_err_abort()")
        {
            Self::FDSan
        } else if msg.contains("UndefinedBehaviorSanitizer") {
            Self::Undefined
        } else {
            Self::Others(msg.to_string())
        }
    }
}

#[derive(Default)]
struct Counter {
    total: usize,
    succ: usize,
    syntax: usize,
    link: usize,
    execute: usize,
    hang: usize,
    fuzzer: usize,
    coverage: usize,
}

impl Counter {
    fn clear(&mut self) {
        self.total = 0;
        self.succ = 0;
        self.syntax = 0;
        self.link = 0;
        self.execute = 0;
        self.hang = 0;
        self.fuzzer = 0;
        self.coverage = 0;
    }

    fn from_capture(captures: Captures) -> Result<Self> {
        Ok(Counter {
            total: captures.get(1).unwrap().as_str().parse()?,
            succ: captures.get(2).unwrap().as_str().parse()?,
            syntax: captures.get(3).unwrap().as_str().parse()?,
            link: captures.get(4).unwrap().as_str().parse()?,
            execute: captures.get(5).unwrap().as_str().parse()?,
            hang: captures.get(6).unwrap().as_str().parse()?,
            fuzzer: captures.get(7).unwrap().as_str().parse()?,
            coverage: captures.get(8).unwrap().as_str().parse()?,
        })
    }
}

#[derive(Default)]
struct AsanCounter {
    df: usize,
    uaf: usize,
    h_overflow: usize,
    s_overflow: usize,
    leak: usize,
    segv: usize,
    err_free: usize,
    undefined: usize,
    fdsan: usize,
    other: usize,
}

impl AsanCounter {
    fn from_capture(captures: Captures) -> Result<Self> {
        Ok(Self {
            df: captures.get(1).unwrap().as_str().parse()?,
            uaf: captures.get(2).unwrap().as_str().parse()?,
            h_overflow: captures.get(3).unwrap().as_str().parse()?,
            s_overflow: captures.get(4).unwrap().as_str().parse()?,
            leak: captures.get(5).unwrap().as_str().parse()?,
            segv: captures.get(6).unwrap().as_str().parse()?,
            undefined: captures.get(7).unwrap().as_str().parse()?,
            fdsan: captures.get(8).unwrap().as_str().parse()?,
            other: captures.get(9).unwrap().as_str().parse()?,
            err_free: 0,
        })
    }
}

#[derive(Default)]
pub struct ProgramLogger {
    // round counter
    rc: Counter,
    // global counter
    gc: Counter,
    // asan err statistic
    sc: AsanCounter,
}

impl ProgramLogger {
    pub fn get_rc_total(&self) -> usize {
        self.rc.total
    }

    pub fn get_rc_succ(&self) -> usize {
        self.rc.succ
    }

    pub fn get_gc_total(&self) -> usize {
        self.gc.total
    }

    pub fn log_err(&mut self, err_msg: &ProgramError) {
        self.rc.total += 1;
        self.gc.total += 1;
        match err_msg {
            ProgramError::Syntax(_) => {
                self.rc.syntax += 1;
                self.gc.syntax += 1;
            }
            ProgramError::Link(_) => {
                self.rc.link += 1;
                self.gc.link += 1;
            }
            ProgramError::Execute(msg) => {
                self.rc.execute += 1;
                self.gc.execute += 1;
                let asan_err = AsanError::from(msg);
                self.log_asan_err(asan_err);
            }
            ProgramError::Fuzzer(msg) => {
                self.rc.fuzzer += 1;
                self.gc.fuzzer += 1;
                let asan_err = AsanError::from(msg);
                self.log_asan_err(asan_err);
            }
            ProgramError::Hang(_) => {
                self.rc.hang += 1;
                self.gc.hang += 1;
            }
            ProgramError::Coverage(_) => {
                self.rc.coverage += 1;
                self.gc.coverage += 1;
            }
        }
    }

    fn log_asan_err(&mut self, err: AsanError) {
        match err {
            AsanError::DoubleFree => self.sc.df += 1,
            AsanError::UAF => self.sc.uaf += 1,
            AsanError::HeapOverflow => self.sc.h_overflow += 1,
            AsanError::StackOverflow => self.sc.s_overflow += 1,
            AsanError::Leak => self.sc.leak += 1,
            AsanError::Segv => self.sc.segv += 1,
            AsanError::ErrFree => self.sc.err_free += 1,
            AsanError::Undefined => self.sc.undefined += 1,
            AsanError::FDSan => self.sc.fdsan += 1,
            AsanError::Others(_msg) => {
                self.sc.other += 1;
                //log::warn!("Meet unkown Asan err:\n{msg}");
            }
        }
    }

    pub fn log_succ(&mut self) {
        self.rc.total += 1;
        self.gc.total += 1;
        self.rc.succ += 1;
        self.gc.succ += 1;
    }

    pub fn reset_round(&mut self) {
        self.rc.clear();
    }

    fn sync_round(&mut self, round_counter: Counter) {
        self.rc = round_counter
    }

    pub fn snyc_from_str(log_str: &str) -> Result<Self> {
        let mut logger = Self::default();
        let round_re = Regex::new(
            r"\[round\] total: ([0-9]+), succ: ([0-9]+), syntax: ([0-9]+), link: ([0-9]+), execute: ([0-9]+), hang: ([0-9]+), fuzzer: ([0-9]+), coverage: ([0-9]+)",
        )?;
        let global_re = Regex::new(
            r"\[global\] total: ([0-9]+), succ: ([0-9]+), syntax: ([0-9]+), link: ([0-9]+), execute: ([0-9]+), hang: ([0-9]+), fuzzer: ([0-9]+), coverage: ([0-9]+)",
        )?;
        let san_re = Regex::new(
            r"\[Asan\] df: ([0-9]+), uaf: ([0-9]+), ho: ([0-9]+), so: ([0-9]+), leak: ([0-9]+), segv: ([0-9]+), undefined: ([0-9]+), FDSan: ([0-9]+), others: ([0-9]+)",
        )?;
        if let Some(captures) = round_re.captures_iter(log_str).last() {
            let round_counter = Counter::from_capture(captures)?;
            logger.sync_round(round_counter);
        }
        if let Some(captures) = global_re.captures_iter(log_str).last() {
            let global_counter = Counter::from_capture(captures)?;
            logger.sync_global(global_counter);
        }
        if let Some(captures) = san_re.captures_iter(log_str).last() {
            let asan_counter = AsanCounter::from_capture(captures)?;
            logger.sync_san(asan_counter);
        }
        log::info!("Restore the ProgramLogger succesfully!");
        logger.print_succ_round();
        Ok(logger)
    }

    fn sync_global(&mut self, global_counter: Counter) {
        self.gc = global_counter
    }

    fn sync_san(&mut self, sc: AsanCounter) {
        self.sc = sc;
    }

    pub fn print_succ_round(&self) {
        log::debug!(
            "[round] total: {}, succ: {}, syntax: {}, link: {}, execute: {}, hang: {}, fuzzer: {}, coverage: {}",
            self.rc.total,
            self.rc.succ,
            self.rc.syntax,
            self.rc.link,
            self.rc.execute,
            self.rc.hang,
            self.rc.fuzzer,
            self.rc.coverage
        );
        log::debug!(
            "[global] total: {}, succ: {}, syntax: {}, link: {}, execute: {}, hang: {}, fuzzer: {}, coverage: {}",
            self.gc.total,
            self.gc.succ,
            self.gc.syntax,
            self.gc.link,
            self.gc.execute,
            self.gc.hang,
            self.gc.fuzzer,
            self.gc.coverage
        );
        log::debug!(
            "[Asan] df: {}, uaf: {}, ho: {}, so: {}, leak: {}, segv: {}, undefined: {}, FDSan:{}, others: {}",
            self.sc.df,
            self.sc.uaf,
            self.sc.h_overflow,
            self.sc.s_overflow,
            self.sc.leak,
            self.sc.segv,
            self.sc.undefined,
            self.sc.fdsan,
            self.sc.other
        );
    }
}

pub struct TimeUsage {
    start: Instant,
    dir: PathBuf,
}

impl TimeUsage {
    pub fn new(dir: PathBuf) -> Self {
        let mut dir = dir.clone();
        dir.push("time_usage");
        crate::deopt::utils::create_dir_if_nonexist(&dir)
            .unwrap_or_else(|_| panic!("create dir failed! {dir:?}"));
        Self {
            start: time::Instant::now(),
            dir,
        }
    }

    fn get_ty_usage_file(&self, ty: &str) -> PathBuf {
        let mut save_path = self.dir.clone();
        save_path.push(ty);
        save_path.set_extension("cost");
        save_path
    }

    pub fn log(&self, ty: &str) -> eyre::Result<()> {
        let usage = time::Instant::elapsed(&self.start).as_secs_f32();
        let save_path = self.get_ty_usage_file(ty);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(save_path)?;
        std::io::Write::write_fmt(&mut file, format_args!("{}", usage))?;
        Ok(())
    }

    pub fn load(&self, ty: &str) -> eyre::Result<f32> {
        let log_path = self.get_ty_usage_file(ty);
        if !log_path.exists() {
            return Ok(0_f32);
        }
        let buf = std::fs::read_to_string(log_path)?;
        let usage: f32 = buf.parse()?;
        Ok(usage)
    }
}

/// GlobalTimeLogger is used to log and analyze the time cost of each submodule of PromptFuzz.
#[derive(Debug, Default)]
pub struct GlobalTimeLogger {
    req: f32,
    syntax: f32,
    link: f32,
    execute: f32,
    fuzz: f32,
    coverage: f32,
    update: f32,
}

impl GlobalTimeLogger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_req(&mut self, req: f32) {
        self.req += req;
        log::debug!("Global LLM generate time: {}s", self.req);
    }

    pub fn inc_san(
        &mut self,
        syntax: f32,
        link: f32,
        execute: f32,
        fuzz: f32,
        coverage: f32,
        update: f32,
    ) {
        self.syntax += syntax;
        self.link += link;
        self.execute += execute;
        self.fuzz += fuzz;
        self.coverage += coverage;
        self.update += update;
        log::debug!("Global sanitization time cost: syntax: {}s, link: {}s, execute: {}s, fuzz: {}s, coverage: {}s, update: {}s", self.syntax, self.link, self.execute, self.fuzz, self.coverage, self.update);
    }
}

pub static GTL: OnceCell<RwLock<GlobalTimeLogger>> = OnceCell::new();

pub fn init_gtl() {
    GTL.set(RwLock::new(GlobalTimeLogger::new())).unwrap();
}

pub fn get_gtl() -> RwLockReadGuard<'static, GlobalTimeLogger> {
    GTL.get().expect("GTL should not be None").read().unwrap()
}

pub fn get_gtl_mut() -> RwLockWriteGuard<'static, GlobalTimeLogger> {
    GTL.get().expect("GTL should not be None").write().unwrap()
}
