use eyre::Result;
use prompt_fuzz::execution::Compile;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use chrono::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use prompt_fuzz::analysis::adg::ADGBuilder;
use prompt_fuzz::analysis::cfg::CFGBuilder;
use prompt_fuzz::deopt::{self, Deopt};
use prompt_fuzz::execution::{logger::ProgramError, Executor};
use prompt_fuzz::feedback::observer::Observer;
use prompt_fuzz::minimize::minimize;
use prompt_fuzz::program::infer::infer_constraints;
use prompt_fuzz::program::libfuzzer::{sanitize_crash, LibFuzzer};
use strum_macros::Display;

/// Command Parser
#[derive(Parser, Debug)]
#[command(author="Anonymous", name = "LLMFuzzer-harness", version, about="The harness to invoke each component in PromptFuzz", long_about = None)]
pub struct Config {
    /// Target project to proceed
    project: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// check a program whether is correct.
    Check { program: PathBuf },
    /// Recheck the seeds whether are correct.
    ReCheck,
    /// transform a program to a fuzzer.
    Transform {
        program: PathBuf,
        #[arg(short, default_value = "true")]
        use_cons: bool,
        /// corpora used to perform transform check
        #[arg(short = 'p', default_value = "None")]
        corpora: Option<PathBuf>,
    },
    /// Fuse the programs in seeds to fuzzers.
    FuseFuzzer {
        /// transform fuzzer with constraints
        #[arg(short, default_value = "true")]
        use_cons: bool,
        /// the number of condensed fuzzer you want to fuse
        #[arg(short, default_value = "1")]
        n_fuzzer: usize,
        seed_dir: Option<PathBuf>,
    },
    /// Run a synthesized fuzzer in the fuzz dir.
    FuzzerRun {
        /// which fuzzer you want to run. default is "output/$Library/fuzzers"
        #[arg(short = 'u', default_value = "true")]
        use_cons: bool,
        /// the amount of time you wish your fuzzer to run. The default is 86400s (24 hours), the unit is second. 0 is for unlimit.
        time_limit: Option<u64>,
        /// whether minimize the fuzzing corpus before running
        minimize: Option<bool>,
    },
    /// collect code coverage
    Coverage {
        /// Coverage kind to collect
        kind: CoverageKind,
        /// -u means the exploit fuzzers
        #[arg(short = 'u', default_value = "true")]
        exploit: bool,
    },
    Compile {
        kind: Compile,
        #[arg(short = 'u', default_value = "true")]
        exploit: bool,
    },
    /// infer constraints
    Infer,
    /// Minimize the seeds by unique branches.
    Minimize,
    /// Sanitize duplicate and spurious crashes
    SanitizeCrash {
        #[arg(short = 'u', default_value = "true")]
        exploit: bool,
    },
    /// archive the results
    Archive { suffix: Option<String> },
    ///  Build ADG from seeds
    Adg {
        /// ADG kind to build: sparse or dense
        kind: ADGKind,
        /// The path of target programs to build the ADG.
        target: Option<PathBuf>,
    },
}

#[derive(Debug, ValueEnum, Clone, Copy, Display, PartialEq, PartialOrd)]
enum CoverageKind {
    /// collect coverage for the entire library
    Collect,
    /// report the coverage summary for the entire library.
    Report,
    /// ReCompute the branch coverage on the seeds.
    Seed,
}

#[derive(Debug, ValueEnum, Clone, Copy, Display, PartialEq, PartialOrd)]
enum ADGKind {
    Sparse,
    Dense,
}

pub fn transform(
    project: String,
    program_path: &Path,
    use_cons: bool,
    corpora: Option<PathBuf>,
) -> Result<()> {
    let deopt = Deopt::new(project)?;
    prompt_fuzz::program::transform::transform(&deopt, program_path, use_cons, corpora)?;
    Ok(())
}

pub fn check(project: String, program: &Path) -> Result<Option<ProgramError>> {
    let deopt = Deopt::new(project)?;
    let executor = Executor::new(&deopt)?;
    let has_err = executor.check_program_is_correct(program)?;
    Ok(has_err)
}

pub fn recheck(project: String) -> Result<()> {
    let mut deopt = Deopt::new(project)?;
    let mut executor = Executor::new(&deopt)?;
    executor.recheck_seed(&mut deopt)?;
    Ok(())
}

pub fn fuzzer_run(
    project: String,
    run_exploit: bool,
    time_limit: Option<u64>,
    minimize: Option<bool>,
) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let executor = Executor::new(&deopt)?;
    executor.run_libfuzzer(run_exploit, time_limit, minimize)?;
    Ok(())
}

fn collect_cov(project: String, kind: &CoverageKind, exploit: bool) -> ExitCode {
    let deopt: Deopt = Deopt::new(project).unwrap();
    let fuzzers_dir = if exploit {
        deopt.get_library_fuzzer_dir(true).unwrap()
    } else {
        deopt.get_library_fuzzer_dir(false).unwrap()
    };
    if !fuzzers_dir.exists() || !fuzzers_dir.is_dir() {
        panic!("{fuzzers_dir:?} should be a directory.")
    }
    let executor = Executor::new(&deopt).unwrap();
    match kind {
        // collect the library code coverage from all the synthesized fuzzers.
        CoverageKind::Collect => {
            let res = executor.collect_lib_cov_all_fuzzers(&fuzzers_dir);
            if let Err(err) = res {
                eprintln!("{}", err);
                return ExitCode::from(44);
            }
            ExitCode::SUCCESS
        }
        CoverageKind::Report => {
            let res = executor.report_lib_cov_all_fuzzers(&fuzzers_dir);
            if let Err(err) = res {
                eprintln!("{}", err);
                return ExitCode::from(45);
            }
            ExitCode::SUCCESS
        }
        CoverageKind::Seed => {
            executor.calculate_seed_coverage().unwrap();
            ExitCode::SUCCESS
        }
    }
}

fn fuse_fuzzer(
    project: String,
    seed_dir: &Option<PathBuf>,
    n_fuzzer: usize,
    use_cons: bool,
) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let test_dir: PathBuf = if let Some(seed_dir) = seed_dir {
        seed_dir.clone()
    } else {
        deopt.get_library_seed_dir()?
    };
    let programs = crate::deopt::utils::read_sort_dir(&test_dir)?;
    let batch_size = programs.len() / n_fuzzer;

    let mut lib_fuzzer = LibFuzzer::new(programs, batch_size, deopt, use_cons);
    lib_fuzzer.transform()?;
    lib_fuzzer.synthesis()?;
    lib_fuzzer.compile()?;
    Ok(())
}

fn compile_fuzzer(project: String, kind: Compile, exploit: bool) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let executor = Executor::new(&deopt)?;
    for dir in std::fs::read_dir(deopt.get_library_fuzzer_dir(exploit)?)? {
        let fuzzer_dir = dir?.path();
        if fuzzer_dir.is_dir() {
            log::info!("Compile to Fuzzer: {fuzzer_dir:?}");
            let fuzzer_name = match kind {
                Compile::SANITIZE => "fuzzer_san",
                Compile::FUZZER => "fuzzer",
                Compile::COVERAGE => "fuzzer_cov",
                Compile::Minimize => "fuzzer_evo",
            };
            let fuzzer_binary: PathBuf = [fuzzer_dir.clone(), fuzzer_name.into()].iter().collect();
            executor.compile_lib_fuzzers(&fuzzer_dir, &fuzzer_binary, kind.clone())?;
            deopt.copy_library_init_file(&fuzzer_dir)?;
        }
    }
    Ok(())
}

fn archive(project: String, suffix: &Option<String>) -> Result<()> {
    let current_date = Local::now().format("%Y-%m-%d").to_string();

    let out: String = if let Some(suffix) = suffix {
        format!("{project}_{suffix}_{current_date}.tar.gz")
    } else {
        format!("{project}_{current_date}.tar.gz")
    };

    let deopt = Deopt::new(project.clone())?;
    let driver_dir = deopt.get_library_driver_dir()?;
    if driver_dir.exists() {
        std::fs::remove_dir_all(driver_dir)?;
    }

    let fuzzer_dir: PathBuf = deopt.get_library_fuzzer_dir(false)?;
    let exploit_fuzzer_dir: PathBuf = deopt.get_library_fuzzer_dir(true)?;
    let fuzzer_dirs = vec![fuzzer_dir, exploit_fuzzer_dir];
    for fuzz_dir in fuzzer_dirs {
        for entry in crate::deopt::utils::read_sort_dir(&fuzz_dir)? {
            if entry.is_dir() {
                let corpus_path: PathBuf = [entry.clone(), "corpus".into()].iter().collect();
                if corpus_path.exists() {
                    std::fs::remove_dir_all(corpus_path)?;
                }
                let profraw: PathBuf = [entry.clone(), "profraw".into()].iter().collect();
                if profraw.exists() {
                    std::fs::remove_dir_all(profraw)?;
                }
            }
        }
    }

    let _cmd = Command::new("tar")
        .current_dir(Deopt::get_crate_output_dir()?)
        .arg("-cvf")
        .arg(&out)
        .arg("-C")
        .arg(Deopt::get_crate_output_dir()?)
        .arg(format!("--exclude={project}/work"))
        .arg(&project)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?;

    let _cmd = Command::new("coscli")
        .current_dir(Deopt::get_crate_output_dir()?)
        .arg("cp")
        .arg(out.clone())
        .arg(format!(
            "cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/{project}/{out}"
        ))
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()?;
    Ok(())
}

fn build_adg(project: String, kind: &ADGKind, target: &Option<PathBuf>) -> Result<()> {
    let deopt = Deopt::new(project)?;
    match kind {
        ADGKind::Sparse => {
            if let Some(program_path) = target {
                let ast = Executor::extract_ast(program_path, vec![], &deopt)?;
                let cfg = CFGBuilder::build_cfg(ast)?;
                let adg = ADGBuilder::new().sparse_build(cfg)?;
                let save_path: PathBuf = [deopt.get_library_adg_dir()?, "sparse.adg".into()]
                    .iter()
                    .collect();
                adg.dump_to_file(&save_path, true)?;
            }
        }
        ADGKind::Dense => {
            let mut observer = Observer::new(&deopt);
            let seed_dir = if let Some(dir) = target {
                dir.clone()
            } else {
                deopt.get_library_seed_dir()?
            };
            for entry in std::fs::read_dir(seed_dir)? {
                let seed = entry?.path();
                observer.add_program_to_adg(&seed)?;
            }
            observer.save_coalesced_adg()?;
        }
    }
    Ok(())
}

fn constraint_infer(project: String) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let dir = deopt.get_library_succ_seed_dir()?;
    let programs = deopt::utils::read_sort_dir(&dir)?;
    infer_constraints(&programs, &deopt)?;
    Ok(())
}

fn sanitize_crash(project: String, exploit: bool) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let fuzzer_dir = deopt.get_library_fuzzer_dir(exploit)?;
    sanitize_crash::sanitize_crash(&fuzzer_dir, &deopt)?;
    Ok(())
}

fn main() -> ExitCode {
    let config = Config::parse();
    prompt_fuzz::config::Config::init_test(&config.project);
    let project = config.project.clone();
    match &config.command {
        Commands::Check { program } => {
            let res: Option<ProgramError> = check(project, program).unwrap();
            if let Some(err) = res {
                let dump_err = serde_json::to_string(&err).unwrap();
                eprintln!("{dump_err}");
                return ExitCode::from(41);
            }
            return ExitCode::SUCCESS;
        }
        Commands::ReCheck => {
            recheck(project).unwrap();
            return ExitCode::SUCCESS;
        }
        Commands::Transform {
            program,
            use_cons,
            corpora,
        } => {
            let res = transform(project, program, *use_cons, corpora.clone());
            if let Err(err) = res {
                eprintln!("{}", err);
                return ExitCode::from(42);
            }
            return ExitCode::SUCCESS;
        }
        Commands::FuzzerRun {
            use_cons,
            time_limit,
            minimize,
        } => {
            let res = fuzzer_run(project, *use_cons, *time_limit, *minimize);
            if let Err(err) = res {
                eprintln!("{}", err);
                return ExitCode::from(43);
            }
            return ExitCode::SUCCESS;
        }
        Commands::Coverage { kind, exploit } => {
            return collect_cov(project, kind, *exploit);
        }
        Commands::Archive { suffix } => {
            archive(project, suffix).unwrap();
        }
        Commands::Adg { kind, target } => {
            build_adg(project, kind, target).unwrap();
        }
        Commands::FuseFuzzer {
            use_cons,
            n_fuzzer,
            seed_dir,
        } => {
            fuse_fuzzer(project, seed_dir, *n_fuzzer, *use_cons).unwrap();
        }
        Commands::Minimize => {
            let deopt = Deopt::new(project).unwrap();
            minimize(&deopt).unwrap();
        }
        Commands::Infer => {
            constraint_infer(project).unwrap();
        }
        Commands::SanitizeCrash { exploit } => sanitize_crash(project, *exploit).unwrap(),
        Commands::Compile { kind, exploit } => {
            compile_fuzzer(project, kind.clone(), *exploit).unwrap()
        }
    };
    ExitCode::SUCCESS
}
