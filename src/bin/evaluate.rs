use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use eyre::Result;
use plotters::prelude::*;
use prompt_fuzz::{
    deopt::{self, Deopt},
    execution::Executor,
    program::Program,
};

fn get_bench_dir() -> Result<PathBuf> {
    let crate_dir = crate::Deopt::get_crate_dir()?;
    let mut dir = PathBuf::from(crate_dir);
    dir.push("benchmark");
    Ok(dir)
}

fn get_acc_bench_dir() -> Result<PathBuf> {
    let mut dir = get_bench_dir()?;
    dir.push("acc_coverage");
    Ok(dir)
}

fn get_library_acc_bench_dir(deopt: &Deopt) -> Result<PathBuf> {
    let mut acc_bench = get_acc_bench_dir()?;
    acc_bench.push(&deopt.project_name);
    deopt::utils::create_dir_if_nonexist(&acc_bench)?;
    Ok(acc_bench)
}

fn get_acc_coverage_save_file(deopt: &Deopt) -> Result<PathBuf> {
    let mut save_file = deopt.get_library_misc_dir()?;
    save_file.push("acc_coverage.json");
    Ok(save_file)
}

fn get_acc_coverage_bench_file(deopt: &Deopt) -> Result<PathBuf> {
    let mut file = get_library_acc_bench_dir(deopt)?;
    file.push("bench.json");
    Ok(file)
}

fn get_acc_coverage_rand_bench_file(deopt: &Deopt) -> Result<PathBuf> {
    let mut file = get_library_acc_bench_dir(deopt)?;
    file.push("rand_bench.json");
    Ok(file)
}

fn get_acc_coverage_save_image(deopt: &Deopt) -> Result<PathBuf> {
    let mut save_file = deopt.get_library_misc_dir()?;
    save_file.push("acc_coverage.png");
    Ok(save_file)
}

fn get_acc_coverage_compare_save_image(deopt: &Deopt) -> Result<PathBuf> {
    let mut image = get_library_acc_bench_dir(deopt)?;
    image.push("comparison.png");
    Ok(image)
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author="Tencent", name = "LLMFuzzer", version, about="A LLM based Fuzer", long_about = None)]
pub struct Config {
    /// The target project you decide to fuzz. Available: ["cJSON", "c-ares", "libvpx", "libaom", "libpng", e.g.]
    pub project: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Coverage {
        kind: ACCKind,
        #[arg(short, long, default_value = "false")]
        rand_bench: bool,
    },
}

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, PartialOrd)]
enum ACCKind {
    /// collect coverage for the entire library
    Collect,
    Plot,
    Compare,
}

struct BranchCounter<'a> {
    deopt: &'a Deopt,
    cover_files: Vec<PathBuf>,
}

impl<'a> BranchCounter<'a> {
    fn new(deopt: &'a Deopt) -> Self {
        Self {
            deopt,
            cover_files: Vec::new(),
        }
    }

    fn init(&self) -> Result<()> {
        let acc_file = self.get_seeds_accumulated_coverage_file()?;
        if acc_file.exists() {
            std::fs::remove_file(&acc_file)?;
        }
        Ok(())
    }

    fn get_seeds_accumulated_coverage_file(&self) -> Result<PathBuf> {
        let mut out_profdata = self.deopt.get_library_misc_dir()?;
        out_profdata.push("seed_acc_coverage.profdata");
        Ok(out_profdata)
    }

    fn push(&mut self, seed: usize) -> Result<()> {
        let profdata = self.deopt.get_seed_coverage_file(seed)?;
        self.cover_files.push(profdata);
        Ok(())
    }

    fn count_branch(&self) -> Result<usize> {
        let acc_file = self.get_seeds_accumulated_coverage_file()?;

        Executor::merge_profdata(&self.cover_files, &acc_file)?;
        if !acc_file.exists() {
            eyre::bail!("seed accumulated coverage file not found");
        }
        let executor = Executor::new(self.deopt)?;
        let code_coverage = executor.obtain_cov_from_profdata(&acc_file)?;
        let branch_count = code_coverage.get_covered_branch().len();
        Ok(branch_count)
    }
}

fn collect_accumulation_coverage(deopt: &Deopt, is_rand_bench: bool) -> Result<()> {
    let succ_seed_dir = deopt.get_library_succ_seed_dir()?;
    let succ_seeds = prompt_fuzz::deopt::utils::read_sort_dir(&succ_seed_dir)?;
    let mut last_seed_id = 0;
    let mut last_seed_coverage = 0;
    let mut counter = BranchCounter::new(deopt);
    counter.init()?;

    let mut acc_coverage = Vec::new();
    for seed in succ_seeds.iter() {
        let program = Program::load_from_path(seed)?;
        counter.push(program.id)?;
        let covered_branches = counter.count_branch()?;
        log::info!("seed: {seed:?}, covered_branches: {covered_branches}");
        let mut should_infill = program.id - last_seed_id;
        while should_infill > 1 {
            acc_coverage.push(last_seed_coverage);
            should_infill -= 1;
        }
        acc_coverage.push(covered_branches);
        last_seed_id = program.id;
        last_seed_coverage = covered_branches;
    }
    let save_file = get_acc_coverage_save_file(deopt)?;
    let bench_file = if is_rand_bench {
        get_acc_coverage_rand_bench_file(deopt)?
    } else {
        get_acc_coverage_bench_file(deopt)?
    };

    let dump_str = serde_json::to_string(&acc_coverage)?;
    std::fs::write(save_file, &dump_str)?;
    std::fs::write(&bench_file, dump_str)?;
    log::info!("accumulation coverage is saved to: {bench_file:?}");
    Ok(())
}

fn plot_acc_coverage(deopt: &Deopt) -> Result<()> {
    let acc_file = get_acc_coverage_save_file(deopt)?;
    let raw_str = std::fs::read_to_string(acc_file)?;
    let acc_coverage: Vec<usize> = serde_json::from_str(&raw_str)?;

    let image_save_file = get_acc_coverage_save_image(deopt)?;

    let x_limit = acc_coverage.len();
    let y_limit = acc_coverage.iter().max().unwrap();

    let root_area = BitMapBackend::new(&image_save_file, (600, 400)).into_drawing_area();
    root_area.fill(&WHITE).unwrap();
    let mut ctx = ChartBuilder::on(&root_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .caption("Line Plot Demo", ("sans-serif", 40))
        .build_cartesian_2d(0..x_limit, 0..*y_limit)
        .unwrap();

    ctx.configure_mesh().draw().unwrap();

    ctx.draw_series(LineSeries::new(
        acc_coverage
            .iter()
            .enumerate()
            .map(|(id, coverage)| (id, *coverage)),
        &GREEN,
    ))
    .unwrap();
    Ok(())
}

fn plot_acc_coverage_comparison(deopt: &Deopt) -> Result<()> {
    let bench_file = get_acc_coverage_bench_file(deopt)?;
    let rand_bench_file = get_acc_coverage_rand_bench_file(deopt)?;
    if !bench_file.exists() || !rand_bench_file.exists() {
        eyre::bail!("No bench file found.")
    }
    let raw_str = std::fs::read_to_string(bench_file)?;
    let bench_coverage: Vec<usize> = serde_json::from_str(&raw_str)?;

    let raw_str = std::fs::read_to_string(rand_bench_file)?;
    let rand_coverage: Vec<usize> = serde_json::from_str(&raw_str)?;

    let x_limit = usize::max(bench_coverage.len(), rand_coverage.len());
    let y_limit = usize::max(
        *bench_coverage.iter().max().unwrap(),
        *rand_coverage.iter().max().unwrap(),
    );
    let x_limit = (x_limit as f32 * 1.1_f32) as usize;
    let y_limit = (y_limit as f32 * 1.1_f32) as usize;

    let image_save_file = get_acc_coverage_compare_save_image(deopt)?;
    let root_area = BitMapBackend::new(&image_save_file, (600, 400)).into_drawing_area();
    root_area.fill(&WHITE).unwrap();
    let mut ctx = ChartBuilder::on(&root_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .caption("Line Plot Demo", ("sans-serif", 40))
        .build_cartesian_2d(0..x_limit, 0..y_limit)
        .unwrap();

    ctx.configure_mesh().draw().unwrap();
    ctx.draw_series(LineSeries::new(
        bench_coverage
            .iter()
            .enumerate()
            .map(|(id, coverage)| (id, *coverage)),
        &RED,
    ))
    .unwrap();
    ctx.draw_series(LineSeries::new(
        rand_coverage
            .iter()
            .enumerate()
            .map(|(id, coverage)| (id, *coverage)),
        &GREEN,
    ))
    .unwrap();
    Ok(())
}

fn coverage(project: String, kind: &ACCKind, is_rand_bench: bool) -> Result<()> {
    let deopt = Deopt::new(project)?;
    match kind {
        ACCKind::Collect => collect_accumulation_coverage(&deopt, is_rand_bench)?,
        ACCKind::Plot => {
            collect_accumulation_coverage(&deopt, is_rand_bench)?;
            plot_acc_coverage(&deopt)?;
        }
        ACCKind::Compare => plot_acc_coverage_comparison(&deopt)?,
    }
    Ok(())
}

fn main() -> Result<()> {
    let config = Config::parse();
    prompt_fuzz::config::Config::init_test(&config.project);
    match &config.command {
        Commands::Coverage { kind, rand_bench } => {
            coverage(config.project.clone(), kind, *rand_bench)?
        }
    }
    Ok(())
}
