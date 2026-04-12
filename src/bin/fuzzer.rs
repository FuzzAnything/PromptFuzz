use eyre::Result;
use prompt_fuzz::{
    config::{self, get_config},
    fuzzer::Fuzzer,
    init_logger,
};

fn main() -> Result<()> {
    dotenv::dotenv().ok();
    config::init_openai_env();
    config::parse_config()?;
    //config::Config::init_test("cJSON");
    init_logger()?;
    let mut fuzzer = Fuzzer::new()?;
    fuzzer.fuzz_loop()?;
    if get_config().fuzzer_run {
        fuzzer.fuzzer_run()?;
    }
    //fuzzer.build_adg_from_seeds()?;
    Ok(())
}
