use std::sync::{RwLock, RwLockReadGuard};

use clap::Parser;
use once_cell::sync::OnceCell;

use crate::deopt::Deopt;

pub const CONNECT_TIMEOUT: u64 = 1;

// LLM Service Interface configure options
pub static OPENAI_MODEL_NAME: OnceCell<String> = OnceCell::new();

pub static OPENAI_ENDPOINT: OnceCell<String> = OnceCell::new();


// General model configure options.
pub const MUTATE_LINE: usize = 3;

pub const MAX_TOKENS: u16 = 2048_u16;

pub const MAX_INST_TOKENS: u16 = 256_u16;

pub const MUTATE_SEED_ROUND: u8 = 0;

pub const RETRY_N: u8 = 5;

pub const MAX_SAMPLE_LEN: usize = 20;

pub const DEFAULT_COMB_LEN: usize = 5;

pub static CONFIG_INSTANCE: OnceCell<RwLock<Config>> = OnceCell::new();

pub const FDP_PATH: &str = "src/extern";

// Program check options
pub const EXECUTION_TIMEOUT: u64 = 180;

pub const SANITIZATION_TIMEOUT: u64 = 1200;

pub const MIN_FUZZ_TIME: u64 = 60;

pub const MAX_FUZZ_TIME: u64 = 600;

pub const MAX_CONTEXT_APIS: usize = 100;

// recover the report of UBSan, or we can use UBSAN_OPTIONS=symbolize=1:print_stacktrace=1:halt_on_error=1 instead.
pub const SANITIZER_FLAGS: [&str; 7] = [
    "-fsanitize=fuzzer",
    "-g",
    "-O1",
    "-fsanitize=address,undefined",
    "-ftrivial-auto-var-init=zero",
    "-fsanitize-trap=undefined",
    "-fno-sanitize-recover=undefined",
];

pub const FUZZER_FLAGS: [&str; 5] = [
    "-fsanitize=fuzzer",
    "-O1",
    "-g",
    "-fsanitize=address,undefined",
    "-ftrivial-auto-var-init=zero",
];

pub const COVERAGE_FLAGS: [&str; 9] = [
    "-g",
    "-fsanitize=fuzzer",
    "-fprofile-instr-generate",
    "-fcoverage-mapping",
    "-Wl,--no-as-needed",
    "-Wl,-ldl",
    "-Wl,-lm",
    "-Wno-unused-command-line-argument",
    "-ftrivial-auto-var-init=zero",
];

pub const ASAN_OPTIONS: [&str; 2] = ["exitcode=168", "alloc_dealloc_mismatch=0"];

pub fn get_openai_model_name() -> String {
    OPENAI_MODEL_NAME.get().unwrap().to_string()
}

pub fn get_openai_endpoint() -> String {
    OPENAI_ENDPOINT.get().unwrap().to_string()
}


pub fn init_openai_env() {
    let model = std::env::var("OPENAI_MODEL_NAME").unwrap_or_else(|_| panic!("OPENAI_MODEL_NAME not set"));
    let endpoint = std::env::var("OPENAI_ENDPOINT").unwrap_or_else(|_| panic!("OPENAI_ENDPOINT not set"));

    OPENAI_MODEL_NAME.set(model).unwrap();
    OPENAI_ENDPOINT.set(endpoint).unwrap();
}

pub fn get_config() -> RwLockReadGuard<'static, Config>{
    CONFIG_INSTANCE.get().unwrap().read().unwrap()
}


pub fn get_library_name() -> String {
    let config = CONFIG_INSTANCE.get().unwrap().read().unwrap();
    
    config.target.clone()
}

pub fn get_sample_num() -> u8 {
    let config = CONFIG_INSTANCE.get().unwrap().read().unwrap();
    config.n_sample
}

pub fn get_minimize_compile_flag() -> &'static str {
    static MIN_FLAG: OnceCell<String> = OnceCell::new();
    MIN_FLAG.get_or_init(|| {
        let mut minimize_flag: String = "-fsanitize-coverage-ignorelist=".into();
        let bl_file = Deopt::get_coverage_bl_file_name().unwrap();
        minimize_flag.push_str(&bl_file);
        minimize_flag
    })
}
pub fn parse_config() -> eyre::Result<()> {
    let config = Config::parse();
    CONFIG_INSTANCE.set(RwLock::new(config)).unwrap();
    let deopt = Deopt::new(get_library_name())?;
    let data = deopt.get_library_data_dir()?;
    if !data.exists() {
        eyre::bail!(
            "Cannot find the entry {} in `data` dir, please prepare it in anvance.",
            deopt.config.project_name
        );
    }
    let lib = deopt.get_library_build_lib_path()?;
    if !lib.exists() {
        eyre::bail!("Cannot find the build library {} in `output/build` dir, please build it by build.sh in anvance.", deopt.config.project_name);
    }
    Ok(())
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author="Anonymous", name = "LLMFuzzer", version, about="A LLM based Fuzer", long_about = None)]
pub struct Config {
    /// The target project you decide to fuzz. Available: ["cJSON", "c-ares", "libvpx", "libaom", "libpng", "cre2", "curl", "lcms", "libjpeg-turbo", "libmagic", "libtiff", "sqlite3", "zlib", "libpcap"]
    pub target: String,
    /// Sample N outputs per LLM's request, max: 128
    #[arg(short, long, default_value = "10")]
    pub n_sample: u8,
    /// Sampling temperature. Higher values means the model will take more risks. Try 0.9 for more creative applications, and 0 (argmax sampling) for ones with a well-defined answer.
    #[arg(short, long, default_value = "0.9")]
    pub temperature: f32,
    /// Whether to use the deepseek reasoning.
    #[arg(long, default_value = "false")]
    pub deepseek_reasoning: bool,
    /// whether use the power schedule to mutate prompt. true for purly random mutation of prompt.
    #[arg(short, long, default_value = "false")]
    pub disable_power_schedule: bool,
    /// The number of successful programs should be generated for a prompt. Once satisfy, a round is finished.
    #[arg(long = "fr", default_value = "1")]
    pub fuzz_round_succ: usize,
    /// How number of round without new coverage is considered as converge. When the coverage reachs the converge, the fuzzing will stop. Set to 0 to disable the converge check.
    #[arg(long = "fc", default_value = "10")]
    pub fuzz_converge_round: usize,
    /// number of cores used to parallely run the fuzzers.
    #[arg(short, long, default_value = "1")]
    pub cores: usize,
    /// The maximum of cpu cores used in the sanitization phase. Excelerate the validation speed. Default is 0, which means the number of available cpu cores.
    #[arg(short, long, default_value = "0")]
    pub max_cores: usize,
    #[arg(short, long, default_value = "false")]
    pub exponent_branch: bool,
    /// Whether to recheck the seeds during the fuzz loop is a decision that is strongly recommended. Enabling this option can help reduce false positives, but it may come at the cost of increased execution time.
    #[arg(short, long, default_value = "true")]
    pub recheck: bool,
    /// Run condensed fuzzers after the fuzz loop
    #[arg(long, default_value = "false")]
    pub fuzzer_run: bool
}

impl Config {
    pub fn init_test(target: &str) {
        let config = Config {
            target: target.to_string(),
            n_sample: 10,
            temperature: 0.6,
            deepseek_reasoning: false,
            cores: 10,
            max_cores: 0,
            fuzz_round_succ: 1,
            fuzz_converge_round: 10,
            exponent_branch: false,
            recheck: false,
            fuzzer_run: false,
            disable_power_schedule: false,
        };
        let _ = CONFIG_INSTANCE.set(RwLock::new(config));
        crate::init_debug_logger().unwrap();
    }
}


/// custom configuration of each project
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LibConfig {
    ///the project name that used in build.sh
    pub project_name: String,
    /// the name of the static linked library.
    pub static_lib_name: String,
    /// the name of the static linked library.
    pub dyn_lib_name: String,
    /// vec of functions that are banned.
    pub ban: Option<Vec<String>>,
    /// if the fuzzer input should be terminated with null.
    pub null_term: Option<bool>,
    /// The extra c flags passed to compiler
    pub extra_c_flags: Option<Vec<String>>,
    /// The landmark corpus prompt as example of input.
    pub landmark: Option<bool>,
    /// The types need to be forced added into prompt
    pub force_types: Option<Vec<String>>,
    /// Whether this library should be fuzzed in fork mode.
    pub fuzz_fork: Option<bool>,
    /// The short description of this library to let LLM know what the library is.
    pub desc: Option<String>,
    /// The statements used to initialize the library.
    pub spec: Option<String>,
    /// The additional initialization file used in setup.
    pub init_file: Option<String>,
    /// The extra ASAN options used for libraries.
    pub asan_option: Option<String>,
    /// Whether disable fmemopen.
    pub disable_fmemopen: Option<bool>,
    /// Memory limit passed to libfuzzer
    pub rss_limit_mb: Option<usize>,
}

impl LibConfig {
    pub fn should_terminate_with_null(&self) -> bool {
        if let Some(term) = &self.null_term {
            return *term;
        }
        false
    }
}

/// Template of generative prompt in system role.
pub const SYSTEM_GEN_TEMPLATE: &str = "Act as a C++ langauge Developer, write a fuzz driver that follow user's instructions.
The prototype of fuzz dirver is: `extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t data, size_t size)`.
\n";

/// Template of providing the context of library's structures.
pub const SYSTEM_CONTEXT_TEMPLATE: &str = "
The fuzz dirver should focus on the usage of the {project} library, and several essential aspects of the library are provided below.
Here are the system headers included in {project}. You can utilize the public elements of these headers:
----------------------
{headers}
----------------------

Here are the APIs exported from {project}. You are encouraged to use any of the following APIs once you need to create, initialize or destory variables:
----------------------
{APIs}
----------------------

Here are the custom types declared in {project}. Ensure that the variables you use do not violate declarations:
----------------------
{context}
----------------------
";

pub const USER_GEN_TEMPLATE: &str = "Create a C++ language program step by step by using {project} library APIs and following the instructions below:
1. Here are several APIs in {project}. Specific an event that those APIs could achieve together, if the input is a byte stream of {project}' output data.
{combinations};
2. Complete the LLVMFuzzerTestOneInput function to achieve this event by using those APIs. Each API should be called at least once, if possible.
3. The input data and its size are passed as parameters of LLVMFuzzerTestOneInput: `const uint8_t *data` and `size_t size`. They must be consumed by the {project} APIs.
4. Once you need a `FILE *` variable to read the input data, using `FILE * in_file = fmemopen((void *)data, size, \"rb\")` to produce a `FILE *` variable.
   Once you need a `FILE *` variable to write output data, using `FILE * out_file = fopen(\"output_file\", \"wb\")` to produce a `FILE *` variable.
5. Once you need a `int` type file descriptor, using `fileno(in_file)` or `fileno(out_file)` to produce a file descriptor for reading or writing. 
6. Once you just need a string of file name, directly using \"input_file\" or \"output_file\" as the file name.
7. Release all allocated resources before return.
";

pub fn get_sys_gen_template() -> &'static str {
    pub static TEMPLATE: OnceCell<String> = OnceCell::new();
    TEMPLATE.get_or_init(|| SYSTEM_GEN_TEMPLATE.to_string())
}

pub fn get_user_gen_template() -> &'static str {
    pub static GTEMPLATE: OnceCell<String> = OnceCell::new();
    GTEMPLATE.get_or_init(|| {
        let config = get_config();
        let template = USER_GEN_TEMPLATE.to_string();
        template.replace("{project}", &config.target)
    })
}

pub fn get_user_chat_template() -> String {
    let library_name = get_library_name();
    let deopt = Deopt::new(library_name).unwrap();
    let mut template = get_user_gen_template().to_string();
    if let Some(landmark) = deopt.get_library_landmark_corpus() {
        template.insert_str(0, &format!("The input data is: {landmark}\n\n\n."));
    }
    if let Some(init) = &deopt.config.spec {
        template.push_str(&format!("\nThe begining of the fuzz driver is: \n{init}"))
    }
    if let Some(disable_fmemopen) = &deopt.config.disable_fmemopen {
        if *disable_fmemopen {
            template = template.replace(
                "fmemopen((void *)data, size, \"rb\")",
                "fopen(\"input_file\", \"rb\")",
            );
        }
    }
    template
}
