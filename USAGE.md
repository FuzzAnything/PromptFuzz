# Usage
## 🔧 Build Pre-requisites

You can build the environment from the [Dockerfile](Docekrfile):
```
cd PromptFuzz
docker build -t promptfuzz .
```

Start the docker container in daemon mode:
```
CONTAINER_NAME=<YOUR_CONTAINER_NAME>
docker run -itd -v $(pwd):/root/promptfuzz:Z --security-opt seccomp=unconfined --cap-add SYS_ADMIN --cap-add NET_ADMIN --name ${CONTAINER_NAME} promptfuzz /bin/bash
```
Then, attach into the docker container:
```
docker exec -it${CONTAINER_NAME} /bin/bash
# using tmux to maintian a persistent session
$ tmux new
```

-----
For developers and advance usage, see [DEVELOPER.md](DEVELOPER.md).

## 🦄Basic Usage

### 1. Build library
We provided a set of ready-to-use libraries for *PromptFuzz*. You can see the list in the [libraries](libraries) directory.

*PromptFuzz*'s analysis relies on the building artifacts (i.e., headers and libs). 

We should prepare the building artifacts for your target library by following:
1. Execute the `build.sh` under your library directory. E.g., [build.sh](libraries/cJSON/build.sh) for cJSON.
2. The building artifacts should be generate under the [output/build](output/build) directory..

### 2. Configurate LLM APIs
*PromptFuzz* uses [OPENAI API Specification](https://platform.openai.com/docs/api-reference/introduction) to access LLM API service. You must configurate the following items to enable the LLM invocations:

- `OPENAI_ENDPOINT` : Your LLM service address.
- `OPENAI_MODEL_NAME`: Your LLM service model name.
- `OPENAI_API_KEY`: Your LLM service access key.

Export them as environment variables or write them in the [.env](.env) file, see template [.env_template](.env_template) (reanme this file to .env).

### 4. Generate Fuzz drivers

PromptFuzz generates fuzz drivers in a fuzz loop. 

For instance, the following command is sufficient to perform fuzzing on libaom:
```
cargo run --bin fuzzer -- libaom
```

There are several options that can be tuned in the configuration of promptfuzz. The detailed configurations of promptfuzz:

```
user@ubuntu$ cargo run --bin fuzzer -- --help
```

### 5. Run fuzz drivers
Once the fuzz drivers generated finish, you should follow the follow steps to run the fuzz drivers and detect bugs.

Take libaom is an example, you can run this command to fuse the programs into a fuzz driver that can be fuzzed:

`cargo run --bin harness -- libaom fuse-fuzzer`

And, you can execute the fuzzers you fused:

`cargo run --bin harness -- libaom fuzzer-run`

> Note that, promptfuzz implements the mechanism to detect the crashed program inside the fused fuzz driver.
 If a crash of a program has detected, promptfuzz will disable the code of the crashed program, which enables an continuously fuzzing. So, ensure that executing the fuzz drivers in PromptFuzz.

After 24 hours execution(s), you should deduplicate the reported crashes by PromptFuzz:

`cargo run --bin harness -- libaom sanitize-crash`


Then, you can collect and verbose the code coverage of your fuzzers by:

`cargo run --bin harness -- libaom coverage collect`

and 

`cargo run --bin harness -- libaom coverage report`


## 🎈Advance Usage
We also provide a harness named `harness` to facilitate you access some core components of PromptFuzz.

Here is the command input of `harness`:
```
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
        /// the count of cpu cores you could use
        #[arg(short, default_value = "10")]
        cpu_cores: usize,
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

```