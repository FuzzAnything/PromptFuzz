# Prepare for a new project
If you need to work on a new project, the following works you should prepare for this.

## 1. Write a build script 
For each project, you are required to write a bash script to specifiy the details about how to build this project and where parts to analyze.

The script is similar and compatiable to [OSS-Fuzz](https://github.com/google/oss-fuzz), but required more customization.

The the very begin of the script, you should always include the `../common.sh` and specific your **project's name** and the **linked library name** you have built.
```
source ../common.sh

PROJECT_NAME=cjson
STALIB_NAME=libcjson.a
DYNLIB_NAME=libcjson.so
```
Environment Variables: 
- **LIB_STORE_DIR**: The directory where store the built link libraries.
- **PROJECT_NAME**: This project's name.
- **STALIB_NAME**: Name of the built statically linked library name.
- **DYNLIB_NAME**:  Name of the built dynamically linked library name.


Also, here are the functions you need implement for each library:
- **download**: specify where to download this project.
- **build_lib**: specify the commands to build this library. The commands could be directly copyied from OSS-Fuzz.
- **build_oss_fuzz**: specify how to build the interal fuzzers of this project.  Could be directly copyied from OSS-Fuzz.
- **build_corpus**: download the fuzzer corpus and copy them to ${LIB_BUILD}/corpus.
- **build_dict**: download the fuzzer dictionary and copy them to ${LIB_BUILD}/fuzzer.dict.
- **copy_include**: copy the header files that you want to analyze to ${LIB_BUILD}/include.

After, a `build_all` is required to call those above processes.

You can refer to the [build.sh](data/cJSON/build.sh) to implement the above functions.

## 2. Write a project configuration
The config file is `config.yaml`, you could write few customization for you project.

The following three fields are mandatory for all library:
- **project_name**: Type(String)
- **static_lib_name**: Type(String)
- **dyn_lib_name**: Type(String)

Those three fields should be same to the **PROJECT_NAME**, **STALIB_NAME** and **DYNLIB_NAME** you write in `build.sh`.

We have also provided some options for you to fine-tune on each project. In most cases, using the default values for these options is sufficient. However, for libraries designed with specific mechanisms, you may need to adjust them to appropriate values in order to increase effectiveness or minimize false positives.
- **ban**: Type(Option\<Vec<String\>>, default=None). The list of functions you do not want to use.
- **null_term**: Type(bool, default=false). If true, the random input passed from fuzzer will be appended with a terminal character of '\x00'.
- **extra_c_flags**: Type(Option\<Vec<String\>>, default=None), The list of compiler flags you want to add in the compilations of programs.
- **landmark**: Type(bool, default=None). If true, choose an corpora from fuzzing copus and provide it as an input example to LLMs.
- **force_types**: Type(Option\<Vec\<String\>\>, default=None). The list of custom types you want to be always prompted to LLMs. 
- **fuzz_fork**: Type(Option\<bool\>, default=false). If true, run LibFuzzer in the fork mode.
- **desc**: Type(Option\<String\>, default=None). Provided short description of this library to let LLMs know what the library is.
- **spec**: Type(Option\<String\>, default=None). The library specifications used in the library.
- **init_file**: Type(Option\<String\>, default=None). The initialization file used in library setup.
- **asan_options**: Type(Option<String>, defalut=None). The extra ASAN options used for sanitization.
- **disable_fmemopen**: Type(bool, default=false). If true, disable the usage of `fmemopen` and replace it to `fopen`.
- **rss_limit_mb**: Type(Option<usize>, default=None). The memory limit that allowed for each fuzz driver in this library.

