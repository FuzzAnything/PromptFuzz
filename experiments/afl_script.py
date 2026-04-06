import argparse
import yaml
import os
import subprocess
import shutil
import datetime

ROOT_DIR = "/root/promptfuzz"
OTUPUT_DIR = f"{ROOT_DIR}/output"
BUILD_DIR = f"{OTUPUT_DIR}/build"
LIBRARY_DATA_DIR = f"{ROOT_DIR}/libraries"


def load_shared_library_name(project_name: str):
    yaml_path = f"{LIBRARY_DATA_DIR}/{project_name}/config.yaml"
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("dyn_lib_name")

def load_static_library_name(project_name: str):
    yaml_path = f"{LIBRARY_DATA_DIR}/{project_name}/config.yaml"
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("static_lib_name")

def load_compilation_extra_flags(project_name: str):
    yaml_path = f"{LIBRARY_DATA_DIR}/{project_name}/config.yaml"
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("extra_c_flags", [])

def get_afl_static_lib_path(project_name: str):
    static_lib_name = load_static_library_name(project_name)
    if not static_lib_name:
        raise ValueError(f"Static library name not found for project {project_name}")
    afl_static_lib_name = static_lib_name.replace(".a", "_afl.a")
    static_lib_path = f"{BUILD_DIR}/{project_name}/lib/{afl_static_lib_name}"
    if not os.path.exists(static_lib_path):
        raise FileNotFoundError(f"Static library {static_lib_path} does not exist.")
    return static_lib_path

def get_cov_static_lib_path(project_name: str):
    static_lib_name = load_static_library_name(project_name)
    if not static_lib_name:
        raise ValueError(f"Static library name not found for project {project_name}")
    cov_static_lib_name = static_lib_name.replace(".a", "_cov.a")
    static_lib_path = f"{BUILD_DIR}/{project_name}/lib/{cov_static_lib_name}"
    if not os.path.exists(static_lib_path):
        raise FileNotFoundError(f"Static library {static_lib_path} does not exist.")
    return static_lib_path

def get_cov_shared_lib_path(project_name: str):
    shared_lib_name = load_shared_library_name(project_name)
    if not shared_lib_name:
        raise ValueError(f"Shared library name not found for project {project_name}")
    cov_shared_lib_name = shared_lib_name.replace(".so", "_cov.so")
    shared_lib_path = f"{BUILD_DIR}/{project_name}/lib/{cov_shared_lib_name}"
    if not os.path.exists(shared_lib_path):
        raise FileNotFoundError(f"Shared library {shared_lib_path} does not exist.")
    return shared_lib_path

def get_project_include_dir(project_name: str):
    include_dir = f"{BUILD_DIR}/{project_name}/include"
    if not os.path.exists(include_dir):
        raise FileNotFoundError(f"Include directory {include_dir} does not exist.")
    return include_dir

def get_3rd_party_lib_dirs(project_name: str) -> str | None:
    entry = f"{BUILD_DIR}/{project_name}/work//lib"
    if os.path.exists(entry):
        return entry
    return None

def compile_afl_fuzzer(project_name):
    # Placeholder for the actual compilation logic
    print(f"Compiling AFL fuzzer for project: {project_name}")
    # Here you would add the actual commands to compile the AFL fuzzer
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")
    
    cc_files = [f for f in os.listdir(fuzzer_dir) if f.endswith(".cc")]
    if not cc_files:
        raise FileNotFoundError(f"No .cc files found in {fuzzer_dir}.")
    cmd = [
        "afl-clang-lto++",
        f"-I{get_project_include_dir(project_name)}",
        f"-I/root/promptfuzz/src/extern",
        get_afl_static_lib_path(project_name),
        "-fsanitize=address,fuzzer,undefined",
        "-o", f"afl_fuzzer",
    ]
    if get_3rd_party_lib_dirs(project_name):
        cmd.append(f"-L{get_3rd_party_lib_dirs(project_name)}")
    cmd.extend([os.path.join(fuzzer_dir, f) for f in cc_files])
    extra_flags = load_compilation_extra_flags(project_name)
    if extra_flags:
        cmd.extend(extra_flags)
    print("Compilation command:", " ".join(cmd))
    output = subprocess.run(cmd, cwd=fuzzer_dir, capture_output=True, text=True)
    if output.returncode != 0:
        print("Compilation failed with the following error:")
        print(output.stderr)
        raise RuntimeError("AFL fuzzer compilation failed.")
    else:
        print("AFL fuzzer compiled successfully.")
        print("Run the fuzzer with the following command: `afl-fuzz -i corpus -o output -V 86400 -t 10000 -- ./afl_fuzzer`")
        print("If you are testing network libraries, please using brwap to isolate the netwrok: `bwrap --bind / / --dev /dev --proc /proc --unshare-net -- afl-fuzz -i corpus -o output -V 86400 -t 10000 -- ./afl_fuzzer`")

def compile_cov_fuzzer(project_name):
        # Placeholder for the actual compilation logic
    print(f"analyzing coverage data for project: {project_name}")
    # Here you would add the actual commands to compile the coverage fuzzer
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")
    
    afl_queue_dir = os.path.join(fuzzer_dir, "output", "default", "queue")
    if not os.path.exists(afl_queue_dir):
        raise FileNotFoundError(f"AFL queue directory {afl_queue_dir} does not exist.")
    corpus_dir = os.path.join(fuzzer_dir, "corpus")
    if os.path.exists(corpus_dir):
        shutil.copytree( corpus_dir, corpus_dir + "_orig", dirs_exist_ok=True)
        shutil.rmtree(corpus_dir, ignore_errors=True)
    minimized_corpus_dir = os.path.join(fuzzer_dir, "minimized_corpus")
    if os.path.exists(minimized_corpus_dir):
        shutil.rmtree(minimized_corpus_dir, ignore_errors=True)
    shutil.copytree(afl_queue_dir, minimized_corpus_dir, dirs_exist_ok=True)
    dot_state_dir = os.path.join(minimized_corpus_dir, ".state")
    if os.path.exists(dot_state_dir):
        shutil.rmtree(dot_state_dir, ignore_errors=True)
    print(f"Copied AFL queue files from {afl_queue_dir} to {minimized_corpus_dir} for coverage fuzzing.")
    print(f"Please execute `cargo run --bin harness -- {project_name} coverage collect` to collect the coverage in fuzzing.")
    for file in os.listdir(fuzzer_dir):
        if file.endswith(".cc") and file.startswith("id_"):
            continue
        if file == "fuzzer.cc":
            continue
        file_path = os.path.join(fuzzer_dir, file)
        if not os.path.isfile(file_path):
            continue
        if file in ["afl_fuzzer", "fuzzer", "fuzzer_cov", "default.profdata"]:
            continue
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Failed to remove {file_path}: {e}")
        


def analyze_afl_crashes(project_name: str):
    # Placeholder for the actual analysis logic
    print(f"Analyzing AFL crashes for project: {project_name}")
    # Here you would add the actual commands to analyze the AFL crashes
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")
    afl_crashes_dir = os.path.join(fuzzer_dir, "output", "default", "crashes")
    if not os.path.exists(afl_crashes_dir):
        raise FileNotFoundError(f"AFL crashes directory {afl_crashes_dir} does not exist.")
    crash_number = len(os.listdir(afl_crashes_dir))
    print(f"Number of AFL crashes found: {crash_number}")
    crash_save_dir = os.path.join(fuzzer_dir, "work")
    os.makedirs(crash_save_dir, exist_ok=True)
    for crash_file in os.listdir(afl_crashes_dir):
        crash_path = os.path.join(afl_crashes_dir, crash_file)
        if os.path.isfile(crash_path):
            save_path = os.path.join(crash_save_dir, "crash-" + crash_file)
            shutil.copy2(crash_path, save_path)
    print(f"Copied AFL crashes to {crash_save_dir}")
    print(f"Please execute `cargo run --bin harness -- {project_name} sanitize-crash` to analyze the crashes.")


def archive_afl_results(project_name: str):
    print(f"Archiving AFL results for project: {project_name}")
    src_dir = f"{OTUPUT_DIR}/{project_name}"
    if not os.path.exists(src_dir):
        print(f"Project directory {src_dir} does not exist.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_dir = f"{OTUPUT_DIR}/{project_name}_{timestamp}"
    
    os.makedirs(dest_dir, exist_ok=True)

    # 1. 保留error_seeds, seeds, misc, succeeds, 和log文件
    for item in ["error_seeds", "seeds", "misc", "succeeds", "succ_seeds"]:
        src_item = os.path.join(src_dir, item)
        dest_item = os.path.join(dest_dir, item)
        if os.path.exists(src_item):
            if os.path.isdir(src_item):
                shutil.copytree(src_item, dest_item)
            else:
                shutil.copy2(src_item, dest_item)

    for item in os.listdir(src_dir):
        if item.endswith(".log"):
            shutil.copy2(os.path.join(src_dir, item), dest_dir)

    # 2. 对于work目录，每个子目录下面，比如id_000002，只保留default.profdata
    src_work = os.path.join(src_dir, "work")
    dest_work = os.path.join(dest_dir, "work")
    if os.path.exists(src_work):
        os.makedirs(dest_work, exist_ok=True)
        for subdir in os.listdir(src_work):
            src_subdir = os.path.join(src_work, subdir)
            dest_subdir = os.path.join(dest_work, subdir)
            if os.path.isdir(src_subdir):
                os.makedirs(dest_subdir, exist_ok=True)
                profdata_src = os.path.join(src_subdir, "default.profdata")
                if os.path.exists(profdata_src):
                    shutil.copy2(profdata_src, dest_subdir)

    # 3. 对于exploit_fuzzers目录下面，只保留所有以.cc结尾的文件
    src_exploit = os.path.join(src_dir, "exploit_fuzzers")
    dest_exploit = os.path.join(dest_dir, "exploit_fuzzers")
    if os.path.exists(src_exploit):
        os.makedirs(dest_exploit, exist_ok=True)
        for fuzzer_dir in os.listdir(src_exploit):
            src_fuzzer = os.path.join(src_exploit, fuzzer_dir)
            dest_fuzzer = os.path.join(dest_exploit, fuzzer_dir)
            if os.path.isdir(src_fuzzer):
                os.makedirs(dest_fuzzer, exist_ok=True)
                for file_item in os.listdir(src_fuzzer):
                    if file_item.endswith(".cc"):
                        shutil.copy2(os.path.join(src_fuzzer, file_item), dest_fuzzer)
                    if file_item.startswith("error_") or file_item.startswith("ubsan_"):
                        shutil.copytree(os.path.join(src_fuzzer, file_item), os.path.join(dest_fuzzer, file_item))

    print(f"Archived {project_name} to {dest_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze AFL coverage data")
    parser.add_argument("project_name", type=str, help="Name of the project to analyze")
    parser.add_argument("--compile", action="store_true", help="Whether to compile the AFL fuzzer")
    parser.add_argument("--analyze", action="store_true", help="Analyze crash and coverage data")
    parser.add_argument("--archive", action="store_true", help="Whether to archive the AFL results")

    args = parser.parse_args()
    project_name = args.project_name
    if args.compile:
        compile_afl_fuzzer(project_name)
    if args.analyze:
        compile_cov_fuzzer(project_name)
        analyze_afl_crashes(project_name)
    if args.archive:
        archive_afl_results(project_name)
    afl_dir = f"{OTUPUT_DIR}/afl/{args.project_name}"
