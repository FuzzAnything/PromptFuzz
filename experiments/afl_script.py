import argparse
import yaml
import os
import subprocess
import shutil
import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
    entry = f"{BUILD_DIR}/{project_name}/work/lib"
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
        print("If you are testing network libraries, please using brwap to isolate the netwrok: `bwrap --bind / / --dev /dev --proc /proc --unshare-net --tmpfs /tmp -- afl-fuzz -i corpus -o output -V 86400 -t 10000 -- ./afl_fuzzer`")

def compile_cov_fuzzer(project_name):
        # Placeholder for the actual compilation logic
    print(f"compile coverage fuzzer for project: {project_name}")
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

def compile_repeat_cov_fuzzer(project_name: str):
    print(f"Compiling repeat coverage fuzzer for project: {project_name}")
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")

    cc_files = [f for f in os.listdir(fuzzer_dir) if f.endswith(".cc")]
    if not cc_files:
        raise FileNotFoundError(f"No .cc files found in {fuzzer_dir}.")

    cmd = [
        "clang++",
        f"-I{get_project_include_dir(project_name)}",
        "-I/root/promptfuzz/src/extern",
        "-g",
        "-fsanitize=fuzzer",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        "-Wl,--no-as-needed",
        "-Wl,-ldl",
        "-Wl,-lm",
        "-Wno-unused-command-line-argument",
        "-ftrivial-auto-var-init=zero",
        "-o",
        "fuzzer_cov",
    ]
    if get_3rd_party_lib_dirs(project_name):
        cmd.append(f"-L{get_3rd_party_lib_dirs(project_name)}")
    cmd.extend([os.path.join(fuzzer_dir, f) for f in cc_files])
    cmd.append(get_cov_static_lib_path(project_name))

    extra_flags = load_compilation_extra_flags(project_name)
    if extra_flags:
        cmd.extend(extra_flags)

    print("Compilation command:", " ".join(cmd))
    output = subprocess.run(cmd, cwd=fuzzer_dir, capture_output=True, text=True)
    if output.returncode != 0:
        print("Compilation failed with the following error:")
        print(output.stderr)
        raise RuntimeError("repeat coverage fuzzer compilation failed.")
    print("repeat coverage fuzzer compiled successfully.")

def _find_repeat_round_dirs(fuzzer_dir: str):
    round_dirs = []
    for entry in os.listdir(fuzzer_dir):
        if not entry.startswith("output_round_"):
            continue
        suffix = entry.replace("output_round_", "", 1)
        if not suffix.isdigit():
            continue
        round_dirs.append((int(suffix), os.path.join(fuzzer_dir, entry)))
    round_dirs.sort(key=lambda x: x[0])
    return round_dirs

def _run_cov_fuzzer_on_queue(fuzzer_cov: str, queue_dir: str, profraw_dir: str, run_log: str):
    env = os.environ.copy()
    fuzzer_dir = os.path.dirname(fuzzer_cov)
    queue_files = []
    for item in sorted(os.listdir(queue_dir)):
        if item.startswith("."):
            continue
        path = os.path.join(queue_dir, item)
        if os.path.isfile(path):
            queue_files.append(path)

    if not queue_files:
        raise RuntimeError(f"No valid queue files found in {queue_dir}")

    failed = 0
    with open(run_log, "w") as logf:
        for idx, seed in enumerate(queue_files):
            profraw = os.path.join(profraw_dir, f"seed_{idx:06d}.profraw")
            env["LLVM_PROFILE_FILE"] = profraw
            sandbox_cmd = [
                "bwrap",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--unshare-net",
                "--bind", fuzzer_dir, fuzzer_dir,
                "--tmpfs", "/tmp",
                "--die-with-parent",
                "--new-session",
            ]
            cmd = sandbox_cmd + ["stdbuf", "-oL", "-eL", fuzzer_cov, seed, "-runs=0"]
            try:
                output = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    timeout=120,
                    cwd=fuzzer_dir,
                )
                output = type("R", (), {
                    "returncode": output.returncode,
                    "stdout": output.stdout.decode("utf-8", errors="replace"),
                    "stderr": output.stderr.decode("utf-8", errors="replace"),
                })()
            except subprocess.TimeoutExpired as exc:
                failed += 1
                logf.write(f"=== seed: {seed} ===\n")
                logf.write("returncode: timeout\n")
                if exc.stdout:
                    logf.write(str(exc.stdout))
                if exc.stderr:
                    logf.write(str(exc.stderr))
                logf.write("\n")
                continue
            logf.write(f"=== seed: {seed} ===\n")
            logf.write(f"returncode: {output.returncode}\n")
            if output.stdout:
                logf.write(output.stdout)
            if output.stderr:
                logf.write(output.stderr)
            logf.write("\n")

            if output.returncode != 0:
                failed += 1

    print(f"Executed {len(queue_files)} queue files from {queue_dir}, failed: {failed}")

def _merge_profraw_to_profdata(profraw_dir: str, profdata: str):
    profraw_files = [
        os.path.join(profraw_dir, f)
        for f in os.listdir(profraw_dir)
        if f.endswith(".profraw")
    ]
    if not profraw_files:
        raise RuntimeError(f"No .profraw files found in {profraw_dir}")

    cmd = ["llvm-profdata", "merge", "-sparse"]
    if len(profraw_files) > 5000:
        cmd.append(profraw_dir)
    else:
        cmd.extend(profraw_files)
    cmd.extend(["-o", profdata])

    output = subprocess.run(cmd, capture_output=True, text=True)
    if output.returncode != 0:
        print(output.stderr)
        raise RuntimeError("llvm-profdata merge failed")

def _export_round_cov(cov_lib: str, profdata: str, export_json: str, report_txt: str):
    export_cmd = [
        "llvm-cov",
        "export",
        cov_lib,
        "--skip-expansions",
        f"--instr-profile={profdata}",
    ]
    with open(export_json, "w") as f:
        output = subprocess.run(export_cmd, stdout=f, stderr=subprocess.PIPE, text=True)
    if output.returncode != 0:
        print(output.stderr)
        raise RuntimeError("llvm-cov export failed")

    report_cmd = [
        "llvm-cov",
        "report",
        cov_lib,
        f"--instr-profile={profdata}",
    ]
    with open(report_txt, "w") as f:
        output = subprocess.run(report_cmd, stdout=f, stderr=subprocess.PIPE, text=True)
    if output.returncode != 0:
        print(output.stderr)
        raise RuntimeError("llvm-cov report failed")

def execute_repeat_cov(project_name: str):
    compile_repeat_cov_fuzzer(project_name)

    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    fuzzer_cov = os.path.join(fuzzer_dir, "fuzzer_cov")
    if not os.path.exists(fuzzer_cov):
        raise FileNotFoundError(f"coverage fuzzer binary {fuzzer_cov} does not exist")
    cov_lib = get_cov_shared_lib_path(project_name)

    round_dirs = _find_repeat_round_dirs(fuzzer_dir)
    if not round_dirs:
        raise FileNotFoundError(f"No repeat AFL outputs found under {fuzzer_dir}")

    for round_id, round_output_dir in round_dirs:
        queue_dir = os.path.join(round_output_dir, "default", "queue")
        if not os.path.exists(queue_dir):
            print(f"Skip round {round_id}: queue not found in {queue_dir}")
            continue

        cov_dir = os.path.join(round_output_dir, "coverage")
        if os.path.exists(cov_dir):
            shutil.rmtree(cov_dir, ignore_errors=True)
        profraw_dir = os.path.join(cov_dir, "profraw")
        Path(profraw_dir).mkdir(parents=True, exist_ok=True)

        profdata = os.path.join(cov_dir, "round.profdata")
        export_json = os.path.join(cov_dir, "llvm_cov_export.json")
        report_txt = os.path.join(cov_dir, "llvm_cov_report.txt")
        run_log = os.path.join(cov_dir, "fuzzer_cov_run.log")

        print(f"Collecting coverage for round {round_id} from {queue_dir}")
        _run_cov_fuzzer_on_queue(fuzzer_cov, queue_dir, profraw_dir, run_log)
        _merge_profraw_to_profdata(profraw_dir, profdata)
        _export_round_cov(cov_lib, profdata, export_json, report_txt)
        print(f"Saved round {round_id} coverage artifacts under {cov_dir}")
        
def execute_afl_fuzzer_repeat(project_name: str, repeat: int):
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")
    corpus_dir = os.path.join(fuzzer_dir, "corpus")
    corpus_orig_dir = os.path.join(fuzzer_dir, "corpus_orig")
    if not os.path.exists(corpus_dir) and not os.path.exists(corpus_orig_dir):
        raise FileNotFoundError(f"Corpus directory {corpus_dir} does not exist.")
    if not os.path.exists(corpus_orig_dir):
        shutil.copytree(corpus_dir, corpus_orig_dir, dirs_exist_ok=True)
    with ThreadPoolExecutor(max_workers=repeat) as executor:
        futures = []
        for round in range(repeat):
            print(f"Starting AFL fuzzing round {round + 1}/{repeat} for project {project_name}")
            future = executor.submit(execute_afl_fuzzer, project_name, round + 1)
            futures.append(future)
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error during AFL fuzzing execution: {e}")

def execute_afl_fuzzer(project_name: str, round: int):
        # Placeholder for the actual compilation logic
    print(f"analyzing coverage data for project: {project_name}")
    # Here you would add the actual commands to compile the coverage fuzzer
    fuzzer_dir = f"{OTUPUT_DIR}/{project_name}/exploit_fuzzers/Fuzzer_000"
    if not os.path.exists(fuzzer_dir):
        raise FileNotFoundError(f"Fuzzer directory {fuzzer_dir} does not exist.")
    fuzzer = os.path.join(fuzzer_dir, "afl_fuzzer")
    if not os.path.exists(fuzzer):
        raise FileNotFoundError(f"AFL fuzzer binary {fuzzer} does not exist. Please compile the AFL fuzzer first.")
    
    round_output_dir = os.path.join(fuzzer_dir, f"output_round_{round}")
    if os.path.exists(round_output_dir):
        shutil.rmtree(round_output_dir, ignore_errors=True)
    os.makedirs(round_output_dir, exist_ok=True)
    corpus_dir = os.path.join(fuzzer_dir, "corpus_orig")
    if not os.path.exists(corpus_dir):
        raise FileNotFoundError(f"Original corpus directory {corpus_dir} does not exist.")
    sandbox_cmd = [
        "bwrap",
        "--ro-bind", "/", "/",       # 1. mount root directory as read-only (Read-Only)
        "--dev", "/dev",             # 2. mount /dev (program usually needs /dev/null, /dev/random)
        "--proc", "/proc",           # 3. mount /proc (if program needs to check process information)
        "--unshare-net",
        "--bind", fuzzer_dir, fuzzer_dir, # 4. mount fuzzer directory as read-write (Read-Write)             
        "--bind", round_output_dir, round_output_dir, # 4. mount output_dir as read-write (Read-Write)
        "--tmpfs", "/tmp",           # Provide an isolated in-memory /tmp for mkstemp
        "--die-with-parent",         # 6. parent process dies, child process dies too
        "--new-session",           # 7. create new process session
    ]

    envs = os.environ.copy()

    envs["AFL_SKIP_CPUFREQ"] = "1"
    envs["AFL_NO_UI"] = "1"
    envs["AFL_DRIVER_CLOSE_FD_MASK"] = "3"
    cmd = sandbox_cmd + ["stdbuf", "-oL", "-eL", "afl-fuzz", "-i", corpus_dir, "-o", round_output_dir,  "-t", "60000", "-V", "86400" ,"--", fuzzer, "@@"]
   
    cmd_str = " ".join(cmd)
    print(f"Executing AFL fuzzer with command: {cmd_str}")
    fuzz_log = os.path.join(round_output_dir, "fuzzing.log")
    with open(fuzz_log, "w") as f:
        outpput = subprocess.run(cmd, env=envs, stdout=f, stderr=subprocess.STDOUT, cwd=round_output_dir, bufsize=1, text=True)
    if outpput.returncode != 0:
        print(f"AFL fuzzer execution failed with return code {outpput.returncode}. Check the log file {fuzz_log} for details.")

        


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
    parser.add_argument("--repeat-exec", type=int, default=0, help="Number of times to repeat AFL fuzzing")
    parser.add_argument("--repeat-cov", action="store_true", help="Collect per-round branch coverage from repeat AFL outputs")

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
    if args.repeat_exec > 0:
        execute_afl_fuzzer_repeat(project_name, args.repeat_exec)
    if args.repeat_cov:
        execute_repeat_cov(project_name)
