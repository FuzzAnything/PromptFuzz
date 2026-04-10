import os
import re
import argparse
import json
import subprocess
import matplotlib.pyplot as plt
import matplotlib as mpl
from afl_script import get_cov_shared_lib_path

ROOT_DIR = "/root/promptfuzz"
OTUPUT_DIR = f"{ROOT_DIR}/output"

# Pricing per 1M tokens (USD) for DeepSeek V3.2
PRICE_CACHE_HIT_PER_1M = 0.028    # cached input tokens
PRICE_CACHE_MISS_PER_1M = 0.28    # non-cached input tokens
PRICE_OUTPUT_PER_1M = 0.42        # output (completion) tokens

def get_coverage(profdata_path, cov_so_path):
    cmd = [
        "llvm-cov", "export",
        "--summary-only",
        f"-instr-profile={profdata_path}",
        cov_so_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return 0
    try:
        data = json.loads(result.stdout)
        branches = data["data"][0]["totals"]["branches"]["covered"]
        return branches
    except (KeyError, IndexError, json.JSONDecodeError):
        return 0


def process_coverage(project, statistics_dir):
    work_dir = os.path.join(OTUPUT_DIR, project, "work")
    cov_so_path = get_cov_shared_lib_path(project)
    
    if not os.path.isdir(work_dir):
        print(f"Directory not found: {work_dir}")
        return 0
        
    seeds = []
    for dir_name in os.listdir(work_dir):
        if not dir_name.startswith("id_"):
            continue
            
        seed_dir = os.path.join(work_dir, dir_name)
        profdata_path = os.path.join(seed_dir, "default.profdata")
        
        if os.path.isfile(profdata_path):
            mtime = os.path.getmtime(profdata_path)
            seeds.append({
                "id": dir_name,
                "profdata": profdata_path,
                "time": mtime
            })
            
    if not seeds:
        print("No default.profdata found in work directory.")
        return 0
        
    seeds.sort(key=lambda x: x["time"])
    
    start_time = seeds[0]["time"]
    times = []
    coverages = []
    
    merged_profdata = f"{project}_merged.profdata"
    
    for i, seed in enumerate(seeds):
        relative_time = seed["time"] - start_time
        
        if i == 0:
            cmd = ["llvm-profdata", "merge", "-sparse", seed["profdata"], "-o", merged_profdata]
        else:
            cmd = ["llvm-profdata", "merge", "-sparse", merged_profdata, seed["profdata"], "-o", merged_profdata]
            
        subprocess.run(cmd, capture_output=True)
        covered_branches = get_coverage(merged_profdata, cov_so_path)
        
        times.append(relative_time)
        coverages.append(covered_branches)
        print(f"Processed {i+1}/{len(seeds)}: {seed['id']} at {relative_time:.2f}s - {covered_branches} branches")

    if os.path.exists(merged_profdata):
        os.remove(merged_profdata)
        
    output_json = os.path.join(statistics_dir, "coverage_growth.json")
    with open(output_json, "w") as f:
        json.dump({"times": times, "coverages": coverages}, f, indent=4)
    print(f"Coverage data saved to {output_json}")
    
    return coverages[-1] if coverages else 0


def analyze_seed_statistics(project_name):
    project_output_dir = f"{OTUPUT_DIR}/{project_name}"
    seeds_dir = os.path.join(project_output_dir, "seeds")
    succ_seeds_dir = os.path.join(project_output_dir, "succ_seeds")
    error_seeds_dir = os.path.join(project_output_dir, "error_seeds")
    execute_error_seeds_dir = os.path.join(error_seeds_dir, "execute")
    fuzzer_error_seeds_dir = os.path.join(error_seeds_dir, "fuzzer")
    hang_error_seeds_dir = os.path.join(error_seeds_dir, "hang")
    syntax_error_seeds_dir = os.path.join(error_seeds_dir, "syntax")
    
    num_seeds = len(os.listdir(seeds_dir)) if os.path.exists(seeds_dir) else 0
    num_succ_seeds = len(os.listdir(succ_seeds_dir)) if os.path.exists(succ_seeds_dir) else 0
    num_execute_error_seeds = len(os.listdir(execute_error_seeds_dir)) if os.path.exists(execute_error_seeds_dir) else 0
    num_fuzzer_error_seeds = len(os.listdir(fuzzer_error_seeds_dir)) if os.path.exists(fuzzer_error_seeds_dir) else 0
    num_hang_error_seeds = len(os.listdir(hang_error_seeds_dir)) if os.path.exists(hang_error_seeds_dir) else 0
    num_syntax_error_seeds = len(os.listdir(syntax_error_seeds_dir)) if os.path.exists(syntax_error_seeds_dir) else 0

    total_harnesses = num_succ_seeds + num_execute_error_seeds + num_fuzzer_error_seeds + num_hang_error_seeds + num_syntax_error_seeds
    
    return {
        "Total harnesses": total_harnesses,
        "Unique seeds": num_seeds,
        "Successful seeds": num_succ_seeds,
        "Execution error seeds": num_execute_error_seeds,
        "Fuzzer error seeds": num_fuzzer_error_seeds,
        "Hang error seeds": num_hang_error_seeds,
        "Syntax error seeds": num_syntax_error_seeds
    }

def analyze_log_directory(directory_path):
    grand_total_prompt = 0
    grand_total_cached = 0
    grand_total_completion = 0
    grand_total_tokens = 0
    grand_total_cost = 0.0

    if not os.path.isdir(directory_path):
        return {
            "Total Tokens": 0,
            "Prompt Tokens": 0,
            "Cached Tokens": 0,
            "Completion Tokens": 0,
            "Total Cost($)": 0.0
        }

    for filename in os.listdir(directory_path):
        if filename.endswith(".log"):
            file_path = os.path.join(directory_path, filename)
            
            file_prompt = 0
            file_cached = 0
            file_completion = 0
            file_total = 0
            
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    pm = re.search(r"Prompt Tokens:\s*(\d+)", line)
                    if pm:
                        file_prompt += int(pm.group(1))
                    cm = re.search(r"Completion Tokens:\s*(\d+)", line)
                    if cm:
                        file_completion += int(cm.group(1))
                    tm = re.search(r"Total Tokens:\s*(\d+)", line)
                    if tm:
                        file_total += int(tm.group(1))
                    cache_m = re.search(r"Cached Tokens:\s*(\d+)", line)
                    if cache_m:
                        file_cached += int(cache_m.group(1))
            
            file_uncached = max(0, file_prompt - file_cached)
            file_cost = (
                (file_cached / 1_000_000) * PRICE_CACHE_HIT_PER_1M +
                (file_uncached / 1_000_000) * PRICE_CACHE_MISS_PER_1M +
                (file_completion / 1_000_000) * PRICE_OUTPUT_PER_1M
            )

            grand_total_prompt += file_prompt
            grand_total_cached += file_cached
            grand_total_completion += file_completion
            grand_total_tokens += file_total
            grand_total_cost += file_cost
            
    return {
        "Total Tokens": grand_total_tokens,
        "Prompt Tokens": grand_total_prompt,
        "Cached Tokens": grand_total_cached,
        "Completion Tokens": grand_total_completion,
        "Total Cost($)": grand_total_cost
    }

def plot_coverage_growth(project, statistics_dir):
    json_path = os.path.join(statistics_dir, "coverage_growth.json")
    if not os.path.isfile(json_path):
        print(f"Error: Could not find coverage data at {json_path}")
        return
        
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {json_path}: {e}")
        return
        
    times_sec = data.get("times", [])
    coverages = data.get("coverages", [])
    
    if not times_sec or not coverages:
        print("Error: Empty or invalid data in coverage_growth.json")
        return
        
    # Convert times from seconds to hours
    times_hours = [t / 3600.0 for t in times_sec]
    
    # Configure Academic Style
    plt.style.use('seaborn-v0_8-paper')
    mpl.rcParams['font.family'] = 'serif'
    mpl.rcParams['axes.labelsize'] = 12
    mpl.rcParams['xtick.labelsize'] = 10
    mpl.rcParams['ytick.labelsize'] = 10
    mpl.rcParams['axes.titlesize'] = 14
    mpl.rcParams['legend.fontsize'] = 10
    mpl.rcParams['figure.dpi'] = 300
    mpl.rcParams['savefig.dpi'] = 300
    
    plt.figure(figsize=(8, 5))
    
    # Plot data
    plt.plot(times_hours, coverages, linestyle='-', marker='', color='#1f77b4', linewidth=2, label=project)
    
    # Configure axes
    plt.xlabel('Time (Hours)')
    plt.ylabel('Covered Branches')
    
    max_time = max(times_hours) if times_hours else 0
    plt.xlim(0, max(24.0, max_time + 0.5))
    
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.title('Coverage Growth Over Time')
    plt.legend(loc='lower right')
    
    plt.tight_layout()
    
    output_png = os.path.join(statistics_dir, "coverage_growth_24h_chart.png")
    output_pdf = os.path.join(statistics_dir, "coverage_growth_24h_chart.pdf")
    
    plt.savefig(output_png, format='png', bbox_inches='tight')
    plt.savefig(output_pdf, format='pdf', bbox_inches='tight')
    plt.close()
    
    print(f"Coverage growth charts saved to:\n  - {output_png}\n  - {output_pdf}")


def main():
    parser = argparse.ArgumentParser(description="Analyze results and plot branch coverage.")
    parser.add_argument("project", help="Project name (e.g., libpng, curl)")
    args = parser.parse_args()
    
    project = args.project
    statistics_dir = os.path.join(OTUPUT_DIR, project, "statistics")
    os.makedirs(statistics_dir, exist_ok=True)
    
    # 1. Process coverage
    final_branches = process_coverage(project, statistics_dir)
    
    # 2. Get seed statistics
    seed_stats = analyze_seed_statistics(project)
    
    # 3. Process logs for cost
    cost_stats = analyze_log_directory(os.path.join(OTUPUT_DIR, project))
    
    # 4. Save results to txt
    cost_file_path = os.path.join(statistics_dir, "cost_info.txt")
    with open(cost_file_path, "w", encoding='utf-8') as f:
        for k, v in seed_stats.items():
            f.write(f"{k}: {v}\n")
            
        for k, v in cost_stats.items():
            if "Cost" in k:
                f.write(f"{k}: {v:.6f}\n")
            else:
                f.write(f"{k}: {v}\n")
                
        f.write(f"Final Covered Branches: {final_branches}\n")
        
    print(f"Statistics saved to {cost_file_path}")
    
    # 5. Plot coverage growth curve
    plot_coverage_growth(project, statistics_dir)

if __name__ == "__main__":
    main()
