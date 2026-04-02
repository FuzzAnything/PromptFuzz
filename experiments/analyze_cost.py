import os
import re
import argparse

ROOT_DIR = "/root/promptfuzz"
OTUPUT_DIR = f"{ROOT_DIR}/output"

# Pricing per 1M tokens (USD) for DeepSeek V3.2
PRICE_CACHE_HIT_PER_1M = 0.028    # cached input tokens
PRICE_CACHE_MISS_PER_1M = 0.28    # non-cached input tokens
PRICE_OUTPUT_PER_1M = 0.42        # output (completion) tokens

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
    print(f"Total harnesses: {total_harnesses}")
    print(f"Successful seeds: {num_succ_seeds}")
    print(f"Unique seeds: {num_seeds}")
    print(f"Execution error seeds: {num_execute_error_seeds}")
    print(f"Fuzzer error seeds: {num_fuzzer_error_seeds}")
    print(f"Hang error seeds: {num_hang_error_seeds}")
    print(f"Syntax error seeds: {num_syntax_error_seeds}")
    



def analyze_log_directory(directory_path):
    grand_total_prompt = 0
    grand_total_cached = 0
    grand_total_completion = 0
    grand_total_tokens = 0
    grand_total_cost = 0.0
    
    print(f"{'FileName':<30} | {'Prompt':>10} | {'Cached':>10} | {'Completion':>10} | {'Total':>10} | {'Cost($)':>10}")
    print("-" * 95)

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
            
            print(f"{filename[:30]:<30} | {file_prompt:>10,} | {file_cached:>10,} | {file_completion:>10,} | {file_total:>10,} | {file_cost:>10.4f}")

    print("-" * 95)
    print(f"{'Total':<30} | {grand_total_prompt:>10,} | {grand_total_cached:>10,} | {grand_total_completion:>10,} | {grand_total_tokens:>10,} | {grand_total_cost:>10.4f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze log files for token usage.")
    parser.add_argument("project_name", help="Name of the project to analyze")
    args = parser.parse_args()
    
    analyze_seed_statistics(args.project_name)
    analyze_log_directory(f"{OTUPUT_DIR}/{args.project_name}")
