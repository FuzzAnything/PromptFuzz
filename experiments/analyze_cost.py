import os
import re

def analyze_log_directory(directory_path):
    pattern = r"Prompt:\s*(\d+),\s*Completion:\s*(\d+),\s*Total:\s*(\d+)"
    
    grand_total_prompt = 0
    grand_total_completion = 0
    grand_total_tokens = 0
    
    print(f"{'文件名':<30} | {'Prompt':>10} | {'Completion':>10} | {'Total':>10}")
    print("-" * 70)

    for filename in os.listdir(directory_path):
        if filename.endswith(".log"):
            file_path = os.path.join(directory_path, filename)
            
            file_prompt = 0
            file_completion = 0
            file_total = 0
            
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(pattern, line)
                    if match:
                        file_prompt += int(match.group(1))
                        file_completion += int(match.group(2))
                        file_total += int(match.group(3))
            
            grand_total_prompt += file_prompt
            grand_total_completion += file_completion
            grand_total_tokens += file_total
            
            print(f"{filename[:30]:<30} | {file_prompt:>10,} | {file_completion:>10,} | {file_total:>10,}")

    print("-" * 70)
    print(f"{'所有文件总计':<30} | {grand_total_prompt:>10,} | {grand_total_completion:>10,} | {grand_total_tokens:>10,}")

log_dir = '/root/promptfuzz/output/ffmpeg' 
analyze_log_directory(log_dir)