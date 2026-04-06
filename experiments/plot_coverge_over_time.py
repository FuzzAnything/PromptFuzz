import argparse
import os
import json
import subprocess
import matplotlib.pyplot as plt
from afl_script import get_cov_shared_lib_path, OTUPUT_DIR

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

def main():
    parser = argparse.ArgumentParser(description="Plot branch coverage over time for a project.")
    parser.add_argument("project", help="Project name (e.g., libpng, curl)")
    args = parser.parse_args()
    
    project = args.project
    work_dir = os.path.join(OTUPUT_DIR, project, "work")
    
    if not os.path.isdir(work_dir):
        print(f"Directory not found: {work_dir}")
        return

    cov_so_path = get_cov_shared_lib_path(project)
    
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
        return
        
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

    plt.figure(figsize=(10, 6))
    plt.plot(times, coverages, marker='o', linestyle='-', markersize=4)
    plt.title(f"Branch Coverage Over Time for {project}")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Number of Covered Branches")
    plt.grid(True)
    
    misc_dir = os.path.join(OTUPUT_DIR, project, "misc")
    os.makedirs(misc_dir, exist_ok=True)
    
    output_png = os.path.join(misc_dir, f"{project}_branch_coverage.png")
    plt.savefig(output_png)
    print(f"Plot saved to {output_png}")
    
    output_json = os.path.join(misc_dir, f"{project}_branch_coverage_raw.json")
    with open(output_json, "w") as f:
        json.dump({"times": times, "coverages": coverages}, f, indent=4)
    print(f"Raw data saved to {output_json}")

if __name__ == "__main__":
    main()
