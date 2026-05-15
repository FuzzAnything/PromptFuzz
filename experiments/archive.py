import argparse
import os
import shutil
import tarfile
import datetime
from pathlib import Path


ROOT_DIR = "/home/yunlong/work/PromptFuzz"
OUTPUT_DIR = f"{ROOT_DIR}/output_1"


def get_project_list(output_dir: str, project_name: str) -> list[str]:
    """Get list of projects to archive.

    If project_name == "all", return all valid project directories.
    Otherwise return the specified project list.
    Filters out non-project directories (build, buffered_output, etc.)
    """
    if project_name != "all":
        project_path = os.path.join(output_dir, project_name)
        if not os.path.isdir(project_path):
            raise FileNotFoundError(f"Project directory {project_path} does not exist.")
        return [project_name]

    # Get all project directories
    projects = []
    for entry in os.listdir(output_dir):
        entry_path = os.path.join(output_dir, entry)
        if not os.path.isdir(entry_path):
            continue
        # Filter out non-project directories
        if entry in ["build"]:
            continue
        # Check if it has at least one of the expected directories
        expected_dirs = ["seeds", "error_seeds", "succ_seeds", "statistics", "shared_corpus"]
        has_expected = any(os.path.isdir(os.path.join(entry_path, d)) for d in expected_dirs)
        if has_expected:
            projects.append(entry)

    return sorted(projects)


def archive_project_seeds(output_dir: str, project_name: str, temp_dir: str):
    """Archive seeds, error_seeds, succ_seeds, statistics, shared_corpus directories and fuzzer*.log files."""
    src_project = os.path.join(output_dir, project_name)
    dest_project = os.path.join(temp_dir, project_name)
    os.makedirs(dest_project, exist_ok=True)

    dirs_to_archive = ["seeds", "error_seeds", "succ_seeds", "statistics", "shared_corpus"]
    for dir_name in dirs_to_archive:
        src_dir = os.path.join(src_project, dir_name)
        dest_dir = os.path.join(dest_project, dir_name)
        if os.path.isdir(src_dir):
            shutil.copytree(src_dir, dest_dir)
            print(f"  Copied {dir_name} for {project_name}")

    # Copy fuzzer*.log files
    for item in os.listdir(src_project):
        if item.startswith("fuzzer") and item.endswith(".log"):
            src_file = os.path.join(src_project, item)
            dest_file = os.path.join(dest_project, item)
            shutil.copy2(src_file, dest_file)
            print(f"  Copied {item} for {project_name}")


def archive_exploit_fuzzers(output_dir: str, project_name: str, temp_dir: str):
    """Archive exploit_fuzzers with special handling.

    Only keep:
    - All .cc files
    - All output_round_X/coverage directories (without profraw)
    - error_* and ubsan_* directories
    """
    src_exploit = os.path.join(output_dir, project_name, "exploit_fuzzers")
    if not os.path.isdir(src_exploit):
        return

    dest_exploit = os.path.join(temp_dir, project_name, "exploit_fuzzers")
    os.makedirs(dest_exploit, exist_ok=True)

    for fuzzer_entry in os.listdir(src_exploit):
        src_fuzzer = os.path.join(src_exploit, fuzzer_entry)
        dest_fuzzer = os.path.join(dest_exploit, fuzzer_entry)

        if not os.path.isdir(src_fuzzer):
            continue

        os.makedirs(dest_fuzzer, exist_ok=True)

        # Copy .cc files
        for item in os.listdir(src_fuzzer):
            if item.endswith(".cc"):
                src_file = os.path.join(src_fuzzer, item)
                dest_file = os.path.join(dest_fuzzer, item)
                shutil.copy2(src_file, dest_file)

        # Copy error_* and ubsan_* directories
        for item in os.listdir(src_fuzzer):
            if item.startswith("error_") or item.startswith("ubsan_"):
                src_item = os.path.join(src_fuzzer, item)
                dest_item = os.path.join(dest_fuzzer, item)
                if os.path.isdir(src_item):
                    shutil.copytree(src_item, dest_item)
                    print(f"  Copied {item} for {project_name}")

        # Copy coverage directories from output_round_X
        for round_entry in os.listdir(src_fuzzer):
            if not round_entry.startswith("output_round_"):
                continue
            src_round = os.path.join(src_fuzzer, round_entry)
            if not os.path.isdir(src_round):
                continue

            src_coverage = os.path.join(src_round, "coverage")
            if not os.path.isdir(src_coverage):
                continue
            
            # Remove profraw directory if exists
            profraw_dir = os.path.join(src_coverage, "profraw")
            if os.path.isdir(profraw_dir):
                shutil.rmtree(profraw_dir)
                print(f"  Removed profraw from {round_entry}/coverage for {project_name}")

            dest_round = os.path.join(dest_fuzzer, round_entry)
            dest_coverage = os.path.join(dest_round, "coverage")
            shutil.copytree(src_coverage, dest_coverage)
            print(f"  Copied coverage from {round_entry} for {project_name}")


def create_archive(temp_dir: str, output_path: str, project_name: str) -> str:
    """Create tar.gz archive from temp directory."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if project_name == "all":
        archive_name = f"experiment_results_{timestamp}.tar.gz"
    else:
        archive_name = f"experiment_results_{project_name}_{timestamp}.tar.gz"

    archive_path = os.path.join(output_path, archive_name)

    with tarfile.open(archive_path, "w:gz") as tar:
        for item in os.listdir(temp_dir):
            item_path = os.path.join(temp_dir, item)
            tar.add(item_path, arcname=item)

    return archive_path


def main():
    parser = argparse.ArgumentParser(description="Archive experiment results from output directory")
    parser.add_argument(
        "--project",
        type=str,
        default="all",
        help="Target project to archive (default: all)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=".",
        help="Output directory for the archive (default: current directory)"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=OUTPUT_DIR,
        help=f"Input output directory (default: {OUTPUT_DIR})"
    )

    args = parser.parse_args()

    # Validate output directory
    if not os.path.isdir(args.output):
        os.makedirs(args.output, exist_ok=True)

    # Get project list
    print(f"Getting project list for: {args.project}")
    project_list = get_project_list(args.input, args.project)
    print(f"Found {len(project_list)} projects: {project_list}")

    # Create temporary directory for staging
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_dir = os.path.join(args.output, f"temp_archive_{timestamp}")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # Archive each project
        for project_name in project_list:
            print(f"\nArchiving project: {project_name}")
            archive_project_seeds(args.input, project_name, temp_dir)
            archive_exploit_fuzzers(args.input, project_name, temp_dir)

        # Create main archive
        print(f"\nCreating archive...")
        archive_path = create_archive(temp_dir, args.output, args.project)
        print(f"\nArchive created: {archive_path}")

    finally:
        # Cleanup temp directory
        if os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"Cleaned up temporary directory: {temp_dir}")


if __name__ == "__main__":
    main()