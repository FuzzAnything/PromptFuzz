import argparse
import csv
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_OUTPUT_DIR = "/root/promptfuzz/output"
ROUND_DIR_PATTERN = re.compile(r"output_round_(\d+)$")


@dataclass
class RoundCoverage:
    project: str
    round_id: int
    report_path: str
    total_branches: int
    total_missed_branches: int
    adjusted_branches: int
    adjusted_missed_branches: int
    covered_branches: int
    removed_files: int
    removed_branches: int
    removed_missed_branches: int


def parse_int(raw: str) -> int:
    return int(raw.replace(",", ""))


def parse_report_rows(report_path: Path):
    rows = []
    with report_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("Filename"):
                continue
            if line.startswith("-"):
                continue
            if line.startswith("Files which contain no functions"):
                continue

            # llvm-cov report format: filename + 12 columns.
            parts = line.rsplit(None, 12)
            if len(parts) != 13:
                continue

            filename = parts[0]
            try:
                branches = parse_int(parts[10])
                missed_branches = parse_int(parts[11])
            except ValueError:
                continue

            rows.append(
                {
                    "filename": filename,
                    "branches": branches,
                    "missed_branches": missed_branches,
                }
            )
    return rows


def collect_round_coverage(report_path: Path, project: str, round_id: int, skip_keyword: str) -> RoundCoverage:
    rows = parse_report_rows(report_path)
    total_row = next((r for r in rows if r["filename"].upper() == "TOTAL"), None)

    if total_row is None:
        raise ValueError(f"TOTAL row not found in {report_path}")

    removed_rows = [
        r
        for r in rows
        if r["filename"].upper() != "TOTAL" and skip_keyword in r["filename"].lower()
    ]
    removed_branches = sum(r["branches"] for r in removed_rows)
    removed_missed = sum(r["missed_branches"] for r in removed_rows)

    adjusted_branches = max(0, total_row["branches"] - removed_branches)
    adjusted_missed = max(0, total_row["missed_branches"] - removed_missed)
    covered = max(0, adjusted_branches - adjusted_missed)

    return RoundCoverage(
        project=project,
        round_id=round_id,
        report_path=str(report_path),
        total_branches=total_row["branches"],
        total_missed_branches=total_row["missed_branches"],
        adjusted_branches=adjusted_branches,
        adjusted_missed_branches=adjusted_missed,
        covered_branches=covered,
        removed_files=len(removed_rows),
        removed_branches=removed_branches,
        removed_missed_branches=removed_missed,
    )


def discover_projects(output_dir: Path, explicit_projects: list[str] | None) -> list[str]:
    if explicit_projects:
        return explicit_projects
    projects = []
    for entry in sorted(output_dir.iterdir()):
        if not entry.is_dir():
            continue
        fuzzer_root = entry / "exploit_fuzzers" / "Fuzzer_000"
        if fuzzer_root.is_dir():
            projects.append(entry.name)
    return projects


def collect_all(output_dir: Path, projects: list[str], skip_keyword: str) -> list[RoundCoverage]:
    results: list[RoundCoverage] = []
    for project in projects:
        fuzzer_root = output_dir / project / "exploit_fuzzers" / "Fuzzer_000"
        if not fuzzer_root.is_dir():
            continue

        round_dirs = []
        for d in fuzzer_root.iterdir():
            if not d.is_dir():
                continue
            match = ROUND_DIR_PATTERN.match(d.name)
            if match:
                round_dirs.append((int(match.group(1)), d))

        round_dirs.sort(key=lambda item: item[0])
        for round_id, round_dir in round_dirs:
            report_path = round_dir / "coverage" / "llvm_cov_report.txt"
            if not report_path.is_file():
                continue
            try:
                results.append(collect_round_coverage(report_path, project, round_id, skip_keyword))
            except ValueError as exc:
                print(f"[WARN] {exc}")
    return results


def print_table(results: list[RoundCoverage]):
    if not results:
        print("No coverage reports found.")
        return

    header = (
        f"{'project':<15} {'round':>5} {'covered':>10} {'branches':>10} "
        f"{'missed':>10} {'removed_files':>13} {'removed_br':>11} {'report'}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.project:<15} {r.round_id:>5} {r.covered_branches:>10} "
            f"{r.adjusted_branches:>10} {r.adjusted_missed_branches:>10} "
            f"{r.removed_files:>13} {r.removed_branches:>11} {r.report_path}"
        )


def write_csv(results: list[RoundCoverage], csv_path: Path):
    fieldnames = list(asdict(results[0]).keys()) if results else list(RoundCoverage.__annotations__.keys())
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(asdict(item))


def write_json(results: list[RoundCoverage], json_path: Path):
    payload = [asdict(item) for item in results]
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Collect per-round branch coverage from llvm_cov_report.txt under "
            "output/{project}/exploit_fuzzers/Fuzzer_000/output_round_x/coverage"
        )
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Root output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--project",
        action="append",
        default=None,
        help="Specify project(s). Can be used multiple times. If omitted, scan all projects.",
    )
    parser.add_argument(
        "--skip-keyword",
        default="absl",
        help="Exclude rows whose filename contains this keyword (default: absl)",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Optional path to save CSV output",
    )
    parser.add_argument(
        "--json",
        default=None,
        help="Optional path to save JSON output",
    )

    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    projects = discover_projects(output_dir, args.project)
    results = collect_all(output_dir, projects, args.skip_keyword.lower())
    print_table(results)

    if args.csv:
        csv_path = Path(args.csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        write_csv(results, csv_path)
        print(f"Saved CSV: {csv_path}")

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(results, json_path)
        print(f"Saved JSON: {json_path}")


if __name__ == "__main__":
    main()