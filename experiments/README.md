# PromptFuzz Experiment Scripts

This directory contains helper scripts for running and analyzing PromptFuzz experiments.

## Scripts

### 1. afl_script.py

Helper script for AFL++ workflow - compile fuzz drivers and analyze AFL output.

For complete documentation, see [AFLPlusPlus.md](../AFLPlusPlus.md).

**Quick reference**:
```bash
# Compile AFL fuzzer binary
python3 experiments/afl_script.py <project> --compile

# Analyze AFL output (copy queue/crashes)
python3 experiments/afl_script.py <project> --analyze
```

---

### 2. analyze_statistics.py

Analyze PromptFuzz experiment results and generate coverage growth charts.

**Features**:
- Process coverage data from `work/` directory using `llvm-cov`
- Analyze seed statistics (seeds, succ_seeds, error_seeds counts)
- Parse log files for token usage and API costs (DeepSeek V3.2 pricing)
- Plot coverage growth over time (PNG + PDF charts)

**Usage**:
```bash
python3 experiments/analyze_statistics.py <project>
```

**Output files** (saved to `output/{project}/statistics/`):
- `coverage_growth.json` - coverage data over time
- `coverage_growth_24h_chart.png` / `.pdf` - coverage charts
- `cost_info.txt` - summary statistics (seeds, tokens, costs, branches)

**Dependencies**: `matplotlib`

---

### 3. collect_round_branch_coverage.py

Collect per-round branch coverage from `llvm_cov_report.txt` files.

**Features**:
- Parse `llvm-cov report` output from coverage directories
- Collect coverage for each round (`output_round_X`)
- Filter files by keyword (default excludes "absl")
- Output to CSV and/or JSON

**Usage**:
```bash
# Collect all projects
python3 experiments/collect_round_branch_coverage.py

# Collect specific projects
python3 experiments/collect_round_branch_coverage.py --project libpng --project curl

# Save to CSV/JSON
python3 experiments/collect_round_branch_coverage.py --csv coverage.csv --json coverage.json
```

**Options**:
| Option | Description | Default |
|--------|-------------|---------|
| `--output-dir` | Root output directory | `/root/promptfuzz/output` |
| `--project` | Specify project(s), can repeat | scan all |
| `--skip-keyword` | Exclude files containing keyword | `absl` |
| `--csv` | Path for CSV output | none |
| `--json` | Path for JSON output | none |

---

### 4. archive.py

Archive experiment results into a tar.gz file for backup or transfer.

**Features**:
- Archive seeds, error_seeds, succ_seeds, statistics, shared_corpus directories
- Archive fuzzer log files (`fuzzer*.log`)
- Archive exploit_fuzzers with special handling:
  - Keep `.cc` source files
  - Keep `output_round_X/coverage` directories (removes profraw)
  - Keep `error_*` and `ubsan_*` directories
- Create timestamped tar.gz archive

**Usage**:
```bash
# Archive all projects
python3 experiments/archive.py --project all --output /path/to/output

# Archive specific project
python3 experiments/archive.py --project libpng --output /path/to/output
```

**Options**:
| Option | Description | Default |
|--------|-------------|---------|
| `--project` | Target project to archive | `all` |
| `--output` | Output directory for archive | current directory |
| `--input` | Input output directory | `/home/yunlong/work/PromptFuzz/output` |

## Notes

Some scripts contain hardcoded paths (e.g., `ROOT_DIR = "/root/promptfuzz"`). Adjust these when running outside the Docker container.