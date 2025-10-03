# Coding Standard Investigations - Autofix Script

## Overview
`droid-autofix.sh` runs parallel reviews of C sources against `review_guidelines.md` and writes findings to a timestamped CSV.

## Usage
```bash
./droid-autofix.sh [options] [concurrency]
```
Options:
- `-v|--verbose` verbose logs
- `-q|--quiet` only errors
- `--log-file <path>` also log to file
- `--no-color` disable colors
- `-h|--help` show help

## Behavior
- Builds a file list of `*.c` and `*.h` up to `MAX_FILES` (default 10).
- Runs reviews in parallel (default concurrency 10) and appends rows to `<timestamp>_results.csv`.
- Shows periodic progress and summary.
- Cleans up temporary files automatically.

## Environment
- Best effort checks for `xargs`, `awk`, `sed`, `mktemp`, `find`, `dirname`, and `droid` CLI. If `droid` is missing, rows are marked `DROID-ERROR`.

## Output
- CSV columns: `file_path,folder,violation_id,guideline_section,title,line,why,suggested_fix,context_snippet`.

## Tuning
- Limit files via `MAX_FILES` at the top of the script.
- Control parallelism with the positional `concurrency` argument.
