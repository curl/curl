#!/bin/bash
set -euo pipefail

# Droid Review Script - Parallel C code review against review_guidelines.md
# Usage: ./droid-autofix.sh [options] [concurrency]
# Options:
#   -v|--verbose       Verbose (debug) logging
#   -q|--quiet         Only errors
#   --log-file <path>  Also write logs to file
#   --no-color         Disable ANSI colors
#   -h|--help          Show this help

DEFAULT_CONCURRENCY=10
LOG_LEVEL="info"   # error,warn,info,debug
LOG_FILE=""
USE_COLOR=1
MAX_FILES=10

START_TS=$(date +%Y%m%d_%H%M%S)
RESULTS_CSV="${START_TS}_results.csv"
FILE_LIST="c_files_to_review.txt"
PROGRESS_FILE=""
FAIL_FILE=""
WATCHER_PID=""

usage() {
  cat >&2 <<USAGE
Usage: $0 [options] [concurrency]
Options:
  -v, --verbose        Verbose (debug) logging
  -q, --quiet          Only errors
  --log-file <path>    Also write logs to file
  --no-color           Disable ANSI colors
  -h, --help           Show this help
USAGE
}

_level_num() {
  case "${1:-info}" in
    error) echo 0;;
    warn)  echo 1;;
    info)  echo 2;;
    debug) echo 3;;
    *)     echo 2;;
  esac
}

_ts() { date +%H:%M:%S; }

_maybe_color() {
  local code="$1"; shift || true
  if [[ "$USE_COLOR" -eq 1 && -t 2 ]]; then printf "\033[%sm" "$code"; fi
}

_color_reset() { [[ "$USE_COLOR" -eq 1 && -t 2 ]] && printf "\033[0m" || true; }

_log_base() {
  local level="$1"; shift
  local msg="$*"
  local want=$(_level_num "$LOG_LEVEL")
  local have=$(_level_num "$level")
  if [[ "$have" -le "$want" ]]; then
    local color=""; case "$level" in
      error) color=31;;
      warn)  color=33;;
      info)  color=36;;
      debug) color=90;;
    esac
    {
      _maybe_color "$color"; printf "%s [%s] %s" "$(_ts)" "$level" "$msg"; _color_reset; printf "\n"
    } >&2
    if [[ -n "$LOG_FILE" ]]; then
      printf "%s [%s] %s\n" "$(_ts)" "$level" "$msg" >> "$LOG_FILE" || true
    fi
  fi
}

log_info()  { _log_base info  "$*"; }
log_warn()  { _log_base warn  "$*"; }
log_error() { _log_base error "$*"; }
log_debug() { _log_base debug "$*"; }

# Parse args
CONCURRENCY="$DEFAULT_CONCURRENCY"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) LOG_LEVEL="debug"; shift ;;
    -q|--quiet)   LOG_LEVEL="error"; shift ;;
    --log-file)   LOG_FILE="${2:-}"; [[ -z "$LOG_FILE" ]] && { log_error "--log-file requires a path"; exit 2; }; shift 2 ;;
    --no-color)   USE_COLOR=0; shift ;;
    -h|--help)    usage; exit 0 ;;
    ''|*[!0-9]*)  log_error "Unknown argument: $1"; usage; exit 2 ;;
    *)            CONCURRENCY="$1"; shift ;;
  esac
done

# Dependencies (best-effort)
for dep in xargs awk sed mktemp find dirname; do
  command -v "$dep" >/dev/null 2>&1 || log_warn "Dependency missing: $dep"
done
command -v droid >/dev/null 2>&1 || log_warn "'droid' CLI not found; rows will record DROID-ERROR"

# Build list of C files and store locally
find . -type f \( -name "*.c" -o -name "*.h" \) -print | sed 's|^\./||' | head -n "$MAX_FILES" > "$FILE_LIST"

TOTAL_FILES=$(wc -l < "$FILE_LIST" | tr -d ' ')

# CSV header
echo "file_path,folder,violation_id,guideline_section,title,line,why,suggested_fix,context_snippet" > "$RESULTS_CSV"

log_info "Start: ts=$START_TS concurrency=$CONCURRENCY files=$TOTAL_FILES results=$RESULTS_CSV list=$FILE_LIST"

cleanup() {
  local ec=$?
  if [[ -n "${WATCHER_PID:-}" ]] && kill -0 "$WATCHER_PID" >/dev/null 2>&1; then kill "$WATCHER_PID" >/dev/null 2>&1 || true; fi
  [[ -n "${PROGRESS_FILE:-}" ]] && rm -f "$PROGRESS_FILE" || true
  [[ -n "${FAIL_FILE:-}" ]] && rm -f "$FAIL_FILE" || true
  [[ -n "${FILE_LIST:-}" ]] && rm -f "$FILE_LIST" || true
  log_debug "Cleanup done (exit=$ec)"
}
trap cleanup EXIT INT TERM

PROGRESS_FILE=$(mktemp)
FAIL_FILE=$(mktemp)

watch_progress() {
  while :; do
    local processed failures
    processed=$(wc -l < "$PROGRESS_FILE" | tr -d ' ')
    failures=$(wc -l < "$FAIL_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    log_info "Progress: ${processed}/${TOTAL_FILES} processed; failures: ${failures:-0}"
    if [[ "$processed" -ge "$TOTAL_FILES" ]]; then break; fi
    sleep 5
  done
}

watch_progress &
WATCHER_PID=$!

run_droid_review() {
  local file="$1"
  local folder
  folder=$(dirname "$file")
  local tmpout prompt start_s end_s duration_s status rows processed_output
  tmpout=$(mktemp)
  start_s=$(date +%s)

  # Lightweight child logger respecting LOG_LEVEL
  _child_level_num() { case "$1" in error) echo 0;; warn) echo 1;; info) echo 2;; debug) echo 3;; *) echo 2;; esac; }
  _child_log() {
    local level="$1"; shift; local msg="$*"
    local want=$(_child_level_num "${LOG_LEVEL}")
    local have=$(_child_level_num "$level")
    if [[ "$have" -le "$want" ]]; then
      printf "%s [%s] %s\n" "$(date +%H:%M:%S)" "$level" "$msg" >&2
      if [[ -n "${LOG_FILE}" ]]; then printf "%s [%s] %s\n" "$(date +%H:%M:%S)" "$level" "$msg" >> "${LOG_FILE}" || true; fi
    fi
  }

  _child_log info "START ${file}"

  prompt=$(cat <<EOF
Review the C source file "./$file" against @review_guidelines.md.
Return ONLY rows, no prose, using this exact header and order with '|' (pipe) as delimiter:
file_path|folder|violation_id|guideline_section|title|line|why|suggested_fix|context_snippet
Rules:
- violation_id: stable short ID (e.g., NAMING-BOOLEAN, INT-CONVERSION, DOC-DOXYGEN).
- guideline_section: like 17.3 or 23.1.
- line: number or range; "-" if unknown.
- context_snippet: one line; escape commas and quotes; no newlines.
- Do NOT use the '|' character inside fields.
- If no issues: output one row with violation_id=NO_ISSUES and '-' for other columns except file_path and folder.
- For file_path use "$file" and for folder use "$folder".
EOF
)

  status="ok"
  if ! droid exec --skip-permissions-unsafe "$prompt" > "$tmpout" 2>/dev/null; then
    echo "$file,$folder,DROID-ERROR,-,Execution failed,-,Failed to run droid exec,-,-" >> "$RESULTS_CSV"
    echo "$file" >> "$FAIL_FILE"
    status="fail"
  else
    processed_output=$(awk -v f="$file" -v folder="$folder" '
      BEGIN {
        FS = "|";
      }
      # Skip header
      NR==1 && ($0 ~ /^file_path\|folder\|violation_id\|/) { next }
      # Skip blank lines
      $0 ~ /^[[:space:]]*$/ { next }
      function csvq(s,    t) { gsub(/"/,"\"\"",s); return "\"" s "\"" }
      {
        fp=""; fld=""; v3=""; v4=""; v5=""; v6=""; v7=""; v8=""; v9="";
        if (NF==9) {
          fp=$1; fld=$2; v3=$3; v4=$4; v5=$5; v6=$6; v7=$7; v8=$8; v9=$9;
        } else if (NF==7) {
          fp=f; fld=folder; v3=$1; v4=$2; v5=$3; v6=$4; v7=$5; v8=$6; v9=$7;
        } else {
          fp=f; fld=folder; v3="DROID-ERROR"; v4="-"; v5="Format error"; v6="-"; v7="Invalid output row"; v8="-"; v9="-";
        }
        print csvq(fp) "," csvq(fld) "," csvq(v3) "," csvq(v4) "," csvq(v5) "," csvq(v6) "," csvq(v7) "," csvq(v8) "," csvq(v9);
      }
    ' "$tmpout")

    if [[ -n "$processed_output" ]]; then
      printf "%s\n" "$processed_output" >> "$RESULTS_CSV"
      rows=$(printf "%s\n" "$processed_output" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
    else
      rows=0
    fi
  fi

  end_s=$(date +%s)
  duration_s=$(( end_s - start_s ))

  if [[ "$status" == "ok" ]]; then
    _child_log info "DONE ${file} in ${duration_s}s (rows=${rows:-0})"
  else
    _child_log error "FAIL ${file} in ${duration_s}s"
  fi

  echo "$file" >> "$PROGRESS_FILE"
  rm -f "$tmpout"
}

export -f run_droid_review
export LOG_LEVEL LOG_FILE PROGRESS_FILE FAIL_FILE RESULTS_CSV

# Parallelize reviews
cat "$FILE_LIST" | xargs -n 1 -P "$CONCURRENCY" -I {} bash -c 'run_droid_review "$1"' _ {}

# Final progress update and summary
if [[ -n "${WATCHER_PID:-}" ]] && kill -0 "$WATCHER_PID" >/dev/null 2>&1; then
  wait "$WATCHER_PID" || true
fi

TOTAL_ROWS=$(awk 'NR>1 {c++} END{print c+0}' "$RESULTS_CSV")
ERROR_ROWS=$(awk -F, 'NR>1 && $3=="DROID-ERROR" {c++} END{print c+0}' "$RESULTS_CSV")
NOISSUE_ROWS=$(awk -F, 'NR>1 && $3=="NO_ISSUES" {c++} END{print c+0}' "$RESULTS_CSV")

log_info "Summary: files=${TOTAL_FILES}, rows=${TOTAL_ROWS}, NO_ISSUES=${NOISSUE_ROWS}, errors=${ERROR_ROWS}"

log_debug "Top violations:"
awk -F, 'NR>1 {c[$3]++} END { for (k in c) if (k!="NO_ISSUES") printf("%s,%d\n", k, c[k]) }' "$RESULTS_CSV" |
  sort -t, -k2,2nr | head -n 5 | while IFS=, read -r viol cnt; do
    [[ -n "$viol" ]] && log_debug "  ${viol}: ${cnt}"
  done

printf "Results written to %s\n" "$RESULTS_CSV"