#!/usr/bin/env sh
set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

printf 'Project root: %s\n\n' "$PROJECT_ROOT"

check_cmd() {
  name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    path="$(command -v "$name")"
    printf '[ok]   %-18s %s\n' "$name" "$path"
  else
    printf '[miss] %-18s install or add to PATH\n' "$name"
  fi
}

check_path() {
  label="$1"
  path="$2"
  if [ -e "$path" ]; then
    printf '[ok]   %-18s %s\n' "$label" "$path"
  else
    printf '[miss] %-18s %s\n' "$label" "$path"
  fi
}

check_cmd git
check_cmd python3
check_cmd go
check_cmd unzip
check_cmd 7z
check_cmd binwalk
check_cmd strings
check_cmd file

printf '\n'
check_path .venv "$PROJECT_ROOT/.venv"
check_path inputs "$PROJECT_ROOT/inputs"
check_path runs "$PROJECT_ROOT/runs"
check_path cache "$PROJECT_ROOT/.cache"
check_path payload-dumper-go "$PROJECT_ROOT/tools/payload-dumper-go/payload-dumper-go"
check_path ghidraRun "$PROJECT_ROOT/tools/ghidra_11.3.2_PUBLIC/ghidraRun"
check_path mcp-config "$PROJECT_ROOT/.mcp.json"

printf '\nPipeline status:\n'
python3 "$PROJECT_ROOT/src/pipeline.py" --status
