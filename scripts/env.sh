#!/usr/bin/env sh
# Source this file from the project root before working:
# . scripts/env.sh

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

export FIRMWARE_INPUTS_DIR="${FIRMWARE_INPUTS_DIR:-$PROJECT_ROOT/inputs}"
export FIRMWARE_CACHE_DIR="${FIRMWARE_CACHE_DIR:-$PROJECT_ROOT/.cache}"
export FIRMWARE_RUNS_DIR="${FIRMWARE_RUNS_DIR:-$PROJECT_ROOT/runs}"
export FIRMWARE_RETAIN_RUNS="${FIRMWARE_RETAIN_RUNS:-30}"
export FIRMWARE_RETAIN_EXTRACTED="${FIRMWARE_RETAIN_EXTRACTED:-2}"

if [ -d "$PROJECT_ROOT/.venv" ]; then
  # shellcheck disable=SC1091
  . "$PROJECT_ROOT/.venv/bin/activate"
fi

printf 'firmware_project environment loaded\n'
printf '  PROJECT_ROOT=%s\n' "$PROJECT_ROOT"
printf '  FIRMWARE_INPUTS_DIR=%s\n' "$FIRMWARE_INPUTS_DIR"
printf '  FIRMWARE_CACHE_DIR=%s\n' "$FIRMWARE_CACHE_DIR"
printf '  FIRMWARE_RUNS_DIR=%s\n' "$FIRMWARE_RUNS_DIR"
