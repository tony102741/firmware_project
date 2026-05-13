#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: observe_mr90x_sync.sh [--include-meshd] [--sample-interval SEC] [--output-dir DIR]

Passive runtime observation toolkit for the MR90X sync-server/helper pipeline.

This script:
- does not send packets
- does not modify router state
- only collects passive observer output and read-only snapshots

Flags:
  --include-meshd       Also attach strace to meshd if present
  --sample-interval N   Periodic /tmp/sync-server snapshot interval in seconds (default: 5)
  --output-dir DIR      Override output directory
  -h, --help            Show this help
EOF
}

log() {
  printf '[observe_mr90x_sync] %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

find_pid() {
  local name="$1"
  if need_cmd pidof; then
    pidof "$name" 2>/dev/null | awk '{print $1}'
    return 0
  fi
  ps w 2>/dev/null | awk -v n="$name" '$0 ~ ("(^|/)" n "([[:space:]]|$)") {print $1; exit}'
}

INCLUDE_MESHD=0
SAMPLE_INTERVAL=5
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --include-meshd)
      INCLUDE_MESHD=1
      shift
      ;;
    --sample-interval)
      SAMPLE_INTERVAL="${2:?missing value for --sample-interval}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$REPO_ROOT/research/regeneration/full_corpus_20260508/runtime_observation/$TS"
fi

mkdir -p "$OUTPUT_DIR"/{snapshots,tmp_sync_server,meta}

SYNC_PID="$(find_pid sync-server || true)"
MESHD_PID="$(find_pid meshd || true)"

if [[ -z "$SYNC_PID" ]]; then
  echo "sync-server PID not found" >&2
  exit 1
fi

METADATA="$OUTPUT_DIR/meta/metadata.txt"
PIDS_FILE="$OUTPUT_DIR/meta/observer_pids.txt"
WARNINGS="$OUTPUT_DIR/meta/warnings.txt"
touch "$PIDS_FILE" "$WARNINGS"

{
  echo "timestamp=$TS"
  echo "repo_root=$REPO_ROOT"
  echo "output_dir=$OUTPUT_DIR"
  echo "sync_server_pid=$SYNC_PID"
  echo "meshd_pid=${MESHD_PID:-}"
  echo "include_meshd=$INCLUDE_MESHD"
  echo "sample_interval=$SAMPLE_INTERVAL"
  echo "user=$(id -un 2>/dev/null || true)"
  echo "uid=$(id -u 2>/dev/null || true)"
  echo "kernel=$(uname -a 2>/dev/null || true)"
} > "$METADATA"

OBSERVER_PIDS=()

record_pid() {
  local name="$1"
  local pid="$2"
  echo "$name=$pid" >> "$PIDS_FILE"
  OBSERVER_PIDS+=("$pid")
}

start_bg() {
  local name="$1"
  shift
  "$@" &
  local pid=$!
  record_pid "$name" "$pid"
}

snapshot_tmp_sync() {
  local stamp dest
  stamp="$(date +%Y%m%d_%H%M%S)"
  dest="$OUTPUT_DIR/snapshots/$stamp"
  mkdir -p "$dest"
  if [[ -d /tmp/sync-server ]]; then
    cp -a /tmp/sync-server/. "$dest/" 2>>"$WARNINGS" || true
  fi
}

cleanup() {
  local pid
  log "stopping observers"
  for pid in "${OBSERVER_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  snapshot_tmp_sync
  log "artifacts saved under $OUTPUT_DIR"
}

trap cleanup EXIT INT TERM

snapshot_tmp_sync

if need_cmd logread; then
  start_bg logread bash -lc "logread -f > '$OUTPUT_DIR/logread.log' 2>&1"
else
  echo "logread not available" >> "$WARNINGS"
fi

if need_cmd ubus; then
  start_bg ubus_monitor bash -lc "ubus monitor > '$OUTPUT_DIR/ubus_monitor.log' 2>&1"
else
  echo "ubus not available" >> "$WARNINGS"
fi

if need_cmd inotifywait && [[ -d /tmp/sync-server ]]; then
  start_bg inotify bash -lc "inotifywait -m -r /tmp/sync-server > '$OUTPUT_DIR/inotifywait.log' 2>&1"
else
  echo "inotifywait unavailable or /tmp/sync-server missing" >> "$WARNINGS"
fi

if need_cmd strace; then
  start_bg strace_sync_server bash -lc "strace -ff -tt -s 4096 -p '$SYNC_PID' -e trace=execve,openat,read,write -o '$OUTPUT_DIR/sync_server_strace' 2>'$OUTPUT_DIR/sync_server_strace.stderr'"
  if [[ "$INCLUDE_MESHD" -eq 1 ]]; then
    if [[ -n "$MESHD_PID" ]]; then
      start_bg strace_meshd bash -lc "strace -ff -tt -s 4096 -p '$MESHD_PID' -e trace=execve,openat,read,write -o '$OUTPUT_DIR/meshd_strace' 2>'$OUTPUT_DIR/meshd_strace.stderr'"
    else
      echo "--include-meshd requested but meshd PID not found" >> "$WARNINGS"
    fi
  fi
else
  echo "strace not available" >> "$WARNINGS"
fi

start_bg snapshot_loop bash -lc "
  while true; do
    sleep '$SAMPLE_INTERVAL'
    if [[ -d /tmp/sync-server ]]; then
      stamp=\$(date +%Y%m%d_%H%M%S)
      dest='$OUTPUT_DIR/snapshots'/\$stamp
      mkdir -p \"\$dest\"
      cp -a /tmp/sync-server/. \"\$dest/\" 2>>'$WARNINGS' || true
    fi
  done
"

log "sync-server PID: $SYNC_PID"
if [[ -n "$MESHD_PID" ]]; then
  log "meshd PID: $MESHD_PID"
fi
log "output dir: $OUTPUT_DIR"
log "press Ctrl-C to stop"

while true; do
  sleep 3600
done
