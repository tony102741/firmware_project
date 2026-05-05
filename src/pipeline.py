"""
Firmware analysis pipeline.

Supports five input formats, detected automatically:
  - OTA zip (.zip)       → unzip → payload-dumper-go → rootfs
  - tar bundle (.tar)    → untar → nested firmware/rootfs
  - payload.bin          → payload-dumper-go → rootfs
  - raw partition (.img) → 7z unpack → rootfs
  - IoT firmware (.bin)  → binwalk extract → squashfs-root → rootfs

Run from the project root:
  python3 src/pipeline.py [--input FILE] [--type auto|zip|tar|payload|img|iot] [--skip]
  python3 src/pipeline.py --dry-run          # validate tools and input only
  python3 src/pipeline.py --output out.json  # save results as JSON
"""

import os
import sys
import subprocess
import shutil
import argparse
import time
import tempfile
import re
import shlex
import lzma
import zlib
import zipfile
import json
import hashlib
import atexit
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

INPUTS_DIR = os.environ.get("FIRMWARE_INPUTS_DIR", os.path.join(PROJECT_ROOT, "inputs"))
CACHE_DIR = os.environ.get("FIRMWARE_CACHE_DIR", os.path.join(PROJECT_ROOT, ".cache"))
FIRMWARE_DIR  = INPUTS_DIR
WORK_DIR      = os.path.join(CACHE_DIR, "build")
ROOTFS_DIR    = os.path.join(CACHE_DIR, "rootfs")
EXTRACTED_DIR = os.path.join(CACHE_DIR, "extracted")
TEMP_INPUTS_DIR = os.path.join(CACHE_DIR, "tmp_inputs")
RUNS_DIR = os.environ.get("FIRMWARE_RUNS_DIR", os.path.join(PROJECT_ROOT, "runs"))
DEFAULT_RETAIN_RUNS = int(os.environ.get("FIRMWARE_RETAIN_RUNS", "30"))
DEFAULT_RETAIN_EXTRACTED = int(os.environ.get("FIRMWARE_RETAIN_EXTRACTED", "2"))
DEFAULT_STALE_MAX_AGE_HOURS = int(os.environ.get("FIRMWARE_STALE_MAX_AGE_HOURS", "12"))
_STALE_PREFIX = ".__stale_"

DUMPER      = os.path.join(PROJECT_ROOT, "tools/payload-dumper-go/payload-dumper-go")
DUMPER_DIR  = os.path.dirname(DUMPER)
DUMPER_REPO = "https://github.com/ssut/payload-dumper-go"

# ── Constants ─────────────────────────────────────────────────────────────────

_MAGIC_ZIP     = b"PK\x03\x04"
_MAGIC_RAR4    = b"Rar!"
_MAGIC_RAR5    = b"Rar!\x1a\x07"
_MAGIC_PAYLOAD = b"CrAU"
_MAGIC_SPARSE  = b"\x3a\xff\x26\xed"
_MAGIC_EXT4    = b"\x53\xef"       # at offset 0x438 in ext4 superblock
_MAGIC_EROFS   = b"\xe2\xe1\xf5\xe0"
_MAGIC_TAR     = b"ustar"
_MAGIC_FDT     = b"\xd0\x0d\xfe\xed"
_FS_MAGIC_PATTERNS = (
    ("squashfs", b"hsqs"),
    ("squashfs", b"sqsh"),
    ("squashfs", b"qshs"),
    ("squashfs", b"shsq"),
    ("cramfs",   b"\x45\x3d\xcd\x28"),
    ("ubifs",    b"UBI#"),
)
_EMBEDDED_PAYLOAD_PATTERNS = (
    ("gzip", b"\x1f\x8b\x08", ".gz"),
    ("zip", b"PK\x03\x04", ".zip"),
    ("xz", b"\xfd7zXZ\x00", ".xz"),
    ("lzma", b"\x5d\x00\x00\x80", ".lzma"),
)
_NESTED_BLOB_EXTS = (".xz", ".lzma", ".7z", ".bin", ".img", ".raw", ".fs", ".blob")
_UBIREADER_FALLBACK_DIRS = (
    os.path.expanduser("~/.venvs/ubireader/bin"),
    os.path.expanduser("~/.local/bin"),
)

_PARTITION_INDICATORS = {"bin", "lib", "lib64", "etc", "app", "framework", "priv-app"}
_SEARCH_SKIP = {"rootfs", ".git", "node_modules", "__pycache__"}
_ARCHIVE_FIRMWARE_EXTS = (".bin", ".img", ".web", ".trx", ".w", ".pkgtb")
_ARCHIVE_NOISE_EXTS = (
    ".txt", ".pdf", ".doc", ".docx", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
    ".html", ".htm", ".css", ".js",
    ".md", ".csv", ".xml",
)
_DJI_SKIP_SIG_EXTS = (".pro.fw.sig", ".cfg.sig")
_DJI_PRIORITY_NAMES = (
    "decompressed.bin",
    "payload.bin",
    "ap.img",
    "system.img",
    "vendor.img",
    "system_ext.img",
    "product.img",
    "odm.img",
    "vendor_boot.img",
    "boot.img",
    "dtbo.img",
)
_DJI_INTERNAL_NESTED_ALLOWLIST = {"decompressed.bin", "payload.bin", "ap.img"}
_DJI_PRAK_PREFERRED_MODULES = {"0200", "0205"}
_DJI_PRAK_EXCLUDED_MODULES = {"0206", "0207", "0600", "1302", "1400"}
_DJI_PRAK_MAX_TARGETS = 2
_DJI_PRAK_PAYLOAD_MAGICS = (
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b\x08"),
)

INPUT_ZIP     = "zip"
INPUT_RAR     = "rar"
INPUT_TAR     = "tar"
INPUT_PAYLOAD = "payload"
INPUT_IMG     = "img"
INPUT_IOT     = "iot"
INPUT_UNKNOWN = "unknown"

_W = 65  # output width
_EXTRACTED_ACTIVE = False
_TEMP_INPUT_DIRS = []
_PATH_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_ZONE_SUFFIX = ":Zone.Identifier"


# ── Output helpers ─────────────────────────────────────────────────────────────

def _stage(n, total, title):
    """Print a numbered pipeline stage header, always flushed immediately."""
    label = f"  [{n}/{total}] {title}  "
    pad = max(0, _W - len(label) - 3)
    print(f"\n{'─' * 3}{label}{'─' * pad}", flush=True)


def _ok(msg):
    print(f"    [OK] {msg}", flush=True)


def _warn(msg):
    print(f"    [!]  {msg}", flush=True)


def _info(msg):
    print(f"    {msg}", flush=True)


def _fmt_time(seconds):
    """Format elapsed seconds as '2m 31s' or '8s'."""
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


def _slugify(text):
    text = re.sub(r'[^A-Za-z0-9._-]+', "-", text or "")
    text = re.sub(r'-{2,}', "-", text.strip("-"))
    return (text or "run").lower()


def _path_label(text):
    text = _PATH_INVALID_CHARS.sub("-", (text or "").strip())
    text = re.sub(r"\s+", " ", text)
    return text.strip(" .-") or "UNKNOWN"


def _short_run_label(input_path=None, max_len=24):
    if not input_path:
        return "run"

    stem = os.path.splitext(os.path.basename(input_path))[0]
    slug = _slugify(stem)
    if len(slug) <= max_len:
        return slug

    parts = [p for p in re.split(r"[-_.]+", slug) if p]
    if not parts:
        return slug[:max_len]

    chosen = []
    total = 0
    for part in parts:
        piece = part[:10] if not chosen and len(part) > 10 else part
        extra = len(piece) + (1 if chosen else 0)
        if total + extra > max_len:
            break
        chosen.append(piece)
        total += extra

    if chosen:
        return "-".join(chosen)
    return slug[:max_len]


def _iter_input_files(base_dir):
    if not os.path.isdir(base_dir):
        return []

    files = []
    for root, dirs, names in os.walk(base_dir):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(names):
            if name.endswith(_ZONE_SUFFIX):
                continue
            full = os.path.join(root, name)
            if os.path.isfile(full):
                files.append(full)
    return sorted(files)


def _derive_run_labels(input_path=None):
    product_label = os.environ.get("FIRMWARE_PRODUCT_LABEL", "").strip()
    version_label = os.environ.get("FIRMWARE_VERSION_LABEL", "").strip()
    if product_label and version_label:
        return _path_label(product_label), _path_label(version_label)

    if input_path:
        abs_input = os.path.abspath(input_path)
        stem = os.path.splitext(os.path.basename(abs_input))[0]
        try:
            rel = os.path.relpath(abs_input, INPUTS_DIR)
        except ValueError:
            rel = None
        if rel and not rel.startswith(".."):
            parts = rel.split(os.sep)
            if len(parts) >= 2:
                return _path_label(parts[0]), _path_label(stem)
        return _path_label(_short_run_label(stem, max_len=48)), _path_label(stem)

    return "UNKNOWN", "run"


def _json_dump(path, payload):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _iot_extract_dir_for(bin_path):
    """
    Give each firmware blob its own extraction directory so nested extraction
    results from previous runs cannot contaminate rootfs selection.
    """
    stem = os.path.splitext(os.path.basename(bin_path))[0]
    slug = _short_run_label(stem, max_len=32)
    digest = _sha256_file(bin_path)[:8]
    return os.path.join(WORK_DIR, f"_iot_extract_{slug}_{digest}")


def _dir_size_bytes(path):
    total = 0
    if not os.path.exists(path):
        return total
    for root, _, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            try:
                total += os.path.getsize(full)
            except OSError:
                continue
    return total


def _recent_dirs(base_dir, prefix=None):
    if not os.path.isdir(base_dir):
        return []
    items = []
    for name in os.listdir(base_dir):
        full = os.path.join(base_dir, name)
        if not os.path.isdir(full):
            continue
        if prefix and not name.startswith(prefix):
            continue
        items.append((os.path.getmtime(full), full))
    return [path for _, path in sorted(items, reverse=True)]


def _prune_dir_set(paths, keep):
    if keep is None or keep < 0:
        return []
    removed = []
    for path in paths[keep:]:
        shutil.rmtree(path, ignore_errors=True)
        removed.append(path)
    return removed


def _prune_stale_dirs(base_dir, max_age_hours=DEFAULT_STALE_MAX_AGE_HOURS, keep_newest=0):
    if not os.path.isdir(base_dir):
        return []
    now = time.time()
    stale = []
    for name in os.listdir(base_dir):
        full = os.path.join(base_dir, name)
        if not os.path.isdir(full):
            continue
        if not name.startswith(_STALE_PREFIX):
            continue
        try:
            mtime = os.path.getmtime(full)
        except OSError:
            continue
        stale.append((mtime, full))
    stale.sort(reverse=True)
    removed = []
    for idx, (mtime, path) in enumerate(stale):
        age_hours = (now - mtime) / 3600.0
        if idx < max(0, keep_newest):
            continue
        if max_age_hours is not None and age_hours < max_age_hours:
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed.append(path)
    return removed


def _dir_count_with_prefix(base_dir, prefix):
    if not os.path.isdir(base_dir):
        return 0
    count = 0
    for name in os.listdir(base_dir):
        full = os.path.join(base_dir, name)
        if os.path.isdir(full) and name.startswith(prefix):
            count += 1
    return count


def _prepare_run_artifacts(input_path=None):
    os.makedirs(RUNS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    suffix = _short_run_label(input_path)
    product_label, version_label = _derive_run_labels(input_path)
    base_dir = os.path.join(RUNS_DIR, product_label, version_label)
    os.makedirs(base_dir, exist_ok=True)
    run_dir = os.path.join(base_dir, f"run_{ts}_{suffix}")
    os.makedirs(run_dir, exist_ok=True)
    return {
        "run_id": os.path.relpath(run_dir, RUNS_DIR),
        "run_dir": run_dir,
        "log_path": os.path.join(run_dir, "run.log"),
        "result_path": os.path.join(run_dir, "results.json"),
        "manifest_path": os.path.join(run_dir, "manifest.json"),
        "dossier_dir": os.path.join(run_dir, "dossiers"),
    }


class _Tee:
    """
    Write to both the original stream and an open log file handle simultaneously.

    Replacing sys.stdout / sys.stderr with a _Tee instance captures all
    print() calls from within this process. Output from child subprocesses
    (which write directly to fd 1) is captured separately by each subprocess
    setting up its own _Tee via the FIRMWARE_LOG_FILE environment variable.
    """
    def __init__(self, stream, log_fh):
        self._stream = stream
        self._log    = log_fh

    def write(self, data):
        self._stream.write(data)
        try:
            self._log.write(data)
        except Exception:
            pass   # never suppress terminal output because of a log error

    def flush(self):
        self._stream.flush()
        try:
            self._log.flush()
        except Exception:
            pass

    def fileno(self):
        # Delegates to the real stream so subprocess stdout inheritance still works
        return self._stream.fileno()

    def isatty(self):
        return hasattr(self._stream, "isatty") and self._stream.isatty()


# ── Subprocess helpers ────────────────────────────────────────────────────────

def run(cmd, env=None, timeout=None, label=None, quiet=False):
    """
    Run a shell command.

    label — human-readable description printed before the command runs.
            If omitted and quiet=False, the raw command is printed.
    quiet — suppress both stdout and stderr of the tool.
            Use for extraction tools (binwalk, ubireader, 7z) whose
            warnings/progress output would pollute the pipeline log.

    sys.stdout is flushed before the subprocess starts to prevent Python's
    output buffer from appearing after the subprocess's direct fd writes.
    """
    if label:
        print(f"    {label}", flush=True)
    elif not quiet:
        print(f"    {cmd}", flush=True)
    sys.stdout.flush()
    try:
        return subprocess.run(
            cmd, shell=True, env=env, timeout=timeout,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )
    except subprocess.TimeoutExpired:
        print(f"\n[FATAL] Command timed out after {timeout}s", flush=True)
        print(f"[FATAL] Command was: {cmd}", flush=True)
        sys.exit(1)


def run_critical(cmd, fatal_msg, env=None, timeout=None, label=None, quiet=False):
    """
    Run a shell command. Abort with `fatal_msg` on non-zero exit.
    Use this for steps where partial success is worse than a clean stop.
    """
    result = run(cmd, env=env, timeout=timeout, label=label, quiet=quiet)
    if result.returncode != 0:
        print(f"\n[FATAL] {fatal_msg}", flush=True)
        print(f"[FATAL] Command exited {result.returncode}: {cmd}", flush=True)
        sys.exit(result.returncode)
    return result


# ── Heartbeat runner ──────────────────────────────────────────────────────────

def run_with_heartbeat(cmd, env=None, timeout=None, label=None, interval=5):
    """
    Run cmd with a periodic elapsed-time heartbeat printed in place (\\r).

    Used for long quiet operations (payload extraction, image unpacking) so
    the terminal never looks frozen. stdout and stderr of the child process
    are suppressed; only the heartbeat line is shown.

    Returns the completed Popen object (caller checks .returncode).
    """
    if label:
        print(f"    {label}", flush=True)
    sys.stdout.flush()

    proc = subprocess.Popen(
        cmd, shell=True, env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    start = time.time()
    last_heartbeat = 0
    heartbeat_shown = False

    while True:
        time.sleep(1)
        if proc.poll() is not None:
            break

        elapsed = int(time.time() - start)

        if timeout is not None and elapsed >= timeout:
            proc.kill()
            proc.wait()
            print(f"\n[FATAL] Command timed out after {timeout}s", flush=True)
            print(f"[FATAL] Command was: {cmd}", flush=True)
            sys.exit(1)

        if elapsed >= last_heartbeat + interval:
            last_heartbeat = elapsed
            print(f"\r    [..] still working  ({_fmt_time(elapsed)})",
                  end="", flush=True)
            heartbeat_shown = True

    if heartbeat_shown:
        print(flush=True)   # end the \\r line cleanly

    return proc


def run_critical_with_heartbeat(cmd, fatal_msg, env=None, timeout=None,
                                label=None, interval=5):
    """Heartbeat version of run_critical — aborts on non-zero exit."""
    proc = run_with_heartbeat(cmd, env=env, timeout=timeout,
                              label=label, interval=interval)
    if proc.returncode != 0:
        print(f"\n[FATAL] {fatal_msg}", flush=True)
        print(f"[FATAL] Command exited {proc.returncode}: {cmd}", flush=True)
        sys.exit(proc.returncode)
    return proc


# ── Tool validation ───────────────────────────────────────────────────────────

_REQUIRED_TOOLS = {
    "strings": "binutils (apt install binutils)",
    "unzip":   "unzip (apt install unzip)",
    "7z":      "p7zip-full (apt install p7zip-full)",
}

_RAR_FALLBACK_TOOLS = ("unrar", "unar", "bsdtar")


def _check_required_tools():
    """
    Verify that every external binary the pipeline calls is present in PATH.
    Fails fast with an actionable message rather than silently producing
    empty results later (e.g., 'strings' missing → 0 analysis hits).
    """
    missing = []
    for tool, hint in _REQUIRED_TOOLS.items():
        if shutil.which(tool) is None:
            missing.append((tool, hint))
    if missing:
        print("[FATAL] Required external tools not found in PATH:", flush=True)
        for tool, hint in missing:
            print(f"        {tool}  →  install: {hint}", flush=True)
        sys.exit(1)
    _ok("tools: strings, unzip, 7z")


# ── Tool validation: payload-dumper-go ───────────────────────────────────────

def ensure_dumper():
    """
    Validate that the payload-dumper-go binary is present and executable.

    If it is missing, attempt to recover automatically:
      1. git clone the repository into tools/payload-dumper-go/
      2. go build -o payload-dumper-go .

    Aborts the pipeline (sys.exit) if the binary cannot be made available.
    """
    if os.path.isfile(DUMPER) and os.access(DUMPER, os.X_OK):
        try:
            probe = subprocess.run(
                [DUMPER],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            if probe.returncode in (0, 1, 2):
                _ok("payload-dumper-go")
                return
        except subprocess.TimeoutExpired:
            _ok("payload-dumper-go")
            return
        except OSError as exc:
            _warn(f"payload-dumper-go is not runnable on this host: {exc}")
        except Exception:
            pass

    _warn(f"payload-dumper-go not usable: {DUMPER}")
    _info("Attempting automatic build from source ...")

    os.makedirs(os.path.join(PROJECT_ROOT, "tools"), exist_ok=True)

    if not os.path.isdir(DUMPER_DIR):
        result = subprocess.run(
            f'git clone "{DUMPER_REPO}" "{DUMPER_DIR}"',
            shell=True,
        )
        if result.returncode != 0:
            print(f"\n[FATAL] git clone failed (repo: {DUMPER_REPO})", flush=True)
            print("[FATAL] Check network access or manually place the binary at:",
                  flush=True)
            print(f"        {DUMPER}", flush=True)
            sys.exit(1)
    else:
        _info(f"source directory exists: {DUMPER_DIR}")
        if not os.path.isfile(os.path.join(DUMPER_DIR, "go.mod")):
            print("[FATAL] payload-dumper-go source files are missing.", flush=True)
            print("[FATAL] Only a prebuilt binary is present, and it is not runnable here.",
                  flush=True)
            print("[FATAL] Replace it with a host-compatible binary or clone the source into:",
                  flush=True)
            print(f"        {DUMPER_DIR}", flush=True)
            sys.exit(1)
        go_bin = shutil.which("go")
        if go_bin is None:
            print("[FATAL] Go toolchain not found; cannot rebuild payload-dumper-go.",
                  flush=True)
            print("[FATAL] Current binary is not runnable on this host.", flush=True)
            print("[FATAL] Install Go and rebuild from source, or replace the binary at:",
                  flush=True)
            print(f"        {DUMPER}", flush=True)
            sys.exit(1)

    result = subprocess.run(
        f'cd "{DUMPER_DIR}" && go build -o payload-dumper-go .',
        shell=True,
    )
    if result.returncode != 0:
        print("[FATAL] go build failed for payload-dumper-go", flush=True)
        print("[FATAL] Install the Go toolchain (golang.org) or replace the binary at:",
              flush=True)
        print(f"        {DUMPER}", flush=True)
        sys.exit(1)

    if not (os.path.isfile(DUMPER) and os.access(DUMPER, os.X_OK)):
        print(f"[FATAL] Binary still not executable after build: {DUMPER}", flush=True)
        sys.exit(1)

    _ok(f"payload-dumper-go built: {DUMPER}")


# ── Input detection ───────────────────────────────────────────────────────────

def _read_magic(path, size, offset=0):
    """Read `size` bytes from `path` at `offset` for magic byte detection."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(size)
    except Exception:
        return b""


def detect_input_type(path):
    """
    Detect input file type using extension first, magic bytes as fallback.

    Returns one of: INPUT_ZIP, INPUT_RAR, INPUT_TAR, INPUT_PAYLOAD, INPUT_IMG, INPUT_UNKNOWN
    """
    ext  = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    path_lower = path.lower()

    if ext == ".zip":
        return INPUT_ZIP
    if ext == ".rar":
        return INPUT_RAR
    if ext == ".tar":
        return INPUT_TAR
    if ext in (".w", ".trx", ".web"):
        return INPUT_IOT
    if "pureubi" in name or "pureubi" in path_lower:
        return INPUT_IOT
    if name == "payload.bin":
        return INPUT_PAYLOAD
    if ext == ".img":
        return INPUT_IMG

    magic4 = _read_magic(path, 4)

    if magic4 == _MAGIC_ZIP:
        return INPUT_ZIP
    if magic4 == _MAGIC_RAR4 or _read_magic(path, 7) == _MAGIC_RAR5:
        return INPUT_RAR
    if _read_magic(path, len(_MAGIC_TAR), offset=257) == _MAGIC_TAR:
        return INPUT_TAR
    if magic4 == _MAGIC_PAYLOAD:
        return INPUT_PAYLOAD
    if magic4 == _MAGIC_SPARSE:
        return INPUT_IMG
    if magic4 == _MAGIC_EROFS:
        return INPUT_IMG
    if _read_magic(path, 2, offset=0x438) == _MAGIC_EXT4:
        return INPUT_IMG
    for _, magic in _FS_MAGIC_PATTERNS:
        if magic4 == magic:
            return INPUT_IOT
    if ext == ".bin":
        return INPUT_IOT

    return INPUT_UNKNOWN


def _find_largest_firmware_file(base_dir):
    payload_hit = None
    best_path = None
    best_size = -1

    for dirpath, dirnames, filenames in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if d not in _SEARCH_SKIP]
        for name in filenames:
            full = os.path.join(dirpath, name)
            lower = name.lower()
            if lower == "payload.bin":
                payload_hit = full
                break
            if not lower.endswith(_ARCHIVE_FIRMWARE_EXTS):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > best_size:
                best_path = full
                best_size = size
        if payload_hit:
            break

    if payload_hit:
        return payload_hit
    return best_path


def _find_largest_extracted_blob(base_dir, min_size=32 * 1024):
    """
    Last-resort archive resolver fallback. If a vendor packages firmware under
    an unexpected name, pick the largest non-obviously-document file so the
    pipeline can still attempt analysis instead of aborting early.
    """
    best_path = None
    best_size = -1

    for dirpath, dirnames, filenames in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if d not in _SEARCH_SKIP]
        for name in filenames:
            lower = name.lower()
            if lower.endswith(_ARCHIVE_NOISE_EXTS):
                continue
            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size < min_size:
                continue
            if size > best_size:
                best_path = full
                best_size = size

    return best_path


def _list_archive_members(archive_path):
    result = subprocess.run(
        f'7z l "{archive_path}"',
        shell=True,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []

    members = []
    for line in result.stdout.splitlines():
        m = re.match(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(\d+)\s+\d+\s+(.+)$', line)
        if not m:
            continue
        try:
            size = int(m.group(1))
        except ValueError:
            continue
        name = m.group(2).strip()
        members.append((name, size))
    return members


def _dir_has_entries(path):
    try:
        return os.path.isdir(path) and any(os.scandir(path))
    except Exception:
        return False


def _available_rar_fallbacks():
    return [tool for tool in _RAR_FALLBACK_TOOLS if shutil.which(tool)]


def _try_extract_rar_with_fallbacks(rar_path, temp_dir, member=None):
    """
    Try optional RAR-capable backends when 7z cannot decode a sample.

    member:
      - None: extract the whole archive into temp_dir
      - str : try to extract a single named member
    """
    for tool in _available_rar_fallbacks():
        if tool == "unrar":
            if member:
                cmd = f'unrar e -y "{rar_path}" "{member}" "{temp_dir}/"'
                label = f"unrar member  {os.path.basename(member)}"
            else:
                cmd = f'unrar x -y "{rar_path}" "{temp_dir}/"'
                label = f"unrar archive  {os.path.basename(rar_path)}"
        elif tool == "unar":
            # unar does not reliably support single-member extraction on every build;
            # use whole-archive extraction in that case.
            cmd = f'unar -force-overwrite -output-directory "{temp_dir}" "{rar_path}"'
            label = (
                f"unar archive  {os.path.basename(rar_path)}"
                if member is None else
                f"unar archive  {os.path.basename(rar_path)}  (member fallback)"
            )
        else:  # bsdtar
            if member:
                cmd = f'bsdtar -x -f "{rar_path}" -C "{temp_dir}" "{member}"'
                label = f"bsdtar member  {os.path.basename(member)}"
            else:
                cmd = f'bsdtar -x -f "{rar_path}" -C "{temp_dir}"'
                label = f"bsdtar archive  {os.path.basename(rar_path)}"

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and _find_largest_firmware_file(temp_dir):
            _info(f"{tool} fallback succeeded")
            return True
        if result.returncode == 0 and _dir_has_entries(temp_dir):
            _info(f"{tool} fallback produced extracted files")
            return True
    return False


def _extract_selected_archive_members(archive_path, temp_dir, members):
    for name in members:
        result = subprocess.run(
            f'7z e "{archive_path}" "{name}" -o"{temp_dir}" -y',
            shell=True,
            capture_output=True,
            text=True,
        )
        _info(f"extract member  {os.path.basename(name)}")
        extracted_path = os.path.join(temp_dir, os.path.basename(name))
        if result.returncode == 0 and os.path.isfile(extracted_path):
            return True
        if os.path.isfile(extracted_path) and os.path.getsize(extracted_path) > 0:
            return True
        stderr = (result.stderr or "") + (result.stdout or "")
        if "Unsupported Method" in stderr:
            _warn(
                f"7z created {os.path.basename(name)} but could not decode the RAR compression method"
            )
            if _try_extract_rar_with_fallbacks(archive_path, temp_dir, member=name):
                return True
            continue
        if os.path.isfile(extracted_path):
            _warn(
                f"7z extracted {os.path.basename(name)} with size {os.path.getsize(extracted_path)} bytes but returned {result.returncode}"
            )
            continue
        _warn(
            f"failed to extract {os.path.basename(name)} from RAR (exit {result.returncode})"
        )
    return False


def _list_zip_members(zip_path):
    result = subprocess.run(
        f'unzip -Z1 "{zip_path}"',
        shell=True,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _cleanup_registered_temp_inputs():
    for path in reversed(_TEMP_INPUT_DIRS):
        shutil.rmtree(path, ignore_errors=True)


def _make_temp_input_dir():
    os.makedirs(TEMP_INPUTS_DIR, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="fw_input_", dir=TEMP_INPUTS_DIR)
    _TEMP_INPUT_DIRS.append(temp_dir)
    return temp_dir


atexit.register(_cleanup_registered_temp_inputs)


def _resolve_zip_firmware(zip_path):
    temp_dir = _make_temp_input_dir()
    run_critical(
        f'unzip -o "{zip_path}" -d "{temp_dir}"',
        fatal_msg=f"Failed to inspect ZIP input: {zip_path}",
        label=f"inspect zip  {os.path.basename(zip_path)}",
        quiet=True,
    )

    resolved = _find_largest_firmware_file(temp_dir)
    if not resolved:
        resolved = _find_largest_extracted_blob(temp_dir)
        if resolved:
            _warn("no known firmware extension found inside ZIP; using largest extracted blob fallback")
        else:
            print("[FATAL] No payload.bin, .bin, .img, .web, .trx, .w, or .pkgtb found inside ZIP.", flush=True)
            print(f"        ZIP: {zip_path}", flush=True)
            sys.exit(1)

    resolved_type = detect_input_type(resolved)
    _info(f"resolved firmware: {os.path.relpath(resolved, PROJECT_ROOT)}")
    return resolved, resolved_type


def _resolve_rar_firmware(rar_path):
    temp_dir = _make_temp_input_dir()
    _info(f"inspect rar  {os.path.basename(rar_path)}")
    result = subprocess.run(
        f'7z x "{rar_path}" -o"{temp_dir}" -y',
        shell=True,
        capture_output=True,
        text=True,
    )

    resolved = _find_largest_firmware_file(temp_dir)
    if resolved and os.path.getsize(resolved) == 0:
        resolved = None

    if result.returncode != 0 and not resolved:
        stderr = (result.stderr or "") + (result.stdout or "")
        if "Unsupported Method" in stderr:
            _warn("7z could list the RAR but could not decode at least one member compression method")
            if _try_extract_rar_with_fallbacks(rar_path, temp_dir):
                resolved = _find_largest_firmware_file(temp_dir)
        members = _list_archive_members(rar_path)
        preferred = []
        others = []
        for name, size in members:
            lower = os.path.basename(name).lower()
            if lower == "payload.bin":
                preferred.append(name)
            elif lower.endswith(_ARCHIVE_FIRMWARE_EXTS):
                others.append((size, name))

        selected = preferred + [name for _, name in sorted(others, reverse=True)]
        if not resolved and (not selected or not _extract_selected_archive_members(rar_path, temp_dir, selected)):
            print(
                f"[FATAL] Failed to inspect RAR input: {rar_path}",
                flush=True,
            )
            if "Unsupported Method" in stderr:
                print(
                    "[FATAL] 7z reported an unsupported RAR compression method and no optional fallback extractor succeeded. Install unrar/unar/bsdtar or handle this sample as BLOCKED.",
                    flush=True,
                )
            sys.exit(1)

    resolved = resolved or _find_largest_firmware_file(temp_dir)
    resolved = resolved or _find_largest_extracted_blob(temp_dir)
    if resolved and os.path.getsize(resolved) == 0:
        print(f"[FATAL] Extracted firmware blob is empty after RAR unpack: {resolved}", flush=True)
        print(
            "[FATAL] The current extractor likely does not support this RAR compression method.",
            flush=True,
        )
        sys.exit(1)
    if not resolved:
        print("[FATAL] No payload.bin, .bin, .img, .web, .trx, .w, or .pkgtb found inside RAR.", flush=True)
        print(f"        RAR: {rar_path}", flush=True)
        sys.exit(1)

    resolved_type = detect_input_type(resolved)
    _info(f"resolved firmware: {os.path.relpath(resolved, PROJECT_ROOT)}")
    return resolved, resolved_type


def _resolve_tar_firmware(tar_path):
    temp_dir = _make_temp_input_dir()
    run_critical(
        f'tar -xf "{tar_path}" -C "{temp_dir}"',
        fatal_msg=f"Failed to inspect TAR input: {tar_path}",
        label=f"inspect tar  {os.path.basename(tar_path)}",
        quiet=True,
    )

    resolved = _find_largest_firmware_file(temp_dir)
    if not resolved:
        resolved = _find_largest_extracted_blob(temp_dir)
        if resolved:
            _warn("no known firmware extension found inside TAR; using largest extracted blob fallback")
        else:
            print("[FATAL] No payload.bin, .bin, .img, .web, .trx, .w, or .pkgtb found inside TAR.", flush=True)
            print(f"        TAR: {tar_path}", flush=True)
            sys.exit(1)

    resolved_type = detect_input_type(resolved)
    _info(f"resolved firmware: {os.path.relpath(resolved, PROJECT_ROOT)}")
    return resolved, resolved_type


# ── Clean ─────────────────────────────────────────────────────────────────────

def clean(skip):
    global _EXTRACTED_ACTIVE
    os.makedirs(CACHE_DIR, exist_ok=True)
    _prune_stale_dirs(CACHE_DIR)
    if skip:
        _info("reuse mode — skipping extraction")
        return

    _info("cleaning .cache/build and .cache/rootfs/ ...")
    _reset_dir_fast(WORK_DIR)
    _reset_dir_fast(ROOTFS_DIR)

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "system"), exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "vendor"), exist_ok=True)

    # .cache/extracted/ is never deleted — payload re-extraction is expensive
    os.makedirs(EXTRACTED_DIR, exist_ok=True)
    # ensure input dir exists for user guidance
    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    _EXTRACTED_ACTIVE = False


def _reset_dir_fast(path):
    """
    Make a workspace directory immediately reusable, even when the previous tree
    contains millions of files. Old contents are deleted in the background.
    """
    if not os.path.lexists(path):
        return

    parent = os.path.dirname(path)
    base = os.path.basename(path.rstrip(os.sep))
    quarantine = os.path.join(
        parent,
        f".__stale_{base}_{int(time.time())}_{os.getpid()}",
    )

    try:
        os.replace(path, quarantine)
    except FileNotFoundError:
        return
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
        return

    try:
        subprocess.Popen(
            ["rm", "-rf", quarantine],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        shutil.rmtree(quarantine, ignore_errors=True)


# ── OTA unzip ─────────────────────────────────────────────────────────────────

def unzip_firmware(zip_path):
    run_critical(
        f'unzip -o "{zip_path}" -d "{WORK_DIR}"',
        fatal_msg=f"Failed to unzip OTA archive: {zip_path}",
        label=f"unzip  {os.path.basename(zip_path)}",
        quiet=True,
    )


# ── payload.bin extraction ────────────────────────────────────────────────────

def extract_payload(payload_path=None):
    """
    Extract partitions from a payload.bin using payload-dumper-go.

    Returns True on success, False on missing file or tool/extraction failure.
    """
    if payload_path is None:
        payload_path = os.path.join(WORK_DIR, "payload.bin")

    if not os.path.exists(payload_path):
        _warn(f"payload.bin not found: {payload_path}")
        return False

    try:
        ensure_dumper()
    except SystemExit:
        _warn("payload-dumper-go unavailable; continuing without payload extraction")
        return False

    try:
        run_critical_with_heartbeat(
            f'"{DUMPER}" -o "{EXTRACTED_DIR}" "{payload_path}"',
            fatal_msg="payload-dumper-go failed — extracted partition set incomplete.",
            label="payload-dumper-go  (extracting partitions, this may take several minutes)",
            timeout=1800,   # 30 min; large OTAs can take 5–10 min
            interval=10,    # heartbeat every 10s — avoids flooding for long extractions
        )
    except SystemExit:
        _warn("payload-dumper-go extraction failed; continuing with fallback analysis roots")
        return False
    global _EXTRACTED_ACTIVE
    _EXTRACTED_ACTIVE = True
    return True


# ── Collect images from extracted directories ─────────────────────────────────

def collect_images():
    """
    Surface .img files and partition directories produced by payload-dumper-go.

    Moves any extracted_<timestamp>/ directories from the project root into
     .cache/extracted/, then copies .img files / partition directories into
    .cache/build so the rest of the pipeline can find them.
    """
    imgs_found = []
    dirs_found = []

    # Move stray extracted_* dirs from the project root into .cache/extracted/
    for d in os.listdir(PROJECT_ROOT):
        if not d.startswith("extracted_"):
            continue

        src_dir = os.path.join(PROJECT_ROOT, d)
        dst_dir = os.path.join(EXTRACTED_DIR, d)

        if not os.path.exists(dst_dir):
            shutil.move(src_dir, dst_dir)

        for root, dirs, files in os.walk(dst_dir):
            for f in files:
                if f.endswith(".img"):
                    src = os.path.join(root, f)
                    dst = os.path.join(WORK_DIR, f)
                    if not os.path.exists(dst):
                        shutil.copy(src, dst)
                        imgs_found.append(f)
            for sub in list(dirs):
                if sub in ("system", "vendor", "product", "system_ext"):
                    dst_sub = os.path.join(WORK_DIR, sub)
                    if not os.path.exists(dst_sub):
                        shutil.copytree(os.path.join(root, sub), dst_sub)
                        dirs_found.append(sub)
            break  # top-level of each extracted_* only

    # Also surface from .cache/extracted/ directly (when --out was honoured)
    for entry in os.listdir(EXTRACTED_DIR):
        full = os.path.join(EXTRACTED_DIR, entry)
        if os.path.isfile(full) and entry.endswith(".img"):
            dst = os.path.join(WORK_DIR, entry)
            if not os.path.exists(dst):
                shutil.copy(full, dst)
                imgs_found.append(entry)
        elif os.path.isdir(full) and entry in ("system", "vendor", "product", "system_ext"):
            dst_sub = os.path.join(WORK_DIR, entry)
            if not os.path.exists(dst_sub):
                shutil.copytree(full, dst_sub)
                dirs_found.append(entry)

    parts = []
    if imgs_found:
        parts.append(f"{len(imgs_found)} image(s): {', '.join(imgs_found)}")
    if dirs_found:
        parts.append(f"{len(dirs_found)} partition dir(s): {', '.join(dirs_found)}")
    if parts:
        _info(f"collected {';  '.join(parts)}")


def _validate_partition_images():
    """
    Gate check after collect_images(): confirm that system partition material
    is reachable. Aborts if nothing can be found.
    """
    system_img = os.path.join(WORK_DIR, "system.img")
    system_dir = os.path.join(WORK_DIR, "system")

    if os.path.exists(system_img):
        return True
    if os.path.isdir(system_dir) and os.listdir(system_dir):
        return True

    found = _search_for_partition("system", EXTRACTED_DIR)
    if found:
        return True

    _warn("system partition not found after extraction; rootfs assembly will use fallback analysis roots")
    _info(f"searched: {system_img}")
    _info(f"          {system_dir}")
    _info(f"          {EXTRACTED_DIR} (recursive)")
    return False


# ── Partition directory search ────────────────────────────────────────────────

def _looks_like_partition_root(path):
    """
    True if the directory is a real Android partition root (bin/ or lib/ present
    and non-empty, not just broken symlinks or empty scaffolding).
    """
    try:
        entries = os.listdir(path)
    except Exception:
        return False

    for name in entries:
        if name not in _PARTITION_INDICATORS:
            continue
        full = os.path.join(path, name)
        if not os.path.isdir(full):
            continue
        try:
            if any(os.path.isfile(os.path.join(full, f)) for f in os.listdir(full)):
                return True
        except Exception:
            continue

    return False


def _search_for_partition(name, search_root, max_depth=6):
    """
    Walk search_root looking for a directory named `name` that looks like
    an Android partition root. Returns the first match, or None.
    """
    name_lower = name.lower()

    for root, dirs, _ in os.walk(search_root):
        dirs[:] = [
            d for d in dirs
            if d not in _SEARCH_SKIP
            and not d.startswith(".")
            and (root.count(os.sep) - search_root.count(os.sep)) < max_depth
        ]

        for d in dirs:
            if d.lower() == name_lower:
                candidate = os.path.join(root, d)
                if _looks_like_partition_root(candidate):
                    return candidate

    return None


def find_partition_dir(name):
    """
    Locate the extracted partition directory for `name`.

    Search order:
      1. .cache/build/<name>/
      2. .cache/extracted/**/<name>/
      3. PROJECT_ROOT/**/<name>/
    """
    candidate = os.path.join(WORK_DIR, name)
    if os.path.isdir(candidate) and _looks_like_partition_root(candidate):
        return candidate

    result = _search_for_partition(name, EXTRACTED_DIR)
    if result:
        return result

    result = _search_for_partition(name, PROJECT_ROOT)
    if result:
        return result

    return None


# ── Build rootfs ──────────────────────────────────────────────────────────────

def _count_files(path):
    """Count regular files in a directory tree."""
    total = 0
    for _, _, files in os.walk(path):
        total += len(files)
    return total


def safe_copy(src, dst):
    skipped = 0
    for root, _, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target_dir = os.path.join(dst, rel)
        os.makedirs(target_dir, exist_ok=True)
        for f in files:
            try:
                shutil.copy2(os.path.join(root, f), os.path.join(target_dir, f))
            except Exception:
                skipped += 1
    if skipped:
        _warn(f"safe_copy: {skipped} file(s) skipped (permissions/broken symlinks)")


def extract_img(img_name, out_dir):
    """
    Extract a partition image into out_dir using 7z.

    Detects Android sparse format and converts with simg2img if available,
    falling back to direct 7z extraction.
    """
    img_path = os.path.join(WORK_DIR, img_name)
    if not os.path.exists(img_path):
        _warn(f"{img_name} not found, skipping")
        return False

    if _read_magic(img_path, 4) == _MAGIC_SPARSE:
        if shutil.which("simg2img"):
            raw_path = img_path + ".raw"
            result = run(
                f'simg2img "{img_path}" "{raw_path}"',
                label=f"simg2img  {img_name}  (sparse → raw)",
            )
            if result.returncode == 0 and os.path.exists(raw_path):
                img_path = raw_path
            else:
                _warn(f"simg2img failed for {img_name}, attempting 7z directly")
        else:
            _warn(f"{img_name} is sparse — simg2img not found, trying 7z directly")

    os.makedirs(out_dir, exist_ok=True)
    proc = run_with_heartbeat(
        f'7z x "{img_path}" -o"{out_dir}" -y',
        label=f"7z extract  {img_name}",
        interval=5,
    )
    if proc.returncode != 0:
        # 7z may return a warning exit code for ext images that still extract
        # correctly (for example "data after the end of archive").
        try:
            extracted_entries = os.listdir(out_dir)
        except Exception:
            extracted_entries = []
        if extracted_entries:
            _warn(f"7z returned warning status for {img_name} (exit {proc.returncode}); using extracted output")
            return True
        _warn(f"7z extraction failed for {img_name} (exit {proc.returncode})")
        return False
    return True


def _find_partition_root_in_extract(base, partition_name):
    """
    After 7z extraction the layout may be nested (base/system/ or base/0/system/).
    Walk up to 3 levels to find the real partition root.
    """
    for _ in range(3):
        named_child = os.path.join(base, partition_name)
        if os.path.isdir(named_child) and _looks_like_partition_root(named_child):
            return named_child
        if _looks_like_partition_root(base):
            return base
        try:
            subdirs = [e for e in os.listdir(base)
                       if os.path.isdir(os.path.join(base, e))]
        except Exception:
            break
        if len(subdirs) == 1:
            base = os.path.join(base, subdirs[0])
        elif partition_name in subdirs:
            base = os.path.join(base, partition_name)
        else:
            break
    return base


def build_rootfs_for_partition(name):
    dst = os.path.join(ROOTFS_DIR, name)

    found = find_partition_dir(name)
    if found:
        safe_copy(found, dst)
        count = _count_files(dst)
        if count == 0:
            _warn(f"{name}: directory found but 0 files copied — check {found}")
            return False
        _ok(f"{name:<10} → .cache/rootfs/{name} ({count} files)")
        return True

    img_tmp = os.path.join(WORK_DIR, f"_tmp_{name}")
    if extract_img(f"{name}.img", img_tmp):
        inner = _find_partition_root_in_extract(img_tmp, name)
        safe_copy(inner, dst)
        count = _count_files(dst)
        if count == 0:
            _warn(f"{name}: extraction produced 0 files — verify {img_tmp}")
            return False
        _ok(f"{name:<10} → .cache/rootfs/{name} ({count} files)")
        return True

    _warn(f"{name}: not found — .cache/rootfs/{name} will be empty")
    return False


def _validate_rootfs_structure():
    """
    Verify that the assembled system rootfs contains the critical Android
    directory layout: bin/, lib[64]/, etc/.

    A non-zero file count does not guarantee a usable rootfs — a structurally
    broken extraction can produce files without the expected hierarchy.
    """
    system = os.path.join(ROOTFS_DIR, "system")

    lib_ok = (
        os.path.isdir(os.path.join(system, "lib")) or
        os.path.isdir(os.path.join(system, "lib64"))
    )
    checks = {
        "bin":     os.path.isdir(os.path.join(system, "bin")),
        "lib[64]": lib_ok,
        "etc":     os.path.isdir(os.path.join(system, "etc")),
    }
    missing = [name for name, ok in checks.items() if not ok]

    if missing:
        print("\n[FATAL] Invalid rootfs — missing critical directories:", flush=True)
        for name in missing:
            print(f"         .cache/rootfs/system/{name}", flush=True)
        print("        The firmware extraction may have failed or used an unsupported format.",
              flush=True)
        sys.exit(1)

    _ok("rootfs structure verified  (bin, lib, etc)")


def _best_effort_analysis_root(*base_dirs):
    """
    Choose a non-empty directory to analyze when ideal rootfs assembly fails.
    Prefer directories with more files and stronger web/system hints.
    """
    best = None
    best_score = -1
    for base_dir in base_dirs:
        if not base_dir or not os.path.isdir(base_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(base_dir):
            dirnames[:] = [d for d in dirnames if d not in _SEARCH_SKIP and not d.startswith("_nested_")]
            file_count = len(filenames)
            if file_count == 0:
                continue
            score = file_count
            lower = dirpath.lower()
            if any(tok in lower for tok in ("/www", "/web", "/cgi-bin", "/htdocs", "/system", "/vendor", "/usr/lib/lua/luci")):
                score += 100
            if any(name in filenames for name in ("payload.bin", "ap.img", "system.img", "vendor.img")):
                score += 50
            if score > best_score:
                best_score = score
                best = dirpath
    return best


def _active_fallback_dirs():
    dirs = [WORK_DIR]
    if _EXTRACTED_ACTIVE:
        dirs.append(EXTRACTED_DIR)
    return dirs


def _fallback_analysis_root_for_input(path=None):
    """
    Pick a survivable analysis root after extraction/assembly failure.
    Preference order:
      1. workspace build dir
      2. extracted payload dir
      3. directory containing the original input
    """
    candidate = _best_effort_analysis_root(*_active_fallback_dirs())
    if candidate:
        return candidate
    if path:
        parent = os.path.dirname(os.path.abspath(path))
        if os.path.isdir(parent):
            return parent
    return None


def build_rootfs():
    system_ok = build_rootfs_for_partition("system")
    build_rootfs_for_partition("vendor")

    if not system_ok:
        fallback = _best_effort_analysis_root(*_active_fallback_dirs())
        if fallback:
            _warn("failed to populate .cache/rootfs/system; using best-effort extracted analysis root")
            _ok(f"analysis root: {os.path.relpath(fallback, PROJECT_ROOT)}")
            return fallback
        print("\n[FATAL] Failed to populate .cache/rootfs/system.", flush=True)
        print(f"        Expected: {os.path.join(ROOTFS_DIR, 'system')}", flush=True)
        print("        Verify extraction output in .cache/extracted/ and .cache/build",
              flush=True)
        sys.exit(1)

    try:
        _validate_rootfs_structure()
    except SystemExit:
        fallback = _best_effort_analysis_root(
            os.path.join(ROOTFS_DIR, "system"),
            *_active_fallback_dirs(),
        )
        if fallback:
            _warn("assembled rootfs is incomplete; using best-effort analysis root")
            _ok(f"analysis root: {os.path.relpath(fallback, PROJECT_ROOT)}")
            return fallback
        raise

    return os.path.join(ROOTFS_DIR, "system")


# ── Extraction handlers (one per input type) ──────────────────────────────────

def handle_zip_input(zip_path):
    unzip_firmware(zip_path)

    ok = extract_payload()
    if not ok:
        _warn("payload.bin not found inside OTA zip; continuing with extracted archive contents")
        return False

    collect_images()
    return _validate_partition_images()


def handle_payload_input(payload_path):
    ok = extract_payload(payload_path=payload_path)
    if not ok:
        _warn(f"payload.bin not found: {payload_path}; continuing with best-effort fallback")
        return False

    collect_images()
    return _validate_partition_images()


def _looks_like_iot_img(img_path):
    magic4 = _read_magic(img_path, 4)
    if magic4 in {_MAGIC_FDT, b"UBI#", b"hsqs", b"sqsh", b"qshs", b"shsq"}:
        return True
    return bool(_find_fs_magic_offsets(img_path, max_hits=1))


def handle_img_input(img_path):
    if _looks_like_iot_img(img_path):
        _info("img payload looks like embedded IoT firmware; routing through IoT extractor")
        return extract_iot_firmware(img_path)
    dst = os.path.join(WORK_DIR, os.path.basename(img_path))
    if not os.path.exists(dst):
        shutil.copy2(img_path, dst)
    return None


# ── IoT firmware extraction ───────────────────────────────────────────────────

def _count_files_quiet(path):
    try:
        return _count_files(path)
    except Exception:
        return 0


def _dir_size_quiet(path):
    total = 0
    try:
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                try:
                    total += os.path.getsize(full)
                except OSError:
                    pass
    except Exception:
        return 0
    return total


def _format_size(num_bytes):
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f}G"
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f}K"
    return f"{num_bytes}B"


def _latest_run_manifest():
    for run_dir in _recent_dirs(RUNS_DIR, prefix="run_"):
        manifest = os.path.join(run_dir, "manifest.json")
        if os.path.isfile(manifest):
            try:
                with open(manifest, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                continue
    return None


def print_cache_status():
    print("Cache / workspace status", flush=True)
    print(f"  inputs          : {_format_size(_dir_size_bytes(FIRMWARE_DIR))}", flush=True)
    print(f"  .cache/extracted: {_format_size(_dir_size_bytes(EXTRACTED_DIR))}", flush=True)
    print(f"  .cache/rootfs   : {_format_size(_dir_size_bytes(ROOTFS_DIR))}", flush=True)
    print(f"  .cache/build    : {_format_size(_dir_size_bytes(WORK_DIR))}", flush=True)
    print(f"  runs            : {_format_size(_dir_size_bytes(RUNS_DIR))}", flush=True)
    print(f"  stale cache dirs: {_dir_count_with_prefix(CACHE_DIR, _STALE_PREFIX)}", flush=True)

    extracted = _recent_dirs(EXTRACTED_DIR, prefix="extracted_")
    print(f"  extracted sets  : {len(extracted)}", flush=True)
    if extracted:
        print(f"  latest extract  : {os.path.relpath(extracted[0], PROJECT_ROOT)}", flush=True)

    runs = _recent_dirs(RUNS_DIR, prefix="run_")
    print(f"  run artifacts   : {len(runs)}", flush=True)
    latest = _latest_run_manifest()
    if latest:
        print(f"  latest run      : {latest.get('run_id')}", flush=True)
        summary = latest.get("summary") or {}
        if summary:
            print(f"  latest summary  : {summary}", flush=True)


def cleanup_targets(targets):
    mapping = {
        "build": [WORK_DIR],
        "rootfs": [ROOTFS_DIR],
        "runs": [RUNS_DIR],
        "extracted": [EXTRACTED_DIR],
        "input": [FIRMWARE_DIR],
        "all-temp": [WORK_DIR, ROOTFS_DIR],
    }
    seen = set()
    for target in targets:
        for path in mapping[target]:
            if path in seen:
                continue
            seen.add(path)
            shutil.rmtree(path, ignore_errors=True)
            print(f"removed: {path}", flush=True)


def apply_retention_limits(retain_runs=None, retain_extracted=None):
    removed = []
    if retain_runs is not None:
        removed.extend(_prune_dir_set(_recent_dirs(RUNS_DIR, prefix="run_"), retain_runs))
    if retain_extracted is not None:
        removed.extend(_prune_dir_set(_recent_dirs(EXTRACTED_DIR, prefix="extracted_"), retain_extracted))
    removed.extend(_prune_stale_dirs(CACHE_DIR))
    for path in removed:
        print(f"pruned: {os.path.relpath(path, PROJECT_ROOT)}", flush=True)
    return removed


def _describe_rootfs_candidate(path):
    file_count = _count_files_quiet(path)
    size_bytes = _dir_size_quiet(path)

    core_dirs = [
        d for d in ("bin", "etc", "usr", "lib", "sbin")
        if os.path.isdir(os.path.join(path, d))
    ]
    web_hits = [
        rel for rel in (
            "www",
            "web",
            "web/cgi-bin",
            "htdocs",
            "var/www",
            "var/web",
            "cgi-bin",
            "web/cgi-bin/cstecgi.cgi",
            "bin/boa",
            "bin/httpd",
            "bin/goahead",
            "bin/uhttpd",
            "sbin/boa",
            "sbin/httpd",
            "sbin/goahead",
            "sbin/uhttpd",
            "usr/sbin/boa",
            "usr/sbin/httpd",
            "usr/sbin/goahead",
            "usr/sbin/uhttpd",
            "etc/boa.org/boa.conf",
            "etc/boa/boa.conf",
            "etc/boa.conf",
            "etc/lighttpd/lighttpd.conf",
            "etc/lighttpd.conf",
            "etc/config/uhttpd",
            "www/apply.cgi",
            "www/goform",
            "www/boafrm",
            "www/cgi-bin",
        )
        if os.path.exists(os.path.join(path, rel))
    ]
    init_hits = [
        rel for rel in (
            "etc/init.d",
            "etc/inittab",
            "etc/rcS",
            "etc/init.d/rcS",
            "bin/init",
            "sbin/init",
            "init",
        )
        if os.path.exists(os.path.join(path, rel))
    ]
    exec_hits = [
        rel for rel in (
            "bin/busybox",
            "bin/boa",
            "sbin/httpd",
            "usr/sbin/httpd",
            "usr/sbin/uhttpd",
            "web/cgi-bin/cstecgi.cgi",
        )
        if os.path.exists(os.path.join(path, rel))
    ]

    score = 0
    why = []

    if file_count > 800:
        score += 3
        why.append("files>800")
    if file_count < 120:
        score -= 5
        why.append("files<120")

    for d in core_dirs:
        score += 2
    if core_dirs:
        why.append("core:" + ",".join(core_dirs))

    if web_hits:
        score += 5
        why.append("web")
    if init_hits:
        score += 2
        why.append("init")
    if exec_hits:
        score += 4
        why.append("exec")
    if size_bytes > 2 * 1024 * 1024:
        score += 2
        why.append("size>2M")
    if os.path.basename(path).lower() == "_raw_fs":
        score += 2
        why.append("raw-fs")

    # Prefer fuller outer roots over repeated nested duplicates.
    nested_depth = path.count("_nested_")
    if nested_depth:
        score -= nested_depth * 2
        why.append(f"nested-{nested_depth}")

    return {
        "path": path,
        "score": score,
        "file_count": file_count,
        "size_bytes": size_bytes,
        "core_dirs": core_dirs,
        "why": why,
    }


def _score_rootfs_candidate(path):
    info = _describe_rootfs_candidate(path)
    return info["score"], info["file_count"]


def _looks_like_rootfs_candidate(path):
    info = _describe_rootfs_candidate(path)
    core_count = len(info["core_dirs"])
    webish = any(tag in info["why"] for tag in ("web", "exec", "init"))
    if core_count >= 4:
        return True
    if core_count >= 3 and info["size_bytes"] >= 2 * 1024 * 1024:
        return True
    if core_count >= 2 and webish and info["file_count"] >= 200:
        return True
    if core_count >= 1 and webish and info["size_bytes"] >= 1 * 1024 * 1024 and info["file_count"] >= 80:
        return True
    return False


def _find_rootfs_candidates(base_dir):
    candidates = []
    seen = set()
    for dirpath, dirnames, _ in os.walk(base_dir):
        current_real = os.path.realpath(dirpath)
        if current_real not in seen and _looks_like_rootfs_candidate(dirpath):
            seen.add(current_real)
            candidates.append(_describe_rootfs_candidate(dirpath))
        for d in sorted(dirnames):
            candidate = os.path.join(dirpath, d)
            real_candidate = os.path.realpath(candidate)
            if real_candidate in seen:
                continue
            if not _looks_like_rootfs_candidate(candidate):
                continue
            seen.add(real_candidate)
            info = _describe_rootfs_candidate(candidate)
            candidates.append(info)

    # Penalize nested duplicates that do not add useful content over a parent.
    for child in sorted(candidates, key=lambda x: len(x["path"])):
        for parent in candidates:
            if parent is child:
                continue
            if not child["path"].startswith(parent["path"] + os.sep):
                continue
            if child["file_count"] <= parent["file_count"] and \
               child["size_bytes"] <= parent["size_bytes"]:
                child["score"] -= 2
                child["why"].append("nested-dup")
                break

    candidates.sort(
        key=lambda x: (-x["score"], -x["file_count"], -x["size_bytes"], x["path"])
    )
    return candidates


def find_squashfs_root(base_dir):
    """
    Walk base_dir for extracted filesystem roots and choose the best candidate.
    Preference order:
      1. real router web roots (/www, /web, /cgi-bin)
      2. core system directories (/bin, /etc, /usr, ...)
      3. larger extracted subtree
    Returns the best match, or None.
    """
    candidates = _find_rootfs_candidates(base_dir)
    return candidates[0]["path"] if candidates else None


def _collect_ranked_rootfs_candidates(*base_dirs):
    merged = {}
    for base_dir in base_dirs:
        if not base_dir or not os.path.isdir(base_dir):
            continue
        for info in _find_rootfs_candidates(base_dir):
            real_path = os.path.realpath(info["path"])
            current = merged.get(real_path)
            if current is None or info["score"] > current["score"]:
                merged[real_path] = info

    candidates = list(merged.values())
    candidates.sort(
        key=lambda x: (-x["score"], -x["file_count"], -x["size_bytes"], x["path"])
    )
    return candidates


def _looks_like_segmented_bundle_dir(dirpath):
    """
    Detect firmware layouts that unpack into many large extensionless chunks
    rather than a classic rootfs tree. TP-Link C80 images currently look like
    this after binwalk/LZMA expansion.
    """
    try:
        names = os.listdir(dirpath)
    except OSError:
        return False

    large_chunks = 0
    hexish_chunks = 0
    total_large_bytes = 0
    for name in names:
        path = os.path.join(dirpath, name)
        if not os.path.isfile(path):
            continue
        if "." in name:
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size < 128 * 1024:
            continue
        large_chunks += 1
        total_large_bytes += size
        if re.fullmatch(r"[0-9A-Fa-f]{2,}", name):
            hexish_chunks += 1

    return (
        large_chunks >= 8
        and hexish_chunks >= max(4, large_chunks // 3)
        and total_large_bytes >= 8 * 1024 * 1024
    )


def _find_segmented_bundle_root(base_dir):
    if not base_dir or not os.path.isdir(base_dir):
        return None
    for dirpath, dirnames, _ in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith("_nested_")]
        if _looks_like_segmented_bundle_dir(dirpath):
            return dirpath
    return None


def _find_segmented_partial_layout(base_dir):
    if not base_dir or not os.path.isdir(base_dir):
        return None
    for dirpath, dirnames, _ in os.walk(base_dir):
        if os.path.basename(dirpath) == "_segmented_partial_layout":
            return dirpath
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
    return None


def _collect_ranked_bundle_candidates(*base_dirs):
    candidates = []
    seen = set()
    for base_dir in base_dirs:
        if not base_dir or not os.path.isdir(base_dir):
            continue
        for dirpath, _, filenames in os.walk(base_dir):
            parts = set(Path(dirpath).parts)
            if parts & {"_openssl_auto", "_offset_probe", ".openssl_auto", ".offset_probe"}:
                continue
            key = os.path.realpath(dirpath)
            if key in seen:
                continue
            seen.add(key)

            bundle_files = []
            for name in filenames:
                lower = name.lower()
                if lower.endswith(_DJI_SKIP_SIG_EXTS):
                    continue
                if lower.endswith((".img", ".bin", ".fw", ".sig")):
                    bundle_files.append(name)
            if len(bundle_files) >= 5:
                score = len(bundle_files)
                why = [f"bundle-files:{len(bundle_files)}"]
                if any(name.lower() == "ap_version.txt" for name in filenames):
                    score += 4
                    why.append("ap-version")
                subdirs = []
                try:
                    subdirs = [
                        d for d in os.listdir(dirpath)
                        if os.path.isdir(os.path.join(dirpath, d))
                    ]
                except Exception:
                    pass
                if any(re.fullmatch(r"(universal|wa\d+)", d.lower()) for d in subdirs):
                    score += 4
                    why.append("module-variants")

                candidates.append({
                    "path": dirpath,
                    "score": score,
                    "file_count": len(filenames),
                    "size_bytes": _dir_size_quiet(dirpath),
                    "core_dirs": [],
                    "why": why,
                    "bundle_files": len(bundle_files),
                })
                continue

            if _looks_like_segmented_bundle_dir(dirpath):
                candidates.append({
                    "path": dirpath,
                    "score": 10,
                    "file_count": len(filenames),
                    "size_bytes": _dir_size_quiet(dirpath),
                    "core_dirs": [],
                    "why": ["segmented-bundle", "large-extensionless-chunks"],
                    "bundle_files": 0,
                })

    candidates.sort(
        key=lambda x: (-x["score"], -x["bundle_files"], -x["size_bytes"], x["path"])
    )
    return candidates


def _find_fs_magic_offsets(path, max_hits=8, chunk_size=8 * 1024 * 1024):
    max_magic = max(len(magic) for _, magic in _FS_MAGIC_PATTERNS)
    overlap = max_magic - 1
    hits = []
    seen = set()
    offset = 0
    tail = b""

    try:
        with open(path, "rb") as fh:
            while len(hits) < max_hits:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break

                window = tail + chunk
                base_offset = offset - len(tail)

                for fs_name, magic in _FS_MAGIC_PATTERNS:
                    start = 0
                    while True:
                        idx = window.find(magic, start)
                        if idx < 0:
                            break
                        abs_idx = base_offset + idx
                        key = (fs_name, abs_idx)
                        if key not in seen:
                            hits.append((fs_name, abs_idx))
                            seen.add(key)
                            if len(hits) >= max_hits:
                                return sorted(hits, key=lambda x: x[1])
                        start = idx + 1

                offset += len(chunk)
                tail = window[-overlap:] if overlap > 0 else b""
    except Exception:
        return []

    return sorted(hits, key=lambda x: x[1])


def _carve_from_offset_command(src_path, dst_path, offset):
    # BSD dd with bs=1 becomes unusably slow on multi-GB inputs. tail -c +N
    # skips directly to the byte offset and streams the remainder efficiently.
    start = offset + 1
    return (
        f'tail -c +{start} {shlex.quote(src_path)} > {shlex.quote(dst_path)}'
    )


def _scan_raw_fs_offsets(blob_path, *candidate_roots):
    hits = _find_fs_magic_offsets(blob_path)
    if not hits:
        return []

    _warn("binwalk did not locate a trusted filesystem root; scanning raw offsets")
    scanned_roots = []
    for fs_name, offset in hits:
        carved = os.path.join(WORK_DIR, f"_carve_{fs_name}_{offset:x}.bin")
        run_critical(
            _carve_from_offset_command(blob_path, carved, offset),
            fatal_msg=f"dd carve failed at offset {offset} for {fs_name}",
            label=f"dd carve  {fs_name} @ 0x{offset:x}",
            quiet=True,
        )
        carve_out = os.path.join(WORK_DIR, f"_extract_{fs_name}_{offset:x}")
        _try_extract_iot_blob(
            carved,
            carve_out,
            f"binwalk raw  {fs_name} @ 0x{offset:x}",
        )
        scanned_roots.extend(root for root in candidate_roots if root)
        scanned_roots.append(carve_out)
    return _collect_ranked_rootfs_candidates(*scanned_roots)


def _find_embedded_payload_offsets(path, max_hits=6, chunk_size=8 * 1024 * 1024):
    max_magic = max(len(magic) for _, magic, _ in _EMBEDDED_PAYLOAD_PATTERNS)
    overlap = max_magic - 1
    hits = []
    seen = set()
    offset = 0
    tail = b""

    try:
        with open(path, "rb") as fh:
            while len(hits) < max_hits:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                window = tail + chunk
                base_offset = offset - len(tail)

                for kind, magic, ext in _EMBEDDED_PAYLOAD_PATTERNS:
                    start = 0
                    while True:
                        idx = window.find(magic, start)
                        if idx < 0:
                            break
                        abs_idx = base_offset + idx
                        key = (kind, abs_idx)
                        if key not in seen:
                            hits.append((kind, abs_idx, ext))
                            seen.add(key)
                            if len(hits) >= max_hits:
                                return sorted(hits, key=lambda x: x[1])
                        start = idx + 1

                offset += len(chunk)
                tail = window[-overlap:] if overlap > 0 else b""
    except Exception:
        return []

    return sorted(hits, key=lambda x: x[1])


def _scan_embedded_payloads(blob_path, *candidate_roots):
    lower = str(blob_path).lower()
    if lower.endswith((".gz", ".zip", ".xz", ".lzma")):
        return []
    base = os.path.basename(lower)
    if base.startswith(("payload_", "_carve_", "carve_")):
        return []
    for _kind, magic, _ext in _EMBEDDED_PAYLOAD_PATTERNS:
        if _read_magic(blob_path, len(magic)) == magic:
            return []

    hits = _find_embedded_payload_offsets(blob_path)
    if not hits:
        return []

    _warn("filesystem scan did not yield a trusted root; probing embedded payload offsets")
    scanned_roots = []
    for kind, offset, ext in hits:
        if offset == 0:
            continue
        carved = os.path.join(WORK_DIR, f"_carve_{kind}_{offset:x}{ext}")
        run(
            _carve_from_offset_command(blob_path, carved, offset),
            label=f"carve embedded  {kind} @ 0x{offset:x}",
            quiet=True,
        )
        if not os.path.isfile(carved):
            continue
        try:
            size = os.path.getsize(carved)
        except OSError:
            size = 0
        if size < 64 * 1024:
            continue
        carve_out = os.path.join(WORK_DIR, f"_extract_{kind}_{offset:x}")
        structure = _structure_info(carved)
        decoded_target, decoded_structure = _decode_embedded_payload(
            carved,
            carve_out,
            structure,
        )
        if decoded_structure:
            _record_container_evidence(carve_out, decoded_target or carved, {
                "kind": decoded_structure.get("kind"),
                "confidence": decoded_structure.get("confidence"),
                "reasons": decoded_structure.get("reasons"),
                "size_bytes": decoded_structure.get("size_bytes", 0),
                "entropy": decoded_structure.get("entropy"),
                "printable_ratio": decoded_structure.get("printable_ratio"),
                "extract_offset": decoded_structure.get("extract_offset"),
                "salvage_source": f"embedded-{kind}-decode",
                "decoded_from": decoded_structure.get("decoded_from"),
                "decoded_output_size": decoded_structure.get("decoded_output_size", decoded_structure.get("output_size", 0)),
            })
        target_for_extract = decoded_target or carved
        target_structure = decoded_structure or structure
        if _should_attempt_nested_extract(target_structure):
            _try_extract_iot_blob(
                target_for_extract,
                carve_out,
                f"embedded payload  {kind} @ 0x{offset:x}",
            )
        scanned_roots.extend(root for root in candidate_roots if root)
        scanned_roots.append(carve_out)
    return _collect_ranked_rootfs_candidates(*scanned_roots)


def _sample_entropy(path, sample_size=64 * 1024):
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_size)
    except OSError:
        return 0.0
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _sample_printable_ratio(path, sample_size=64 * 1024):
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_size)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    printable = 0
    for b in data:
        if b in (9, 10, 13) or 32 <= b <= 126:
            printable += 1
    return printable / len(data)


def _structure_info(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    head = _read_prefix(path, 4096)
    entropy = round(_sample_entropy(path), 4)
    printable_ratio = round(_sample_printable_ratio(path), 4)

    kind = "opaque-random"
    confidence = "low"
    reasons = []
    extract_offset = None

    if not head:
        return {
            "kind": "missing",
            "confidence": "low",
            "size_bytes": size,
            "entropy": entropy,
            "printable_ratio": printable_ratio,
            "reasons": ["empty-or-unreadable"],
            "extract_offset": None,
        }

    if head.startswith(_MAGIC_ZIP):
        kind = "zip-payload"
        confidence = "high"
        reasons.append("zip-magic@0")
    elif head.startswith(b"\x1f\x8b\x08"):
        kind = "gzip-payload"
        confidence = "high"
        reasons.append("gzip-magic@0")
    elif head.startswith(b"\xfd7zXZ\x00"):
        kind = "xz-payload"
        confidence = "high"
        reasons.append("xz-magic@0")
    elif head.startswith(b"\x5d\x00\x00\x80"):
        kind = "lzma-payload"
        confidence = "medium"
        reasons.append("lzma-magic@0")
    elif head.startswith(b"UBI#"):
        kind = "ubi-image"
        confidence = "high"
        reasons.append("ubi-magic@0")
    elif head.startswith(b"hsqs") or head.startswith(b"sqsh") or head.startswith(b"qshs") or head.startswith(b"shsq"):
        kind = "squashfs-image"
        confidence = "high"
        reasons.append("squashfs-magic@0")
    elif head.startswith(b"\x7fELF"):
        kind = "elf-binary"
        confidence = "medium"
        reasons.append("elf-magic@0")
    elif _detect_dlink_wrapper(path):
        kind = "wrapped-container"
        confidence = "high"
        reasons.append("dlink-wrapper@0")
    elif head.startswith(_MAGIC_PAYLOAD):
        kind = "android-payload"
        confidence = "high"
        reasons.append("payload-bin@0")
    else:
        fs_hits = _find_fs_magic_offsets(path, max_hits=2, chunk_size=1024 * 1024)
        if fs_hits:
            fs_name, offset = fs_hits[0]
            kind = f"embedded-{fs_name}"
            confidence = "medium"
            reasons.append(f"{fs_name}-magic@0x{offset:x}")
            if offset > 0:
                extract_offset = offset
        else:
            embedded = _find_embedded_payload_offsets(path, max_hits=2, chunk_size=1024 * 1024)
            if embedded:
                payload_kind, offset, _ext = embedded[0]
                kind = f"embedded-{payload_kind}"
                confidence = "medium"
                reasons.append(f"{payload_kind}-magic@0x{offset:x}")
                if offset > 0:
                    extract_offset = offset

    if not reasons:
        if printable_ratio >= 0.70:
            kind = "text-heavy-blob"
            confidence = "medium"
            reasons.append(f"printable-ratio:{printable_ratio:.2f}")
        elif entropy >= 7.85:
            kind = "opaque-random"
            confidence = "low"
            reasons.append(f"high-entropy:{entropy:.2f}")
        else:
            kind = "opaque-binary"
            confidence = "low"
            reasons.append(f"binary-blob entropy={entropy:.2f}")

    return {
        "kind": kind,
        "confidence": confidence,
        "size_bytes": size,
        "entropy": entropy,
        "printable_ratio": printable_ratio,
        "reasons": reasons,
        "extract_offset": extract_offset,
    }


def _should_attempt_nested_extract(structure):
    kind = str((structure or {}).get("kind") or "")
    if kind.startswith(("zip-", "gzip-", "xz-", "lzma-", "ubi-", "squashfs-", "wrapped-", "android-")):
        return True
    if kind.startswith("embedded-"):
        return True
    return False


def _probe_gzip_stream(path, offset=0, chunk_size=1024 * 1024):
    out_bytes = 0
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                data = dec.decompress(chunk)
                out_bytes += len(data)
                if dec.eof:
                    tail = dec.flush()
                    out_bytes += len(tail)
                    return {
                        "valid": True,
                        "output_size": out_bytes,
                        "unused_tail": len(dec.unused_data or b""),
                    }
            tail = dec.flush()
            out_bytes += len(tail)
            return {"valid": False, "output_size": out_bytes, "reason": "gzip-eof-not-reached"}
    except zlib.error as exc:
        return {"valid": False, "output_size": out_bytes, "reason": str(exc)}
    except OSError as exc:
        return {"valid": False, "output_size": out_bytes, "reason": str(exc)}


def _decode_embedded_payload(carved_path, out_dir, structure):
    kind = str((structure or {}).get("kind") or "")
    extract_offset = int((structure or {}).get("extract_offset") or 0)
    if not kind.startswith((
        "gzip", "embedded-gzip",
        "xz", "embedded-xz",
        "lzma", "embedded-lzma",
        "zip", "zip-payload", "embedded-zip",
    )):
        return None, None

    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    source_path = carved_path
    if extract_offset > 0:
        source_path = os.path.join(out_dir, "_stream_payload.bin")
        run(
            _carve_from_offset_command(carved_path, source_path, extract_offset),
            label=f"carve stream  {os.path.basename(carved_path)} @ 0x{extract_offset:x}",
            quiet=True,
        )
        if not os.path.isfile(source_path):
            return None, None

    if "gzip" in kind:
        probe = _probe_gzip_stream(source_path, offset=0)
        if not probe.get("valid"):
            return None, {
                "kind": "gzip-invalid",
                "confidence": "low",
                "reasons": [probe.get("reason") or "gzip-parse-failed"],
                "output_size": probe.get("output_size", 0),
            }
        decoded = os.path.join(out_dir, "decoded_from_gzip.bin")
        try:
            with open(source_path, "rb") as src, open(decoded, "wb") as dst:
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    data = dec.decompress(chunk)
                    if data:
                        dst.write(data)
                    if dec.eof:
                        tail = dec.flush()
                        if tail:
                            dst.write(tail)
                        break
        except Exception:
            return None, {
                "kind": "gzip-invalid",
                "confidence": "low",
                "reasons": ["gzip-decode-write-failed"],
                "output_size": probe.get("output_size", 0),
            }
        decoded_structure = _structure_info(decoded)
        decoded_structure["decoded_from"] = kind
        decoded_structure["decoded_output_size"] = probe.get("output_size", 0)
        return decoded, decoded_structure

    if "xz" in kind or "lzma" in kind:
        decoded = os.path.join(out_dir, "decoded_from_lzma.bin")
        if _decompress_lzma_blob(source_path, decoded):
            decoded_structure = _structure_info(decoded)
            decoded_structure["decoded_from"] = kind
            return decoded, decoded_structure
        return None, {
            "kind": "lzma-invalid",
            "confidence": "low",
            "reasons": ["lzma-decode-failed"],
            "output_size": 0,
        }

    if "zip" in kind and zipfile.is_zipfile(source_path):
        extract_dir = os.path.join(out_dir, "_zip")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(source_path) as zf:
                zf.extractall(extract_dir)
        except Exception:
            return None, {
                "kind": "zip-invalid",
                "confidence": "low",
                "reasons": ["zip-extract-failed"],
                "output_size": 0,
            }
        return extract_dir, {
            "kind": "zip-layout",
            "confidence": "medium",
            "reasons": ["zip-extract-ok"],
            "output_size": _dir_size_bytes(extract_dir),
        }

    return None, None


def _record_container_evidence(base_dir, payload_path, entry):
    if not base_dir:
        return
    record_path = os.path.join(base_dir, "CONTAINER_EVIDENCE.json")
    payload_rel = None
    try:
        payload_rel = os.path.relpath(payload_path, base_dir)
    except Exception:
        payload_rel = payload_path
    item = dict(entry or {})
    item["payload"] = payload_rel
    existing = []
    try:
        if os.path.isfile(record_path):
            with open(record_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list):
                existing = loaded
    except Exception:
        existing = []

    dedup_key = (
        item.get("payload"),
        item.get("kind"),
        item.get("extract_offset"),
    )
    filtered = []
    for row in existing:
        row_key = (
            row.get("payload"),
            row.get("kind"),
            row.get("extract_offset"),
        )
        if row_key != dedup_key:
            filtered.append(row)
    filtered.append(item)
    filtered.sort(key=lambda row: (str(row.get("kind") or ""), str(row.get("payload") or "")))
    _json_dump(record_path, filtered)


def _load_container_evidence(base_dir):
    record_path = os.path.join(base_dir, "CONTAINER_EVIDENCE.json")
    try:
        with open(record_path, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, list):
            return loaded
    except Exception:
        pass
    return []


def _safe_link_or_copy(src, dst):
    try:
        if os.path.lexists(dst):
            os.unlink(dst)
        os.symlink(os.path.relpath(src, os.path.dirname(dst)), dst)
        return
    except OSError:
        pass
    shutil.copy2(src, dst)


def _summarize_segment_cluster(members):
    extract_offsets = [m.get("extract_offset") for m in members if isinstance(m.get("extract_offset"), int)]
    carve_offsets = [m.get("carve_offset") for m in members if isinstance(m.get("carve_offset"), int)]
    payload_sizes = [m.get("size_bytes") for m in members if isinstance(m.get("size_bytes"), int)]
    valid_decodes = []
    invalid_decodes = []
    for member in members:
        decode_kind = str(member.get("decode_kind") or "")
        if not decode_kind:
            continue
        if decode_kind.endswith("-invalid"):
            invalid_decodes.append(member)
            continue
        if decode_kind.startswith((
            "zip-", "gzip-", "xz-", "lzma-", "ubi-", "squashfs-", "elf-", "embedded-"
        )):
            valid_decodes.append(member)

    extract_span = (max(extract_offsets) - min(extract_offsets)) if len(extract_offsets) >= 2 else 0
    carve_span = (max(carve_offsets) - min(carve_offsets)) if len(carve_offsets) >= 2 else 0
    size_span = (max(payload_sizes) - min(payload_sizes)) if len(payload_sizes) >= 2 else 0

    if valid_decodes:
        relation = "independent-or-decodable-streams"
    elif invalid_decodes and len(invalid_decodes) == len(members) and extract_span <= 0x8000 and size_span <= 0x8000:
        relation = "overlapping-segments-of-larger-container"
    elif len(members) >= 3 and extract_span <= 0x10000:
        relation = "clustered-segments-unconfirmed"
    else:
        relation = "isolated-fragments"

    return {
        "relation": relation,
        "member_count": len(members),
        "valid_decode_count": len(valid_decodes),
        "invalid_decode_count": len(invalid_decodes),
        "extract_span": extract_span,
        "carve_span": carve_span,
        "size_span": size_span,
        "promotion_safe": bool(valid_decodes) and relation == "independent-or-decodable-streams",
    }


def _reconstruct_container_partial_layout(base_dir, cluster_gap=0x8000, max_links_per_cluster=4):
    rows = _load_container_evidence(base_dir)
    if not rows:
        return None

    decode_rows = {}
    for row in rows:
        source = str(row.get("salvage_source") or "")
        if "decode" not in source:
            continue
        key = (
            row.get("wrapper_kind"),
            row.get("carve_offset"),
            row.get("payload"),
        )
        decode_rows[key] = row

    candidates = []
    for row in rows:
        kind = str(row.get("kind") or "")
        if not kind.startswith("embedded-"):
            continue
        payload_rel = row.get("payload")
        if not payload_rel:
            continue
        payload_path = os.path.join(base_dir, payload_rel)
        if not os.path.isfile(payload_path):
            continue
        extract_offset = row.get("extract_offset")
        if not isinstance(extract_offset, int):
            continue
        decode = decode_rows.get((
            row.get("wrapper_kind"),
            row.get("carve_offset"),
            payload_rel,
        ))
        entry = dict(row)
        entry["payload_path"] = payload_path
        entry["decode_kind"] = (decode or {}).get("kind")
        entry["decode_reasons"] = (decode or {}).get("reasons")
        candidates.append(entry)

    if not candidates:
        return None

    candidates.sort(key=lambda row: (
        str(row.get("wrapper_kind") or row.get("salvage_source") or ""),
        str(row.get("kind") or ""),
        int(row.get("extract_offset") or 0),
        int(row.get("carve_offset") or 0),
    ))

    clusters = []
    for row in candidates:
        family = str(row.get("wrapper_kind") or row.get("salvage_source") or "container")
        stream_kind = str(row.get("kind") or "")
        if not clusters:
            clusters.append({
                "family": family,
                "stream_kind": stream_kind,
                "members": [row],
                "min_offset": int(row.get("extract_offset") or 0),
                "max_offset": int(row.get("extract_offset") or 0),
            })
            continue
        current = clusters[-1]
        if (
            current["family"] == family and
            current["stream_kind"] == stream_kind and
            abs(int(row.get("extract_offset") or 0) - current["max_offset"]) <= cluster_gap
        ):
            current["members"].append(row)
            current["max_offset"] = max(current["max_offset"], int(row.get("extract_offset") or 0))
            current["min_offset"] = min(current["min_offset"], int(row.get("extract_offset") or 0))
            continue
        clusters.append({
            "family": family,
            "stream_kind": stream_kind,
            "members": [row],
            "min_offset": int(row.get("extract_offset") or 0),
            "max_offset": int(row.get("extract_offset") or 0),
        })

    materialized = []
    for cluster in clusters:
        summary = _summarize_segment_cluster(cluster["members"])
        if summary["member_count"] < 2 and summary["valid_decode_count"] == 0:
            continue
        cluster["summary"] = summary
        materialized.append(cluster)

    if not materialized:
        return None

    layout_dir = os.path.join(base_dir, "_container_partial_layout")
    shutil.rmtree(layout_dir, ignore_errors=True)
    os.makedirs(layout_dir, exist_ok=True)

    manifest = {
        "reconstruction_level": "partial-segment-layout",
        "promotion_safe": False,
        "clusters": [],
    }

    for idx, cluster in enumerate(materialized, 1):
        cluster_dir = os.path.join(layout_dir, f"cluster_{idx:02d}")
        seg_dir = os.path.join(cluster_dir, "segments")
        os.makedirs(seg_dir, exist_ok=True)

        reps = sorted(
            cluster["members"],
            key=lambda row: (
                int(row.get("carve_offset") or 0),
                int(row.get("extract_offset") or 0),
            ),
        )[:max_links_per_cluster]

        rep_entries = []
        for rep in reps:
            src = rep["payload_path"]
            name = (
                f"carve_{int(rep.get('carve_offset') or 0):x}"
                f"__extract_{int(rep.get('extract_offset') or 0):x}"
                f"__{os.path.basename(src)}"
            )
            dst = os.path.join(seg_dir, name)
            _safe_link_or_copy(src, dst)
            rep_entries.append({
                "path": os.path.relpath(dst, layout_dir),
                "carve_offset": rep.get("carve_offset"),
                "extract_offset": rep.get("extract_offset"),
                "decode_kind": rep.get("decode_kind"),
                "decode_reasons": rep.get("decode_reasons"),
                "size_bytes": rep.get("size_bytes"),
            })

        cluster_manifest = {
            "family": cluster["family"],
            "stream_kind": cluster["stream_kind"],
            "offset_range": [cluster["min_offset"], cluster["max_offset"]],
            "summary": cluster["summary"],
            "representatives": rep_entries,
        }
        _json_dump(os.path.join(cluster_dir, "CLUSTER.json"), cluster_manifest)
        manifest["clusters"].append(cluster_manifest)

    if not manifest["clusters"]:
        shutil.rmtree(layout_dir, ignore_errors=True)
        return None

    _json_dump(os.path.join(layout_dir, "PARTIAL_LAYOUT.json"), manifest)
    return layout_dir


def _looks_like_opaque_nested_blob(path):
    base = os.path.basename(path)
    if "." in base:
        return False
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size < 512 * 1024:
        return False
    if _read_magic(path, 4) == b"UBI#":
        return True
    return _sample_entropy(path) >= 7.2


def _looks_like_nested_blob(path):
    lower = path.lower().replace("\\", "/")
    base_lower = os.path.basename(lower)
    noisy_markers = (
        ".apk.extracted/",
        ".jar.extracted/",
        ".so.extracted/",
        "/lib/",
        "/lib64/",
        "/framework/",
        "/priv-app/",
    )
    if any(marker in lower for marker in noisy_markers):
        return False
    if ".pro.fw.sig.extracted/" in lower:
        extracted_depth = lower.count(".extracted/")
        if base_lower not in _DJI_INTERNAL_NESTED_ALLOWLIST:
            return False
        if base_lower in ("decompressed.bin", "payload.bin") and extracted_depth > 1:
            return False
        if base_lower == "ap.img":
            if extracted_depth > 2:
                return False
            if re.search(r"/(universal|wa\d+)/", lower):
                return False
    if lower.endswith((".apk", ".jar", ".so", ".dex", ".odex", ".vdex")):
        return False
    if lower.endswith(_DJI_SKIP_SIG_EXTS):
        return False
    if lower.endswith(_NESTED_BLOB_EXTS):
        return True
    for _, magic in _FS_MAGIC_PATTERNS:
        if _read_magic(path, len(magic)) == magic:
            return True
    if _looks_like_opaque_nested_blob(path):
        return True
    return False


def _rank_nested_blob(path):
    lower = path.lower().replace("\\", "/")
    base = os.path.basename(lower)
    score = 0

    if base.endswith(".7z"):
        score += 30
    if base.endswith(".xz") or base.endswith(".lzma"):
        score += 25
    if base.endswith(".img"):
        score += 20
    if base.endswith(".bin"):
        score += 10

    for _, magic in _FS_MAGIC_PATTERNS:
        if _read_magic(path, len(magic)) == magic:
            score += 100
            break

    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size >= 8 * 1024 * 1024:
        score += 20
    elif size >= 1 * 1024 * 1024:
        score += 10

    if ".extracted/_decoded.bin" in lower:
        score -= 10

    return score, size, path


def _has_ubi_magic(path):
    return _read_magic(path, 4) == b"UBI#"


_DLINK_WRAPPER_OFFSETS = (0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000)


def _read_prefix(path, size):
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _detect_dlink_wrapper(path):
    head = _read_prefix(path, 4096)
    for sig, kind, label in (
        (b"SHRS", "shrs", "D-Link SHRS wrapped image"),
        (b"encrpted_img", "encrypted_img", "D-Link encrpted_img wrapper"),
    ):
        idx = head.find(sig)
        if idx < 0:
            continue
        fields = []
        body = head[idx + len(sig): idx + len(sig) + 16]
        for off in range(0, len(body) - 1, 2):
            be = int.from_bytes(body[off:off + 2], "big")
            le = int.from_bytes(body[off:off + 2], "little")
            for value in (be, le):
                if 0x20 <= value <= 0x4000:
                    fields.append(value)
        rel_offsets = list(_DLINK_WRAPPER_OFFSETS)
        rel_offsets.extend(fields)
        deduped = []
        seen = set()
        for value in sorted(rel_offsets):
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return {
            "kind": kind,
            "label": label,
            "signature_offset": idx,
            "header_fields": deduped[:12],
            "candidate_offsets": tuple(deduped[:16]),
        }
    return None


def _try_extract_dlink_wrapped_blob(blob_path, out_dir):
    wrapper = _detect_dlink_wrapper(blob_path)
    if not wrapper:
        return None

    _info(
        f"{wrapper['label']} detected; trying common D-Link payload offsets "
        f"({', '.join(hex(o) for o in wrapper['candidate_offsets'])})"
    )

    candidates = []
    header_base = int(wrapper.get("signature_offset") or 0)
    for offset in wrapper["candidate_offsets"]:
        absolute_offset = header_base + offset
        carved = os.path.join(out_dir, f"_dlink_payload_0x{absolute_offset:x}.bin")
        run(
            _carve_from_offset_command(blob_path, carved, absolute_offset),
            label=f"dlink carve  {os.path.basename(blob_path)} @ 0x{absolute_offset:x}",
            quiet=True,
        )
        if not os.path.isfile(carved) or os.path.getsize(carved) < (1 << 20):
            continue

        structure = _structure_info(carved)
        _record_container_evidence(out_dir, carved, {
            "kind": structure.get("kind"),
            "confidence": structure.get("confidence"),
            "reasons": structure.get("reasons"),
            "size_bytes": structure.get("size_bytes"),
            "entropy": structure.get("entropy"),
            "printable_ratio": structure.get("printable_ratio"),
            "extract_offset": structure.get("extract_offset"),
            "salvage_source": "dlink-wrapper-carve",
            "wrapper_kind": wrapper.get("kind"),
            "wrapper_signature_offset": wrapper.get("signature_offset"),
            "wrapper_header_fields": wrapper.get("header_fields"),
            "carve_offset": absolute_offset,
        })
        nested_dir = os.path.join(out_dir, f"_dlink_extract_0x{absolute_offset:x}")
        decoded_target, decoded_structure = _decode_embedded_payload(
            carved,
            nested_dir,
            structure,
        )
        if decoded_structure:
            _record_container_evidence(out_dir, decoded_target or carved, {
                "kind": decoded_structure.get("kind"),
                "confidence": decoded_structure.get("confidence"),
                "reasons": decoded_structure.get("reasons"),
                "size_bytes": decoded_structure.get("size_bytes", 0),
                "entropy": decoded_structure.get("entropy"),
                "printable_ratio": decoded_structure.get("printable_ratio"),
                "extract_offset": decoded_structure.get("extract_offset"),
                "salvage_source": "dlink-wrapper-decode",
                "wrapper_kind": wrapper.get("kind"),
                "wrapper_signature_offset": wrapper.get("signature_offset"),
                "wrapper_header_fields": wrapper.get("header_fields"),
                "carve_offset": absolute_offset,
                "decoded_from": decoded_structure.get("decoded_from"),
                "decoded_output_size": decoded_structure.get("decoded_output_size", decoded_structure.get("output_size", 0)),
            })
        target_for_extract = decoded_target or carved
        target_structure = decoded_structure or structure
        if not _should_attempt_nested_extract(target_structure):
            continue

        _try_extract_iot_blob(target_for_extract, nested_dir, f"dlink nested  0x{absolute_offset:x}")
        candidates.extend(_collect_ranked_rootfs_candidates(nested_dir))

    if not candidates:
        return None

    candidates.sort(key=lambda x: (-x["score"], -x["size_bytes"], x["path"]))
    return candidates[0]["path"]


def _ubireader_available():
    return _resolve_ubireader_tools() is not None


def _resolve_ubireader_tools():
    files = shutil.which("ubireader_extract_files")
    images = shutil.which("ubireader_extract_images")
    if files and images:
        return files, images

    for base in _UBIREADER_FALLBACK_DIRS:
        cand_files = os.path.join(base, "ubireader_extract_files")
        cand_images = os.path.join(base, "ubireader_extract_images")
        if os.path.isfile(cand_files) and os.access(cand_files, os.X_OK) and \
           os.path.isfile(cand_images) and os.access(cand_images, os.X_OK):
            return cand_files, cand_images

    return None


def _fail_missing_ubireader(blob_path):
    _warn("UBI/UBIFS firmware detected but ubireader tools are missing")
    _info("Install: pip3 install ubireader  or  your distro's ubireader package")
    _info(f"Blob: {blob_path}")
    return None


def _extract_ubi_blob(blob_path, out_dir):
    tools = _resolve_ubireader_tools()
    if tools is None:
        return _fail_missing_ubireader(blob_path)
    extract_files, extract_images = tools

    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    run(
        f'"{extract_images}" -o "{out_dir}" "{blob_path}"',
        label=f"ubireader images  {os.path.basename(blob_path)}",
        quiet=True,
    )
    run(
        f'"{extract_files}" -o "{out_dir}" "{blob_path}"',
        label=f"ubireader files   {os.path.basename(blob_path)}",
        quiet=True,
    )

    rootfs = find_squashfs_root(out_dir)
    if rootfs:
        return rootfs

    # ubireader often emits filesystem volumes as files (for example a
    # rootfs.ubifs payload that is itself SquashFS) instead of unpacked dirs.
    for dirpath, _, filenames in os.walk(out_dir):
        for filename in sorted(filenames):
            candidate = os.path.join(dirpath, filename)
            lower = filename.lower()
            if lower.endswith(".ubi"):
                continue
            if not _looks_like_nested_blob(candidate):
                continue
            nested_out = os.path.join(dirpath, f"_nested_{filename}")
            nested_rootfs = _try_extract_iot_blob(
                candidate,
                nested_out,
                f"ubi nested  {os.path.basename(candidate)}",
            )
            if nested_rootfs:
                return nested_rootfs

    return find_squashfs_root(out_dir)


def _find_ubi_blobs(base_dir):
    blobs = []
    seen = set()
    for dirpath, _, filenames in os.walk(base_dir):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            lower = filename.lower()
            if lower.endswith(".ubi") or _has_ubi_magic(path):
                if path not in seen:
                    seen.add(path)
                    blobs.append(path)
    return blobs


def _decompress_lzma_blob(blob_path, out_path):
    formats = [lzma.FORMAT_AUTO, lzma.FORMAT_ALONE]
    for fmt in formats:
        try:
            decompressor = lzma.LZMADecompressor(format=fmt)
            wrote = False
            with open(blob_path, "rb") as src, open(out_path, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    decoded = decompressor.decompress(chunk)
                    if decoded:
                        dst.write(decoded)
                        wrote = True
                    if decompressor.eof:
                        break
            if wrote and os.path.getsize(out_path) > 0:
                return True
        except Exception:
            pass
        try:
            os.remove(out_path)
        except OSError:
            pass
    return False


def _binwalk_extract_command(blob_path, out_dir, recursive=True):
    # Binwalk 3.x rejects legacy -B usage; this form works on current CLI.
    cmd = ['binwalk', '-e', '-C', out_dir]
    if recursive:
        cmd.append('-M')
    excludes = []
    if shutil.which("unyaffs") is None:
        excludes.append("yaffs")
    if shutil.which("unrar") is None:
        excludes.append("rar")
    if shutil.which("tsk_recover") is None:
        excludes.append("ext")
    for name in excludes:
        cmd.append(f"--exclude={name}")
    cmd.append(blob_path)
    return " ".join(shlex.quote(part) for part in cmd)


def _is_dji_firmware_blob(path):
    base = os.path.basename(path).lower()
    if "dji" in base or "rc520" in base:
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
        return b"rc520_" in head or b"dji" in head.lower()
    except Exception:
        return False


def _is_dji_prak_blob(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except Exception:
        return False
    return b"PRAK" in head


def _dji_module_id(path):
    match = re.search(r"rc\d+_(\d{4})_", os.path.basename(path).lower())
    return match.group(1) if match else None


def _score_dji_prak_candidate(path):
    module_id = _dji_module_id(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    score = 0
    why = []
    if module_id in _DJI_PRAK_PREFERRED_MODULES:
        score += 200
        why.append(f"preferred-module:{module_id}")
    elif module_id in _DJI_PRAK_EXCLUDED_MODULES:
        score -= 200
        why.append(f"excluded-module:{module_id}")

    if size >= 512 * 1024 * 1024:
        score += 80
        why.append("very-large")
    elif size >= 128 * 1024 * 1024:
        score += 40
        why.append("large")
    elif size <= 16 * 1024 * 1024:
        score -= 60
        why.append("small")

    if size == 0:
        score -= 200
        why.append("empty")

    return score, why, size, module_id


def _select_dji_prak_targets(paths, max_targets=_DJI_PRAK_MAX_TARGETS):
    ranked = []
    seen_modules = set()

    for path in paths:
        score, why, size, module_id = _score_dji_prak_candidate(path)
        ranked.append((score, size, module_id, path, why))

    ranked.sort(key=lambda item: (-item[0], -item[1], item[3]))

    selected = []
    for score, size, module_id, path, _why in ranked:
        if score <= 0:
            continue
        key = module_id or os.path.basename(path).lower()
        if key in seen_modules:
            continue
        seen_modules.add(key)
        selected.append(path)
        if len(selected) >= max_targets:
            break

    return selected


def _find_dji_payload_offset(path, search_window=8192):
    try:
        with open(path, "rb") as fh:
            head = fh.read(search_window)
    except Exception:
        return None, None

    best = None
    for kind, magic in _DJI_PRAK_PAYLOAD_MAGICS:
        idx = head.find(magic)
        if idx < 0:
            continue
        if best is None or idx < best[1]:
            best = (kind, idx)
    return best if best else (None, None)


def _extract_dji_prak_blob(blob_path, out_dir):
    payload_kind, payload_offset = _find_dji_payload_offset(blob_path)
    if payload_offset is None:
        return False

    payload_name = f"_payload.{ 'zip' if payload_kind == 'zip' else 'gz' }"
    payload_path = os.path.join(out_dir, payload_name)
    run_critical(
        _carve_from_offset_command(blob_path, payload_path, payload_offset),
        fatal_msg=f"failed to carve DJI payload at 0x{payload_offset:x}",
        label=f"dji carve  {os.path.basename(blob_path)} @ 0x{payload_offset:x}",
        quiet=True,
    )

    if payload_kind == "zip":
        extract_dir = os.path.join(out_dir, "_prak")
        os.makedirs(extract_dir, exist_ok=True)
        proc = run(
            f'7z x "{payload_path}" -o"{extract_dir}" -y',
            label=f"dji unzip   {os.path.basename(blob_path)}",
            quiet=True,
        )
        return proc.returncode == 0 and any(os.scandir(extract_dir))

    decoded = os.path.join(out_dir, "decompressed.bin")
    return _decompress_lzma_blob(payload_path, decoded) or (
        run(
            f'7z x "{payload_path}" -o"{out_dir}" -y',
            label=f"dji gunzip  {os.path.basename(blob_path)}",
            quiet=True,
        ).returncode == 0
    )


def _find_dji_android_payload(base_dir):
    payloads = []
    for dirpath, dirnames, filenames in os.walk(base_dir):
        for filename in filenames:
            if filename.lower() != "payload.bin":
                continue
            full = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            payloads.append((size, full))

    if not payloads:
        return None
    payloads.sort(reverse=True)
    return payloads[0][1]


def _is_relevant_dji_nested_target(path):
    lower = os.path.basename(path).lower()
    if lower in _DJI_PRIORITY_NAMES:
        return True
    if lower.endswith(".pro.fw.sig"):
        module_id = _dji_module_id(path)
        return module_id in _DJI_PRAK_PREFERRED_MODULES
    if lower.endswith(".cfg.sig"):
        return False
    if _is_dji_prak_blob(path):
        return False
    return lower.endswith((".img", ".fw", ".raw"))


def _unpack_nested_blob(blob_path, out_dir):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    extracted = False
    is_dji_sig = blob_path.lower().endswith(".pro.fw.sig")
    if is_dji_sig:
        return _extract_dji_prak_blob(blob_path, out_dir)
    if not is_dji_sig:
        run(
            _binwalk_extract_command(blob_path, out_dir),
            label=f"binwalk nested  {os.path.basename(blob_path)}",
            quiet=True,
        )
        os.makedirs(out_dir, exist_ok=True)
        if _dir_has_entries(out_dir):
            extracted = True

    raw_dir = os.path.join(out_dir, "_raw")
    os.makedirs(raw_dir, exist_ok=True)
    proc = run(
        f'7z x "{blob_path}" -o"{raw_dir}" -y',
        label=f"7z nested  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if (proc.returncode == 0 or _dir_has_entries(raw_dir)) and _dir_has_entries(raw_dir):
        extracted = True

    decoded = os.path.join(out_dir, "_decoded.bin")
    if _decompress_lzma_blob(blob_path, decoded):
        extracted = True

    return extracted


def _expand_dji_bundles(base_dir, max_files=24):
    targets = []
    prak_targets = []
    seen = set()

    for dirpath, dirnames, filenames in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith("_nested_")]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            key = (filename.lower(), os.path.getsize(full) if os.path.exists(full) else -1)
            if key in seen:
                continue
            seen.add(key)
            if filename.lower().endswith(".pro.fw.sig"):
                prak_targets.append(full)
                continue
            if _is_relevant_dji_nested_target(full):
                targets.append(full)

    targets.extend(_select_dji_prak_targets(prak_targets))

    def _priority(path):
        name = os.path.basename(path).lower()
        if name.endswith(".pro.fw.sig"):
            return (-1, len(path), path)
        try:
            rank = _DJI_PRIORITY_NAMES.index(name)
        except ValueError:
            rank = len(_DJI_PRIORITY_NAMES)
        return (rank, len(path), path)

    targets.sort(key=_priority)
    for blob_path in targets[:max_files]:
        nested_dir = os.path.join(
            os.path.dirname(blob_path),
            f"_nested_{os.path.basename(blob_path)}",
        )
        _unpack_nested_blob(blob_path, nested_dir)


def _expand_nested_iot_blobs(base_dir, max_depth=3, max_blobs_per_dir=24):
    queue = [(base_dir, 0)]
    seen = set()

    while queue:
        current_dir, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        pending = []
        for dirpath, dirnames, filenames in os.walk(current_dir):
            dirnames[:] = [d for d in dirnames if not d.startswith("_nested_")]
            for filename in filenames:
                blob_path = os.path.join(dirpath, filename)
                if blob_path in seen or not _looks_like_nested_blob(blob_path):
                    continue
                pending.append(blob_path)

        pending.sort(key=_rank_nested_blob, reverse=True)
        for blob_path in pending[:max_blobs_per_dir]:
            seen.add(blob_path)
            nested_dir = os.path.join(
                os.path.dirname(blob_path),
                f"_nested_{os.path.basename(blob_path)}"
            )
            if _unpack_nested_blob(blob_path, nested_dir):
                queue.append((nested_dir, depth + 1))


def _decode_segmented_chunk(blob_path, out_dir):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    decoded = os.path.join(out_dir, "_decoded.bin")
    if _decompress_lzma_blob(blob_path, decoded):
        return out_dir

    raw_dir = os.path.join(out_dir, "_raw")
    os.makedirs(raw_dir, exist_ok=True)
    proc = run(
        f'7z x "{blob_path}" -o"{raw_dir}" -y',
        label=f"7z segmented  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if (proc.returncode == 0 or _dir_has_entries(raw_dir)) and _dir_has_entries(raw_dir):
        return out_dir
    return None


def _synthesize_segmented_webroot(base_dir, expanded_dirs, max_files=600):
    """
    Build a synthetic, browsable web-root from segmented bundle expansions.
    This does not claim full firmware reconstruction; it only tries to merge
    recovered web assets and CGI/server binaries into a stable analysis tree so
    later stages can still reason about the web surface.
    """
    if not expanded_dirs:
        return None

    interesting_exts = {
        ".html", ".htm", ".js", ".css", ".xml", ".json", ".svg", ".ico",
        ".gif", ".jpg", ".jpeg", ".png", ".asp", ".php", ".cgi", ".lua",
        ".sh", ".conf", ".txt",
    }
    interesting_names = {
        "httpd", "lighttpd", "uhttpd", "boa", "cgi-bin", "index.html",
        "default.html",
    }

    staged = []
    seen_real = set()
    for root in expanded_dirs:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith("_") and not d.startswith(".")]
            for name in filenames:
                src = os.path.join(dirpath, name)
                try:
                    real = os.path.realpath(src)
                    size = os.path.getsize(src)
                except OSError:
                    continue
                if real in seen_real or size <= 0:
                    continue

                rel = os.path.relpath(src, root).replace("\\", "/")
                ext = os.path.splitext(name)[1].lower()
                rel_lower = rel.lower()
                keep = False
                if ext in interesting_exts:
                    keep = True
                elif name.lower() in interesting_names:
                    keep = True
                elif any(token in rel_lower for token in ("/www/", "/web/", "/cgi", "lighttpd", "httpd", "uhttpd")):
                    keep = True
                elif os.access(src, os.X_OK) and size <= 16 * 1024 * 1024:
                    keep = True

                if not keep:
                    continue
                seen_real.add(real)
                staged.append((src, rel, size))

    if len(staged) < 12:
        return None

    staged.sort(key=lambda item: (item[1].count("/"), len(item[1]), -item[2]))
    synth = os.path.join(base_dir, "_segmented_webroot")
    shutil.rmtree(synth, ignore_errors=True)
    os.makedirs(synth, exist_ok=True)
    for sub in ("www", "cgi-bin", "bin", "usr/bin", "etc", "lib"):
        os.makedirs(os.path.join(synth, sub), exist_ok=True)

    copied = 0
    used_names = set()
    for src, rel, _size in staged:
        rel_lower = rel.lower()
        base = os.path.basename(rel)
        if any(token in rel_lower for token in ("/www/", "/web/")) or base.lower().endswith((".html", ".htm", ".js", ".css", ".xml", ".json", ".svg", ".ico", ".gif", ".jpg", ".jpeg", ".png")):
            dest = os.path.join(synth, "www", base)
        elif base.lower().endswith(".cgi") or "/cgi" in rel_lower:
            dest = os.path.join(synth, "cgi-bin", base)
        elif os.access(src, os.X_OK):
            dest = os.path.join(synth, "usr/bin", base)
        elif base.lower().endswith((".conf", ".lua", ".sh", ".txt")):
            dest = os.path.join(synth, "etc", base)
        else:
            dest = os.path.join(synth, "www", base)

        stem, ext = os.path.splitext(dest)
        dedup = 1
        while dest in used_names or os.path.exists(dest):
            dest = f"{stem}_{dedup}{ext}"
            dedup += 1
        try:
            shutil.copy2(src, dest)
            used_names.add(dest)
            copied += 1
        except OSError:
            continue
        if copied >= max_files:
            break

    if copied < 12:
        shutil.rmtree(synth, ignore_errors=True)
        return None

    index_path = os.path.join(synth, "www", "SEGMENTED_BUNDLE_NOTE.txt")
    Path(index_path).write_text(
        "Synthetic webroot assembled from segmented bundle chunks.\n"
        "Use this only for web-surface triage, not as a full firmware rootfs.\n",
        encoding="utf-8",
    )
    return synth


def _synthesize_segmented_partial_layout(base_dir, expanded_dirs, max_segments=16):
    """
    Build a compact analysis layout for segmented bundles when a real webroot
    cannot be reconstructed. This keeps only representative container chunks
    and decoded payloads so downstream triage sees a small, stable set of
    artifacts instead of thousands of noisy carve byproducts.
    """
    reps = []
    seen_real = set()

    try:
        root_names = sorted(os.listdir(base_dir))
    except OSError:
        root_names = []

    for name in root_names:
        path = os.path.join(base_dir, name)
        if not os.path.isfile(path):
            continue
        if not (
            _looks_like_nested_blob(path)
            or name.lower().endswith(".7z")
            or name.lower().endswith(".bin")
        ):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size < 64 * 1024:
            continue
        real = os.path.realpath(path)
        if real in seen_real:
            continue
        seen_real.add(real)
        reps.append({
            "src": path,
            "origin": "segment-root",
            "size_bytes": size,
            "name": name,
        })

    for root in expanded_dirs:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith("_") and not d.startswith(".")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                lower = name.lower()
                if not (
                    lower == "_decoded.bin"
                    or lower.endswith(".7z")
                    or lower.endswith(".bin")
                ):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size < 64 * 1024:
                    continue
                real = os.path.realpath(path)
                if real in seen_real:
                    continue
                seen_real.add(real)
                reps.append({
                    "src": path,
                    "origin": "nested-decode",
                    "size_bytes": size,
                    "name": os.path.relpath(path, root).replace("\\", "/"),
                })

    if len(reps) < 4:
        return None

    reps.sort(
        key=lambda row: (
            0 if row["origin"] == "nested-decode" else 1,
            -row["size_bytes"],
            row["name"],
        )
    )

    layout_dir = os.path.join(base_dir, "_segmented_partial_layout")
    shutil.rmtree(layout_dir, ignore_errors=True)
    seg_dir = os.path.join(layout_dir, "segments")
    os.makedirs(seg_dir, exist_ok=True)

    manifest = {
        "reconstruction_level": "segmented-partial-layout",
        "segment_count": 0,
        "representatives": [],
    }

    used = set()
    copied = 0
    for rep in reps:
        src = rep["src"]
        base = os.path.basename(src)
        dst = os.path.join(seg_dir, base)
        stem, ext = os.path.splitext(dst)
        dedup = 1
        while dst in used or os.path.exists(dst):
            dst = f"{stem}_{dedup}{ext}"
            dedup += 1
        try:
            _safe_link_or_copy(src, dst)
        except OSError:
            continue
        used.add(dst)
        copied += 1
        manifest["representatives"].append({
            "path": os.path.relpath(dst, layout_dir),
            "origin": rep["origin"],
            "size_bytes": rep["size_bytes"],
            "source_name": rep["name"],
        })
        if copied >= max_segments:
            break

    if copied < 4:
        shutil.rmtree(layout_dir, ignore_errors=True)
        return None

    manifest["segment_count"] = copied
    Path(os.path.join(layout_dir, "SEGMENTED_PARTIAL_LAYOUT.txt")).write_text(
        "Representative segmented bundle layout for static triage.\n"
        "This is not a full reconstructed rootfs.\n",
        encoding="utf-8",
    )
    _json_dump(os.path.join(layout_dir, "PARTIAL_LAYOUT.json"), manifest)
    return layout_dir


def _synthesize_probe_partial_layout(base_dir, payload_paths, layout_name="_probe_partial_layout", max_segments=8):
    rows = []
    seen = set()
    for path in payload_paths:
        if not path or not os.path.isfile(path):
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size < 64 * 1024:
            continue
        rows.append((path, size))

    if len(rows) < 2:
        return None

    rows.sort(key=lambda item: (-item[1], os.path.basename(item[0])))
    layout_dir = os.path.join(base_dir, layout_name)
    shutil.rmtree(layout_dir, ignore_errors=True)
    seg_dir = os.path.join(layout_dir, "segments")
    os.makedirs(seg_dir, exist_ok=True)

    manifest = {
        "reconstruction_level": "probe-partial-layout",
        "segment_count": 0,
        "segments": [],
    }

    copied = 0
    used = set()
    for path, size in rows:
        dst = os.path.join(seg_dir, os.path.basename(path))
        stem, ext = os.path.splitext(dst)
        dedup = 1
        while dst in used or os.path.exists(dst):
            dst = f"{stem}_{dedup}{ext}"
            dedup += 1
        _safe_link_or_copy(path, dst)
        used.add(dst)
        copied += 1
        manifest["segments"].append({
            "path": os.path.relpath(dst, layout_dir),
            "size_bytes": size,
        })
        if copied >= max_segments:
            break

    if copied < 2:
        shutil.rmtree(layout_dir, ignore_errors=True)
        return None

    manifest["segment_count"] = copied
    Path(os.path.join(layout_dir, "PARTIAL_LAYOUT.txt")).write_text(
        "Representative offset/decrypt probe payloads for static triage.\n",
        encoding="utf-8",
    )
    _json_dump(os.path.join(layout_dir, "PARTIAL_LAYOUT.json"), manifest)
    return layout_dir


def _candidate_passphrases_from_blob_name(blob_path, vendor_hint=""):
    if "tenda" in vendor_hint.lower():
        return [
            "TENDAWIFI",
            "TendaWiFi",
            "tendawifi",
            "tendawifi.com",
            "Tenda",
            "tenda",
        ]

    seeds = []
    stem = os.path.splitext(os.path.basename(blob_path))[0]
    seeds.extend(re.findall(r"[A-Za-z0-9]+", stem))
    if vendor_hint:
        seeds.extend(re.findall(r"[A-Za-z0-9]+", vendor_hint))
    preferred = ["TENDAWIFI", "TendaWiFi", "tendawifi", "tendawifi.com", "Tenda", "tenda"]
    seeds = preferred + seeds

    out = []
    seen = set()
    for seed in seeds:
        if len(seed) < 3:
            continue
        variants = (seed, seed.lower(), seed.upper())
        for variant in variants:
            if variant in seen:
                continue
            seen.add(variant)
            out.append(variant)

    compact = "".join(ch for ch in stem if ch.isalnum())
    if compact and compact not in seen:
        out.append(compact)
    return out[:64]


def _try_auto_openssl_container_extract(blob_path, out_dir, vendor_hint=""):
    try:
        with open(blob_path, "rb") as fh:
            head = fh.read(0x214)
            if len(head) < 0x214 or head[0x204:0x20C] != b"Salted__":
                return None
            salt = head[0x20C:0x214].hex()
    except OSError:
        return None

    probe_dir = os.path.join(out_dir, ".openssl_auto")
    shutil.rmtree(probe_dir, ignore_errors=True)
    os.makedirs(probe_dir, exist_ok=True)

    ciphertext = os.path.join(probe_dir, "ciphertext.bin")
    with open(blob_path, "rb") as src, open(ciphertext, "wb") as dst:
        src.seek(0x214)
        shutil.copyfileobj(src, dst)

    candidates = _candidate_passphrases_from_blob_name(blob_path, vendor_hint)
    if not candidates:
        return None

    digest_order = ("sha256", "md5")
    cipher_order = ("aes-128-cbc", "aes-256-cbc", "aes-192-cbc")
    attempts = []

    for passphrase in candidates:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", passphrase)[:96] or "candidate"
        for digest in digest_order:
            for cipher in cipher_order:
                out_blob = os.path.join(probe_dir, f"{safe}_{cipher}_{digest}.bin")
                proc = run(
                    " ".join([
                        "openssl", "enc", "-d", f"-{cipher}",
                        "-md", digest, "-S", salt, "-salt",
                        "-pass", shlex.quote(f"pass:{passphrase}"),
                        "-in", shlex.quote(ciphertext),
                        "-out", shlex.quote(out_blob),
                    ]),
                    label=f"openssl auto  {os.path.basename(blob_path)}",
                    quiet=True,
                )
                if proc.returncode != 0 or not os.path.isfile(out_blob):
                    continue
                try:
                    size = os.path.getsize(out_blob)
                except OSError:
                    size = 0
                if size < 256 * 1024:
                    continue
                structure = _structure_info(out_blob)
                attempts.append({
                    "passphrase": passphrase,
                    "cipher": cipher,
                    "digest": digest,
                    "path": os.path.relpath(out_blob, out_dir),
                    "size_bytes": size,
                    "structure": structure,
                })
                _record_container_evidence(out_dir, out_blob, {
                    "kind": structure.get("kind"),
                    "confidence": structure.get("confidence"),
                    "reasons": structure.get("reasons"),
                    "size_bytes": structure.get("size_bytes"),
                    "entropy": structure.get("entropy"),
                    "printable_ratio": structure.get("printable_ratio"),
                    "extract_offset": structure.get("extract_offset"),
                    "salvage_source": "openssl-decrypt",
                    "passphrase": passphrase,
                    "cipher": cipher,
                    "digest": digest,
                })
                if not _should_attempt_nested_extract(structure):
                    continue
                nested_out = os.path.join(
                    probe_dir,
                    f"_nested_{os.path.basename(out_blob)}"
                )
                if isinstance(structure.get("extract_offset"), int) and structure["extract_offset"] > 0:
                    extracted = _try_auto_offset_carve_extract(
                        out_blob,
                        probe_dir,
                        offsets=(structure["extract_offset"],),
                    )
                    if extracted:
                        _ok(
                            "auto OpenSSL carved-payload salvage succeeded: "
                            f"{os.path.relpath(out_blob, PROJECT_ROOT)}"
                        )
                        return extracted
                rootfs = _try_extract_iot_blob(
                    out_blob,
                    nested_out,
                    f"openssl nested  {os.path.basename(out_blob)}",
                )
                if rootfs:
                    _ok(
                        "auto OpenSSL container extract succeeded: "
                        f"{os.path.relpath(out_blob, PROJECT_ROOT)}"
                    )
                    return rootfs
                raw_candidates = _scan_raw_fs_offsets(out_blob, nested_out, probe_dir)
                if raw_candidates:
                    _ok(
                        "auto OpenSSL raw-fs salvage succeeded: "
                        f"{os.path.relpath(out_blob, PROJECT_ROOT)}"
                    )
                    return raw_candidates[0]["path"]
    if attempts:
        _json_dump(os.path.join(probe_dir, "decrypt_attempts.json"), attempts)
        probe_partial_layout = _reconstruct_container_partial_layout(probe_dir)
        if probe_partial_layout:
            _ok(
                "auto OpenSSL probe partial layout assembled: "
                f"{os.path.relpath(probe_partial_layout, PROJECT_ROOT)}"
            )
            return probe_partial_layout
        partial_layout = _reconstruct_container_partial_layout(out_dir)
        if partial_layout:
            _ok(
                "auto OpenSSL partial layout assembled: "
                f"{os.path.relpath(partial_layout, PROJECT_ROOT)}"
            )
            return partial_layout
    return None


def _try_auto_offset_carve_extract(blob_path, out_dir, offsets):
    probe_dir = os.path.join(out_dir, ".offset_probe")
    shutil.rmtree(probe_dir, ignore_errors=True)
    os.makedirs(probe_dir, exist_ok=True)

    try:
        total_size = os.path.getsize(blob_path)
    except OSError:
        return None

    carved_payloads = []

    for offset in offsets:
        if offset <= 0 or offset >= total_size - 4096:
            continue
        carved = os.path.join(probe_dir, f"payload_{offset:x}.bin")
        with open(blob_path, "rb") as src, open(carved, "wb") as dst:
            src.seek(offset)
            shutil.copyfileobj(src, dst)
        carved_payloads.append(carved)
        structure = _structure_info(carved)
        _record_container_evidence(out_dir, carved, {
            "kind": structure.get("kind"),
            "confidence": structure.get("confidence"),
            "reasons": structure.get("reasons"),
            "size_bytes": structure.get("size_bytes"),
            "entropy": structure.get("entropy"),
            "printable_ratio": structure.get("printable_ratio"),
            "extract_offset": structure.get("extract_offset"),
            "salvage_source": "offset-carve",
            "carve_offset": offset,
        })
        decoded_target, decoded_structure = _decode_embedded_payload(
            carved,
            nested_out := os.path.join(probe_dir, f"_nested_{offset:x}"),
            structure,
        )
        if decoded_structure:
            _record_container_evidence(out_dir, decoded_target or carved, {
                "kind": decoded_structure.get("kind"),
                "confidence": decoded_structure.get("confidence"),
                "reasons": decoded_structure.get("reasons"),
                "size_bytes": decoded_structure.get("size_bytes", 0),
                "entropy": decoded_structure.get("entropy"),
                "printable_ratio": decoded_structure.get("printable_ratio"),
                "extract_offset": decoded_structure.get("extract_offset"),
                "salvage_source": "offset-carve-decode",
                "carve_offset": offset,
                "decoded_from": decoded_structure.get("decoded_from"),
                "decoded_output_size": decoded_structure.get("decoded_output_size", decoded_structure.get("output_size", 0)),
            })
        target_for_extract = decoded_target or carved
        target_structure = decoded_structure or structure
        if not _should_attempt_nested_extract(target_structure):
            continue
        rootfs = _try_extract_iot_blob(
            target_for_extract,
            nested_out,
            f"carve nested  {os.path.basename(blob_path)}@0x{offset:x}",
        )
        if rootfs:
            _ok(
                "auto offset-carve extract succeeded: "
                f"{os.path.relpath(carved, PROJECT_ROOT)}"
            )
            return rootfs
        raw_candidates = _scan_raw_fs_offsets(carved, nested_out, probe_dir)
        if raw_candidates:
            _ok(
                "auto offset-carve raw-fs salvage succeeded: "
                f"{os.path.relpath(carved, PROJECT_ROOT)}"
            )
            return raw_candidates[0]["path"]
    partial_layout = _synthesize_probe_partial_layout(probe_dir, carved_payloads)
    if partial_layout:
        _ok(
            "auto offset-carve partial layout assembled: "
            f"{os.path.relpath(partial_layout, PROJECT_ROOT)}"
        )
        return partial_layout
    return None


def _extract_cloud_header_offsets(head):
    offsets = []
    for off in (0x110, 0x114, 0x118, 0x11C):
        if off + 4 > len(head):
            continue
        value = int.from_bytes(head[off:off + 4], "big")
        if 0x200 <= value <= 0x200000:
            offsets.append(value)
    deduped = []
    seen = set()
    for value in offsets:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return tuple(deduped)


def _try_auto_container_extract(blob_path, out_dir):
    """
    Low-cost automatic probes for opaque vendor containers that previously
    required manual probe scripts. Keep this conservative: only try a few
    fixed offsets and common OpenSSL salted layouts.
    """
    try:
        with open(blob_path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None

    if len(head) >= 0x214 and head[0x204:0x20C] == b"Salted__":
        rootfs = _try_auto_openssl_container_extract(
            blob_path,
            out_dir,
            vendor_hint="Tenda style OpenSSL container",
        )
        if rootfs:
            return rootfs

    if b"fw-type:Cloud" in head[:128]:
        header_offsets = _extract_cloud_header_offsets(head)
        offset_candidates = header_offsets + tuple(
            off for off in (0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x10000)
            if off not in header_offsets
        )
        rootfs = _try_auto_offset_carve_extract(
            blob_path,
            out_dir,
            offsets=offset_candidates,
        )
        if rootfs:
            return rootfs

    return None


def _expand_segmented_bundle_chunks(base_dir, max_blobs=8):
    lowered_base = str(base_dir).lower().replace("\\", "/")
    if "/_extract_" in lowered_base or "/_carve_" in lowered_base:
        return []

    pending = []
    for dirpath, dirnames, filenames in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith("_nested_")]
        if not _looks_like_segmented_bundle_dir(dirpath):
            continue
        for filename in filenames:
            blob_path = os.path.join(dirpath, filename)
            if not _looks_like_nested_blob(blob_path):
                continue
            pending.append(blob_path)

    if not pending:
        try:
            fallback_files = [
                os.path.join(base_dir, name)
                for name in os.listdir(base_dir)
            ]
        except OSError:
            fallback_files = []
        for blob_path in fallback_files:
            if not os.path.isfile(blob_path):
                continue
            if _looks_like_opaque_nested_blob(blob_path):
                pending.append(blob_path)

    pending.sort(key=_rank_nested_blob, reverse=True)
    expanded = []
    for blob_path in pending[:max_blobs]:
        nested_dir = os.path.join(
            os.path.dirname(blob_path),
            f"_nested_{os.path.basename(blob_path)}"
        )
        expanded_dir = _decode_segmented_chunk(blob_path, nested_dir)
        if expanded_dir:
            expanded.append(expanded_dir)
    return expanded


def _try_extract_iot_blob(blob_path, out_dir, label):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    if _has_ubi_magic(blob_path):
        return _extract_ubi_blob(blob_path, os.path.join(out_dir, "_ubi_extract"))

    dlink_root = _try_extract_dlink_wrapped_blob(blob_path, out_dir)
    if dlink_root:
        return dlink_root

    dji_fast = _is_dji_firmware_blob(blob_path)
    run(
        _binwalk_extract_command(blob_path, out_dir, recursive=not dji_fast),
        label=label,
        quiet=True,
    )
    early_sqfs = find_squashfs_root(out_dir)
    if early_sqfs:
        return early_sqfs
    segmented_root = _find_segmented_bundle_root(out_dir)
    segmented_expanded = []
    if segmented_root:
        _info(
            "segmented firmware bundle detected; probing top nested chunks "
            f"({os.path.relpath(segmented_root, PROJECT_ROOT)})"
        )
        segmented_expanded = _expand_segmented_bundle_chunks(segmented_root)
        for nested_dir in segmented_expanded:
            _expand_nested_iot_blobs(nested_dir, max_depth=2, max_blobs_per_dir=8)
        sqfs = find_squashfs_root(out_dir)
        if sqfs:
            return sqfs
        synthesized = _synthesize_segmented_webroot(segmented_root, segmented_expanded)
        if synthesized:
            _ok(
                "segmented bundle synthetic webroot assembled: "
                f"{os.path.relpath(synthesized, PROJECT_ROOT)}"
            )
            return synthesized
        segmented_partial = _synthesize_segmented_partial_layout(segmented_root, segmented_expanded)
        if segmented_partial:
            _ok(
                "segmented bundle partial layout assembled: "
                f"{os.path.relpath(segmented_partial, PROJECT_ROOT)}"
            )
            return segmented_partial
    if dji_fast:
        _expand_dji_bundles(out_dir)
    elif not segmented_expanded:
        _expand_nested_iot_blobs(out_dir)

    ubi_blobs = _find_ubi_blobs(out_dir)
    if ubi_blobs:
        sqfs = _extract_ubi_blob(ubi_blobs[0], os.path.join(out_dir, "_ubi_extract"))
        if sqfs:
            return sqfs

    sqfs = find_squashfs_root(out_dir)
    if sqfs:
        return sqfs

    if dji_fast:
        return None

    inner = os.path.join(out_dir, "_raw_fs")
    os.makedirs(inner, exist_ok=True)
    proc = run(
        f'7z x "{blob_path}" -o"{inner}" -y',
        label=f"7z raw scan  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if proc.returncode == 0 or os.listdir(inner):
        early_inner_sqfs = find_squashfs_root(inner)
        if early_inner_sqfs:
            return early_inner_sqfs
        if dji_fast:
            _expand_dji_bundles(inner)
        else:
            _expand_nested_iot_blobs(inner)
        ubi_blobs = _find_ubi_blobs(inner)
        if ubi_blobs:
            sqfs = _extract_ubi_blob(ubi_blobs[0], os.path.join(inner, "_ubi_extract"))
            if sqfs:
                return sqfs
        inner_sqfs = find_squashfs_root(inner)
        if inner_sqfs:
            return inner_sqfs

    rescue_candidates = _scan_raw_fs_offsets(blob_path, out_dir, inner)
    if not rescue_candidates:
        rescue_candidates = _scan_embedded_payloads(blob_path, out_dir, inner)
    if rescue_candidates:
        return rescue_candidates[0]["path"]
    return None


def _validate_iot_rootfs(dst, min_files=2000):
    count = _count_files(dst)
    if count < min_files:
        print("[FATAL] Extracted IoT rootfs is too small to trust.", flush=True)
        print(f"        Found: {count} files  (expected > {min_files} for router firmware)", flush=True)
        print(f"        Path:  {dst}", flush=True)
        sys.exit(1)
    return count


def _has_visible_analysis_artifacts(base_dir):
    if not base_dir or not os.path.isdir(base_dir):
        return False
    note_names = {"container_evidence.json", "decrypt_attempts.json"}
    for dirpath, dirnames, filenames in os.walk(base_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel = os.path.relpath(dirpath, base_dir)
        if rel != "." and rel.startswith("."):
            continue
        for name in filenames:
            if name.startswith("."):
                continue
            if name.lower() in note_names:
                continue
            return True
    return False


def _check_iot_rootfs(candidate, min_files=800):
    if isinstance(candidate, dict):
        info = candidate
        path = info["path"]
        count = info.get("file_count", 0)
        size_bytes = info.get("size_bytes", 0)
        core_dirs = info.get("core_dirs", [])
        score = info.get("score", 0)
        why = info.get("why", [])
    else:
        path = candidate
        info = _describe_rootfs_candidate(path)
        count = info["file_count"]
        size_bytes = info["size_bytes"]
        core_dirs = info["core_dirs"]
        score = info["score"]
        why = info["why"]

    missing_core = [d for d in ("bin", "etc", "usr", "lib") if d not in core_dirs]

    if count > min_files:
        return count, None

    if len(core_dirs) < 3:
        return count, (
            f"missing core dirs ({', '.join(missing_core)})"
            if missing_core else "missing core dirs"
        )

    if count < 300 and size_bytes < 3 * 1024 * 1024:
        return count, (
            f"too small to trust ({count} files, {_format_size(size_bytes)})"
        )

    if size_bytes > 8 * 1024 * 1024 and len(core_dirs) >= 3:
        return count, None

    if score >= 12 and any(tag in why for tag in ("web", "exec", "init")):
        return count, None

    return count, (
        f"insufficient rootfs signals ({count} files, {_format_size(size_bytes)}, "
        f"core={','.join(core_dirs)})"
    )


def _print_rootfs_candidate_summary(candidates, selected=None, rejected=None):
    if not candidates:
        return

    print("    ranked rootfs candidates:", flush=True)
    rejected = rejected or {}
    for idx, info in enumerate(candidates, 1):
        rel = os.path.relpath(info["path"], PROJECT_ROOT)
        line = (
            f"      {idx:>2}. {rel}  "
            f"files={info['file_count']}  "
            f"size={_format_size(info['size_bytes'])}  "
            f"score={info['score']}"
        )
        why = ", ".join(info["why"])
        if why:
            line += f"  [{why}]"
        print(line, flush=True)
        if info["path"] in rejected:
            print(f"          rejected: {rejected[info['path']]}", flush=True)
        if selected is not None and info["path"] == selected["path"]:
            print("          chosen", flush=True)


def extract_iot_firmware(bin_path):
    """
    Extract an IoT firmware .bin with binwalk, locate the squashfs-root,
    and return that rootfs path for the analysis stage.
    Falls back to weaker analysis roots when classic rootfs extraction fails.
    """
    out_dir = _iot_extract_dir_for(bin_path)
    _reset_dir_fast(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    if shutil.which("binwalk") is None:
        _warn("binwalk not found in PATH; using raw blob fallback analysis root")
        raw_copy = os.path.join(out_dir, os.path.basename(bin_path))
        if os.path.abspath(raw_copy) != os.path.abspath(bin_path):
            shutil.copy2(bin_path, raw_copy)
        _ok(f"analysis root: {os.path.relpath(out_dir, PROJECT_ROOT)}")
        return out_dir

    is_dji_blob = _is_dji_firmware_blob(bin_path)

    _try_extract_iot_blob(
        bin_path, out_dir, f"binwalk  {os.path.basename(bin_path)}"
    )

    candidates = _collect_ranked_rootfs_candidates(out_dir)

    if not candidates and not is_dji_blob:
        candidates = _scan_raw_fs_offsets(bin_path, out_dir)
    elif not candidates and is_dji_blob:
        _warn("DJI package detected; skipping raw filesystem carving and deep recursive unpacking")

    if not candidates:
        if is_dji_blob:
            payload_path = _find_dji_android_payload(out_dir)
            if payload_path:
                _info(f"DJI Android payload: {os.path.relpath(payload_path, PROJECT_ROOT)}")
                ensure_dumper()
                extract_payload(payload_path=payload_path)
                collect_images()
                build_rootfs()
                _ok(f"system     → {os.path.relpath(os.path.join(ROOTFS_DIR, 'system'), PROJECT_ROOT)}")
                return os.path.join(ROOTFS_DIR, "system")

        auto_container_rootfs = _try_auto_container_extract(bin_path, out_dir)
        if auto_container_rootfs:
            _ok(f"auto rootfs  → {os.path.relpath(auto_container_rootfs, PROJECT_ROOT)}")
            return auto_container_rootfs

        if not _has_visible_analysis_artifacts(out_dir):
            os.makedirs(out_dir, exist_ok=True)
            raw_copy = os.path.join(out_dir, os.path.basename(bin_path))
            if os.path.abspath(raw_copy) != os.path.abspath(bin_path):
                shutil.copy2(bin_path, raw_copy)

        partial_layout = _reconstruct_container_partial_layout(out_dir)
        if partial_layout:
            _ok(f"partial layout: {os.path.relpath(partial_layout, PROJECT_ROOT)}")
        segmented_partial_layout = _find_segmented_partial_layout(out_dir)
        if segmented_partial_layout and os.path.isdir(segmented_partial_layout):
            partial_layout = segmented_partial_layout
            _ok(f"segmented partial layout: {os.path.relpath(partial_layout, PROJECT_ROOT)}")

        bundle_candidates = _collect_ranked_bundle_candidates(out_dir)
        if partial_layout and os.path.basename(partial_layout) == "_segmented_partial_layout":
            _warn("no classic rootfs found; using segmented partial layout fallback")
            _ok(f"analysis root: {os.path.relpath(partial_layout, PROJECT_ROOT)}")
            return partial_layout
        if bundle_candidates:
            selected = bundle_candidates[0]
            _warn("no classic rootfs found; using generic firmware bundle fallback")
            _ok(f"bundle hint: {os.path.relpath(selected['path'], PROJECT_ROOT)}")
            _ok(f"analysis root: {os.path.relpath(out_dir, PROJECT_ROOT)}")
            _ok(f"selected score: {selected['score']}  ({', '.join(selected['why'])})")
            return out_dir
        if partial_layout:
            _warn("no classic rootfs found; using partial container layout fallback")
            _ok(f"analysis root: {os.path.relpath(partial_layout, PROJECT_ROOT)}")
            return partial_layout
        if _count_files(out_dir) > 0:
            _warn("no classic rootfs or bundle candidate found; using extracted directory fallback")
            _ok(f"analysis root: {os.path.relpath(out_dir, PROJECT_ROOT)}")
            return out_dir
        if is_dji_blob and _count_files(out_dir) > 0:
            _warn("no rootfs found in DJI package; using extracted bundle directory for focused triage")
            _ok(f"analysis root: {os.path.relpath(out_dir, PROJECT_ROOT)}")
            return out_dir

        _warn("binwalk ran but no classic rootfs or bundle candidate was found; using raw blob fallback")
        os.makedirs(out_dir, exist_ok=True)
        raw_copy = os.path.join(out_dir, os.path.basename(bin_path))
        if os.path.abspath(raw_copy) != os.path.abspath(bin_path):
            shutil.copy2(bin_path, raw_copy)
        _ok(f"analysis root: {os.path.relpath(out_dir, PROJECT_ROOT)}")
        return out_dir

    rejected = {}
    selected = None
    for idx, info in enumerate(candidates):
        count, error = _check_iot_rootfs(info)
        if error is None:
            info["validated_file_count"] = count
            selected = info
            if idx > 0:
                _warn("top rootfs candidate was rejected; using next-best candidate")
            break
        rejected[info["path"]] = error

    if selected is None and candidates and not is_dji_blob:
        rescue_candidates = _scan_raw_fs_offsets(bin_path, out_dir)
        if rescue_candidates:
            candidates = rescue_candidates
            rejected = {}
            selected = None
            for idx, info in enumerate(candidates):
                count, error = _check_iot_rootfs(info)
                if error is None:
                    info["validated_file_count"] = count
                    selected = info
                    if idx > 0:
                        _warn("top rootfs candidate was rejected; using raw-offset rescue candidate")
                    break
                rejected[info["path"]] = error

    _print_rootfs_candidate_summary(candidates, selected=selected, rejected=rejected)

    if selected is None:
        best = candidates[0]
        _warn("extracted IoT rootfs is weak; using best candidate anyway for fallback analysis")
        _ok(f"analysis root: {os.path.relpath(best['path'], PROJECT_ROOT)}")
        return best["path"]

    sqfs = selected["path"]
    count = selected["validated_file_count"]
    _ok(f"squashfs-root: {os.path.relpath(sqfs, PROJECT_ROOT)}")
    _ok(f"selected score: {selected['score']}  ({', '.join(selected['why'])})")
    _ok(f"system     → {os.path.relpath(sqfs, PROJECT_ROOT)}  ({count} files)")
    return sqfs


def handle_iot_input(bin_path):
    """Extract IoT firmware and return the selected rootfs path."""
    return extract_iot_firmware(bin_path)


# ── Input resolution ──────────────────────────────────────────────────────────

def resolve_input(input_arg, type_arg):
    """
    Determine the absolute path and type of the input file.

    Auto-detection rules (when --input is not given):
      - 0 files in inputs/ → [FATAL] exit
      - 1 file                 → use it automatically
      - 2+ files               → list them and exit (user must pick with --input)

    Returns (path, type_str) or (None, None) if --input points to a missing file.
    """
    if input_arg:
        path = os.path.abspath(input_arg)
        if not os.path.exists(path):
            _warn(f"input file not found: {path}")
            return None, None
    else:
        candidates = _iter_input_files(FIRMWARE_DIR)

        if not candidates:
            print("\n[FATAL] No input file found in inputs/", flush=True)
            print(f"        Expected: {FIRMWARE_DIR}", flush=True)
            print("        Supported formats: .zip, .rar, .tar, payload.bin, .img, .bin", flush=True)
            sys.exit(1)

        if len(candidates) > 1:
            _warn("Multiple input files found:")
            for i, f in enumerate(candidates, 1):
                try:
                    label = os.path.relpath(f, FIRMWARE_DIR)
                except ValueError:
                    label = f
                print(f"        {i}. {label}", flush=True)
            print(flush=True)
            print("    Use --input <filename> to select one.", flush=True)
            sys.exit(1)

        path = candidates[0]

    if type_arg and type_arg != "auto":
        detected = type_arg
        _info(f"{os.path.basename(path)}  (type: {detected}, forced)")
        if detected == INPUT_ZIP:
            path, detected = _resolve_zip_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected}, forced)")
        elif detected == INPUT_RAR:
            path, detected = _resolve_rar_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected}, forced)")
        elif detected == INPUT_TAR:
            path, detected = _resolve_tar_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected}, forced)")
    else:
        detected = detect_input_type(path)
        if detected == INPUT_ZIP:
            _info(f"{os.path.basename(path)}  (type: zip)")
            path, detected = _resolve_zip_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected})")
        elif detected == INPUT_RAR:
            _info(f"{os.path.basename(path)}  (type: rar)")
            path, detected = _resolve_rar_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected})")
        elif detected == INPUT_TAR:
            _info(f"{os.path.basename(path)}  (type: tar)")
            path, detected = _resolve_tar_firmware(path)
            _info(f"{os.path.basename(path)}  (resolved type: {detected})")
        else:
            _info(f"{os.path.basename(path)}  (type: {detected})")

    return path, detected


# ── Analysis ──────────────────────────────────────────────────────────────────

def run_analysis(output_path=None, system_path=None, vendor_path=None):
    """
    Invoke main.py as a subprocess, with PYTHONPATH set so that imports
    resolve against src/core/ without requiring manual PYTHONPATH export.

    The FIRMWARE_LOG_FILE env var is inherited by the child so it can set up
    its own _Tee and append its output to the same log file.

    sys.stdout is explicitly flushed before the subprocess starts, ensuring
    all pipeline stage output is visible before main.py begins writing.
    """
    core_dir = os.path.join(BASE_DIR, "core")
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{core_dir}:{existing_pythonpath}" if existing_pythonpath else core_dir
    )
    if system_path:
        env["FIRMWARE_SYSTEM_PATH"] = os.path.abspath(system_path)
        if vendor_path:
            env["FIRMWARE_VENDOR_PATH"] = os.path.abspath(vendor_path)
        else:
            env.pop("FIRMWARE_VENDOR_PATH", None)

    sys.stdout.flush()

    cmd = f'python3 -u "{os.path.join(BASE_DIR, "main.py")}"'
    if output_path:
        cmd += f' --output "{output_path}"'
    dossier_dir = env.get("FIRMWARE_DOSSIER_DIR")
    if dossier_dir:
        cmd += f' --dossier-dir "{dossier_dir}"'

    run_critical(
        cmd,
        fatal_msg="Analysis step failed. Check the error above.",
        env=env,
        timeout=3600,    # 1 hr; large rootfs can take a long time to scan
    )


def _write_manifest(path, payload):
    _json_dump(path, payload)


def _load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _manifest_input_entry(path, type_name):
    if not path:
        return None
    entry = {
        "path": os.path.relpath(path, PROJECT_ROOT),
        "type": type_name,
        "exists": os.path.exists(path),
    }
    if os.path.exists(path):
        entry["sha256"] = _sha256_file(path)
        entry["size_bytes"] = os.path.getsize(path)
    return entry


def _is_iot_batch_candidate(path):
    detected = detect_input_type(path)
    base = os.path.basename(path).lower()

    if detected == INPUT_IOT:
        return True
    if detected == INPUT_PAYLOAD or detected == INPUT_IMG:
        return False
    if detected == INPUT_ZIP:
        members = [m.lower() for m in _list_zip_members(path)]
        if any(os.path.basename(m) == "payload.bin" for m in members):
            return False
        return any(os.path.basename(m).endswith(_ARCHIVE_FIRMWARE_EXTS) for m in members)
    if detected == INPUT_RAR:
        members = [name.lower() for name, _ in _list_archive_members(path)]
        if any(os.path.basename(m) == "payload.bin" for m in members):
            return False
        return any(os.path.basename(m).endswith(_ARCHIVE_FIRMWARE_EXTS) for m in members)
    return "pureubi" in base


def ingest_iot_firmware_folder(folder):
    added = []
    skipped = []

    if not os.path.isdir(folder):
        print(f"skipped: {folder} (not a directory)", flush=True)
        print("total added: 0", flush=True)
        return

    os.makedirs(FIRMWARE_DIR, exist_ok=True)

    for name in sorted(os.listdir(folder)):
        src = os.path.join(folder, name)
        if not os.path.isfile(src):
            continue

        dst = os.path.join(FIRMWARE_DIR, name)
        if os.path.exists(dst):
            skipped.append(f"{name} (duplicate)")
            continue

        if _is_iot_batch_candidate(src):
            shutil.copy2(src, dst)
            added.append(name)
        else:
            skipped.append(f"{name} (non-iot/android)")

    print("added files:", flush=True)
    for name in added:
        print(name, flush=True)
    print("skipped files:", flush=True)
    for name in skipped:
        print(name, flush=True)
    print(f"total added: {len(added)}", flush=True)


def _parse_batch_metrics(output):
    rootfs_count = 0
    web_count = 0
    arg_count = 0

    m = re.search(r'system\s+→\s+.+?\s+\((\d+) files\)', output)
    if m:
        rootfs_count = int(m.group(1))
    else:
        m = re.search(r'Found:\s+(\d+) files', output)
        if m:
            rootfs_count = int(m.group(1))

    m = re.search(r'Web-exposed\s+:\s+(\d+)', output)
    if m:
        web_count = int(m.group(1))
    else:
        m = re.search(r'\(web=(\d+)\s+HIGH=', output)
        if m:
            web_count = int(m.group(1))

    arg_count = len(re.findall(r'review control:\s+argument-level', output))
    return rootfs_count, web_count, arg_count


def run_batch_iot_triage():
    rows = []
    candidates = []
    for path in _iter_input_files(FIRMWARE_DIR):
        if _is_iot_batch_candidate(path):
            candidates.append(path)

    name_width = max(20, max((len(os.path.basename(p)) for p in candidates), default=0))

    if not candidates:
        print(f"{'firmware':<{name_width}} {'rootfs':>8} {'web':>5} {'arg':>5} {'decision':>10}  reason", flush=True)
        print("total=0 keep=0 benchmark=0 drop=0", flush=True)
        return

    script_path = os.path.abspath(__file__)
    total = len(candidates)
    for idx, path in enumerate(candidates, 1):
        name = os.path.basename(path)
        print(f"[{idx}/{total}] Processing: {name}", flush=True)
        cmd = ["python3", script_path, "--input", path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        rootfs_count, web_count, arg_count = _parse_batch_metrics(combined)

        if arg_count > 0:
            decision = "KEEP"
        elif rootfs_count >= 1500 and web_count > 0:
            decision = "BENCHMARK"
        else:
            decision = "DROP"

        if decision == "KEEP":
            reason = "arg-level web control"
        elif decision == "BENCHMARK":
            reason = "web surface present, no arg-level control"
        else:
            reason = "weak extraction" if rootfs_count < 1500 else "no useful web surface"

        rows.append((name, rootfs_count, web_count, arg_count, decision, reason))
        print(f"[DONE] {name}", flush=True)

    priority = {"KEEP": 0, "BENCHMARK": 1, "DROP": 2}
    rows.sort(key=lambda r: (priority.get(r[4], 99), r[0].lower()))

    print(f"{'firmware':<{name_width}} {'rootfs':>8} {'web':>5} {'arg':>5} {'decision':>10}  reason", flush=True)
    for name, rootfs_count, web_count, arg_count, decision, reason in rows:
        print(f"{name:<{name_width}} {rootfs_count:>8} {web_count:>5} {arg_count:>5} {decision:>10}  {reason}", flush=True)

    keep = sum(1 for *_, decision, _reason in rows if decision == "KEEP")
    benchmark = sum(1 for *_, decision, _reason in rows if decision == "BENCHMARK")
    drop = sum(1 for *_, decision, _reason in rows if decision == "DROP")
    print(f"total={len(rows)} keep={keep} benchmark={benchmark} drop={drop}", flush=True)

    recheck_rows = [r for r in rows if r[4] == "BENCHMARK"]
    if recheck_rows:
        print("\nrecheck targets", flush=True)
        print(f"{'firmware':<{name_width}} {'rootfs':>8} {'web':>5}  reason", flush=True)
        for name, rootfs_count, web_count, _arg_count, _decision, reason in recheck_rows:
            print(f"{name:<{name_width}} {rootfs_count:>8} {web_count:>5}  {reason}", flush=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Firmware analysis pipeline — auto-detects input type")
    parser.add_argument(
        "--skip", action="store_true",
        help="reuse existing rootfs, skip all extraction stages")
    parser.add_argument(
        "--input", metavar="FILE",
        help="path to input file (OTA zip / tar / payload.bin / .img / .bin); "
             "default: the single file found in inputs/")
    parser.add_argument(
        "--type", metavar="TYPE",
        choices=["auto", "zip", "rar", "tar", "payload", "img", "iot"],
        default="auto",
        help="force input type (auto|zip|rar|tar|payload|img|iot)  [default: auto]")
    parser.add_argument(
        "--output", metavar="FILE",
        help="save analysis results as JSON  (e.g. results.json)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="validate tools and input file without running the pipeline")
    parser.add_argument(
        "--batch-iot", action="store_true",
        help="run compact triage across all current IoT firmware inputs under inputs/")
    parser.add_argument(
        "--ingest-dir", metavar="DIR",
        help="scan a folder and copy only IoT-like firmware inputs into inputs/")
    parser.add_argument(
        "--status", action="store_true",
        help="show cache/workspace status and latest run metadata")
    parser.add_argument(
        "--cleanup", nargs="+",
        choices=["build", "rootfs", "runs", "extracted", "input", "all-temp"],
        help="remove selected cached directories")
    parser.add_argument(
        "--retain-runs", type=int,
        help="keep only the newest N run artifact directories under runs/")
    parser.add_argument(
        "--retain-extracted", type=int,
        help="keep only the newest N extracted_* directories under .cache/extracted/")
    args = parser.parse_args()

    if args.retain_runs is None:
        args.retain_runs = DEFAULT_RETAIN_RUNS
    if args.retain_extracted is None:
        args.retain_extracted = DEFAULT_RETAIN_EXTRACTED

    if args.status:
        print_cache_status()
        sys.exit(0)

    if args.cleanup:
        cleanup_targets(args.cleanup)
        if args.retain_runs is not None or args.retain_extracted is not None:
            apply_retention_limits(args.retain_runs, args.retain_extracted)
        sys.exit(0)

    if (args.retain_runs is not None or args.retain_extracted is not None) and not any([
        args.dry_run,
        args.skip,
        args.input,
        args.output,
        args.batch_iot,
        args.ingest_dir,
    ]):
        apply_retention_limits(args.retain_runs, args.retain_extracted)
        sys.exit(0)

    original_input_path = None
    original_input_type = args.type
    if args.input:
        original_input_path = os.path.abspath(args.input)
    elif not args.skip and not args.batch_iot and not args.ingest_dir:
        original_candidates = _iter_input_files(FIRMWARE_DIR)
        if len(original_candidates) == 1:
            original_input_path = original_candidates[0]

    preflight_path = None
    preflight_type = None
    if not args.skip and not args.batch_iot and not args.ingest_dir:
        preflight_path, preflight_type = resolve_input(args.input, args.type)
        if preflight_path is None:
            sys.exit(1)
        if args.type == "auto":
            if original_input_path and os.path.abspath(original_input_path) == os.path.abspath(preflight_path):
                original_input_type = preflight_type
            elif original_input_path:
                original_input_type = detect_input_type(original_input_path)
            else:
                original_input_type = preflight_type

    run_artifacts = _prepare_run_artifacts(original_input_path or preflight_path)
    _log_fh = None
    if not args.batch_iot:
        _log_fh = open(run_artifacts["log_path"], "a", encoding="utf-8", errors="replace", buffering=1)
        sys.stdout = _Tee(sys.stdout, _log_fh)
        sys.stderr = _Tee(sys.stderr, _log_fh)
        os.environ["FIRMWARE_LOG_FILE"] = run_artifacts["log_path"]
        os.environ["FIRMWARE_RUN_DIR"] = run_artifacts["run_dir"]
        os.environ["FIRMWARE_DOSSIER_DIR"] = run_artifacts["dossier_dir"]
        os.environ["FIRMWARE_RUN_ID"] = run_artifacts["run_id"]

    total = 4 if not args.skip else 2

    if args.ingest_dir:
        ingest_iot_firmware_folder(os.path.abspath(args.ingest_dir))
        if not args.batch_iot:
            sys.exit(0)

    if args.batch_iot:
        run_batch_iot_triage()
        sys.exit(0)

    print("─" * _W, flush=True)
    print("  Firmware Vulnerability Analysis Pipeline", flush=True)
    print(f"  Run dir: {os.path.relpath(run_artifacts['run_dir'], PROJECT_ROOT)}", flush=True)
    print(f"  Log: {os.path.relpath(run_artifacts['log_path'], PROJECT_ROOT)}", flush=True)
    print("─" * _W, flush=True)

    t_total = time.time()
    output_path = os.path.abspath(args.output) if args.output else run_artifacts["result_path"]
    manifest = {
        "run_id": run_artifacts["run_id"],
        "run_dir": os.path.relpath(run_artifacts["run_dir"], PROJECT_ROOT),
        "log_path": os.path.relpath(run_artifacts["log_path"], PROJECT_ROOT),
        "result_path": os.path.relpath(output_path, PROJECT_ROOT),
        "canonical_result_path": os.path.relpath(run_artifacts["result_path"], PROJECT_ROOT),
        "dossier_dir": os.path.relpath(run_artifacts["dossier_dir"], PROJECT_ROOT),
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "status": "running",
        "input": {
            "original": _manifest_input_entry(original_input_path, original_input_type),
            "resolved": None,
        },
        "retention": {
            "retain_runs": args.retain_runs,
            "retain_extracted": args.retain_extracted,
        },
    }
    _write_manifest(run_artifacts["manifest_path"], manifest)

    # ── [0] Pre-flight ────────────────────────────────────────────────────────
    _stage(0, total, "Pre-flight checks")
    _check_required_tools()

    # ── Dry run mode (exits after validation) ─────────────────────────────────
    if args.dry_run:
        print(flush=True)
        _info("DRY RUN — validating prerequisites only, nothing will execute")
        path, input_type = preflight_path, preflight_type
        if path is None:
            path, input_type = resolve_input(args.input, args.type)
        if path is None:
            sys.exit(1)
        if input_type != INPUT_IOT:
            ensure_dumper()
        manifest["input"]["resolved"] = _manifest_input_entry(path, input_type)
        manifest["status"] = "dry_run_complete"
        manifest["finished_at"] = datetime.now().isoformat(timespec="seconds")
        _write_manifest(run_artifacts["manifest_path"], manifest)
        print(flush=True)
        _info(f"Input file:   {os.path.basename(path)}")
        _info(f"Input type:   {input_type}")
        _info(f"Rootfs:       {ROOTFS_DIR}")
        _info(f"Run dir:      {run_artifacts['run_dir']}")
        _info(f"JSON output:  {output_path}")
        print(flush=True)
        _info("Pipeline would execute:")
        _info("  [2/4] Extraction    → unzip / payload-dumper-go / 7z")
        _info("  [3/4] Rootfs        → assemble .cache/rootfs/system, vendor")
        _info("  [4/4] Analysis      → parse .rc files + binary scan")
        print(flush=True)
        _ok("Dry run complete — no files modified")
        print("─" * _W, flush=True)
        sys.exit(0)

    # ── [1] Workspace ─────────────────────────────────────────────────────────
    _stage(1, total, "Workspace")
    clean(args.skip)

    analysis_system_path = None
    analysis_vendor_path = None
    assembled_root = None
    input_type = preflight_type

    if not args.skip:
        # ── [2] Extraction ────────────────────────────────────────────────────
        _stage(2, total, "Extraction")
        _info("Running...")
        t_ext = time.time()

        path, input_type = resolve_input(args.input, args.type)
        if path is None:
            print("\n[!] Input file not found.", flush=True)
            sys.exit(1)
        manifest["input"]["resolved"] = _manifest_input_entry(path, input_type)
        _write_manifest(run_artifacts["manifest_path"], manifest)
        os.environ["FIRMWARE_INPUT_PATH"] = os.path.abspath(path)
        os.environ["FIRMWARE_INPUT_TYPE"] = input_type
        if original_input_path:
            os.environ["FIRMWARE_ORIGINAL_INPUT_PATH"] = os.path.abspath(original_input_path)
            os.environ["FIRMWARE_ORIGINAL_INPUT_TYPE"] = original_input_type or input_type

        try:
            if input_type == INPUT_ZIP:
                handle_zip_input(path)
            elif input_type == INPUT_PAYLOAD:
                handle_payload_input(path)
            elif input_type == INPUT_IMG:
                analysis_system_path = handle_img_input(path)
                if analysis_system_path == os.path.join(ROOTFS_DIR, "system"):
                    analysis_vendor_path = os.path.join(ROOTFS_DIR, "vendor")
            elif input_type == INPUT_IOT:
                analysis_system_path = handle_iot_input(path)
                if analysis_system_path == os.path.join(ROOTFS_DIR, "system"):
                    analysis_vendor_path = os.path.join(ROOTFS_DIR, "vendor")
            else:
                _warn(f"cannot determine file type for: {os.path.basename(path)}")
                _warn("using best-effort fallback analysis root")
                analysis_system_path = _fallback_analysis_root_for_input(path)
                analysis_vendor_path = None
                if not analysis_system_path:
                    sys.exit(1)
                _ok(f"analysis root: {os.path.relpath(analysis_system_path, PROJECT_ROOT)}")
        except SystemExit as exc:
            if input_type == INPUT_IOT:
                fallback_root = _fallback_analysis_root_for_input(path)
                if not fallback_root:
                    raise
                _warn(
                    f"IoT extraction failed with exit {getattr(exc, 'code', 1)}; "
                    "continuing with fallback analysis root"
                )
                _ok(f"analysis root: {os.path.relpath(fallback_root, PROJECT_ROOT)}")
                analysis_system_path = fallback_root
                analysis_vendor_path = None
            else:
                fallback_root = _fallback_analysis_root_for_input(path)
                if not fallback_root:
                    raise
                _warn(
                    f"extraction/assembly failed with exit {getattr(exc, 'code', 1)}; "
                    "continuing with best-effort fallback analysis root"
                )
                _ok(f"analysis root: {os.path.relpath(fallback_root, PROJECT_ROOT)}")
                analysis_system_path = fallback_root
                analysis_vendor_path = None

        _ok(f"Extraction complete  ({_fmt_time(time.time() - t_ext)})")

        # ── [3] Rootfs assembly (skipped for IoT — done inside extraction) ────
        if input_type != INPUT_IOT and analysis_system_path is None:
            _stage(3, total, "Rootfs assembly")
            _info("Running...")
            t_rootfs = time.time()
            try:
                assembled_root = build_rootfs()
            except SystemExit as exc:
                assembled_root = _fallback_analysis_root_for_input(path)
                if not assembled_root:
                    raise
                _warn(
                    f"rootfs assembly failed with exit {getattr(exc, 'code', 1)}; "
                    "continuing with fallback analysis root"
                )
                _ok(f"analysis root: {os.path.relpath(assembled_root, PROJECT_ROOT)}")
            _ok(f"Rootfs assembly complete  ({_fmt_time(time.time() - t_rootfs)})")

    # ── [N] Vulnerability analysis ────────────────────────────────────────────
    _stage(total, total, "Vulnerability analysis")
    _info("Running...")
    if args.skip:
        analysis_system_path = None
        analysis_vendor_path = None
    elif input_type != INPUT_IOT and analysis_system_path is None:
        analysis_system_path = assembled_root or os.path.join(ROOTFS_DIR, "system")
        analysis_vendor_path = (
            os.path.join(ROOTFS_DIR, "vendor")
            if analysis_system_path == os.path.join(ROOTFS_DIR, "system")
            else None
        )

    run_analysis(
        output_path=output_path,
        system_path=analysis_system_path,
        vendor_path=analysis_vendor_path,
    )

    result_payload = _load_json(output_path) or {}
    if result_payload and os.path.abspath(output_path) != os.path.abspath(run_artifacts["result_path"]):
        _json_dump(run_artifacts["result_path"], result_payload)
    manifest["status"] = "completed"
    manifest["finished_at"] = datetime.now().isoformat(timespec="seconds")
    manifest["elapsed_seconds"] = int(time.time() - t_total)
    manifest["summary"] = result_payload.get("summary")
    manifest["analysis"] = result_payload.get("analysis")
    _write_manifest(run_artifacts["manifest_path"], manifest)

    if args.retain_runs is not None or args.retain_extracted is not None:
        apply_retention_limits(args.retain_runs, args.retain_extracted)

    print(f"\n[DONE] Total execution time: {_fmt_time(time.time() - t_total)}", flush=True)
    print("─" * _W, flush=True)


if __name__ == "__main__":
    main()
