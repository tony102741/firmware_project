"""
Firmware analysis pipeline.

Supports four input formats, detected automatically:
  - OTA zip (.zip)       → unzip → payload-dumper-go → rootfs
  - payload.bin          → payload-dumper-go → rootfs
  - raw partition (.img) → 7z unpack → rootfs
  - IoT firmware (.bin)  → binwalk extract → squashfs-root → rootfs

Run from the project root:
  python3 src/pipeline.py [--input FILE] [--type auto|zip|payload|img|iot] [--skip]
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
import lzma
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

FIRMWARE_DIR  = os.path.join(PROJECT_ROOT, "data/input")
WORK_DIR      = os.path.join(PROJECT_ROOT, "build")
ROOTFS_DIR    = os.path.join(PROJECT_ROOT, "data/rootfs")
EXTRACTED_DIR = os.path.join(PROJECT_ROOT, "data/extracted")

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
_FS_MAGIC_PATTERNS = (
    ("squashfs", b"hsqs"),
    ("squashfs", b"sqsh"),
    ("squashfs", b"qshs"),
    ("squashfs", b"shsq"),
    ("cramfs",   b"\x45\x3d\xcd\x28"),
    ("ubifs",    b"UBI#"),
)
_NESTED_BLOB_EXTS = (".xz", ".lzma", ".bin", ".img", ".raw", ".fs", ".blob")
_UBIREADER_FALLBACK_DIRS = (
    os.path.expanduser("~/.venvs/ubireader/bin"),
    os.path.expanduser("~/.local/bin"),
)

_PARTITION_INDICATORS = {"bin", "lib", "lib64", "etc", "app", "framework", "priv-app"}
_SEARCH_SKIP = {"rootfs", ".git", "node_modules", "__pycache__"}
_ARCHIVE_FIRMWARE_EXTS = (".bin", ".img", ".web", ".trx", ".w", ".pkgtb")

INPUT_ZIP     = "zip"
INPUT_RAR     = "rar"
INPUT_PAYLOAD = "payload"
INPUT_IMG     = "img"
INPUT_IOT     = "iot"
INPUT_UNKNOWN = "unknown"

_W = 65  # output width


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
    quiet — suppress the tool's own stdout.
            stderr is always passed through so real errors remain visible.

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
        _ok("payload-dumper-go")
        return

    _warn(f"payload-dumper-go not found: {DUMPER}")
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

    result = subprocess.run(
        f'cd "{DUMPER_DIR}" && go build -o payload-dumper-go .',
        shell=True,
    )
    if result.returncode != 0:
        print("[FATAL] go build failed for payload-dumper-go", flush=True)
        print("[FATAL] If running in Docker: the pre-built binary should have been",
              flush=True)
        print("[FATAL] copied by docker-entrypoint.sh from /opt/tools/payload-dumper-go.",
              flush=True)
        print("[FATAL] If running outside Docker: install the Go toolchain (golang.org).",
              flush=True)
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

    Returns one of: INPUT_ZIP, INPUT_RAR, INPUT_PAYLOAD, INPUT_IMG, INPUT_UNKNOWN
    """
    ext  = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    path_lower = path.lower()

    if ext == ".zip":
        return INPUT_ZIP
    if ext == ".rar":
        return INPUT_RAR
    if ext in (".w", ".trx", ".web"):
        return INPUT_IOT
    if "pureubi" in name or "pureubi" in path_lower:
        return INPUT_IOT
    if name == "payload.bin":
        return INPUT_PAYLOAD
    if ext == ".img":
        return INPUT_IMG
    if ext == ".bin":
        return INPUT_IOT

    magic4 = _read_magic(path, 4)

    if magic4 == _MAGIC_ZIP:
        return INPUT_ZIP
    if magic4 == _MAGIC_RAR4 or _read_magic(path, 7) == _MAGIC_RAR5:
        return INPUT_RAR
    if magic4 == _MAGIC_PAYLOAD:
        return INPUT_PAYLOAD
    if magic4 == _MAGIC_SPARSE:
        return INPUT_IMG
    if magic4 == _MAGIC_EROFS:
        return INPUT_IMG
    if _read_magic(path, 2, offset=0x438) == _MAGIC_EXT4:
        return INPUT_IMG

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


def _extract_selected_archive_members(archive_path, temp_dir, members):
    for name in members:
        result = run(
            f'7z e "{archive_path}" "{name}" -o"{temp_dir}" -y',
            label=f"extract member  {os.path.basename(name)}",
            quiet=True,
        )
        if result.returncode == 0:
            return True
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


def _resolve_zip_firmware(zip_path):
    temp_parent = WORK_DIR if os.path.isdir(WORK_DIR) else PROJECT_ROOT
    temp_dir = tempfile.mkdtemp(prefix="fw_input_", dir=temp_parent)
    run_critical(
        f'unzip -o "{zip_path}" -d "{temp_dir}"',
        fatal_msg=f"Failed to inspect ZIP input: {zip_path}",
        label=f"inspect zip  {os.path.basename(zip_path)}",
        quiet=True,
    )

    resolved = _find_largest_firmware_file(temp_dir)
    if not resolved:
        print("[FATAL] No payload.bin, .bin, .img, .web, .trx, .w, or .pkgtb found inside ZIP.", flush=True)
        print(f"        ZIP: {zip_path}", flush=True)
        sys.exit(1)

    resolved_type = detect_input_type(resolved)
    _info(f"resolved firmware: {os.path.relpath(resolved, PROJECT_ROOT)}")
    return resolved, resolved_type


def _resolve_rar_firmware(rar_path):
    temp_parent = WORK_DIR if os.path.isdir(WORK_DIR) else PROJECT_ROOT
    temp_dir = tempfile.mkdtemp(prefix="fw_input_", dir=temp_parent)
    result = run(
        f'7z x "{rar_path}" -o"{temp_dir}" -y',
        label=f"inspect rar  {os.path.basename(rar_path)}",
        quiet=True,
    )

    if result.returncode != 0:
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
        if not selected or not _extract_selected_archive_members(rar_path, temp_dir, selected):
            print(f"[FATAL] Failed to inspect RAR input: {rar_path}", flush=True)
            sys.exit(1)

    resolved = _find_largest_firmware_file(temp_dir)
    if not resolved:
        print("[FATAL] No payload.bin, .bin, .img, .web, .trx, .w, or .pkgtb found inside RAR.", flush=True)
        print(f"        RAR: {rar_path}", flush=True)
        sys.exit(1)

    resolved_type = detect_input_type(resolved)
    _info(f"resolved firmware: {os.path.relpath(resolved, PROJECT_ROOT)}")
    return resolved, resolved_type


# ── Clean ─────────────────────────────────────────────────────────────────────

def clean(skip):
    if skip:
        _info("reuse mode — skipping extraction")
        return

    _info("cleaning build/ and data/rootfs/ ...")
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    shutil.rmtree(ROOTFS_DIR, ignore_errors=True)

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "system"), exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "vendor"), exist_ok=True)

    # data/extracted/ is never deleted — payload re-extraction is expensive
    os.makedirs(EXTRACTED_DIR, exist_ok=True)
    # ensure input dir exists for user guidance
    os.makedirs(FIRMWARE_DIR, exist_ok=True)


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

    Returns True on success, False if the file is missing.
    Aborts on tool failure — a partial extraction leaves rootfs undefined.
    """
    if payload_path is None:
        payload_path = os.path.join(WORK_DIR, "payload.bin")

    if not os.path.exists(payload_path):
        _warn(f"payload.bin not found: {payload_path}")
        return False

    run_critical_with_heartbeat(
        f'"{DUMPER}" "{payload_path}" --out "{EXTRACTED_DIR}"',
        fatal_msg="payload-dumper-go failed — extracted partition set incomplete.",
        label="payload-dumper-go  (extracting partitions, this may take several minutes)",
        timeout=1800,   # 30 min; large OTAs can take 5–10 min
        interval=10,    # heartbeat every 10s — avoids flooding for long extractions
    )
    return True


# ── Collect images from extracted directories ─────────────────────────────────

def collect_images():
    """
    Surface .img files and partition directories produced by payload-dumper-go.

    Moves any extracted_<timestamp>/ directories from the project root into
    data/extracted/, then copies .img files / partition directories into
    build/ so the rest of the pipeline can find them.
    """
    imgs_found = []
    dirs_found = []

    # Move stray extracted_* dirs from the project root into data/extracted/
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

    # Also surface from data/extracted/ directly (when --out was honoured)
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
        return
    if os.path.isdir(system_dir) and os.listdir(system_dir):
        return

    found = _search_for_partition("system", EXTRACTED_DIR)
    if found:
        return

    print("\n[FATAL] system partition not found after extraction.", flush=True)
    print(f"        Searched: {system_img}", flush=True)
    print(f"                  {system_dir}", flush=True)
    print(f"                  {EXTRACTED_DIR} (recursive)", flush=True)
    print("        Verify that payload-dumper-go produced output in data/extracted/",
          flush=True)
    sys.exit(1)


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
      1. build/<name>/
      2. data/extracted/**/<name>/
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
        _ok(f"{name:<10} → data/rootfs/{name} ({count} files)")
        return True

    img_tmp = os.path.join(WORK_DIR, f"_tmp_{name}")
    if extract_img(f"{name}.img", img_tmp):
        inner = _find_partition_root_in_extract(img_tmp, name)
        safe_copy(inner, dst)
        count = _count_files(dst)
        if count == 0:
            _warn(f"{name}: extraction produced 0 files — verify {img_tmp}")
            return False
        _ok(f"{name:<10} → data/rootfs/{name} ({count} files)")
        return True

    _warn(f"{name}: not found — data/rootfs/{name} will be empty")
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
            print(f"        data/rootfs/system/{name}", flush=True)
        print("        The firmware extraction may have failed or used an unsupported format.",
              flush=True)
        sys.exit(1)

    _ok("rootfs structure verified  (bin, lib, etc)")


def build_rootfs():
    system_ok = build_rootfs_for_partition("system")
    build_rootfs_for_partition("vendor")

    if not system_ok:
        print("\n[FATAL] Failed to populate data/rootfs/system.", flush=True)
        print(f"        Expected: {os.path.join(ROOTFS_DIR, 'system')}", flush=True)
        print("        Verify extraction output in data/extracted/ and build/",
              flush=True)
        sys.exit(1)

    _validate_rootfs_structure()


# ── Extraction handlers (one per input type) ──────────────────────────────────

def handle_zip_input(zip_path):
    unzip_firmware(zip_path)

    ok = extract_payload()
    if not ok:
        print("[FATAL] payload.bin not found inside OTA zip.", flush=True)
        print("        The archive may be incomplete or not a standard OTA package.",
              flush=True)
        sys.exit(1)

    collect_images()
    _validate_partition_images()


def handle_payload_input(payload_path):
    ok = extract_payload(payload_path=payload_path)
    if not ok:
        print(f"[FATAL] payload.bin not found: {payload_path}", flush=True)
        sys.exit(1)

    collect_images()
    _validate_partition_images()


def handle_img_input(img_path):
    dst = os.path.join(WORK_DIR, os.path.basename(img_path))
    if not os.path.exists(dst):
        shutil.copy2(img_path, dst)


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


def _describe_rootfs_candidate(path):
    file_count = _count_files_quiet(path)
    size_bytes = _dir_size_quiet(path)

    core_dirs = [
        d for d in ("bin", "etc", "usr", "lib")
        if os.path.isdir(os.path.join(path, d))
    ]
    web_hits = [
        rel for rel in (
            "www",
            "web",
            "htdocs",
            "var/www",
            "var/web",
            "cgi-bin",
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

    score = 0
    why = []

    if file_count > 1500:
        score += 3
        why.append("files>1500")
    if file_count < 500:
        score -= 5
        why.append("files<500")

    for d in core_dirs:
        score += 2
    if core_dirs:
        why.append("core:" + ",".join(core_dirs))

    if web_hits:
        score += 4
        why.append("web")
    if init_hits:
        score += 2
        why.append("init")
    if size_bytes > 5 * 1024 * 1024:
        score += 2
        why.append("size>5M")

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


def _find_rootfs_candidates(base_dir):
    candidates = []
    seen = set()
    for dirpath, dirnames, _ in os.walk(base_dir):
        for d in sorted(dirnames):
            dl = d.lower()
            if "squashfs" not in dl and "cramfs" not in dl and "ubifs" not in dl and "ubi" not in dl and dl not in ("rootfs", "root"):
                continue
            candidate = os.path.join(dirpath, d)
            real_candidate = os.path.realpath(candidate)
            if real_candidate in seen:
                continue
            if not any(os.path.isdir(os.path.join(candidate, ind))
                       for ind in ("bin", "lib", "etc", "usr", "sbin")):
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


def _find_fs_magic_offsets(path, max_hits=8):
    try:
        data = open(path, "rb").read()
    except Exception:
        return []

    hits = []
    seen = set()
    for fs_name, magic in _FS_MAGIC_PATTERNS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            key = (fs_name, idx)
            if key not in seen:
                hits.append((fs_name, idx))
                seen.add(key)
            start = idx + 1
            if len(hits) >= max_hits:
                return sorted(hits, key=lambda x: x[1])
    return sorted(hits, key=lambda x: x[1])


def _looks_like_nested_blob(path):
    lower = path.lower()
    if lower.endswith(_NESTED_BLOB_EXTS):
        return True
    for _, magic in _FS_MAGIC_PATTERNS:
        if _read_magic(path, len(magic)) == magic:
            return True
    return False


def _has_ubi_magic(path):
    return _read_magic(path, 4) == b"UBI#"


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
    print("[FATAL] UBI/UBIFS firmware detected but ubireader tools are missing.", flush=True)
    print("        Install: pip3 install ubireader  or  your distro's ubireader package", flush=True)
    print(f"        Blob: {blob_path}", flush=True)
    sys.exit(1)


def _extract_ubi_blob(blob_path, out_dir):
    tools = _resolve_ubireader_tools()
    if tools is None:
        _fail_missing_ubireader(blob_path)
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
    try:
        with open(blob_path, "rb") as src:
            data = src.read()
        decoded = lzma.decompress(data)
        with open(out_path, "wb") as dst:
            dst.write(decoded)
        return os.path.getsize(out_path) > 0
    except Exception:
        return False


def _unpack_nested_blob(blob_path, out_dir):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    extracted = False
    run(
        f'binwalk -MeB "{blob_path}" -C "{out_dir}"',
        label=f"binwalk nested  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if any(os.scandir(out_dir)):
        extracted = True

    raw_dir = os.path.join(out_dir, "_raw")
    os.makedirs(raw_dir, exist_ok=True)
    proc = run(
        f'7z x "{blob_path}" -o"{raw_dir}" -y',
        label=f"7z nested  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if proc.returncode == 0 and any(os.scandir(raw_dir)):
        extracted = True

    decoded = os.path.join(out_dir, "_decoded.bin")
    if _decompress_lzma_blob(blob_path, decoded):
        extracted = True

    return extracted


def _expand_nested_iot_blobs(base_dir, max_depth=3):
    queue = [(base_dir, 0)]
    seen = set()

    while queue:
        current_dir, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for dirpath, dirnames, filenames in os.walk(current_dir):
            dirnames[:] = [d for d in dirnames if not d.startswith("_nested_")]
            for filename in filenames:
                blob_path = os.path.join(dirpath, filename)
                if blob_path in seen or not _looks_like_nested_blob(blob_path):
                    continue
                seen.add(blob_path)
                nested_dir = os.path.join(
                    dirpath, f"_nested_{os.path.basename(blob_path)}"
                )
                if _unpack_nested_blob(blob_path, nested_dir):
                    queue.append((nested_dir, depth + 1))


def _try_extract_iot_blob(blob_path, out_dir, label):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    if _has_ubi_magic(blob_path):
        return _extract_ubi_blob(blob_path, os.path.join(out_dir, "_ubi_extract"))

    run(
        f'binwalk -MeB "{blob_path}" -C "{out_dir}"',
        label=label,
        quiet=True,
    )
    _expand_nested_iot_blobs(out_dir)

    ubi_blobs = _find_ubi_blobs(out_dir)
    if ubi_blobs:
        sqfs = _extract_ubi_blob(ubi_blobs[0], os.path.join(out_dir, "_ubi_extract"))
        if sqfs:
            return sqfs

    sqfs = find_squashfs_root(out_dir)
    if sqfs:
        return sqfs

    inner = os.path.join(out_dir, "_raw_fs")
    os.makedirs(inner, exist_ok=True)
    proc = run(
        f'7z x "{blob_path}" -o"{inner}" -y',
        label=f"7z raw scan  {os.path.basename(blob_path)}",
        quiet=True,
    )
    if proc.returncode == 0 or os.listdir(inner):
        _expand_nested_iot_blobs(inner)
        ubi_blobs = _find_ubi_blobs(inner)
        if ubi_blobs:
            sqfs = _extract_ubi_blob(ubi_blobs[0], os.path.join(inner, "_ubi_extract"))
            if sqfs:
                return sqfs
        return find_squashfs_root(inner)
    return None


def _validate_iot_rootfs(dst, min_files=2000):
    count = _count_files(dst)
    if count < min_files:
        print("[FATAL] Extracted IoT rootfs is too small to trust.", flush=True)
        print(f"        Found: {count} files  (expected > {min_files} for router firmware)", flush=True)
        print(f"        Path:  {dst}", flush=True)
        sys.exit(1)
    return count


def _check_iot_rootfs(candidate, min_files=1500):
    if isinstance(candidate, dict):
        info = candidate
        path = info["path"]
        count = info.get("file_count", 0)
        size_bytes = info.get("size_bytes", 0)
        core_dirs = info.get("core_dirs", [])
    else:
        path = candidate
        info = _describe_rootfs_candidate(path)
        count = info["file_count"]
        size_bytes = info["size_bytes"]
        core_dirs = info["core_dirs"]

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

    if size_bytes > 10 * 1024 * 1024 and len(core_dirs) >= 3:
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
    Aborts the pipeline if binwalk fails or squashfs-root is not found.
    """
    if shutil.which("binwalk") is None:
        print("[FATAL] binwalk not found in PATH.", flush=True)
        print("        Install: pip3 install binwalk  or  apt install binwalk", flush=True)
        sys.exit(1)

    out_dir = os.path.join(WORK_DIR, "_iot_extract")
    os.makedirs(out_dir, exist_ok=True)

    _try_extract_iot_blob(
        bin_path, out_dir, f"binwalk  {os.path.basename(bin_path)}"
    )

    candidates = _collect_ranked_rootfs_candidates(out_dir)

    if not candidates:
        _warn("binwalk did not locate a filesystem root; scanning raw offsets")
        for fs_name, offset in _find_fs_magic_offsets(bin_path):
            carved = os.path.join(WORK_DIR, f"_carve_{fs_name}_{offset:x}.bin")
            run_critical(
                f'dd if="{bin_path}" of="{carved}" bs=1 skip={offset} status=none',
                fatal_msg=f"dd carve failed at offset {offset} for {fs_name}",
                label=f"dd carve  {fs_name} @ 0x{offset:x}",
                quiet=True,
            )
            carve_out = os.path.join(WORK_DIR, f"_extract_{fs_name}_{offset:x}")
            _try_extract_iot_blob(
                carved, carve_out, f"binwalk raw  {fs_name} @ 0x{offset:x}"
            )
            candidates = _collect_ranked_rootfs_candidates(out_dir, carve_out)

    if not candidates:
        print("[FATAL] binwalk ran but no squashfs/cramfs/ubifs root was found.",
              flush=True)
        print(f"        Searched: {out_dir}", flush=True)
        print("        Checked extracted output and raw filesystem magic offsets.", flush=True)
        sys.exit(1)

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

    _print_rootfs_candidate_summary(candidates, selected=selected, rejected=rejected)

    if selected is None:
        best = candidates[0]
        print("[FATAL] Extracted IoT rootfs is too small to trust.", flush=True)
        print(f"        Best candidate: {best['path']}", flush=True)
        print(f"        Found: {best['file_count']} files  (expected > 2000 for router firmware)",
              flush=True)
        sys.exit(1)

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
      - 0 files in data/input/ → [FATAL] exit
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
        try:
            candidates = sorted(
                f for f in os.listdir(FIRMWARE_DIR)
                if os.path.isfile(os.path.join(FIRMWARE_DIR, f))
            )
        except FileNotFoundError:
            candidates = []

        if not candidates:
            print("\n[FATAL] No input file found in data/input/", flush=True)
            print(f"        Expected: {FIRMWARE_DIR}", flush=True)
            print("        Supported formats: .zip (OTA), payload.bin, .img", flush=True)
            sys.exit(1)

        if len(candidates) > 1:
            _warn("Multiple input files found:")
            for i, f in enumerate(candidates, 1):
                print(f"        {i}. {f}", flush=True)
            print(flush=True)
            print("    Use --input <filename> to select one.", flush=True)
            sys.exit(1)

        path = os.path.join(FIRMWARE_DIR, candidates[0])

    if type_arg and type_arg != "auto":
        detected = type_arg
        _info(f"{os.path.basename(path)}  (type: {detected}, forced)")
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

    run_critical(
        cmd,
        fatal_msg="Analysis step failed. Check the error above.",
        env=env,
        timeout=3600,    # 1 hr; large rootfs can take a long time to scan
    )


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
    for name in sorted(os.listdir(FIRMWARE_DIR)):
        path = os.path.join(FIRMWARE_DIR, name)
        if os.path.isfile(path) and _is_iot_batch_candidate(path):
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
        help="path to input file (OTA zip / payload.bin / .img); "
             "default: the single file found in data/input/")
    parser.add_argument(
        "--type", metavar="TYPE",
        choices=["auto", "zip", "payload", "img", "iot"],
        default="auto",
        help="force input type (auto|zip|payload|img|iot)  [default: auto]")
    parser.add_argument(
        "--output", metavar="FILE",
        help="save analysis results as JSON  (e.g. results.json)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="validate tools and input file without running the pipeline")
    parser.add_argument(
        "--batch-iot", action="store_true",
        help="run compact triage across all current IoT firmware inputs under data/input/")
    parser.add_argument(
        "--ingest-dir", metavar="DIR",
        help="scan a folder and copy only IoT-like firmware inputs into data/input/")
    args = parser.parse_args()

    if not args.batch_iot:
        # ── Log file setup (before any output so everything is captured) ──────
        log_dir = os.path.join(PROJECT_ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_name = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        log_path = os.path.join(log_dir, log_name)
        _log_fh  = open(log_path, "a", encoding="utf-8", errors="replace", buffering=1)
        sys.stdout = _Tee(sys.stdout, _log_fh)
        sys.stderr = _Tee(sys.stderr, _log_fh)
        # Inherited by main.py subprocess so it can append its output to the same file
        os.environ["FIRMWARE_LOG_FILE"] = log_path

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
    print(f"  Log: logs/{log_name}", flush=True)
    print("─" * _W, flush=True)

    t_total = time.time()

    # ── [0] Pre-flight ────────────────────────────────────────────────────────
    _stage(0, total, "Pre-flight checks")
    _check_required_tools()

    # ── Dry run mode (exits after validation) ─────────────────────────────────
    if args.dry_run:
        print(flush=True)
        _info("DRY RUN — validating prerequisites only, nothing will execute")
        ensure_dumper()
        path, input_type = resolve_input(args.input, args.type)
        if path is None:
            sys.exit(1)
        print(flush=True)
        _info(f"Input file:   {os.path.basename(path)}")
        _info(f"Input type:   {input_type}")
        _info(f"Rootfs:       {ROOTFS_DIR}")
        _info(f"Logs:         logs/")
        if args.output:
            _info(f"JSON output:  {args.output}")
        print(flush=True)
        _info("Pipeline would execute:")
        _info("  [2/4] Extraction    → unzip / payload-dumper-go / 7z")
        _info("  [3/4] Rootfs        → assemble data/rootfs/system, vendor")
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

    if not args.skip:
        # ── [2] Extraction ────────────────────────────────────────────────────
        _stage(2, total, "Extraction")
        _info("Running...")
        t_ext = time.time()

        path, input_type = resolve_input(args.input, args.type)
        if path is None:
            print("\n[!] Input file not found.", flush=True)
            sys.exit(1)

        if input_type != INPUT_IOT:
            ensure_dumper()

        if input_type == INPUT_ZIP:
            handle_zip_input(path)
        elif input_type == INPUT_PAYLOAD:
            handle_payload_input(path)
        elif input_type == INPUT_IMG:
            handle_img_input(path)
        elif input_type == INPUT_IOT:
            analysis_system_path = handle_iot_input(path)
        else:
            print(f"\n[!] Cannot determine file type for: {os.path.basename(path)}",
                  flush=True)
            print("    Use --type zip|payload|img|iot to specify it explicitly",
                  flush=True)
            sys.exit(1)

        _ok(f"Extraction complete  ({_fmt_time(time.time() - t_ext)})")

        # ── [3] Rootfs assembly (skipped for IoT — done inside extraction) ────
        if input_type != INPUT_IOT:
            _stage(3, total, "Rootfs assembly")
            _info("Running...")
            t_rootfs = time.time()
            build_rootfs()
            _ok(f"Rootfs assembly complete  ({_fmt_time(time.time() - t_rootfs)})")

    # ── [N] Vulnerability analysis ────────────────────────────────────────────
    _stage(total, total, "Vulnerability analysis")
    _info("Running...")
    if args.skip:
        analysis_system_path = None
        analysis_vendor_path = None
    elif input_type != INPUT_IOT:
        analysis_system_path = os.path.join(ROOTFS_DIR, "system")
        analysis_vendor_path = os.path.join(ROOTFS_DIR, "vendor")

    run_analysis(
        output_path=args.output,
        system_path=analysis_system_path,
        vendor_path=analysis_vendor_path,
    )

    print(f"\n[DONE] Total execution time: {_fmt_time(time.time() - t_total)}", flush=True)
    print("─" * _W, flush=True)


if __name__ == "__main__":
    main()
