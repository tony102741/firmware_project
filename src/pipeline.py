"""
Firmware analysis pipeline.

Supports three input formats, detected automatically:
  - OTA zip (.zip)       → unzip → payload-dumper-go → rootfs
  - payload.bin          → payload-dumper-go → rootfs
  - raw partition (.img) → 7z unpack → rootfs

Run from the project root:
  python3 src/pipeline.py [--input FILE] [--type auto|zip|payload|img] [--skip]
"""

import os
import sys
import subprocess
import shutil
import argparse

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

FIRMWARE_DIR  = os.path.join(PROJECT_ROOT, "data/raw")
WORK_DIR      = os.path.join(PROJECT_ROOT, "build")
ROOTFS_DIR    = os.path.join(PROJECT_ROOT, "data/rootfs")
EXTRACTED_DIR = os.path.join(PROJECT_ROOT, "data/extracted")

DUMPER      = os.path.join(PROJECT_ROOT, "tools/payload-dumper-go/payload-dumper-go")
DUMPER_DIR  = os.path.dirname(DUMPER)
DUMPER_REPO = "https://github.com/ssut/payload-dumper-go"

# ── Constants ─────────────────────────────────────────────────────────────────

# File magic signatures for input type detection
_MAGIC_ZIP     = b"PK\x03\x04"
_MAGIC_PAYLOAD = b"CrAU"
_MAGIC_SPARSE  = b"\x3a\xff\x26\xed"
_MAGIC_EXT4    = b"\x53\xef"       # at offset 0x438 in ext4 superblock
_MAGIC_EROFS   = b"\xe2\xe1\xf5\xe0"

# Directories that look like Android partition roots
_PARTITION_INDICATORS = {"bin", "lib", "lib64", "etc", "app", "framework", "priv-app"}

# Directories to skip entirely during recursive search (too large / irrelevant)
_SEARCH_SKIP = {"rootfs", ".git", "node_modules", "__pycache__"}

# Input type constants
INPUT_ZIP     = "zip"
INPUT_PAYLOAD = "payload"
INPUT_IMG     = "img"
INPUT_UNKNOWN = "unknown"


# ── Subprocess helpers ────────────────────────────────────────────────────────

def run(cmd, env=None, timeout=None, label=None, quiet=False):
    """
    Run a shell command.

    label  — human-readable description printed before the command runs.
             If omitted and quiet=False, the raw command is printed.
    quiet  — suppress the tool's own stdout (file listings, progress bars).
             stderr is always passed through so real errors remain visible.
    """
    if label:
        print(f"    {label}")
    elif not quiet:
        print(f"    {cmd}")
    try:
        return subprocess.run(
            cmd, shell=True, env=env, timeout=timeout,
            stdout=subprocess.DEVNULL if quiet else None,
        )
    except subprocess.TimeoutExpired:
        print(f"\n[FATAL] Command timed out after {timeout}s")
        print(f"[FATAL] Command was: {cmd}")
        sys.exit(1)


def run_critical(cmd, fatal_msg, env=None, timeout=None, label=None, quiet=False):
    """
    Run a shell command. Abort the pipeline with `fatal_msg` if it fails.
    Use this for steps where partial success is worse than a clean stop.
    """
    result = run(cmd, env=env, timeout=timeout, label=label, quiet=quiet)
    if result.returncode != 0:
        print(f"\n[FATAL] {fatal_msg}")
        print(f"[FATAL] Command exited {result.returncode}: {cmd}")
        sys.exit(result.returncode)
    return result


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
        print("[FATAL] Required external tools not found in PATH:")
        for tool, hint in missing:
            print(f"        {tool}  →  install: {hint}")
        sys.exit(1)
    print("    tools OK  (strings, unzip, 7z)")


# ── Tool validation: payload-dumper-go ───────────────────────────────────────

def ensure_dumper():
    """
    Validate that the payload-dumper-go binary is present and executable.

    If it is missing, attempt to recover automatically:
      1. git clone the repository into tools/payload-dumper-go/
      2. go build -o payload-dumper-go .

    Aborts the pipeline (sys.exit) if the binary cannot be made available,
    because every payload extraction step depends on it.
    """
    if os.path.isfile(DUMPER) and os.access(DUMPER, os.X_OK):
        print("    payload-dumper-go OK")
        return

    print(f"[!] payload-dumper-go not found: {DUMPER}")
    print("[*] Attempting automatic build from source ...")

    os.makedirs(os.path.join(PROJECT_ROOT, "tools"), exist_ok=True)

    if not os.path.isdir(DUMPER_DIR):
        result = subprocess.run(
            f'git clone "{DUMPER_REPO}" "{DUMPER_DIR}"',
            shell=True,
        )
        if result.returncode != 0:
            print(f"[FATAL] git clone failed (repo: {DUMPER_REPO})")
            print("[FATAL] Check network access or manually place the binary at:")
            print(f"        {DUMPER}")
            sys.exit(1)
    else:
        print(f"[*] Source directory already exists: {DUMPER_DIR}")

    result = subprocess.run(
        f'cd "{DUMPER_DIR}" && go build -o payload-dumper-go .',
        shell=True,
    )
    if result.returncode != 0:
        print("[FATAL] go build failed for payload-dumper-go")
        print("[FATAL] If running in Docker: the pre-built binary should have been")
        print("[FATAL] copied by docker-entrypoint.sh from /opt/tools/payload-dumper-go.")
        print("[FATAL] If running outside Docker: install the Go toolchain (golang.org).")
        sys.exit(1)

    if not (os.path.isfile(DUMPER) and os.access(DUMPER, os.X_OK)):
        print(f"[FATAL] Binary still not executable after build: {DUMPER}")
        sys.exit(1)

    print(f"[*] payload-dumper-go built successfully: {DUMPER}")


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

    Extension rules (fast path):
      - .zip                        → INPUT_ZIP
      - basename == "payload.bin"   → INPUT_PAYLOAD
      - .img                        → INPUT_IMG

    Magic-byte fallback (handles renamed / extension-less files):
      - PK\\x03\\x04                  (ZIP local header)      → INPUT_ZIP
      - CrAU                         (Chrome OS payload)      → INPUT_PAYLOAD
      - \\x3a\\xff\\x26\\xed          (Android sparse img)    → INPUT_IMG
      - \\xe2\\xe1\\xf5\\xe0          (erofs superblock)      → INPUT_IMG
      - \\x53\\xef at offset 0x438    (ext4 superblock)       → INPUT_IMG

    Returns one of: INPUT_ZIP, INPUT_PAYLOAD, INPUT_IMG, INPUT_UNKNOWN
    """
    ext  = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()

    # Extension-based detection (fast path)
    if ext == ".zip":
        return INPUT_ZIP
    if name == "payload.bin":
        return INPUT_PAYLOAD
    if ext == ".img":
        return INPUT_IMG

    # Magic-byte fallback
    magic4 = _read_magic(path, 4)

    if magic4 == _MAGIC_ZIP:
        return INPUT_ZIP
    if magic4 == _MAGIC_PAYLOAD:
        return INPUT_PAYLOAD
    if magic4 == _MAGIC_SPARSE:
        return INPUT_IMG
    if magic4 == _MAGIC_EROFS:
        return INPUT_IMG

    # ext4 superblock magic lives at a fixed offset
    if _read_magic(path, 2, offset=0x438) == _MAGIC_EXT4:
        return INPUT_IMG

    return INPUT_UNKNOWN


# ── Clean ─────────────────────────────────────────────────────────────────────

def clean(skip):
    if skip:
        return

    print("    cleaning build/ and data/rootfs/ ...")
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    shutil.rmtree(ROOTFS_DIR, ignore_errors=True)

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "system"), exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "vendor"), exist_ok=True)

    # extracted/ is never deleted — payload re-extraction is expensive
    os.makedirs(EXTRACTED_DIR, exist_ok=True)


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

    Args:
        payload_path: explicit path to payload.bin; if None, looks for
                      payload.bin inside WORK_DIR (post-unzip OTA workflow).

    Returns:
        True on success, False if the file is missing.

    On tool failure (non-zero exit), aborts the pipeline immediately —
    a partial extraction leaves the rootfs in an undefined state and there
    is no safe way to continue.
    """
    if payload_path is None:
        payload_path = os.path.join(WORK_DIR, "payload.bin")

    if not os.path.exists(payload_path):
        print(f"[!] payload.bin not found: {payload_path}")
        return False

    run_critical(
        f'"{DUMPER}" "{payload_path}" --out "{EXTRACTED_DIR}"',
        fatal_msg="payload-dumper-go failed. "
                  "The extracted partition set would be incomplete; cannot continue.",
        label="payload-dumper-go  (extracting partitions — this may take a few minutes)",
        quiet=True,
        timeout=1800,   # 30 min; large OTAs can take 5–10 min
    )
    return True


# ── Collect images from extracted_* directories ───────────────────────────────

def collect_images():
    """
    Surface .img files and partition directories produced by payload-dumper-go.

    payload-dumper-go may create extracted_<timestamp>/ directories in the
    project root when --out is not honoured by older builds.  This function
    moves those into EXTRACTED_DIR and then copies .img files / partition
    directories into WORK_DIR so the rest of the pipeline can find them.
    """
    imgs_found = []
    dirs_found = []

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

    # Also surface any .img / partition dirs that payload-dumper-go placed
    # directly inside EXTRACTED_DIR (when --out was honoured).
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
        print(f"    collected {';  '.join(parts)}")


def _validate_partition_images():
    """
    Gate check after collect_images(): confirm that at least system partition
    material (system.img or system/ directory) is reachable somewhere.
    Aborts the pipeline if nothing can be found — continuing past this point
    would produce an empty or partial rootfs and silent false-negative results.
    """
    system_img = os.path.join(WORK_DIR, "system.img")
    system_dir = os.path.join(WORK_DIR, "system")

    if os.path.exists(system_img):
        return
    if os.path.isdir(system_dir) and os.listdir(system_dir):
        return

    # One last chance: search EXTRACTED_DIR
    found = _search_for_partition("system", EXTRACTED_DIR)
    if found:
        return

    print("\n[FATAL] system partition not found after extraction.")
    print(f"        Searched: {system_img}")
    print(f"                  {system_dir}")
    print(f"                  {EXTRACTED_DIR} (recursive)")
    print("        Verify that payload-dumper-go produced output in data/extracted/")
    sys.exit(1)


# ── Partition directory search ────────────────────────────────────────────────

def _looks_like_partition_root(path):
    """
    True if the directory is a real Android partition root.

    Requirements (both must hold):
    1. At least one indicator subdirectory (bin/, lib/, etc.) exists as a
       real directory — not a broken symlink, not an empty placeholder.
    2. That subdirectory contains at least one regular file, confirming the
       partition was actually populated during extraction.

    This rejects:
    - Directories where indicator names are broken symlinks (e.g. Android
      root fs has bin -> /system/bin which becomes a broken absolute symlink
      on the host after 7z extraction).
    - Empty scaffolding directories created by a previous failed extraction.
    """
    try:
        entries = os.listdir(path)
    except Exception:
        return False

    for name in entries:
        if name not in _PARTITION_INDICATORS:
            continue
        full = os.path.join(path, name)
        if not os.path.isdir(full):   # follows symlinks; broken symlinks → False
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
    an Android partition root (contains bin/, lib/, etc.).

    Returns the first match, or None.
    """
    name_lower = name.lower()

    for root, dirs, _ in os.walk(search_root):
        # Prune irrelevant subtrees
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
    Locate the extracted partition directory for `name` (e.g. "system", "vendor").

    Search order:
      1. build/<name>/              — standard pipeline output
      2. data/extracted/**/<name>/  — payload-dumper-go output
      3. PROJECT_ROOT/**/<name>/    — catch-all fallback

    Returns the absolute path if found, else None.
    """
    # 1. build/
    candidate = os.path.join(WORK_DIR, name)
    if os.path.isdir(candidate) and _looks_like_partition_root(candidate):
        return candidate

    # 2. data/extracted/
    result = _search_for_partition(name, EXTRACTED_DIR)
    if result:
        return result

    # 3. Entire project tree
    result = _search_for_partition(name, PROJECT_ROOT)
    if result:
        return result

    return None


# ── Build rootfs ──────────────────────────────────────────────────────────────

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
        print(f"[!] safe_copy: {skipped} file(s) could not be copied (permissions / broken symlinks)")


def extract_img(img_name, out_dir):
    img_path = os.path.join(WORK_DIR, img_name)
    if not os.path.exists(img_path):
        print(f"[!] {img_name} not found, skip")
        return False
    os.makedirs(out_dir, exist_ok=True)
    result = run(
        f'7z x "{img_path}" -o"{out_dir}" -y',
        label=f"7z extract  {img_name}",
        quiet=True,
    )
    if result.returncode != 0:
        print(f"    [!] 7z extraction failed for {img_name} (exit {result.returncode})")
        return False
    return True


def _find_partition_root_in_extract(base, partition_name):
    """
    After 7z extraction the layout may be:
      base/            (files directly)
      base/system/     (nested)
      base/0/system/   (erofs/ext4 inode numbering)
    Walk up to 3 levels to find the real partition root.
    """
    for _ in range(3):
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

    # ── Try dynamic search first ──────────────────────────────────────────────
    found = find_partition_dir(name)
    if found:
        print(f"    {name:<10}  ← directory")
        safe_copy(found, dst)
        return True

    # ── Fall back to .img extraction ──────────────────────────────────────────
    img_tmp = os.path.join(WORK_DIR, f"_tmp_{name}")
    if extract_img(f"{name}.img", img_tmp):
        inner = _find_partition_root_in_extract(img_tmp, name)
        print(f"    {name:<10}  ← image extract")
        safe_copy(inner, dst)
        return True

    print(f"    {name:<10}  [!] not found — rootfs/{name} will be empty")
    return False


def build_rootfs():
    system_ok = build_rootfs_for_partition("system")
    build_rootfs_for_partition("vendor")

    # system is mandatory — without it the analysis produces zero results.
    if not system_ok:
        print("\n[FATAL] Failed to populate system partition in rootfs.")
        print(f"        Expected populated directory: {os.path.join(ROOTFS_DIR, 'system')}")
        print("        Verify extraction output in data/extracted/ and build/")
        sys.exit(1)

    print(f"[*] rootfs ready: {ROOTFS_DIR}")


# ── Extraction handlers (one per input type) ──────────────────────────────────

def handle_zip_input(zip_path):
    """
    OTA zip workflow:
      1. Unzip archive into build/
      2. Extract payload.bin with payload-dumper-go (fail-fast on error)
      3. Collect and surface images / partition directories
      4. Validate that system partition material is present
    """
    unzip_firmware(zip_path)

    ok = extract_payload()     # looks for build/payload.bin
    if not ok:
        print("[FATAL] payload.bin not found inside OTA zip.")
        print("        The archive may be incomplete or not a standard OTA package.")
        sys.exit(1)

    collect_images()
    _validate_partition_images()


def handle_payload_input(payload_path):
    """
    Standalone payload.bin workflow:
      1. Run payload-dumper-go directly against the provided file
      2. Collect and surface images / partition directories
      3. Validate that system partition material is present
    """
    ok = extract_payload(payload_path=payload_path)
    if not ok:
        # extract_payload() only returns False when the file is missing;
        # tool errors are handled inside via run_critical().
        print(f"[FATAL] payload.bin not found: {payload_path}")
        sys.exit(1)

    collect_images()
    _validate_partition_images()


def handle_img_input(img_path):
    """
    Standalone .img file workflow:
      1. Copy the image into build/ so the existing extract_img() path picks it up
      2. No payload extraction needed — skip directly to build_rootfs()
    """
    dst = os.path.join(WORK_DIR, os.path.basename(img_path))
    if not os.path.exists(dst):
        shutil.copy2(img_path, dst)


# ── Input resolution ──────────────────────────────────────────────────────────

def resolve_input(input_arg, type_arg):
    """
    Determine the absolute path and type of the input file.

    Resolution order:
      1. --input <file>   use the path as given
      2. (default)        pick the first regular file found in FIRMWARE_DIR

    If --type is not 'auto', the type is taken at face value without probing.

    Returns (path, type_str) or (None, None) on error.
    """
    if input_arg:
        path = os.path.abspath(input_arg)
    else:
        try:
            candidates = sorted(
                f for f in os.listdir(FIRMWARE_DIR)
                if os.path.isfile(os.path.join(FIRMWARE_DIR, f))
            )
        except FileNotFoundError:
            candidates = []
        if not candidates:
            print(f"[!] No input file found in {FIRMWARE_DIR}")
            print("[!] Use --input <file> or place a file in data/raw/")
            return None, None
        path = os.path.join(FIRMWARE_DIR, candidates[0])

    if not os.path.exists(path):
        print(f"[!] Input file not found: {path}")
        return None, None

    if type_arg and type_arg != "auto":
        detected = type_arg
        print(f"    {os.path.basename(path)}  (type: {detected}, forced)")
    else:
        detected = detect_input_type(path)
        print(f"    {os.path.basename(path)}  (type: {detected})")

    return path, detected


# ── Analysis ──────────────────────────────────────────────────────────────────

def run_analysis():
    """
    Invoke main.py as a subprocess, with PYTHONPATH set so that
    'from parser.init_parser import ...' and similar relative imports
    resolve against src/core/ without requiring the caller to export
    PYTHONPATH manually.
    """
    core_dir = os.path.join(BASE_DIR, "core")
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{core_dir}:{existing_pythonpath}" if existing_pythonpath else core_dir
    )

    run_critical(
        f'python3 "{os.path.join(BASE_DIR, "main.py")}"',
        fatal_msg="Analysis step failed. Check the error above.",
        env=env,
        timeout=3600,   # 1 hr; large rootfs can take a long time to scan
        label="python3 src/main.py",
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def _stage(n, title):
    """Print a stage header using a consistent rule style."""
    label = f"  [{n}] {title}  "
    pad = max(0, 62 - len(label))
    print(f"\n{'─' * 3}{label}{'─' * pad}")


def main():
    parser = argparse.ArgumentParser(
        description="Firmware analysis pipeline — auto-detects input type")
    parser.add_argument(
        "--skip", action="store_true",
        help="reuse existing rootfs, skip all extraction stages")
    parser.add_argument(
        "--input", metavar="FILE",
        help="path to input file (OTA zip / payload.bin / .img); "
             "default: first file found in data/raw/")
    parser.add_argument(
        "--type", metavar="TYPE",
        choices=["auto", "zip", "payload", "img"],
        default="auto",
        help="force input type instead of auto-detecting "
             "(auto|zip|payload|img)  [default: auto]")
    args = parser.parse_args()

    print("─" * 65)
    print("  Firmware Vulnerability Analysis Pipeline")
    print("─" * 65)

    # ── Pre-flight ────────────────────────────────────────────────────────────
    _stage(0, "Pre-flight checks")
    _check_required_tools()

    # ── Workspace ─────────────────────────────────────────────────────────────
    _stage(1, "Workspace" + (" (reuse mode — skipping extraction)" if args.skip else ""))
    clean(args.skip)

    if not args.skip:
        # ── Extraction ────────────────────────────────────────────────────────
        _stage(2, "Extraction")
        ensure_dumper()

        path, input_type = resolve_input(args.input, args.type)
        if path is None:
            print("\n[!] No input file found.")
            print("    Place a firmware file in data/raw/  — or use --input <path>")
            print("    Supported formats: .zip (OTA), payload.bin, .img")
            sys.exit(1)

        if input_type == INPUT_ZIP:
            handle_zip_input(path)
        elif input_type == INPUT_PAYLOAD:
            handle_payload_input(path)
        elif input_type == INPUT_IMG:
            handle_img_input(path)
        else:
            print(f"\n[!] Cannot determine file type for: {os.path.basename(path)}")
            print("    Use --type zip|payload|img to specify it explicitly")
            print(f"    (or rename the file with the correct extension)")
            sys.exit(1)

        # ── Rootfs assembly ───────────────────────────────────────────────────
        _stage(3, "Rootfs assembly")
        build_rootfs()

    # ── Analysis ──────────────────────────────────────────────────────────────
    _stage(4 if not args.skip else 2, "Vulnerability analysis")
    run_analysis()

    print("\n" + "─" * 65)


if __name__ == "__main__":
    main()
