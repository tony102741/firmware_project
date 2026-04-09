import os
import subprocess
import shutil
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

FIRMWARE_DIR  = os.path.join(PROJECT_ROOT, "firmware")
WORK_DIR      = os.path.join(PROJECT_ROOT, "work")
ROOTFS_DIR    = os.path.join(PROJECT_ROOT, "rootfs")
EXTRACTED_DIR = os.path.join(PROJECT_ROOT, "extracted")

DUMPER = os.path.join(PROJECT_ROOT, "tools/payload-dumper-go/payload-dumper-go")

# Directories that look like Android partition roots
_PARTITION_INDICATORS = {"bin", "lib", "lib64", "etc", "app", "framework", "priv-app"}

# Directories to skip entirely during recursive search (too large / irrelevant)
_SEARCH_SKIP = {"rootfs", ".git", "node_modules", "__pycache__"}


def run(cmd):
    print(f"[+] {cmd}")
    subprocess.run(cmd, shell=True)


# ── Clean ─────────────────────────────────────────────────────────────────────

def clean(skip):
    if skip:
        print("[*] Skip cleaning (reuse mode)")
        return

    print("[*] Cleaning workspace...")
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    shutil.rmtree(ROOTFS_DIR, ignore_errors=True)

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "system"), exist_ok=True)
    os.makedirs(os.path.join(ROOTFS_DIR, "vendor"), exist_ok=True)

    # extracted/ is never deleted — payload re-extraction is expensive
    os.makedirs(EXTRACTED_DIR, exist_ok=True)


# ── OTA unzip ─────────────────────────────────────────────────────────────────

def unzip_firmware(zip_path):
    print("[*] Extracting OTA zip...")
    run(f"unzip -o {zip_path} -d {WORK_DIR}")


# ── payload.bin extraction ────────────────────────────────────────────────────

def extract_payload():
    payload = os.path.join(WORK_DIR, "payload.bin")
    if not os.path.exists(payload):
        raise Exception("[!] payload.bin not found")
    print("[*] Extracting payload.bin...")
    run(f"{DUMPER} {payload}")


# ── Collect images from extracted_* directories ───────────────────────────────

def collect_images():
    print("[*] Collecting images...")

    for d in os.listdir(PROJECT_ROOT):
        if not d.startswith("extracted_"):
            continue

        src_dir = os.path.join(PROJECT_ROOT, d)
        dst_dir = os.path.join(EXTRACTED_DIR, d)

        print(f"[+] moving {d} → extracted/")
        if not os.path.exists(dst_dir):
            shutil.move(src_dir, dst_dir)

        for root, dirs, files in os.walk(dst_dir):
            for f in files:
                if f.endswith(".img"):
                    src = os.path.join(root, f)
                    dst = os.path.join(WORK_DIR, f)
                    if not os.path.exists(dst):
                        print(f"[+] img: {f}")
                        shutil.copy(src, dst)
            # Surface partition dirs to work/
            for sub in list(dirs):
                if sub in ("system", "vendor", "product", "system_ext"):
                    dst_sub = os.path.join(WORK_DIR, sub)
                    if not os.path.exists(dst_sub):
                        print(f"[+] dir: {sub} → work/")
                        shutil.copytree(os.path.join(root, sub), dst_sub)
            break  # top-level of each extracted_* only


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
      1. work/<name>/               — standard pipeline output
      2. extracted/**/<name>/       — payload-dumper-go moved here
      3. PROJECT_ROOT/**/<name>/    — catch-all (e.g. tools/tmp_system/system/)

    Returns the absolute path if found, else None.
    """
    # 1. work/
    candidate = os.path.join(WORK_DIR, name)
    if os.path.isdir(candidate) and _looks_like_partition_root(candidate):
        return candidate

    # 2. extracted/
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
    for root, _, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target_dir = os.path.join(dst, rel)
        os.makedirs(target_dir, exist_ok=True)
        for f in files:
            try:
                shutil.copy2(os.path.join(root, f), os.path.join(target_dir, f))
            except Exception:
                pass


def extract_img(img_name, out_dir):
    img_path = os.path.join(WORK_DIR, img_name)
    if not os.path.exists(img_path):
        print(f"[!] {img_name} not found, skip")
        return False
    print(f"[*] Extracting {img_name}...")
    os.makedirs(out_dir, exist_ok=True)
    run(f"7z x {img_path} -o{out_dir} -y")
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
        print(f"[*] {name}: using directory  {found}")
        safe_copy(found, dst)
        return True

    # ── Fall back to .img extraction ──────────────────────────────────────────
    img_tmp = os.path.join(WORK_DIR, f"_tmp_{name}")
    if extract_img(f"{name}.img", img_tmp):
        inner = _find_partition_root_in_extract(img_tmp, name)
        print(f"[*] {name}: using img extract  {inner}")
        safe_copy(inner, dst)
        return True

    print(f"[!] {name}: could not locate partition — rootfs/{name} will be empty")
    return False


def build_rootfs():
    print("[*] Building rootfs...")
    build_rootfs_for_partition("system")
    build_rootfs_for_partition("vendor")


# ── Analysis ──────────────────────────────────────────────────────────────────

def run_analysis():
    run(f"python3 {os.path.join(BASE_DIR, 'main.py')}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip", action="store_true", help="reuse existing rootfs")
    args = parser.parse_args()

    clean(args.skip)

    if not args.skip:
        files = os.listdir(FIRMWARE_DIR)
        if not files:
            print("[!] No firmware zip found in firmware/")
            return

        zip_path = os.path.join(FIRMWARE_DIR, files[0])

        unzip_firmware(zip_path)
        extract_payload()
        collect_images()
        build_rootfs()

    run_analysis()


if __name__ == "__main__":
    main()
