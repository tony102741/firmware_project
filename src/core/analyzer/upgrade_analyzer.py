"""
Firmware upgrade path analyzer.

Scans shell scripts and Lua scripts in firmware for upgrade/flash
operations that lack cryptographic signature verification.

This is a distinct vulnerability class from command injection:
  - An attacker who can trigger SYNC_FIRMWARE + SYNC_UPGRADE (or equivalent)
    can flash arbitrary firmware even without RCE in the current firmware,
    because the device downloads and flashes any image as long as the MD5
    checksum (supplied by the attacker) matches.

Detected patterns:
  - Shell: flash/write commands without openssl/rsa verify
  - Lua/script: SYNC_FIRMWARE, do_upgrade, sysupgrade without sig check
  - Download → flash without integrity beyond md5sum
"""

import os
import re

# ── Flash / upgrade command patterns ─────────────────────────────────────────

_FLASH_RE = re.compile(
    r'\b(?:'
    r'sysupgrade|'
    r'mtd\s+write|'
    r'nandwrite|'
    r'flash_erase|'
    r'dd\s+if=|'
    r'nvrammanager\s+-p|'
    r'fw_setenv|'
    r'do_upgrade|'
    r'write_firmware|'
    r'write_flash|'
    r'SYNC_UPGRADE|'
    r'sync_upgrade'
    r')\b',
    re.IGNORECASE,
)

_DOWNLOAD_RE = re.compile(
    r'\b(?:wget|curl|tftp|SYNC_FIRMWARE|sync_firmware|sync_download)\b',
    re.IGNORECASE,
)

# Proper signature verification
_VERIFY_RE = re.compile(
    r'\b(?:'
    r'openssl\s+(?:verify|dgst|rsautl)|'
    r'gpg\s+--verify|'
    r'rsa_verify|'
    r'EVP_VerifyFinal|'
    r'EVP_DigestVerify|'
    r'check_signature|'
    r'verify_signature|'
    r'verify_image|'
    r'image_verify'
    r')\b',
    re.IGNORECASE,
)

# Weak integrity (hash only, not signature)
_WEAK_INTEGRITY_RE = re.compile(
    r'\b(?:md5sum|sha256sum|sha1sum|crc32|checksum)\b',
    re.IGNORECASE,
)

# File name hints
_UPGRADE_NAME_HINTS = (
    "upgrade", "update", "flash", "firmware", "ota",
    "sysupgrade", "fwupgrade", "fw_update",
    "sync-server", "syncserver", "tmpcli", "tmpsvr",
)

# Directories that contain only system utilities — never upgrade scripts
_SKIP_DIRS = frozenset({
    "bin", "sbin",
    os.path.join("usr", "bin"),
    os.path.join("usr", "sbin"),
})

_ELF_MAGIC = b"\x7fELF"

_SCRIPT_EXTENSIONS = {".sh", ".lua", ".py", ".pl"}


def _is_upgrade_related(fpath):
    base = os.path.basename(fpath).lower()
    return any(h in base for h in _UPGRADE_NAME_HINTS)


def _is_elf(fpath):
    try:
        with open(fpath, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


def _is_scannable_script(fpath, rootfs_path):
    """
    Return True if the file is worth scanning for unsigned upgrade patterns.

    Rules (applied in order, first failure → skip):
    1. ELF binaries are skipped unless they are upgrade-related by name.
    2. Files in standard utility dirs (bin/, sbin/, usr/bin/, usr/sbin/)
       are skipped unless upgrade-related by name.
    3. Accepted extensions: .sh .lua .py .pl — OR upgrade-related name.
    4. Size: 4 B – 512 KB.
    5. Content must start with a text marker (#!, --, # ) or be ASCII.
    """
    rel = os.path.relpath(fpath, rootfs_path)
    rel_dir = os.path.dirname(rel)
    base = os.path.basename(fpath)
    upgrade_related = _is_upgrade_related(fpath)

    # Skip standard utility directories unless the file is explicitly
    # upgrade-related (e.g. /usr/bin/tmpcli, /usr/bin/tmpsvr)
    if rel_dir in _SKIP_DIRS and not upgrade_related:
        return False

    # ELF binaries: only scan if upgrade-related
    if _is_elf(fpath):
        return upgrade_related

    try:
        sz = os.path.getsize(fpath)
        if not (4 <= sz <= 512 * 1024):
            return False
    except OSError:
        return False

    _, ext = os.path.splitext(base.lower())
    if ext in _SCRIPT_EXTENSIONS or upgrade_related:
        try:
            with open(fpath, "rb") as f:
                hdr = f.read(4)
            return (
                hdr[:2] == b"#!" or
                hdr[:2] in (b"--", b"# ") or
                (hdr[0:1] != b"\x7f" and all(b < 128 for b in hdr))
            )
        except OSError:
            return False

    return False


def _analyze_script(rel, content, upgrade_related=False):
    """
    Inspect script content for unsigned flash operations.
    Returns a finding dict or None.

    Only produces a finding when:
    - Flash pattern present (HIGH/CRITICAL), OR
    - Download + flash both present (CRITICAL), OR
    - Download-only in explicitly upgrade-related files (MEDIUM)

    Generic curl/wget in non-upgrade scripts is suppressed to avoid
    flooding from DDNS, telemetry, and API-call scripts.
    """
    has_flash = bool(_FLASH_RE.search(content))
    has_download = bool(_DOWNLOAD_RE.search(content))

    # No flash AND not upgrade-related → suppress download-only finding
    if not has_flash and not (has_download and upgrade_related):
        return None

    has_sig = bool(_VERIFY_RE.search(content))
    if has_sig:
        return None

    has_weak = bool(_WEAK_INTEGRITY_RE.search(content))

    # Determine severity and pattern label
    if has_download and has_flash:
        sev = "CRITICAL"
        pattern = "download_and_flash_no_sig"
    elif has_flash:
        sev = "HIGH"
        pattern = "flash_no_sig"
    else:
        # download-only, upgrade-related file
        sev = "MEDIUM"
        pattern = "download_no_sig"

    flash_hits = _FLASH_RE.findall(content)[:3]
    dl_hits = _DOWNLOAD_RE.findall(content)[:2]
    weak_hits = _WEAK_INTEGRITY_RE.findall(content)[:2]

    parts = []
    if flash_hits:
        parts.append(f"flash: {flash_hits}")
    if dl_hits:
        parts.append(f"download: {dl_hits}")
    if has_weak and weak_hits:
        parts.append(f"weak integrity only: {weak_hits}")
    else:
        parts.append("no integrity check")

    return {
        "type": "unsigned_firmware_flash",
        "path": rel,
        "severity": sev,
        "pattern": pattern,
        "has_download": has_download,
        "has_flash": has_flash,
        "has_weak_integrity": has_weak,
        "has_sig_verify": False,
        "evidence": "; ".join(parts),
    }


def scan_upgrade_scripts(rootfs_path):
    """
    Walk firmware rootfs and return findings for scripts that perform
    firmware flash/download without cryptographic signature verification.

    Returns a list of finding dicts sorted CRITICAL → HIGH → MEDIUM.
    Each dict: type, path, severity, pattern, has_download, has_flash,
               has_weak_integrity, has_sig_verify, evidence.
    """
    if not os.path.isdir(rootfs_path):
        return []

    findings = []
    _SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for dirpath, dirnames, filenames in os.walk(rootfs_path):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, rootfs_path)
            upgrade_related = _is_upgrade_related(fpath)

            if not _is_scannable_script(fpath, rootfs_path):
                continue

            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue

            finding = _analyze_script(rel, content, upgrade_related=upgrade_related)
            if finding:
                findings.append(finding)

    findings.sort(key=lambda x: _SEV.get(x.get("severity", "LOW"), 3))
    return findings
