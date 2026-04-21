"""
Cryptographic material scanner.

Detects hardcoded private keys, weak crypto material, and authentication
bypass risks from static cryptographic artifacts in firmware filesystems.

Vulnerability classes:
  pem_private_key       - PEM-encoded private key present in filesystem
  dropbear_ssh_key      - SSH key in Dropbear wire format (d,p,q present)
  hardcoded_group_key   - JSON mesh group-info with shared key + static GID
  hardcoded_symmetric   - High-entropy hex blob in key context
  missing_sig_verify    - ELF performs flash ops without crypto verify imports
"""

import os
import re
import base64
import struct
import json
import math

# ── PEM private key headers ───────────────────────────────────────────────────

_PEM_PRIVATE_HEADERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
]

# ── Key-context indicator keywords ───────────────────────────────────────────

_KEY_CONTEXT_HINTS = {
    b"aes_key", b"des_key", b"hmac_key", b"secret_key", b"master_key",
    b"encryption_key", b"decrypt_key", b"group_key", b"mesh_key",
    b"psk", b"wpa_psk", b"pre_shared", b"private_key", b"priv_key",
}

# High-entropy hex strings (AES-128/192/256 key sizes)
_HEX_KEY_RE = re.compile(
    r'(?<![0-9a-fA-F])([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})(?![0-9a-fA-F])'
)

# Filesystem paths commonly containing crypto material
_CRYPTO_NAME_HINTS = (
    "group-info", "group_info", "mesh_key",
    "device.key", "device.pem", "server.key", "server.pem",
    "private.key", "privkey.pem", "ca.key",
    "host_key", "ssh_host_", "dropbear_",
    "factory_key", "oem_key",
)

_SCAN_EXTENSIONS = {".json", ".conf", ".cfg", ".txt", ".key", ".pem",
                    ".crt", ".der", ".p12", ".pfx", ""}

_SKIP_DIR_TOKENS = (
    "usr/share/doc", "usr/share/man", "usr/share/locale",
    "usr/lib/python", "usr/lib/perl",
)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _should_scan(fpath):
    base = os.path.basename(fpath).lower()
    if any(h in base for h in _CRYPTO_NAME_HINTS):
        return True
    _, ext = os.path.splitext(base)
    if ext not in _SCAN_EXTENSIONS:
        return False
    try:
        sz = os.path.getsize(fpath)
        return 8 <= sz <= 1024 * 1024
    except OSError:
        return False


def _read(fpath, limit=65536):
    try:
        with open(fpath, "rb") as f:
            return f.read(limit)
    except OSError:
        return None


def _entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _parse_mpint(data, off):
    """Read SSH mpint at offset. Returns (bytes, new_off) or (None, off)."""
    if off + 4 > len(data):
        return None, off
    length = struct.unpack(">I", data[off:off + 4])[0]
    if length > 1024 or off + 4 + length > len(data):
        return None, off
    return data[off + 4:off + 4 + length], off + 4 + length


# ── Per-file checks ───────────────────────────────────────────────────────────

def _check_pem(content, rel):
    findings = []
    for hdr in _PEM_PRIVATE_HEADERS:
        if hdr not in content:
            continue
        encrypted = b"ENCRYPTED" in hdr
        findings.append({
            "type": "pem_private_key",
            "path": rel,
            "key_format": hdr.decode("ascii", errors="replace").strip("-").strip(),
            "encrypted": encrypted,
            "severity": "MEDIUM" if encrypted else "CRITICAL",
            "evidence": f"PEM private key header in {os.path.basename(rel)}",
        })
    return findings


def _check_dropbear(content, rel):
    """Detect Dropbear SSH RSA private key (d, p, q present after n, e)."""
    findings = []
    b64_re = re.compile(rb'[A-Za-z0-9+/]{80,}={0,2}')
    for m in b64_re.finditer(content):
        try:
            raw = base64.b64decode(m.group(0) + b"==")
        except Exception:
            continue
        if len(raw) < 50 or not raw.startswith(b"\x00\x00\x00\x07ssh-rsa"):
            continue
        off = 4 + 7
        comps = {}
        for name in ("e", "n", "d", "p", "q"):
            val, off = _parse_mpint(raw, off)
            if val is None:
                break
            comps[name] = val
        if not ("d" in comps and "p" in comps and "q" in comps):
            continue
        n_bits = len(comps.get("n", b"")) * 8
        sev = "CRITICAL" if n_bits <= 512 else ("HIGH" if n_bits <= 1024 else "MEDIUM")
        findings.append({
            "type": "dropbear_ssh_private_key",
            "path": rel,
            "key_format": "Dropbear SSH RSA wire format",
            "key_size_bits": n_bits,
            "encrypted": False,
            "severity": sev,
            "evidence": (
                f"RSA-{n_bits} private key (n,e,d,p,q all present) in "
                f"{os.path.basename(rel)}; "
                f"d={comps['d'][:6].hex()}..."
            ),
        })
    return findings


def _check_group_key(content, rel):
    """Detect TP-Link-style mesh group-info keys (JSON with 'key' + 'gid')."""
    if b'"key"' not in content and b'"gid"' not in content:
        return []
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return []

    data = None
    try:
        data = json.loads(text)
    except Exception:
        m = re.search(r'\{[^{}]*"key"[^{}]*\}', text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
            except Exception:
                pass
    if not isinstance(data, dict):
        return []

    key_val = data.get("key") or data.get("privateKey")
    gid_val = data.get("gid") or data.get("groupId")
    if not key_val:
        return []

    gid_static = bool(
        gid_val and
        re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                 str(gid_val), re.I)
    )
    return [{
        "type": "hardcoded_group_key",
        "path": rel,
        "key_format": "JSON mesh group-info",
        "gid": str(gid_val) if gid_val else None,
        "gid_is_static": gid_static,
        "shared_across_devices": True,
        "severity": "CRITICAL",
        "evidence": (
            f"Mesh group key in {os.path.basename(rel)}; "
            f"GID={gid_val!r} static={gid_static}; "
            f"key shared across all devices with same firmware"
        ),
    }]


def _check_symmetric(content, rel):
    """Detect high-entropy hex blobs in key-context regions."""
    lower = content.lower()
    if not any(h in lower for h in _KEY_CONTEXT_HINTS):
        return []
    findings = []
    try:
        text = content.decode("ascii", errors="replace")
    except Exception:
        return []
    for m in _HEX_KEY_RE.finditer(text):
        hex_str = m.group(1)
        try:
            key_bytes = bytes.fromhex(hex_str)
        except ValueError:
            continue
        ent = _entropy(key_bytes)
        if ent < 3.5:
            continue
        bits = len(key_bytes) * 8
        findings.append({
            "type": "hardcoded_symmetric_key",
            "path": rel,
            "key_size_bits": bits,
            "entropy": round(ent, 2),
            "severity": "HIGH",
            "evidence": (
                f"High-entropy {bits}-bit key in key-context in "
                f"{os.path.basename(rel)}: {hex_str[:16]}..."
            ),
        })
        if len(findings) >= 2:
            break
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_crypto_material(rootfs_path):
    """
    Walk firmware rootfs and return a sorted list of cryptographic material
    findings.  Each finding has: type, path, severity, evidence, and
    optional: key_size_bits, gid, gid_is_static, shared_across_devices.

    Sorted CRITICAL → HIGH → MEDIUM → LOW.
    """
    if not os.path.isdir(rootfs_path):
        return []

    all_findings = []

    for dirpath, dirnames, filenames in os.walk(rootfs_path):
        rel_dir = os.path.relpath(dirpath, rootfs_path).replace("\\", "/")
        if any(tok in rel_dir for tok in _SKIP_DIR_TOKENS):
            dirnames.clear()
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if not _should_scan(fpath):
                continue
            content = _read(fpath)
            if not content:
                continue
            rel = os.path.relpath(fpath, rootfs_path)

            all_findings.extend(_check_pem(content, rel))
            all_findings.extend(_check_dropbear(content, rel))
            all_findings.extend(_check_group_key(content, rel))
            all_findings.extend(_check_symmetric(content, rel))

    # Deduplicate by (type, path)
    seen = set()
    unique = []
    for f in all_findings:
        k = (f["type"], f["path"])
        if k not in seen:
            seen.add(k)
            unique.append(f)

    unique.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "LOW"), 3))
    return unique


_VERIFY_IMPORTS = frozenset({
    "EVP_VerifyFinal", "EVP_DigestVerifyFinal", "EVP_DigestVerify",
    "RSA_public_decrypt", "RSA_verify", "EC_KEY_verify",
    "ECDSA_verify", "DSA_verify",
    "X509_verify", "X509_verify_cert",
})

_FLASH_IMPORTS = frozenset({
    "mtd_write", "nandwrite", "sysupgrade",
    "upgrade_fw", "flash_firmware",
})


def check_elf_missing_sig_verify(path, imports):
    """
    Return a finding dict if this ELF binary performs flash operations but
    does not import any cryptographic signature verification function.
    Returns None if no issue detected.
    """
    if not imports:
        return None
    imp_set = set(imports.keys())
    flash_ops = imp_set & _FLASH_IMPORTS
    if not flash_ops:
        return None
    if imp_set & _VERIFY_IMPORTS:
        return None
    return {
        "type": "missing_sig_verify_elf",
        "path": path,
        "severity": "HIGH",
        "flash_ops": sorted(flash_ops),
        "verify_ops": [],
        "evidence": (
            f"ELF imports flash ops {sorted(flash_ops)} "
            f"but no signature verification imports found"
        ),
    }
