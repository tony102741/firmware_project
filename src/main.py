import os
import sys
import re
import argparse
import json
import shutil
import math
from datetime import datetime, timezone
from pathlib import Path

# Ensure src/core/ is on sys.path so that 'from parser.init_parser import ...'
# resolves to src/core/parser/init_parser.py regardless of how this script is
# invoked (directly, via pipeline.py subprocess, or with a manual PYTHONPATH).
_CORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from parser.init_parser import parse_init_services
from analyzer.risk import analyze_services
from scanner.scan_setuid import scan_setuid
from scanner.scan_perm import scan_world_writable
from scanner.scan_su import scan_su
from scanner.scan_web import scan_web_surface
from analyzer.verify_flow import verify_exploitable_flows
from analyzer.reach_check import analyze_reachability
from analyzer.strings_analyzer import extract_strings
from analyzer.cve_triage import select_cve_candidates, explain_triage
from analyzer.crypto_scanner import scan_crypto_material
from analyzer.upgrade_analyzer import scan_upgrade_scripts


_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_DEFAULT_ROOTFS_DIR = os.path.join(_PROJECT_ROOT, ".cache", "rootfs")
_OVERRIDE_SYSTEM_PATH = os.environ.get("FIRMWARE_SYSTEM_PATH")
_OVERRIDE_VENDOR_PATH = os.environ.get("FIRMWARE_VENDOR_PATH")
_RUN_DIR = os.environ.get("FIRMWARE_RUN_DIR")
_DEFAULT_DOSSIER_DIR = os.environ.get("FIRMWARE_DOSSIER_DIR")
_INPUT_PATH = os.environ.get("FIRMWARE_INPUT_PATH")
_INPUT_TYPE = os.environ.get("FIRMWARE_INPUT_TYPE")
_ORIGINAL_INPUT_PATH = os.environ.get("FIRMWARE_ORIGINAL_INPUT_PATH")
_ORIGINAL_INPUT_TYPE = os.environ.get("FIRMWARE_ORIGINAL_INPUT_TYPE")
_RUN_ID = os.environ.get("FIRMWARE_RUN_ID")

if _OVERRIDE_SYSTEM_PATH:
    SYSTEM_PATH = os.path.abspath(_OVERRIDE_SYSTEM_PATH)
    ROOTFS_DIR = os.path.dirname(SYSTEM_PATH)
    VENDOR_PATH = (
        os.path.abspath(_OVERRIDE_VENDOR_PATH)
        if _OVERRIDE_VENDOR_PATH
        else os.path.join(ROOTFS_DIR, "vendor")
    )
else:
    ROOTFS_DIR = _DEFAULT_ROOTFS_DIR
    SYSTEM_PATH = os.path.join(ROOTFS_DIR, "system")
    VENDOR_PATH = os.path.join(ROOTFS_DIR, "vendor")

_W = 65   # output width — matches pipeline.py


# ── Output helpers ─────────────────────────────────────────────────────────────

def _sec(title):
    """
    Section header — same visual style as pipeline.py's _stage().
    Always flushed so it appears before any subprocess output that follows.
    """
    label = f"  {title}  "
    pad = max(0, _W - len(label) - 3)
    print(f"\n{'─' * 3}{label}{'─' * pad}", flush=True)


def _score_candidate_label_token(token):
    tl = (token or "").strip().lower()
    if not tl:
        return -999
    score = 0
    if tl.startswith("form") and "uploadconfig" not in tl:
        score += 40
    if tl.startswith("submit_"):
        score += 12
    if tl == "submit_dpp_uri" or tl.endswith("submit_dpp_uri"):
        score += 20
    if tl.startswith("apcli_"):
        score += 10
    if any(k in tl for k in (
        "submit", "uploadfile", "connect", "disconnect", "dpp", "wps",
        "site", "survey", "apcli", "pin", "repeater",
    )):
        score += 28
    if any(k in tl for k in ("upload", "scan", "wizard", "easymesh", "vpn")):
        score += 12
    if "scan" in tl and "site" not in tl and "survey" not in tl:
        score -= 10
    if any(tl.startswith(p) for p in ("get_", "set_", "apply_", "trigger_", "validate_", "generate_", "retrieve_", "retrive_")):
        score -= 12
    if tl.startswith(("remove_", "delete_")) or tl.endswith("_status") or "status_" in tl:
        score -= 10
    if tl.startswith("start_"):
        score -= 4
    if "config" in tl and "uploadfile" not in tl:
        score -= 10
    if tl in {"main", "index", "init", "entry", "dispatch", "handler", "callback"}:
        score -= 15
    score += min(8, len(tl) // 5)
    return score


def _choose_candidate_label(raw_name, endpoints=None, handler_symbols=None):
    """
    Turn generic binary names into more analyst-friendly handler labels.

    Examples:
      boa -> boa/formWsc
      mtkwifi.lua -> mtkwifi.lua/apcli_connect
    """
    raw = (raw_name or "").strip()
    if not raw:
        return raw_name

    base = os.path.basename(raw)
    candidates = []
    for ep in endpoints or []:
        token = os.path.basename((ep or "").rstrip("/"))
        if token:
            candidates.append(token)
    for sym in handler_symbols or []:
        if sym:
            candidates.append(sym)

    best = None
    best_score = -999
    for token in candidates:
        score = _score_candidate_label_token(token)
        if score > best_score:
            best = token
            best_score = score

    generic = (
        base in {"boa", "lighttpd", "uhttpd", "httpd", "mini_httpd"}
        or base.endswith(".lua")
        or base.endswith(".cgi")
    )
    if generic and best and best.lower() != base.lower() and best_score >= 10:
        return f"{base}/{best}"
    return raw_name


# ── Result display ────────────────────────────────────────────────────────────

def print_section(title, data):
    """
    Print a result section with full detail for each target.

    Fields displayed:
      - risk level, service name, score, dataflow confidence
      - input type, privilege, dataflow pattern, source partition
      - binary path (relative to project root)
      - all dangerous functions found
      - detected attack surface (sockets, config files, IPC interfaces)
      - fuzzing hints
    """
    _sec(f"{title}  ({len(data)})")

    if not data:
        print("  (none)", flush=True)
        return

    for r in data:
        flow    = r.get("flow_type") or "none"
        conf    = r.get("confidence", "WEAK")
        src     = r.get("source", "system")
        ctrl    = r.get("controllability", "?")
        mem     = r.get("memory_impact", "?")
        vp      = r.get("validation_penalty", 0.0)
        tc      = r.get("taint_confidence", 0.0)

        print(f"\n  ▸ {r['name']}", flush=True)
        print(f"    score={r['score']}  level={r['level']}  "
              f"ctrl={ctrl}  mem_impact={mem}", flush=True)
        print(f"    input={r['input_type']}  priv={r['priv']}  "
              f"flow={flow}  conf={conf}  taint={tc:.2f}  "
              f"val_penalty={vp:.2f}  source={src}", flush=True)

        bp = r.get("binary_path", r["exec"])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        print(f"    path:  {bp}", flush=True)

        all_sinks = r.get("all_sinks") or r.get("sinks") or []
        if all_sinks:
            print(f"    sinks: {', '.join(all_sinks)}", flush=True)

        surface = r.get("attack_surface", {})
        if surface.get("sockets"):
            print(f"    sockets:      {', '.join(surface['sockets'][:4])}", flush=True)
        if surface.get("config_files"):
            print(f"    config files: {', '.join(surface['config_files'][:3])}", flush=True)
        if surface.get("ipc"):
            print(f"    ipc:          {', '.join(surface['ipc'][:3])}", flush=True)

        hints = r.get("fuzzing_hints", [])
        if hints:
            for hint in hints:
                print(f"    → {hint}", flush=True)


def print_attack_surface_map(results):
    """
    Print a compact [input] → [service] → [binary] attack surface map
    for HIGH and MEDIUM targets.
    """
    visible = [r for r in results if r["level"] in ("HIGH", "MEDIUM")]
    if not visible:
        return

    _sec("ATTACK SURFACE MAP  ([input] → [service] → [binary])")

    for r in visible:
        itype   = r["input_type"]
        surface = r.get("attack_surface", {})
        sockets = surface.get("sockets", [])
        configs = surface.get("config_files", [])

        if sockets:
            surface_str = sockets[0]
        elif configs:
            surface_str = configs[0]
        else:
            surface_str = itype

        conf = r.get("confidence", "WEAK")
        ctrl = r.get("controllability", "?")
        mem  = r.get("memory_impact", "?")
        print(f"  [{itype}: {surface_str}]"
              f" → [{r['name']}]"
              f" → [{r['exec']}]"
              f"  ctrl={ctrl}  mem={mem}  ({conf})", flush=True)


def _has_web_layout(root):
    if not os.path.isdir(root):
        return False
    for rel in (
        "www", "web", "cgi-bin", "usr/www", "var/www", "var/web", "www/cgi-bin",
        "web/cgi-bin", "web/cgi-bin/cstecgi.cgi",
        "www/webpages", "etc/wifidog", "usr/lib/lua/luci", "etc/config/uhttpd",
        "etc/boa.org/boa.conf", "etc/boa.conf",
    ):
        if os.path.isdir(os.path.join(root, rel)):
            return True
        if os.path.isfile(os.path.join(root, rel)):
            return True
    return False


def _find_web_servers(root):
    if not os.path.isdir(root):
        return []

    names = {"httpd", "uhttpd", "lighttpd", "nginx", "mini_httpd", "boa"}
    found = []
    for rel in ("bin", "sbin", os.path.join("usr", "bin"), os.path.join("usr", "sbin")):
        base = os.path.join(root, rel)
        if not os.path.isdir(base):
            continue
        for name in names:
            path = os.path.join(base, name)
            if os.path.isfile(path):
                found.append(path)
    return sorted(set(found))


def detect_analysis_mode():
    reasons = []
    web_layout = _has_web_layout(SYSTEM_PATH) or _has_web_layout(VENDOR_PATH)
    web_servers = _find_web_servers(SYSTEM_PATH) + _find_web_servers(VENDOR_PATH)
    has_android_layout = os.path.isdir(SYSTEM_PATH) and os.path.isdir(VENDOR_PATH)

    if web_layout or web_servers:
        if web_layout:
            reasons.append("web paths detected (/www or /cgi-bin)")
        if web_servers:
            reasons.append(
                "web server binaries detected "
                f"({', '.join(sorted({os.path.basename(p) for p in web_servers}))})"
            )
        return "iot_web", "; ".join(reasons)

    if has_android_layout:
        return "android", "Android-style system/vendor layout detected"

    return "general", "no web interface or Android-specific layout detected"


# ── Filesystem cross-reference ────────────────────────────────────────────────

def _exec_key(path):
    """Convert a scanner path (.cache/rootfs/system/bin/foo) to /system/bin/foo."""
    return "/" + os.path.relpath(path, ROOTFS_DIR)


def _annotate(path, exec_map, flag_fn):
    """
    Return an annotation string for a scanned path.
    Looks up the path in exec_map and applies flag_fn to detect high-risk combos.
    """
    svc = exec_map.get(_exec_key(path))
    if svc is None:
        return ""
    tag = f"  → {svc['name']} [{svc['level']}]"
    flag = flag_fn(svc)
    return tag + (f"  !! {flag}" if flag else "")


def run_filesystem_checks(results):
    roots = [p for p in [SYSTEM_PATH, VENDOR_PATH] if os.path.exists(p)]
    if not roots:
        print("\n[*] Filesystem checks: no rootfs paths found, skipping", flush=True)
        return

    total_files = sum(
        sum(len(files) for _, _, files in os.walk(root))
        for root in roots
    )
    print(f"\n[*] Filesystem checks: {total_files} files across {len(roots)} partition(s)",
          flush=True)

    exec_map = {svc["exec"]: svc for svc in results}

    def collect(fn):
        paths = []
        for root in roots:
            paths.extend(fn(root))
        return paths

    def flag_setuid(svc):
        if svc["input_type"] in ("socket", "binder", "netlink"):
            return "setuid + network-exposed"
        return None

    def flag_writable(_svc):
        return "world-writable + executed binary"

    def flag_none(_svc):
        return None

    checks = [
        ("Setuid binaries",        collect(scan_setuid),         flag_setuid),
        ("World-writable files",   collect(scan_world_writable), flag_writable),
        ("su / busybox binaries",  collect(scan_su),             flag_none),
    ]

    printed_header = False
    for label, paths, flag_fn in checks:
        if not paths:
            continue
        if not printed_header:
            _sec("FILESYSTEM CHECKS")
            printed_header = True
        print(f"\n  {label}:", flush=True)
        for path in paths:
            print(f"    {path}{_annotate(path, exec_map, flag_fn)}", flush=True)


# ── IoT firmware detection and analysis ──────────────────────────────────────

def _is_iot_firmware(system_path):
    """
    Return True if the rootfs contains no Android .rc files.
    Android firmware always has init.rc and *.rc service definitions;
    IoT/Linux firmware does not.
    """
    for _, _, files in os.walk(system_path):
        if any(f.endswith(".rc") for f in files):
            return False
    return True


def _is_openwrt_web_script(exec_path):
    lower = (exec_path or "").lower()
    return (
        lower.startswith("/www/cgi-bin/")
        or "/usr/lib/lua/luci/controller/" in lower
        or "/usr/lib/lua/luci/apprpc/" in lower
        or "/usr/lib/lua/luci/jsonrpcbind/" in lower
        or lower.endswith("/luci/sgi/uhttpd.lua")
        or "/usr/libexec/rpcd/" in lower
    )


def _collect_iot_services(system_path, web_bins, cgi_files=None):
    """
    Synthesize service entries for ELF executables in standard IoT binary
    directories.  Web-exposed binaries get a world-accessible socket marker
    so the controllability classifier assigns them HIGH priority.
    """
    _BIN_DIRS = [
        "bin", "sbin",
        os.path.join("usr", "bin"),
        os.path.join("usr", "sbin"),
    ]
    web_set  = {os.path.normpath(p) for p in web_bins}
    cgi_files = cgi_files or []
    services = []
    seen     = set()

    for bin_dir in _BIN_DIRS:
        abs_dir = os.path.join(system_path, bin_dir)
        if not os.path.isdir(abs_dir):
            continue
        for f in sorted(os.listdir(abs_dir)):
            fpath = os.path.normpath(os.path.join(abs_dir, f))
            if not os.path.isfile(fpath):
                continue
            exec_path = "/" + os.path.relpath(fpath, system_path)
            if exec_path in seen:
                continue
            seen.add(exec_path)
            is_web = fpath in web_set
            services.append({
                "name":   f,
                "exec":   exec_path,
                "user":   "root",
                "socket": [{"perm": "666"}] if is_web else [],
                "source": "vendor",
            })

    # Web-exposed binaries outside standard dirs (e.g. CGI executables in /www)
    for wb in sorted(web_bins):
        fpath = os.path.normpath(wb)
        if not os.path.isfile(fpath):
            continue
        exec_path = "/" + os.path.relpath(fpath, system_path)
        if exec_path in seen:
            continue
        seen.add(exec_path)
        services.append({
            "name":   os.path.basename(wb),
            "exec":   exec_path,
            "user":   "root",
            "socket": [{"perm": "666"}],
            "source": "vendor",
        })

    # OpenWrt/LuCI firmware frequently routes HTTP requests through Lua
    # controllers or rpcd helpers rather than standalone CGI ELF binaries.
    # Model those scripts as web-reachable service entries so the risk analyzer
    # can score them instead of silently dropping the entire web stack.
    for script_path in sorted({os.path.normpath(p) for p in cgi_files}):
        if not os.path.isfile(script_path):
            continue
        exec_path = "/" + os.path.relpath(script_path, system_path)
        if exec_path in seen or not _is_openwrt_web_script(exec_path):
            continue
        seen.add(exec_path)
        services.append({
            "name":   os.path.basename(script_path),
            "exec":   exec_path,
            "user":   "root",
            "socket": [{"perm": "666"}],
            "source": "vendor",
        })

    return services


def _collect_generic_blob_services(system_path, max_candidates=None):
    """
    Fallback collector for firmware bundles that do not expose a classic
    rootfs layout. Treat interesting blobs as analysis targets and let the
    string-based analyzer rank them.
    """
    exts = {".bin", ".img", ".so", ".elf", ".fw", ".cgi", ".apk"}
    root_lower = os.path.abspath(system_path).lower()
    allow_extensionless = "_iot_extract" in root_lower
    if max_candidates is None:
        max_candidates = 40 if "_iot_extract" in root_lower or "rc520" in root_lower or "dji" in root_lower else 200
    services = []
    seen = set()
    noisy_tokens = (
        "libxul", "opencv", "mapbox", "mozav", "ffmpeg", "qnnhtp",
        "xnnpack", "ijkplayer", "freebl3", "nss3", "nssckbi",
        "crashlytics", "volc_log", "megazord", "glean", "plugin-container",
        "libc++_shared", "libjnidispatch", "libsoftokn3", "libgraphics-core",
    )

    for dirpath, dirnames, filenames in os.walk(system_path):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel_dir = os.path.relpath(dirpath, system_path).replace("\\", "/").lower()
        for name in sorted(filenames):
            lower = name.lower()
            ext = os.path.splitext(lower)[1]
            is_extensionless_chunk = (
                allow_extensionless
                and not ext
                and re.fullmatch(r"[0-9a-f]{2,}", lower)
            )
            if ext not in exts and not is_extensionless_chunk:
                continue

            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size < 4096:
                continue
            if is_extensionless_chunk and size < 64 * 1024:
                continue
            if ext == ".so":
                if any(tok in lower for tok in noisy_tokens):
                    continue
                if size > 25 * 1024 * 1024:
                    continue
            if ext == ".apk":
                continue

            exec_path = "/" + os.path.relpath(full, system_path)
            if exec_path in seen:
                continue
            seen.add(exec_path)

            service_name = os.path.basename(name)
            if rel_dir not in (".", ""):
                service_name = f"{os.path.basename(dirpath)}::{service_name}"

            services.append({
                "name": service_name,
                "exec": exec_path,
                "user": "root",
                "socket": [],
                "source": "bundle",
            })

    def priority(service):
        exec_path = service["exec"].lower()
        score = 0
        if exec_path.endswith(".so"):
            score -= 50
        if "/lib/" in exec_path:
            score -= 30
        if exec_path.endswith("/_decoded.bin"):
            score += 140
        elif "/_nested_" in exec_path and exec_path.endswith(".bin"):
            score += 80
        if exec_path.endswith(".apk"):
            score += 40
        if exec_path.endswith(("decompressed.bin", "payload.bin")):
            score += 80
        if os.path.basename(exec_path).startswith("v01.00."):
            score += 120
        try:
            size = os.path.getsize(os.path.join(system_path, service["exec"].lstrip("/")))
        except OSError:
            size = 0
        if size > 50 * 1024 * 1024:
            score += 40
        elif 64 * 1024 <= size <= 20 * 1024 * 1024:
            score -= 10
        return (score, exec_path)

    services.sort(key=priority, reverse=True)
    return services[:max_candidates]


def _collect_blob_signal_findings(services, system_path, limit=5):
    findings = []
    web_terms = (
        "http", "https", "login", "password", "portal", "cgi",
        "httpd", "goform", "boafrm", "tp-link", "/cgi", "/www",
    )
    exec_terms = (
        "system(", "popen(", "exec", "execute_cmd", "bootcmd",
        "/bin/sh", "shell", "command",
    )

    for service in services[: min(len(services), 12)]:
        rel_exec = service["exec"].lstrip("/")
        path = os.path.join(system_path, rel_exec)
        strings = extract_strings(path)
        if not strings:
            continue

        joined = "\n".join(strings[:4000]).lower()
        web_hits = sorted({term for term in web_terms if term in joined})
        exec_hits = sorted({term for term in exec_terms if term in joined})
        if len(web_hits) < 2 and not (web_hits and exec_hits):
            continue

        endpoints = []
        for s in strings[:4000]:
            if s.startswith(("GET /", "POST /")):
                parts = s.split()
                if len(parts) >= 2 and parts[1].startswith("/"):
                    endpoints.append(parts[1])
            elif s.startswith("/") and any(tok in s.lower() for tok in ("cgi", "login", "http", "portal")):
                endpoints.append(s.strip())
        endpoints = sorted(dict.fromkeys(endpoints))[:6]

        score = 18 + min(12, len(web_hits) * 3) + min(8, len(exec_hits) * 4)
        level = "MEDIUM" if exec_hits else "LOW"
        summary_bits = []
        if web_hits:
            summary_bits.append(f"web/admin strings: {', '.join(web_hits[:4])}")
        if exec_hits:
            summary_bits.append(f"execution strings: {', '.join(exec_hits[:3])}")

        findings.append({
            "name": f"{service['name']}:blob-signal",
            "exec": service["exec"],
            "binary_path": path,
            "level": level,
            "score": score,
            "confidence": "LOW",
            "input_type": "blob",
            "priv": "unknown",
            "flow_type": "blob_signal",
            "source": service.get("source", "bundle"),
            "controllability": "UNKNOWN",
            "memory_impact": "UNKNOWN",
            "validation_penalty": 0.0,
            "taint_confidence": 0.0,
            "attack_surface": {"config_files": [], "env_vars": [], "ipc": [], "sockets": []},
            "all_sinks": exec_hits,
            "sinks": exec_hits,
            "endpoints": endpoints,
            "vuln_summary": "; ".join(summary_bits),
            "next_steps": [
                "Inspect the blob in Ghidra or binwalk for embedded partitions or packed web assets.",
                "Correlate HTTP/login strings with nearby command or bootloader handlers.",
            ],
        })

    findings.sort(key=lambda r: (r["level"] == "MEDIUM", r["score"]), reverse=True)
    return findings[:limit]


def _collect_container_signal_findings(services, system_path, limit=5):
    findings = []

    def detect_container_markers(path, rel_exec, strings, head):
        markers = []
        head_lower = head.lower()
        haystack = "\n".join(strings[:2000]).lower()
        payload_offset = None
        ciphertext_offset = None
        openssl_salt = None
        crypto_profile = ""

        salted_off = head_lower.find(b"salted__")
        if salted_off >= 0:
            payload_offset = salted_off
            ciphertext_offset = salted_off + 16
            openssl_salt = head[salted_off + 8:salted_off + 16].hex()
            markers.append({
                "kind": "openssl-salted",
                "offset": salted_off,
                "detail": "OpenSSL Salted__ header",
            })

        fw_type_match = re.search(r"fw-type:([a-z0-9_-]+)", haystack, re.I)
        if fw_type_match:
            markers.append({
                "kind": "fw-type",
                "offset": haystack.find("fw-type:"),
                "detail": f"fw-type:{fw_type_match.group(1)}",
            })

        if "cloud" in haystack and "fw-type:" in haystack:
            markers.append({
                "kind": "cloud-tag",
                "offset": haystack.find("cloud"),
                "detail": "Cloud-tagged firmware bundle",
            })

        if "nosign" in rel_exec.lower() or "nosign" in haystack:
            markers.append({
                "kind": "nosign",
                "offset": haystack.find("nosign"),
                "detail": "unsigned/nosign build marker",
            })

        if any(tok in haystack for tok in ("signature", "encrypt", "encrypted", "aes")):
            detail = next(
                (tok for tok in ("signature", "encrypted", "encrypt", "aes") if tok in haystack),
                "encryption/signature metadata",
            )
            markers.append({
                "kind": "crypto-meta",
                "offset": haystack.find(detail),
                "detail": detail,
            })

        vendor_guess = ""
        kinds = {m["kind"] for m in markers}
        if "openssl-salted" in kinds and salted_off == 0x204:
            vendor_guess = "Tenda-style encrypted firmware container"
            crypto_profile = "openssl-enc-compatible salted payload"
        elif "fw-type" in kinds and "cloud-tag" in kinds:
            vendor_guess = "TP-Link/MERCUSYS cloud firmware container"
        elif "fw-type" in kinds:
            vendor_guess = "vendor-tagged firmware container"
        elif "openssl-salted" in kinds:
            vendor_guess = "OpenSSL-wrapped firmware payload"
            crypto_profile = "openssl-enc-compatible salted payload"

        if payload_offset is None and ("fw-type" in kinds or "cloud-tag" in kinds):
            payload_offset = 0x200

        return markers, vendor_guess, payload_offset, ciphertext_offset, openssl_salt, crypto_profile

    def summarize_ciphertext(path, ciphertext_offset):
        if not isinstance(ciphertext_offset, int) or ciphertext_offset < 0:
            return {}
        try:
            with open(path, "rb") as fh:
                fh.seek(ciphertext_offset)
                sample = fh.read(1 << 20)
        except OSError:
            return {}
        if not sample:
            return {}

        freq = [0] * 256
        for b in sample:
            freq[b] += 1
        entropy = -sum((c / len(sample)) * math.log2(c / len(sample)) for c in freq if c)

        first4k = sample[:4096]
        blocks = [first4k[i:i + 16] for i in range(0, len(first4k), 16) if len(first4k[i:i + 16]) == 16]
        unique_blocks = len(set(blocks)) if blocks else 0
        repeated_blocks = len(blocks) - unique_blocks if blocks else 0

        likely_cipher = (
            len(sample) % 16 == 0
            and repeated_blocks == 0
            and entropy >= 7.95
        )
        return {
            "entropy_first_mib": round(entropy, 4),
            "size_mod_16": len(sample) % 16,
            "unique_16byte_blocks_first_4k": unique_blocks,
            "repeated_16byte_blocks_first_4k": repeated_blocks,
            "likely_block_ciphertext": likely_cipher,
        }

    for service in services[: min(len(services), 12)]:
        rel_exec = service["exec"].lstrip("/")
        path = os.path.join(system_path, rel_exec)
        if not os.path.isfile(path):
            continue

        try:
            with open(path, "rb") as fh:
                head = fh.read(4096)
        except OSError:
            continue

        strings = extract_strings(path)
        markers, vendor_guess, payload_offset, ciphertext_offset, openssl_salt, crypto_profile = detect_container_markers(path, rel_exec, strings, head)
        if not markers:
            continue

        score = 14 + min(10, len(markers) * 3)
        marker_details = [m["detail"] for m in markers[:4]]
        try:
            payload_size = max(0, os.path.getsize(path) - (payload_offset or 0))
        except OSError:
            payload_size = None
        try:
            ciphertext_size = (
                max(0, os.path.getsize(path) - ciphertext_offset)
                if isinstance(ciphertext_offset, int)
                else None
            )
        except OSError:
            ciphertext_size = None
        ciphertext_fingerprint = summarize_ciphertext(path, ciphertext_offset)
        findings.append({
            "name": f"{service['name']}:container-signal",
            "exec": service["exec"],
            "binary_path": path,
            "level": "LOW",
            "score": score,
            "confidence": "LOW",
            "input_type": "blob",
            "priv": "unknown",
            "flow_type": "container_signal",
            "source": service.get("source", "bundle"),
            "controllability": "UNKNOWN",
            "memory_impact": "UNKNOWN",
            "validation_penalty": 0.0,
            "taint_confidence": 0.0,
            "attack_surface": {"config_files": [], "env_vars": [], "ipc": [], "sockets": []},
            "all_sinks": [],
            "sinks": [],
            "container_markers": markers,
            "vendor_guess": vendor_guess,
            "payload_offset": payload_offset,
            "payload_size": payload_size,
            "ciphertext_offset": ciphertext_offset,
            "ciphertext_size": ciphertext_size,
            "openssl_salt": openssl_salt,
            "crypto_profile": crypto_profile,
            "ciphertext_fingerprint": ciphertext_fingerprint,
            "endpoints": [],
            "vuln_summary": (
                ("encrypted or signed vendor firmware container detected"
                 + (f" ({vendor_guess})" if vendor_guess else ""))
                + ": "
                + "; ".join(marker_details)
            ),
            "next_steps": [
                "Recover or identify the vendor decryption/signature scheme before expecting a classic rootfs.",
                "Inspect the container header and update the extractor for this vendor-specific format.",
            ],
        })

    findings.sort(key=lambda r: r["score"], reverse=True)
    return findings[:limit]


def _relevel(score, confidence):
    """Re-classify level after a score adjustment."""
    flow_for_high   = confidence in ("HIGH", "MEDIUM")   # proxy for flow_score ≥ 6
    flow_for_medium = confidence != "WEAK"               # proxy for flow_score ≥ 3
    if score >= 15 and flow_for_high:
        return "HIGH"
    if score >= 8 and flow_for_medium:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "LOW"


def _has_exec_sink(result):
    sinks = [s.lower() for s in (result.get("all_sinks") or [])]
    return any(
        "system" in s or "popen" in s or ("exec" in s and "dlsym" not in s and "dlopen" not in s)
        for s in sinks
    )


def _has_confirmed_exec_flow(result):
    if not result.get("verified_flows"):
        return result.get("confidence") in ("HIGH", "MEDIUM")
    for flow in result.get("verified_flows", []):
        verdict = flow.get("verdict")
        sink = (flow.get("sink_sym") or "").lower()
        if verdict in ("CONFIRMED", "LIKELY") and (
            sink == "system" or sink == "popen" or sink.startswith("exec")
        ):
            return True
    return False


def _retune_results(results, cgi_files=None, strict_high=False):
    has_web_scripts = bool(cgi_files)

    for r in results:
        if not has_web_scripts and r.get("input_type") == "socket":
            r["score"] = max(1, int(round(r["score"] * 0.7)))
            if r["level"] == "HIGH":
                r["level"] = "MEDIUM"
            elif r["level"] == "MEDIUM" and r["score"] < 8:
                r["level"] = "LOW"

        if strict_high and r.get("level") == "HIGH":
            user_controlled = r.get("controllability") == "HIGH"
            reachable = bool(r.get("web_exposed")) or bool(r.get("exploit_candidates"))
            sink_confirmed = _has_exec_sink(r) and _has_confirmed_exec_flow(r)
            if not (user_controlled and reachable and sink_confirmed):
                r["level"] = "MEDIUM"

    results.sort(key=lambda x: x["score"], reverse=True)


_SYSTEM_SHELL_DIRS = frozenset({
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
    "bin/", "sbin/", "usr/bin/", "usr/sbin/",
})


def _is_system_managed_shell_script(result):
    """
    Return True when a shell_var_injection result lives in a system utility
    directory and is not directly in a CGI/web path.

    These scripts (e.g. /sbin/wifi, /sbin/ipsec) are invoked by other system
    components, not directly by HTTP handlers.  A basename keyword match in a
    JS or Lua file (e.g. "wifi" in frame.js) is too weak to call them
    web-exposed — it is usually a UI label, not a process invocation.
    """
    if result.get("flow_type") != "shell_var_injection":
        return False
    bp = result.get("binary_path", "")
    rel = os.path.relpath(bp, SYSTEM_PATH).replace("\\", "/")
    return any(rel.startswith(d) for d in _SYSTEM_SHELL_DIRS)


def _is_generic_shell_utility(result):
    generic = {
        "sh", "ash", "bash", "busybox", "ls", "cat", "cp", "mv", "rm", "echo",
        "pwd", "test", "sleep", "grep", "sed", "awk", "tar", "gzip", "gunzip",
        "zcat", "dmesg", "ps", "top", "time", "free", "hexdump", "md5sum",
        "strings", "clear", "uptime", "pidof", "passwd",
        "hostname", "init", "reboot", "poweroff", "halt",
        "ifconfig", "route", "brctl",
    }
    name = (result.get("name") or "").lower()
    sinks = [s.lower() for s in (result.get("all_sinks") or [])]
    return name in generic or any("/bin/sh" in s or "shell=/bin/sh" in s for s in sinks)


def _is_direct_web_exposed(bp, cgi_files):
    bp = os.path.normpath(bp)
    cgi_norm = {os.path.normpath(p) for p in cgi_files}
    if bp in cgi_norm:
        return True

    rel = os.path.relpath(bp, SYSTEM_PATH).replace("\\", "/")
    base = os.path.basename(bp).lower()
    if base in {"httpd", "uhttpd", "lighttpd", "boa", "nginx", "mini_httpd", "thttpd"}:
        return True
    return any(part in rel for part in ("/www/", "/web/", "/cgi-bin/", "/htdocs/", "/webroot/")) or \
        rel.startswith(("www/", "web/", "cgi-bin/", "htdocs/", "webroot/"))


def _has_http_handler_surface(binary_path):
    if not binary_path or not os.path.isfile(binary_path):
        return False
    try:
        strings = extract_strings(binary_path)
    except Exception:
        return False
    return any(
        tok in s for s in strings
        for tok in ("/boafrm/", "formWlSiteSurvey", "formSiteSurveyProfile",
                    "cstecgi.cgi", "topicurl", "formUpload", "formFilter")
    )


_EXEC_PATH_RE = re.compile(r'(/(?:usr/)?s?bin/[A-Za-z0-9_.-]+)')
_EXEC_CMD_RE = re.compile(
    r'(?:system|popen|execlp?|execvp?|execve|execvpe)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HTTP_PATH_RE = re.compile(r'/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+(?:\.(?:cgi|asp|aspx|php|lua|htm|html|json|xml|js))?')
_PARAM_NAME_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]{1,31})=')
_AUTH_HINT_RE = re.compile(r'(login|auth|session|passwd|password|realm|token|cookie)', re.I)


def _extract_runtime_exec_deps(binary_path, rootfs):
    deps = set()
    try:
        strings = extract_strings(binary_path)
    except Exception:
        return deps

    for s in strings:
        for cmd_match in _EXEC_CMD_RE.finditer(s):
            cmd = cmd_match.group(1).strip()
            if cmd in ("/bin/sh", "sh", "/bin/ash", "ash"):
                continue
            if not any(ch in cmd for ch in (" ", "\t")) and cmd.endswith(("/bin/sh", "/bin/ash")):
                continue
            for m in _EXEC_PATH_RE.finditer(cmd):
                path = m.group(1)
                if path in ("/bin/sh", "/usr/bin/sh", "/bin/ash", "/usr/bin/ash"):
                    continue
                rel = path.lstrip("/")
                candidate = os.path.normpath(os.path.join(rootfs, rel))
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    deps.add(candidate)
    return deps


def _reprioritize_iot_results(results, web_bins, cgi_files):
    direct_web_bins = {os.path.normpath(p) for p in web_bins}
    web_reachable = set(direct_web_bins)
    by_path = {
        os.path.normpath(r.get("binary_path", "")): r
        for r in results if r.get("binary_path")
    }

    changed = True
    while changed:
        changed = False
        seeds = list(web_reachable)
        for bp in seeds:
            if not os.path.isfile(bp):
                continue
            for dep in _extract_runtime_exec_deps(bp, SYSTEM_PATH):
                if dep not in web_reachable:
                    web_reachable.add(dep)
                    changed = True

    for r in results:
        bp = os.path.normpath(r.get("binary_path", ""))
        direct_web = _is_direct_web_exposed(bp, cgi_files)
        handler_ref = _has_handler_binary_ref(bp, cgi_files)
        r["web_exposed"] = (
            direct_web
            or (handler_ref
                and not _is_generic_shell_utility(r)
                and not _is_system_managed_shell_script(r))
        )
        r["web_reachable"] = bp in web_reachable
        r["web_candidate"] = r["web_exposed"] or r["web_reachable"]
        r["handler_surface"] = _has_http_handler_surface(bp)

        if r["web_exposed"]:
            r["score"] = int(round(r["score"] * 1.8))
            if r["handler_surface"]:
                r["score"] += 4
        elif r["web_candidate"]:
            r["score"] = int(round(r["score"] * 1.2))
            r["level"] = _relevel(r["score"], r["confidence"])
        elif _is_generic_shell_utility(r):
            r["score"] = max(1, int(round(r["score"] * 0.4)))
            if r["level"] == "HIGH":
                r["level"] = "MEDIUM"
            elif r["level"] == "MEDIUM":
                r["level"] = "LOW"
        else:
            r["level"] = _relevel(r["score"], r["confidence"])

    results.sort(key=lambda x: (
        0 if x.get("handler_surface") else 1 if x.get("web_exposed") else 2 if x.get("web_reachable") else 3,
        -x["score"],
    ))


def _find_frontend_refs(binary_path, cgi_files):
    name = os.path.basename(binary_path)
    refs = []
    pattern = re.compile(
        r'(?:^|[\s\'"(/])' + re.escape(name) + r'(?:\s|["\'\);]|$)',
        re.IGNORECASE,
    )
    for script_path in cgi_files:
        try:
            content = open(script_path, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if pattern.search(content) or name in content:
            refs.append(os.path.relpath(script_path, _PROJECT_ROOT))
    return refs[:3]


def _has_handler_binary_ref(binary_path, cgi_files):
    bp = os.path.normpath(binary_path)
    if not bp or not cgi_files:
        return False

    rel = os.path.relpath(bp, SYSTEM_PATH).replace("\\", "/")
    base = os.path.basename(bp)
    exact_refs = {f"/{rel}".lower(), rel.lower()}
    base_pat = re.compile(
        r'(?:^|[\s\'"(/])' + re.escape(base) + r'(?:\s|["\'\);]|$)',
        re.IGNORECASE,
    )
    allow_basename = base.lower() not in {
        "sh", "ash", "bash", "busybox", "ls", "cat", "cp", "mv", "rm", "echo",
        "pwd", "test", "sleep", "grep", "sed", "awk", "tar", "gzip", "gunzip",
        "zcat", "dmesg", "ps", "top", "time", "free", "hexdump", "md5sum",
        "strings", "clear", "uptime", "pidof", "passwd",
    }

    # Pattern: command execution context — os.execute, luci.sys, system(),
    # popen(), io.popen(), or shell invocation string containing the binary.
    exec_ctx_pat = re.compile(
        r'(?:os\.execute|luci\.sys\.(?:call|exec)|io\.popen|popen|system)\s*\([^)]*'
        + re.escape(base),
        re.IGNORECASE,
    )

    for script_path in cgi_files:
        try:
            content = open(script_path, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        lower = content.lower()
        # Exact full-path reference always counts
        if any(ref in lower for ref in exact_refs):
            return True
        # Basename match only counts when found inside an exec/call context
        if allow_basename and exec_ctx_pat.search(content):
            return True
    return False


def _manual_review_hints(result, cgi_files):
    bp = result.get("binary_path", "")
    if not bp or not os.path.isfile(bp):
        return None
    if result.get("flow_type") == "container_signal":
        return {
            "binary": os.path.relpath(bp, _PROJECT_ROOT),
            "sink": "?",
            "frontend": [],
            "auth": [],
            "paths": [],
            "params": [],
            "control": "container-only",
        }

    sink = next(
        (s for s in (result.get("all_sinks") or [])
         if any(k in s.lower() for k in ("system", "popen", "exec"))),
        ((result.get("all_sinks") or [None])[0]),
    )

    try:
        strings = extract_strings(bp)
    except Exception:
        strings = []

    path_hits = []
    param_hits = []
    auth_hits = []
    for s in strings:
        for m in _HTTP_PATH_RE.finditer(s):
            hit = m.group(0)
            if hit not in path_hits and any(tok in hit for tok in ("/www", "/web", "/cgi-bin", ".cgi", ".asp", ".lua", ".php", ".htm")):
                path_hits.append(hit)
        for m in _PARAM_NAME_RE.finditer(s):
            key = m.group(1)
            if key.lower() not in ("http", "https", "content", "charset") and key not in param_hits:
                param_hits.append(key)
        m = _AUTH_HINT_RE.search(s)
        if m:
            hint = m.group(1).lower()
            if hint not in auth_hits:
                auth_hits.append(hint)

    frontend = _find_frontend_refs(bp, cgi_files)
    if not frontend:
        frontend = [os.path.relpath(p, _PROJECT_ROOT) for p in (_find_web_servers(SYSTEM_PATH)[:1] or _find_web_servers(VENDOR_PATH)[:1])]

    verified = result.get("verified_flows") or []
    arg_level = any(
        f.get("origin") in ("getenv", "fmt_buf", "arg_pass") or
        "arg(" in (f.get("flow_str") or "") or
        "system(" in (f.get("flow_str") or "")
        for f in verified
    )

    return {
        "binary": os.path.relpath(bp, _PROJECT_ROOT),
        "sink": sink or "?",
        "frontend": frontend[:2],
        "auth": auth_hits[:3],
        "paths": path_hits[:4],
        "params": param_hits[:6],
        "control": "argument-level" if arg_level else "coarse/granular",
    }


def _print_iot_entry(r, cgi_files=None):
    flow = r.get("flow_type") or "none"
    conf = r.get("confidence", "WEAK")
    ctrl = r.get("controllability", "?")
    mem  = r.get("memory_impact", "?")
    tc   = r.get("taint_confidence", 0.0)
    tag  = "[WEB]" if r.get("web_exposed") else f"[{r['level']}]"

    print(f"\n  {tag} {r['name']}", flush=True)
    print(f"    score={r['score']}  level={r['level']}  ctrl={ctrl}  mem_impact={mem}",
          flush=True)
    print(f"    input={r['input_type']}  priv={r['priv']}  "
          f"flow={flow}  conf={conf}  taint={tc:.2f}", flush=True)

    bp = r.get("binary_path", r["exec"])
    try:
        bp = os.path.relpath(bp, _PROJECT_ROOT)
    except ValueError:
        pass
    print(f"    path:  {bp}", flush=True)

    all_sinks = r.get("all_sinks") or r.get("sinks") or []
    if all_sinks:
        print(f"    sinks: {', '.join(all_sinks)}", flush=True)

    for hint in r.get("fuzzing_hints", []):
        print(f"    → {hint}", flush=True)

    if r.get("web_exposed") and cgi_files is not None:
        review = _manual_review_hints(r, cgi_files)
        if review:
            print(f"    review binary:   {review['binary']}", flush=True)
            print(f"    review sink:     {review['sink']}", flush=True)
            print(f"    review frontend: {', '.join(review['frontend']) if review['frontend'] else '?'}", flush=True)
            print(f"    review auth:     {', '.join(review['auth']) if review['auth'] else 'none seen'}", flush=True)
            print(f"    review paths:    {', '.join(review['paths']) if review['paths'] else 'none seen'}", flush=True)
            print(f"    review params:   {', '.join(review['params']) if review['params'] else 'none seen'}", flush=True)
            print(f"    review control:  {review['control']}", flush=True)


_SCRIPT_CMD_PATTERNS = re.compile(
    r'\b(?:os\.execute|io\.popen|luci\.sys\.(?:call|exec)|nixio\.exec'
    r'|os\.exec|subprocess\.call|subprocess\.Popen'
    r'|system\s*\(|popen\s*\()\b',
    re.IGNORECASE,
)
_SCRIPT_INPUT_PATTERNS = re.compile(
    r'\b(?:luci\.http\.formvalue|luci\.http\.content|luci\.http\.getenv'
    r'|http\.formvalue|QUERY_STRING|REQUEST_METHOD|CONTENT_LENGTH'
    r'|getenv|argv|formvalue|getparam)\b',
    re.IGNORECASE,
)
_SCRIPT_FMT_PATTERNS = re.compile(
    r'(?:string\.format|%\s*\.\s*\w+|"%s"|"%d"|\.\.\s*\w+)',
    re.IGNORECASE,
)


def _synthesize_script_flow(result, strings):
    """
    Produce a heuristic LIKELY verified_flow for Lua/shell scripts that
    have no ELF imports.

    Guards (all must pass — precision first):
      1. flow_type is cmd_injection / file_path_injection / file_cmd_injection
      2. web_exposed = True (already confirmed by surface scan)
      3. String evidence of a command execution pattern in the script
      4. String evidence of HTTP input (luci.http.formvalue, getenv, etc.)
      5. taint_confidence >= 0.3

    Returns [] when guards fail.
    """
    if not result.get("web_exposed"):
        return []
    if result.get("taint_confidence", 0.0) < 0.3:
        return []

    content = "\n".join(strings) if strings else ""
    has_cmd    = bool(_SCRIPT_CMD_PATTERNS.search(content))
    has_input  = bool(_SCRIPT_INPUT_PATTERNS.search(content))
    has_fmt    = bool(_SCRIPT_FMT_PATTERNS.search(content))

    if not has_cmd or not has_input:
        return []

    # Find a representative command pattern for the flow string
    cmd_m = _SCRIPT_CMD_PATTERNS.search(content)
    inp_m = _SCRIPT_INPUT_PATTERNS.search(content)
    cmd_str = cmd_m.group(0) if cmd_m else "os.execute"
    inp_str = inp_m.group(0) if inp_m else "formvalue"

    verdict = 'LIKELY' if has_fmt else 'UNCERTAIN'

    return [{
        'func_va':   None,
        'func_sym':  '(script-heuristic)',
        'sink_sym':  cmd_str,
        'sink_va':   None,
        'origin':    f"HTTP input ({inp_str})",
        'sanitized': False,
        'flow_str':  f"{inp_str}() → {cmd_str}()",
        'reason':    (f"Script-level: HTTP input ({inp_str}) reaches command sink "
                      f"({cmd_str})"
                      + (" via format string" if has_fmt else "")),
        'verdict':   verdict,
        'fmt_templates': [],
        'cgi_vars':  [],
    }]


def _run_deep_verification(results, top_n=10):
    """
    Run verify_exploitable_flows() on the top-N HIGH/WEB candidates.
    Attaches a 'verified_flows' list to each result dict.
    Operates on at most top_n results to keep runtime bounded.
    """
    from analyzer.elf_analyzer import build_call_graph
    from analyzer.strings_analyzer import extract_strings

    candidates = [r for r in results
                  if r.get("web_exposed") or r["level"] in ("HIGH", "MEDIUM")][:top_n]

    for r in candidates:
        bp = r.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            r["verified_flows"] = []
            continue

        try:
            cg      = build_call_graph(bp)
            imports = r.get("_imports")      # set by risk.py if available
            # Always extract strings for heuristic path — needed to detect
            # CGI env vars and format templates on MIPS/ARM32/script files.
            strings = extract_strings(bp)
            flows   = verify_exploitable_flows(bp, cg or {},
                                               imports=imports,
                                               strings=strings)

            # Script fallback: Lua/shell with cmd_injection but no ELF imports
            # → synthesise a LIKELY flow from string-level evidence.
            if not flows and r.get("flow_type") in (
                    "cmd_injection", "file_path_injection", "file_cmd_injection"):
                flows = _synthesize_script_flow(r, strings)

            r["verified_flows"] = flows
        except Exception:
            r["verified_flows"] = []


def _print_verified_flows(results):
    """
    Print the CONFIRMED / LIKELY flows found by deep verification.
    Skips FALSE_POSITIVE results entirely.
    Returns True if any actionable flows were printed.
    """
    _VERDICT_LABEL = {
        'CONFIRMED': '!! CONFIRMED',
        'LIKELY':    '?  LIKELY   ',
        'UNCERTAIN': '~  UNCERTAIN',
    }
    printed_any = False

    for r in results:
        flows = r.get("verified_flows", [])
        actionable = [f for f in flows if f['verdict'] != 'FALSE_POSITIVE']
        if not actionable:
            continue

        tag = "[WEB]" if r.get("web_exposed") else f"[{r['level']}]"
        print(f"\n  {tag} {r['name']}  (score={r['score']})", flush=True)

        bp = r.get("binary_path", r["exec"])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        print(f"    path: {bp}", flush=True)

        for f in actionable:
            label  = _VERDICT_LABEL.get(f['verdict'], f['verdict'])
            fsym   = f.get('func_sym') or hex(f['func_va']) if f.get('func_va') else '(heuristic)'
            sink   = f['sink_sym']
            flow   = f['flow_str']
            reason = f['reason']
            print(f"    [{label}]  func={fsym}  sink={sink}", flush=True)
            print(f"      flow:   {flow}", flush=True)
            print(f"      reason: {reason}", flush=True)
        printed_any = True

    return printed_any


def _print_exploit_candidates(candidates):
    """
    Print the final list of remotely reachable, exploitable flows.

    Format per candidate:
      endpoint   — URL or port
      binary + function
      parameter  — HTTP param → env var → sink
      scenario   — 1–2 line exploit description
    """
    if not candidates:
        return False

    _AUTH_LABEL = {
        True:  'AUTHENTICATED',
        False: 'UNAUTHENTICATED',
        None:  'AUTH-UNKNOWN',
    }
    _VERDICT_MARK = {
        'CONFIRMED': '!! ',
        'LIKELY':    '?  ',
        'UNCERTAIN': '~  ',
    }

    for idx, entry in enumerate(candidates, 1):
        r      = entry['result']
        flow   = entry['flow']
        reach  = entry['reach']

        verdict  = flow['verdict']
        mark     = _VERDICT_MARK.get(verdict, '   ')
        auth_req = reach['auth_required']
        auth_lbl = _AUTH_LABEL.get(auth_req, 'AUTH-UNKNOWN')
        unauth   = '  ★' if auth_req is False else ''

        print(f"\n  ── Exploit #{idx}  [{mark}{verdict}]  [{auth_lbl}]{unauth}",
              flush=True)

        # Endpoint
        ep = reach.get('endpoint') or '(unknown endpoint)'
        print(f"    endpoint:  {ep}", flush=True)

        # Handler script
        handler = reach.get('handler')
        if handler:
            print(f"    handler:   {handler}", flush=True)

        # Binary + function
        bp = r.get('binary_path', r['exec'])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        fsym = flow.get('func_sym') or '(unknown)'
        sink = flow.get('sink_sym', '?')
        print(f"    binary:    {bp}", flush=True)
        print(f"    function:  {fsym}  →  {sink}()", flush=True)

        # Input parameter chain
        param  = reach.get('input_param', '?')
        method = reach.get('input_method', '?')
        origin = flow.get('flow_str', flow.get('origin', '?'))
        print(f"    input:     {method} param '{param}'  →  {origin}", flush=True)

        # Auth evidence
        if reach.get('auth_evidence'):
            print(f"    auth:      {reach['auth_evidence']}", flush=True)

        # Exploit scenario
        scenario = reach.get('exploit_scenario')
        if scenario:
            print(f"    scenario:", flush=True)
            for line in scenario.splitlines():
                print(f"      {line}", flush=True)

        # Other invoking handlers (if multiple)
        others = (reach.get('all_invokers') or [])[1:3]
        if others:
            print(f"    also via:", flush=True)
            for rel, url in others:
                print(f"      {rel}  ({url})", flush=True)

    return True


def _safe_relpath(path):
    if not path:
        return path
    try:
        return os.path.relpath(path, _PROJECT_ROOT)
    except ValueError:
        return path


def _json_safe(value):
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted(_json_safe(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _candidate_id(result):
    base = os.path.basename(result.get("binary_path") or result.get("exec") or result.get("name") or "candidate")
    base = re.sub(r'[^A-Za-z0-9._-]+', "-", base).strip("-") or "candidate"
    suffix = result.get("name") or base
    suffix = re.sub(r'[^A-Za-z0-9._-]+', "-", suffix).strip("-") or "target"
    return f"{base}__{suffix}".lower()


def _result_path(result):
    return _safe_relpath(result.get("binary_path", result.get("exec")))


def _next_steps_for_result(result, review=None, exploit_paths=None):
    """
    Generate Ghidra-specific, ordered analysis steps for Stage-2 review.

    Priority:
      1. Confirmed function VA / handler symbol → "decompile this exact function"
      2. Config key tracing → "trace nvram_get('wan_ip') to sink"
      3. Injection template → "search string in Ghidra"
      4. Hardening context → exploitation difficulty notes
      5. Cross-binary chain → "verify writer + reader binary pair"
      6. Entry point / PoC sketch
    """
    steps  = []
    path   = _result_path(result)
    sinks  = list((result.get('all_sinks') or result.get('sinks') or []))[:2]
    sink_s = ', '.join(sinks) if sinks else 'dangerous function'
    if result.get("flow_type") == "container_signal":
        marker_lines = []
        for marker in (result.get("container_markers") or [])[:3]:
            offset = marker.get("offset")
            offset_text = f"0x{offset:x}" if isinstance(offset, int) and offset >= 0 else "unknown offset"
            marker_lines.append(f"{marker.get('detail', marker.get('kind', 'marker'))} at {offset_text}")
        payload_offset = result.get("payload_offset")
        payload_offset_text = (
            f"0x{payload_offset:x}"
            if isinstance(payload_offset, int) and payload_offset >= 0
            else "unknown"
        )
        ciphertext_offset = result.get("ciphertext_offset")
        ciphertext_offset_text = (
            f"0x{ciphertext_offset:x}"
            if isinstance(ciphertext_offset, int) and ciphertext_offset >= 0
            else None
        )
        steps.append(
            f"Inspect the container header in `{os.path.basename(path or '')}` and confirm the detected markers: "
            + (", ".join(marker_lines) if marker_lines else "vendor-specific crypto/signature metadata")
            + "."
        )
        steps.append(
            f"Carve the opaque payload starting at `{payload_offset_text}` before attempting decryption or signature bypass."
        )
        vendor_guess = result.get("vendor_guess")
        if vendor_guess:
            steps.append(
                f"Treat this as `{vendor_guess}` and search the vendor GPL/update utility for the matching decrypt or verify routine."
            )
        if result.get("openssl_salt") and ciphertext_offset_text:
            steps.append(
                f"OpenSSL salted container detected: salt=`{result['openssl_salt']}` and ciphertext starts at `{ciphertext_offset_text}`."
            )
        if result.get("crypto_profile") == "openssl-enc-compatible salted payload":
            steps.append(
                "Treat the header as OpenSSL `enc`-style salt framing and start decryption probes with AES-CBC plus EVP_BytesToKey-style KDFs (commonly MD5 or SHA-256)."
            )
        fp = result.get("ciphertext_fingerprint") or {}
        if fp.get("likely_block_ciphertext"):
            steps.append(
                f"Ciphertext fingerprint looks like block-cipher output "
                f"(entropy≈{fp.get('entropy_first_mib')}, 16-byte aligned, no repeated 16-byte blocks in first 4 KiB)."
            )
        steps.append(
            "Do not trace random HTTP params from string noise. First recover the payload format or decryption key schedule."
        )
        return steps[:5]

    # ── 1. Start point in Ghidra ──────────────────────────────────────────────
    verified     = result.get('verified_flows') or []
    confirmed    = [f for f in verified if f.get('verdict') in ('CONFIRMED', 'LIKELY')]
    handler_syms = result.get('handler_symbols') or []
    templates    = result.get('injection_templates') or []

    if confirmed:
        f   = confirmed[0]
        va  = f'0x{f["func_va"]:x}' if isinstance(f.get('func_va'), int) else None
        sym = f.get('func_sym')
        ref = sym or va
        verdict = 'CONFIRMED' if f.get('verdict') == 'CONFIRMED' else 'LIKELY'
        if ref:
            steps.append(
                f"Decompile `{ref}` in Ghidra "
                f"[{verdict} → {f.get('sink_sym', sink_s)}]. "
                f"This is the confirmed vulnerable function."
            )
    elif handler_syms:
        steps.append(
            f"In Ghidra search Functions → `{handler_syms[0]}`. "
            f"Decompile and trace the call chain to {sink_s}."
        )
    elif templates:
        short = templates[0][:55].rstrip()
        steps.append(
            f"In Ghidra search Strings for `{short}`. "
            f"The function referencing it leads to {sink_s}."
        )
    else:
        steps.append(
            f"Load `{os.path.basename(path or '')}` in Ghidra. "
            f"Search Imports for {sink_s} and trace all callers."
        )

    # ── 2. Config key tracing ─────────────────────────────────────────────────
    config_keys = result.get('config_keys') or []
    if config_keys:
        key_sample = ', '.join(f'"{k}"' for k in config_keys[:3])
        steps.append(
            f"Trace `nvram_get`/`mib_get` calls with keys {key_sample}. "
            f"Confirm the returned value reaches {sink_s} without sanitisation."
        )

    # ── 3. HTTP parameter / exploit entry point ───────────────────────────────
    if exploit_paths:
        ep    = exploit_paths[0].get('endpoint', '?')
        param = exploit_paths[0].get('input_param', '?')
        auth  = exploit_paths[0].get('auth_required')
        auth_s = 'UNAUTHENTICATED' if auth is False else 'requires auth'
        steps.append(
            f"Craft PoC: `{ep}` [{auth_s}] — "
            f"inject payload in `{param}` parameter."
        )
    elif review and review.get('params'):
        params = ', '.join(review['params'][:3])
        steps.append(
            f"HTTP params `{params}` are attacker-controlled. "
            f"Confirm they reach {sink_s} without sanitisation."
        )
    elif result.get('web_exposed'):
        steps.append(
            "Confirm HTTP handler routing and auth enforcement "
            "before tracing to sink."
        )

    # ── 4. Hardening exploitation notes ──────────────────────────────────────
    h = result.get('hardening') or {}
    if h:
        notes = []
        if not h.get('canary') and not h.get('pie'):
            notes.append('no canary + no PIE → overflow → ROP at fixed addresses')
        elif not h.get('canary'):
            notes.append('no stack canary → overflows not detected at runtime')
        elif not h.get('pie'):
            notes.append('no PIE → static addresses ease ROP')
        if not h.get('relro'):
            notes.append('no RELRO → GOT overwrite viable')
        if notes:
            steps.append('Exploitation: ' + '; '.join(notes) + '.')

    # ── 5. Cross-binary chain ─────────────────────────────────────────────────
    cc = result.get('cross_chain')
    if cc and cc.get('writer') and cc.get('shared_keys'):
        writer = os.path.basename(cc['writer'])
        keys   = ', '.join(f'"{k}"' for k in cc['shared_keys'][:3])
        steps.append(
            f"Cross-binary chain: `{writer}` writes {keys}; "
            f"this binary reads and passes to {sink_s}. "
            f"Verify the writer binary in Ghidra too."
        )

    # ── 6. Missing-link targeted steps ────────────────────────────────────────
    # For each unconfirmed chain element, generate a specific investigation step.
    # These map directly to the review_checklist gates so analysts know exactly
    # what evidence would upgrade this candidate to CONFIRMED.
    for link in (result.get('missing_links') or []):
        if len(steps) >= 5:
            break
        if link == "exact_input_unknown":
            steps.append(
                "Identify the specific form parameter that reaches the sink. "
                "Check the HTML frontend for field names; search those names in "
                "Ghidra to confirm they appear in the same function as the sink call."
            )
        elif link == "auth_boundary_unknown":
            steps.append(
                "Confirm auth requirement: locate the session/cookie check before "
                "the vulnerable handler in Ghidra. If absent, the path may be "
                "pre-auth; if present, test whether the check is bypassable."
            )
        elif link == "dispatch_unknown":
            steps.append(
                "Verify how this binary is invoked from the web stack. "
                "Search CGI scripts and web configs for the binary name, or trace "
                "the HTTP dispatcher's handler table in Ghidra."
            )
        elif link == "chain_gap_unknown":
            steps.append(
                "Identify the intermediate hop between input and sink. "
                "Look for nvram_get/mib_get/config_get calls immediately before "
                "the sink; confirm the key was written with attacker-controlled data."
            )

    return steps[:5]


def _build_result_snapshot(result, cgi_files=None, exploit_paths=None):
    review = _manual_review_hints(result, cgi_files or []) if cgi_files is not None else None
    verified = [
        flow for flow in (result.get("verified_flows") or [])
        if flow.get("verdict") != "FALSE_POSITIVE"
    ]
    raw_name = result.get("name")
    display_name = _choose_candidate_label(
        raw_name,
        result.get("endpoints") or [],
        result.get("handler_symbols") or [],
    )
    return {
        "id": _candidate_id(result),
        "name": display_name,
        "raw_name": raw_name,
        "level": result.get("level"),
        "score": result.get("score"),
        "binary_path": _result_path(result),
        "exec": result.get("exec"),
        "source": result.get("source"),
        "input_type": result.get("input_type"),
        "priv": result.get("priv"),
        "flow_type": result.get("flow_type"),
        "confidence": result.get("confidence"),
        "controllability": result.get("controllability"),
        "memory_impact": result.get("memory_impact"),
        "taint_confidence": result.get("taint_confidence"),
        "web_exposed": result.get("web_exposed", False),
        "web_reachable": result.get("web_reachable", False),
        "web_candidate": result.get("web_candidate", False),
        "handler_surface": result.get("handler_surface", False),
        "all_sinks": list(result.get("all_sinks") or result.get("sinks") or []),
        "container_markers": _json_safe(result.get("container_markers") or []),
        "vendor_guess": result.get("vendor_guess") or "",
        "payload_offset": result.get("payload_offset"),
        "payload_size": result.get("payload_size"),
        "ciphertext_offset": result.get("ciphertext_offset"),
        "ciphertext_size": result.get("ciphertext_size"),
        "openssl_salt": result.get("openssl_salt"),
        "crypto_profile": result.get("crypto_profile") or "",
        "ciphertext_fingerprint": _json_safe(result.get("ciphertext_fingerprint") or {}),
        "attack_surface": _json_safe(result.get("attack_surface", {})),
        "fuzzing_hints": list(result.get("fuzzing_hints") or []),
        "manual_review": _json_safe(review),
        "verified_flows": _json_safe(verified),
        "exploit_paths": _json_safe(exploit_paths or []),

        # ── Gap 1–6 exploit-context fields ───────────────────────────────────
        "vuln_summary":        result.get("vuln_summary") or "",
        "hardening":           _json_safe(result.get("hardening") or {}),
        "endpoints":           list(result.get("endpoints") or []),
        "injection_templates": list(result.get("injection_templates") or []),
        "config_keys":         list(result.get("config_keys") or []),
        "handler_symbols":     list(result.get("handler_symbols") or []),
        "auth_bypass":         result.get("auth_bypass", "required"),
        "toctou_risk":         bool(result.get("toctou_risk", False)),
        "cross_chain":         _json_safe(result.get("cross_chain")),

        # Actionability and missing-link assessment.
        "actionability_bonus": result.get("actionability_bonus", 0),
        "missing_links":       list(result.get("missing_links") or []),
        "plausibility_bonus":  result.get("plausibility_bonus", 0),

        # CVE triage score — mirrors bundle["cve_candidates"] ranking key.
        "triage_score": explain_triage(result)[0],

        # Structured Ghidra hints — ready for direct MCP tool call construction.
        "ghidra_hints": {
            "binary_path":     _result_path(result),
            "search_functions": list(result.get("handler_symbols") or [])[:3],
            "search_strings":  list(result.get("injection_templates") or [])[:2],
            "nvram_keys":      list(result.get("config_keys") or [])[:5],
            "sink_imports":    list((result.get("all_sinks") or []))[:3],
            "confirmed_vas": [
                hex(f["func_va"]) if isinstance(f.get("func_va"), int) else f.get("func_sym")
                for f in (result.get("verified_flows") or [])
                if f.get("verdict") in ("CONFIRMED", "LIKELY")
                   and (f.get("func_va") or f.get("func_sym"))
            ][:3],
        },

        "next_steps": _next_steps_for_result(result, review=review, exploit_paths=exploit_paths),
    }


def _build_exploit_snapshot(entry):
    result = entry["result"]
    flow = entry["flow"]
    reach = entry["reach"]
    return {
        "candidate_id": _candidate_id(result),
        "candidate_name": result.get("name"),
        "binary_path": _result_path(result),
        "endpoint": reach.get("endpoint"),
        "handler": reach.get("handler"),
        "auth_required": reach.get("auth_required"),
        "auth_evidence": reach.get("auth_evidence"),
        "input_param": reach.get("input_param"),
        "input_method": reach.get("input_method"),
        "verdict": flow.get("verdict"),
        "function": flow.get("func_sym"),
        "sink": flow.get("sink_sym"),
        "flow": flow.get("flow_str"),
        "reason": flow.get("reason"),
        "scenario": reach.get("exploit_scenario"),
        "all_invokers": _json_safe(reach.get("all_invokers") or []),
    }


def _is_actionable_dossier_candidate(result):
    if result.get("web_exposed"):
        return True
    if any(flow.get("verdict") != "FALSE_POSITIVE" for flow in (result.get("verified_flows") or [])):
        return True
    if result.get("exploit_paths"):
        return True
    if result.get("level") == "HIGH" and result.get("web_candidate"):
        return True
    return False


def _write_candidate_dossiers(results, output_dir, cgi_files=None, exploit_candidates=None):
    if not output_dir:
        return []

    os.makedirs(output_dir, exist_ok=True)
    exploit_by_id = {}
    for entry in exploit_candidates or []:
        exploit_by_id.setdefault(_candidate_id(entry["result"]), []).append(_build_exploit_snapshot(entry))

    dossiers = []
    for result in results:
        snapshot = _build_result_snapshot(
            result,
            cgi_files=cgi_files,
            exploit_paths=exploit_by_id.get(_candidate_id(result), []),
        )
        if not _is_actionable_dossier_candidate(snapshot):
            continue
        md_path = os.path.join(output_dir, f"{snapshot['id']}.md")
        # ── Header ───────────────────────────────────────────────────────────
        vuln_sum = snapshot.get('vuln_summary') or ''
        lines = [
            f"# {snapshot['name']}",
            "",
            f"> {vuln_sum}" if vuln_sum else "",
            "",
            f"- **id**: `{snapshot['id']}`",
            f"- **level**: `{snapshot['level']}`  score: `{snapshot['score']}`",
            f"- **binary**: `{snapshot['binary_path']}`",
            f"- **flow**: `{snapshot['flow_type'] or 'none'}`  "
            f"confidence: `{snapshot.get('confidence', '?')}`  "
            f"taint: `{snapshot.get('taint_confidence', 0):.2f}`",
            f"- **sinks**: `{', '.join(snapshot['all_sinks']) if snapshot['all_sinks'] else 'none'}`",
            f"- **controllability**: `{snapshot.get('controllability', '?')}`  "
            f"memory impact: `{snapshot.get('memory_impact', '?')}`",
        ]
        lines = [l for l in lines if l != ""]   # drop blank conditional lines

        # ── Ghidra Analysis Brief ────────────────────────────────────────────
        # This section is the ready-to-paste context for Claude Code + Ghidra.
        h = snapshot.get('hardening') or {}
        hard_parts = []
        if not h.get('canary'): hard_parts.append('no canary')
        if not h.get('pie'):    hard_parts.append('no PIE')
        if not h.get('relro'):  hard_parts.append('no RELRO')
        hard_str = ' · '.join(hard_parts) + ' → unprotected binary' if hard_parts else 'hardened'

        auth_val = snapshot.get('auth_bypass', 'required')
        auth_str = {
            'none':       'UNAUTHENTICATED (no auth guard)',
            'bypassable': 'BYPASSABLE (HNAP/no-auth hint)',
            'required':   'authenticated required',
        }.get(auth_val, auth_val)

        ep_list      = snapshot.get('endpoints') or []
        tmpl_list    = snapshot.get('injection_templates') or []
        key_list     = snapshot.get('config_keys') or []
        sym_list     = snapshot.get('handler_symbols') or []
        hints        = snapshot.get('ghidra_hints') or {}
        conf_vas     = hints.get('confirmed_vas') or []
        search_fns   = hints.get('search_functions') or []
        search_strs  = hints.get('search_strings') or []

        start_hint = (
            f"decompile `{conf_vas[0]}` (confirmed function)" if conf_vas else
            f"search Functions → `{search_fns[0]}`"          if search_fns else
            f"search Strings → `{search_strs[0][:45]}`"      if search_strs else
            f"find {', '.join((snapshot.get('all_sinks') or [])[:1])} in Imports, trace callers"
        )
        exploit_paths_snap = snapshot.get('exploit_paths') or []
        entry_str = '(unknown)'
        if exploit_paths_snap:
            ep0    = exploit_paths_snap[0]
            ep_url = ep0.get('endpoint', '?')
            ep_aut = 'UNAUTHENTICATED' if ep0.get('auth_required') is False else 'auth'
            ep_par = ep0.get('input_param', '?')
            entry_str = f"{ep_url} [{ep_aut}] param `{ep_par}`"
        elif ep_list:
            entry_str = ep_list[0]

        chain_hint = ''
        review_snap = snapshot.get('manual_review') or {}
        params = review_snap.get('params') or []
        if params and key_list:
            chain_hint = (
                f"HTTP `{params[0]}` → nvram_set(`{key_list[0]}`) "
                f"→ [restart] → nvram_get(`{key_list[0]}`) "
                f"→ {(snapshot.get('all_sinks') or ['sink'])[0]}"
            )
        elif key_list:
            chain_hint = (
                f"nvram_get(`{key_list[0]}`) "
                f"→ {(snapshot.get('all_sinks') or ['sink'])[0]}"
            )

        lines += [
            "",
            "## Ghidra Analysis Brief",
            f"- **Vulnerability**: {vuln_sum}",
            f"- **Start**: {start_hint}",
        ]
        if chain_hint:
            lines.append(f"- **Trace**: {chain_hint}")
        lines += [
            f"- **Protections**: {hard_str}",
            f"- **Entry**: {entry_str}",
        ]

        # ── Triage Notes ─────────────────────────────────────────────────────
        # Explains why this candidate ranked here and what is still unknown.
        # Matches the information a human / Claude analyst wants immediately.
        act_bonus   = snapshot.get('actionability_bonus', 0)
        miss_links  = snapshot.get('missing_links') or []
        plaus_bonus = snapshot.get('plausibility_bonus', 0)

        _ACT_REASON = []
        if act_bonus >= 8:
            _ACT_REASON.append("named function visible in strings (concrete Ghidra target)")
        if act_bonus >= 14:
            _ACT_REASON.append("high-information sink artifact (reveals exact operation)")
        elif act_bonus >= 6:
            _ACT_REASON.append("explicit sink string carries operation detail")
        _specific_ep_tokens = ("/boafrm/", "/goform/", "cstecgi", "/hnap1/")
        if any(tok in (ep or "").lower()
               for ep in ep_list
               for tok in _specific_ep_tokens):
            _ACT_REASON.append("specific form-handler endpoint named")
        if act_bonus > 0 and not _ACT_REASON:
            _ACT_REASON.append(f"actionability signals present (bonus={act_bonus})")

        _MISS_LABEL = {
            "exact_input_unknown":   "exact input field not yet mapped to sink",
            "auth_boundary_unknown": "auth boundary not yet confirmed",
            "dispatch_unknown":      "dispatch path not yet confirmed",
            "chain_gap_unknown":     "intermediate hop still inferred only",
            "too_many_unknowns":     "multiple chain elements unconfirmed (score penalised)",
        }

        # Plausibility note: explain what the plausibility adjustment reflects.
        if plaus_bonus >= 3:
            _plaus_note = f"+{plaus_bonus} (direct-path templates; tightly coupled evidence)"
        elif plaus_bonus > 0:
            _plaus_note = f"+{plaus_bonus} (some direct-path evidence)"
        elif plaus_bonus == 0:
            _plaus_note = "0 (neutral — no strong evidence either way)"
        elif plaus_bonus >= -3:
            _plaus_note = f"{plaus_bonus} (error/crash-path evidence; uncertain execution path)"
        else:
            _plaus_note = f"{plaus_bonus} (evidence largely from error handlers; sanitization likely)"

        triage_lines = ["", "## Triage Notes"]
        if _ACT_REASON:
            triage_lines.append(f"- **Why interesting**: {'; '.join(_ACT_REASON)}")
        else:
            triage_lines.append("- **Why interesting**: structural signals only (no named-function evidence)")
        if miss_links:
            visible = [l for l in miss_links if l != "too_many_unknowns"]
            labels  = [_MISS_LABEL.get(l, l) for l in visible]
            triage_lines.append(f"- **Missing links**: {'; '.join(labels) if labels else 'none'}")
            if "too_many_unknowns" in miss_links:
                triage_lines.append("- **Score penalty**: −25% applied (too many unconfirmed links)")
        else:
            triage_lines.append("- **Missing links**: none identified")
        triage_lines.append(f"- **Plausibility**: {_plaus_note}")
        lines += triage_lines

        # ── Exploit Context ──────────────────────────────────────────────────
        lines += [
            "",
            "## Exploit Context",
            f"- **Hardening**: {hard_str}",
            f"- **Auth**: {auth_str}",
        ]
        if ep_list:
            lines.append(f"- **Endpoints**: {', '.join(ep_list[:4])}")
        if tmpl_list:
            lines.append(f"- **Injection template**: `{tmpl_list[0][:80]}`")
            for t in tmpl_list[1:2]:
                lines.append(f"- **Injection template**: `{t[:80]}`")
        if key_list:
            lines.append(f"- **Config keys**: {', '.join(key_list[:8])}")
        if sym_list:
            lines.append(f"- **Handler symbols**: {', '.join(sym_list[:5])}")
        if snapshot.get('toctou_risk'):
            lines.append("- **TOCTOU risk**: check-then-use race condition pattern detected")

        # ── Manual Review ────────────────────────────────────────────────────
        review = snapshot.get("manual_review") or {}
        if review:
            lines.extend([
                "",
                "## Manual Review",
                f"- **frontend**: `{', '.join(review.get('frontend') or []) or 'none'}`",
                f"- **params**: `{', '.join(review.get('params') or []) or 'none'}`",
                f"- **auth hints**: `{', '.join(review.get('auth') or []) or 'none'}`",
                f"- **control**: `{review.get('control') or 'unknown'}`",
            ])

        # ── Verified Flows ───────────────────────────────────────────────────
        if snapshot["verified_flows"]:
            lines.append("")
            lines.append("## Verified Flows")
            for flow in snapshot["verified_flows"][:5]:
                va_str = f" @ {hex(flow['func_va'])}" if isinstance(flow.get('func_va'), int) else ""
                lines.append(
                    f"- `{flow.get('verdict')}` "
                    f"{flow.get('func_sym') or '(heuristic)'}{va_str}"
                    f" → {flow.get('sink_sym')} :: {flow.get('flow_str')}"
                )

        # ── Reachability ─────────────────────────────────────────────────────
        if snapshot["exploit_paths"]:
            lines.append("")
            lines.append("## Reachability")
            for exploit in snapshot["exploit_paths"][:5]:
                auth_lbl = (
                    'UNAUTHENTICATED' if exploit.get('auth_required') is False
                    else 'auth-required' if exploit.get('auth_required')
                    else 'auth-unknown'
                )
                lines.append(
                    f"- `{exploit.get('verdict')}` "
                    f"endpoint `{exploit.get('endpoint') or '?'}` "
                    f"param `{exploit.get('input_param') or '?'}` "
                    f"[{auth_lbl}]"
                )

        # ── Cross-Binary Chain ───────────────────────────────────────────────
        cc = snapshot.get('cross_chain')
        if cc and cc.get('writer'):
            writer_name = os.path.basename(cc['writer'])
            shared      = cc.get('shared_keys') or []
            lines += [
                "",
                "## Cross-Binary Chain",
                f"- **Writer**: `{writer_name}` — writes {', '.join(repr(k) for k in shared[:3])} via nvram_set",
                f"- **Reader**: `{snapshot['name']}` (this binary) — reads and passes to sink",
                f"- **Shared keys**: {', '.join(shared[:5])}",
                f"- **Action**: verify both binaries in Ghidra to confirm the full chain",
            ]

        # ── Next Steps ───────────────────────────────────────────────────────
        lines.append("")
        lines.append("## Next Steps")
        for i, step in enumerate(snapshot["next_steps"], 1):
            lines.append(f"{i}. {step}")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        dossiers.append({
            "candidate_id": snapshot["id"],
            "path": _safe_relpath(md_path),
        })
    return dossiers


def _write_output_bundle(output_path, bundle):
    if not output_path:
        return
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(_json_safe(bundle), fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"\n[OK] Wrote structured results: {output_path}", flush=True)


def _export_ghidra_targets(cve_top, run_dir):
    """
    Copy each CVE-candidate binary into <run_dir>/ghidra_targets/ so the
    analyst can drag-and-drop the folder straight into Ghidra.

    Deduplicates by resolved source path (one copy even if the same binary
    appears under multiple candidate names).

    Returns a list of dicts:
      {"name": str, "src": str, "dest": str}  — paths relative to project root
    """
    if not run_dir or not cve_top:
        return []

    target_dir = os.path.join(run_dir, "ghidra_targets")
    os.makedirs(target_dir, exist_ok=True)

    copied = []
    seen_src = set()

    for c in cve_top:
        rel = c.get("binary_path") or ""
        if not rel:
            continue

        # binary_path is relative to project root
        abs_src = os.path.join(_PROJECT_ROOT, rel)
        abs_src = os.path.normpath(abs_src)

        if not os.path.isfile(abs_src):
            continue
        if abs_src in seen_src:
            continue
        seen_src.add(abs_src)

        dest_name = os.path.basename(abs_src)
        abs_dest  = os.path.join(target_dir, dest_name)

        # Avoid redundant copies on re-runs
        if not os.path.exists(abs_dest) or os.path.getsize(abs_dest) != os.path.getsize(abs_src):
            shutil.copy2(abs_src, abs_dest)

        copied.append({
            "name": c.get("name", dest_name),
            "src":  rel,
            "dest": _safe_relpath(abs_dest),
        })

    return copied


def _export_container_targets(results, run_dir):
    """
    Carve opaque payload regions for container-signal candidates into
    <run_dir>/container_targets/ so the next reverse-engineering step can work
    on the payload directly instead of re-deriving offsets by hand.
    """
    if not run_dir or not results:
        return []

    target_dir = os.path.join(run_dir, "container_targets")
    os.makedirs(target_dir, exist_ok=True)

    def _target_stem(src_rel, abs_src):
        rel = src_rel or os.path.basename(abs_src)
        rel = rel.replace("\\", "/").strip("/")
        if not rel:
            rel = os.path.basename(abs_src)
        stem = os.path.splitext(rel)[0]
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
        return stem[-120:] or os.path.splitext(os.path.basename(abs_src))[0]

    def _candidate_passphrases(base_name, vendor_guess):
        seeds = []
        stem = os.path.splitext(base_name)[0]
        seeds.extend(re.findall(r"[A-Za-z0-9]+", stem))
        if vendor_guess:
            seeds.extend(re.findall(r"[A-Za-z0-9]+", vendor_guess))
        seeds.extend(["tenda", "Tenda", "TendaWiFi", "tendawifi", "tendawifi.com"])

        out = []
        seen_local = set()
        for seed in seeds:
            if len(seed) < 3:
                continue
            variants = {
                seed,
                seed.lower(),
                seed.upper(),
            }
            for variant in variants:
                if variant in seen_local:
                    continue
                seen_local.add(variant)
                out.append(variant)

        compact = "".join(ch for ch in stem if ch.isalnum())
        if compact and compact not in seen_local:
            out.append(compact)
        return out[:48]

    def _write_probe_bundle(target_dir, base_name, export_entry):
        crypto_profile = export_entry.get("crypto_profile")
        vendor_guess = export_entry.get("vendor_guess", "")
        flow_type = export_entry.get("flow_type") or ""
        if flow_type == "blob_signal":
            payload_dest = export_entry.get("dest")
            if not payload_dest:
                return None
            probe_dir = os.path.join(target_dir, f"{os.path.splitext(base_name)[0]}__probe")
            os.makedirs(probe_dir, exist_ok=True)
            payload_rel = os.path.relpath(
                os.path.join(_PROJECT_ROOT, payload_dest),
                probe_dir,
            )
            script_path = os.path.join(probe_dir, "segmented_probe.sh")
            script = f"""#!/usr/bin/env bash
set -euo pipefail

PAYLOAD="{payload_rel}"
OUTDIR="scan_out"
mkdir -p "$OUTDIR"

file "$PAYLOAD" | tee "$OUTDIR/file.txt"
binwalk "$PAYLOAD" > "$OUTDIR/binwalk.txt" 2>&1 || true
strings -a "$PAYLOAD" | head -n 400 > "$OUTDIR/strings_head.txt" || true
strings -a "$PAYLOAD" | grep -E 'https?://|/[A-Za-z0-9._?&=%/-]+' | head -n 120 > "$OUTDIR/http_strings.txt" || true
xxd -l 1024 "$PAYLOAD" > "$OUTDIR/header_xxd.txt" || true

echo "scan outputs: $OUTDIR"
"""
            Path(script_path).write_text(script, encoding="utf-8")
            os.chmod(script_path, 0o755)

            meta_path = os.path.join(probe_dir, "probe_meta.json")
            Path(meta_path).write_text(json.dumps({
                "payload": export_entry.get("dest"),
                "binary_path": export_entry.get("src"),
                "payload_size": export_entry.get("payload_size"),
                "flow_type": flow_type,
                "source": export_entry.get("source"),
                "top_sinks": export_entry.get("all_sinks") or [],
                "sample_endpoints": export_entry.get("endpoints") or [],
                "probe_type": "segmented-bundle-scan-probe",
            }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            return {
                "probe_type": "segmented-bundle-scan-probe",
                "probe_dir": _safe_relpath(probe_dir),
                "script": _safe_relpath(script_path),
                "meta": _safe_relpath(meta_path),
                "candidate_count": 0,
            }

        if crypto_profile != "openssl-enc-compatible salted payload" and "cloud" not in vendor_guess.lower():
            return None
        ciphertext_dest = export_entry.get("ciphertext_dest")
        if crypto_profile == "openssl-enc-compatible salted payload" and not ciphertext_dest:
            return None

        probe_dir = os.path.join(target_dir, f"{os.path.splitext(base_name)[0]}__probe")
        os.makedirs(probe_dir, exist_ok=True)

        if crypto_profile == "openssl-enc-compatible salted payload":
            candidates = _candidate_passphrases(base_name, export_entry.get("vendor_guess", ""))
            wordlist_path = os.path.join(probe_dir, "candidates.txt")
            Path(wordlist_path).write_text("\n".join(candidates) + "\n", encoding="utf-8")

            salt = export_entry.get("openssl_salt") or ""
            ciphertext_rel = os.path.relpath(
                os.path.join(_PROJECT_ROOT, ciphertext_dest),
                probe_dir,
            )
            script_path = os.path.join(probe_dir, "openssl_probe.sh")
            script = f"""#!/usr/bin/env bash
set -euo pipefail

CIPHERTEXT="{ciphertext_rel}"
SALT="{salt}"
OUTDIR="out"
mkdir -p "$OUTDIR"

while IFS= read -r pass; do
  [ -n "$pass" ] || continue
  safe="$(printf '%s' "$pass" | tr -c 'A-Za-z0-9._-' '_')"
  for md in md5 sha256; do
    for cipher in aes-128-cbc aes-192-cbc aes-256-cbc; do
      openssl enc -d "-$cipher" -md "$md" -S "$SALT" -salt -pass "pass:$pass" \\
        -in "$CIPHERTEXT" -out "$OUTDIR/${{safe}}_${{cipher}}_${{md}}.bin" 2>/dev/null || true
    done
  done
done < candidates.txt

echo "probe outputs: $OUTDIR"
"""
            Path(script_path).write_text(script, encoding="utf-8")
            os.chmod(script_path, 0o755)

            meta_path = os.path.join(probe_dir, "probe_meta.json")
            Path(meta_path).write_text(json.dumps({
                "ciphertext": export_entry.get("ciphertext_dest"),
                "salt": salt,
                "crypto_profile": export_entry.get("crypto_profile"),
                "candidate_count": len(candidates),
                "ciphers": ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc"],
                "digests": ["md5", "sha256"],
            }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            return {
                "probe_type": "openssl-enc-probe",
                "probe_dir": _safe_relpath(probe_dir),
                "wordlist": _safe_relpath(wordlist_path),
                "script": _safe_relpath(script_path),
                "meta": _safe_relpath(meta_path),
                "candidate_count": len(candidates),
            }

        payload_dest = export_entry.get("dest")
        if not payload_dest:
            return None
        payload_rel = os.path.relpath(
            os.path.join(_PROJECT_ROOT, payload_dest),
            probe_dir,
        )
        script_path = os.path.join(probe_dir, "scan_probe.sh")
        script = f"""#!/usr/bin/env bash
set -euo pipefail

PAYLOAD="{payload_rel}"
OUTDIR="scan_out"
mkdir -p "$OUTDIR"

file "$PAYLOAD" | tee "$OUTDIR/file.txt"
binwalk "$PAYLOAD" > "$OUTDIR/binwalk.txt" 2>&1 || true
strings -a "$PAYLOAD" | head -n 200 > "$OUTDIR/strings_head.txt" || true
xxd -l 512 "$PAYLOAD" > "$OUTDIR/header_xxd.txt" || true

echo "scan outputs: $OUTDIR"
"""
        Path(script_path).write_text(script, encoding="utf-8")
        os.chmod(script_path, 0o755)

        meta_path = os.path.join(probe_dir, "probe_meta.json")
        Path(meta_path).write_text(json.dumps({
            "payload": export_entry.get("dest"),
            "payload_offset": export_entry.get("payload_offset"),
            "payload_size": export_entry.get("payload_size"),
            "vendor_guess": vendor_guess,
            "probe_type": "container-scan-probe",
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        return {
            "probe_type": "container-scan-probe",
            "probe_dir": _safe_relpath(probe_dir),
            "script": _safe_relpath(script_path),
            "meta": _safe_relpath(meta_path),
            "candidate_count": 0,
        }

    exported = []
    seen = set()
    for result in results:
        flow_type = result.get("flow_type")
        if flow_type not in {"container_signal", "blob_signal"}:
            continue

        src_rel = _result_path(result)
        if not src_rel:
            continue
        abs_src = os.path.normpath(os.path.join(_PROJECT_ROOT, src_rel))
        if not os.path.isfile(abs_src):
            continue

        payload_offset = result.get("payload_offset")
        if flow_type == "blob_signal":
            payload_offset = 0
        if not isinstance(payload_offset, int) or payload_offset < 0:
            continue

        payload_size = result.get("payload_size")
        key = (abs_src, payload_offset, payload_size)
        if key in seen:
            continue
        seen.add(key)

        base = os.path.basename(abs_src)
        stem = _target_stem(src_rel, abs_src)
        carved_name = f"{stem}__payload_0x{payload_offset:x}.bin"
        abs_dest = os.path.join(target_dir, carved_name)

        with open(abs_src, "rb") as in_fh:
            in_fh.seek(payload_offset)
            data = in_fh.read()
        with open(abs_dest, "wb") as out_fh:
            out_fh.write(data)

        export_entry = {
            "name": result.get("name", base),
            "src": src_rel,
            "dest": _safe_relpath(abs_dest),
            "payload_offset": payload_offset,
            "payload_size": len(data),
            "flow_type": flow_type,
            "source": result.get("source") or "",
            "vendor_guess": result.get("vendor_guess") or "",
            "crypto_profile": result.get("crypto_profile") or "",
            "all_sinks": result.get("all_sinks") or [],
            "endpoints": result.get("endpoints") or [],
        }

        ciphertext_offset = result.get("ciphertext_offset")
        if flow_type == "container_signal" and isinstance(ciphertext_offset, int) and ciphertext_offset >= 0:
            ct_name = f"{stem}__ciphertext_0x{ciphertext_offset:x}.bin"
            abs_ct_dest = os.path.join(target_dir, ct_name)
            with open(abs_src, "rb") as in_fh:
                in_fh.seek(ciphertext_offset)
                ct_data = in_fh.read()
            with open(abs_ct_dest, "wb") as out_fh:
                out_fh.write(ct_data)
            export_entry["ciphertext_dest"] = _safe_relpath(abs_ct_dest)
            export_entry["ciphertext_offset"] = ciphertext_offset
            export_entry["ciphertext_size"] = len(ct_data)
            export_entry["openssl_salt"] = result.get("openssl_salt")

        probe_bundle = _write_probe_bundle(target_dir, stem, export_entry)
        if probe_bundle:
            export_entry["probe_bundle"] = probe_bundle

        exported.append(export_entry)

    return exported


def _emit_analysis_bundle(mode, mode_reason, result, *, output_path=None, dossier_dir=None, cgi_files=None):
    all_results = result.get("results") or []
    exploit_candidates = result.get("exploit_candidates") or []
    exploit_by_id = {}
    for entry in exploit_candidates:
        exploit_by_id.setdefault(_candidate_id(entry["result"]), []).append(_build_exploit_snapshot(entry))

    snapshots = [
        _build_result_snapshot(r, cgi_files=cgi_files, exploit_paths=exploit_by_id.get(_candidate_id(r), []))
        for r in all_results
    ]
    dossiers = _write_candidate_dossiers(
        all_results,
        dossier_dir,
        cgi_files=cgi_files,
        exploit_candidates=exploit_candidates,
    )

    # ── CVE triage: pick Top-N from all snapshots ─────────────────────────────
    # Uses the same logic a human/LLM researcher applies when reading the
    # candidate list.  Noise-suppressed, auth-quality-weighted, and
    # web-exposure-gated.  Stored separately so the full candidate list is
    # preserved alongside the filtered CVE shortlist.
    cve_top = select_cve_candidates(snapshots, top_n=3)

    # ── Export CVE-candidate binaries for immediate Ghidra loading ────────────
    ghidra_targets = _export_ghidra_targets(cve_top, _RUN_DIR)
    if ghidra_targets:
        _sec("GHIDRA TARGETS  (ready to load)")
        for t in ghidra_targets:
            print(f"  ▸ {t['name']:<28}  {t['dest']}", flush=True)

    container_targets = _export_container_targets(all_results, _RUN_DIR)
    if container_targets:
        _sec("CONTAINER TARGETS  (carved payloads)")
        for t in container_targets:
            line = (
                f"  ▸ {t['name']:<28}  {t['dest']}  "
                f"(offset=0x{t['payload_offset']:x}, size={t['payload_size']})"
            )
            if t.get("ciphertext_dest"):
                line += (
                    f"\n    ciphertext → {t['ciphertext_dest']}  "
                    f"(offset=0x{t['ciphertext_offset']:x}, size={t['ciphertext_size']})"
                )
                if t.get("openssl_salt"):
                    line += f"  salt={t['openssl_salt']}"
            if t.get("probe_bundle"):
                line += (
                    f"\n    probe → {t['probe_bundle']['script']}  "
                    f"(type={t['probe_bundle']['probe_type']}"
                    + (f", candidates={t['probe_bundle']['candidate_count']}" if t['probe_bundle'].get('candidate_count') else "")
                    + ")"
                )
            print(line, flush=True)

    bundle = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_id": _RUN_ID,
        "run_dir": _safe_relpath(_RUN_DIR),
        "input": {
            "original": {
                "path": _safe_relpath(_ORIGINAL_INPUT_PATH or _INPUT_PATH),
                "type": _ORIGINAL_INPUT_TYPE or _INPUT_TYPE,
            },
            "resolved": {
                "path": _safe_relpath(_INPUT_PATH),
                "type": _INPUT_TYPE,
            },
        },
        "analysis": {
            "mode": mode,
            "reason": mode_reason,
            "system_path": _safe_relpath(SYSTEM_PATH),
            "vendor_path": _safe_relpath(VENDOR_PATH),
        },
        "summary": _json_safe(result.get("summary") or {}),
        "candidates": snapshots,
        "cve_candidates": _json_safe([
            {
                "name":          c.get("name"),
                "raw_name":      c.get("raw_name"),
                "binary_path":   c.get("binary_path"),
                "vuln_summary":  c.get("vuln_summary") or "",
                "triage_score":  c.get("triage_score", 0),
                "score":         c.get("score", 0),
                "auth_bypass":   c.get("auth_bypass"),
                "confidence":    c.get("confidence"),
                "web_exposed":   c.get("web_exposed"),
                "handler_surface": c.get("handler_surface"),
                "endpoints":     c.get("endpoints") or [],
                "handler_symbols": c.get("handler_symbols") or [],
                "all_sinks":     c.get("all_sinks") or [],
                "missing_links": c.get("missing_links") or [],
            }
            for c in cve_top
        ]),
        "exploit_candidates": [
            _build_exploit_snapshot(entry) for entry in exploit_candidates
        ],
        "dossiers": dossiers,
        "ghidra_targets": ghidra_targets,
        "container_targets": container_targets,
        "crypto_findings": _json_safe(result.get("crypto_findings") or []),
        "upgrade_findings": _json_safe(result.get("upgrade_findings") or []),
    }

    # ── Print CVE shortlist to console ────────────────────────────────────────
    _sec(f"CVE CANDIDATES  (top {len(cve_top)})")
    if cve_top:
        for idx, c in enumerate(cve_top, 1):
            auth_tag = {
                "none":       "PRE-AUTH",
                "bypassable": "AUTH-BYPASS",
                "required":   "POST-AUTH",
            }.get(c.get("auth_bypass") or "required", "?")
            print(f"\n  #{idx}  [{auth_tag}]  {c['name']}  "
                  f"triage={c.get('triage_score', 0)}  score={c.get('score', 0)}",
                  flush=True)
            print(f"       {c.get('vuln_summary') or ''}", flush=True)
            eps = c.get("endpoints") or []
            if eps:
                print(f"       endpoints: {', '.join(eps[:3])}", flush=True)
            _, explain_lines = explain_triage(c)
            for line in explain_lines[1:6]:   # skip "triage_score = N" header
                print(f"         {line}", flush=True)
    else:
        print("  (none passed CVE triage filter)", flush=True)

    _write_output_bundle(output_path, bundle)
    return bundle


def run_iot_analysis(show_all=False):
    """
    IoT-specific analysis path.

    1. Scan web roots to identify web-exposed binaries and their CGI scripts.
    2. Synthesize service entries for all ELF executables in standard dirs,
       marking web-exposed ones as world-accessible.
    3. Run the standard analyze_services() pipeline.
    4. Apply a 1.5× score boost to web-exposed results, re-level.
    5. Output web-exposed + HIGH + MEDIUM candidates only.
    """
    _sec("IoT Firmware — Web Surface Scan")

    web_bins, cgi_files = scan_web_surface(SYSTEM_PATH)
    print(f"    web server / CGI binaries : {len(web_bins)}", flush=True)
    print(f"    scripts scanned           : {len(cgi_files)}", flush=True)

    if cgi_files:
        print("    scripts:", flush=True)
        for cf in cgi_files[:8]:
            print(f"      {os.path.relpath(cf, _PROJECT_ROOT)}", flush=True)
        if len(cgi_files) > 8:
            print(f"      … and {len(cgi_files) - 8} more", flush=True)

    services = _collect_iot_services(SYSTEM_PATH, web_bins, cgi_files)
    print(f"\n    {len(services)} service candidates", flush=True)
    print(f"[START] Vulnerability analysis", flush=True)
    sys.stdout.flush()

    results = analyze_services(services, SYSTEM_PATH)

    # ── Reprioritize toward real web-routed components ───────────────────────
    _reprioritize_iot_results(results, web_bins, cgi_files)
    _retune_results(results, cgi_files=cgi_files, strict_high=True)

    # ── Partition results ─────────────────────────────────────────────────────
    focused = [r for r in results if r.get("web_candidate")]
    web_results   = [r for r in focused if r.get("web_exposed")]
    high_results  = [r for r in focused if not r.get("web_exposed") and r["level"] == "HIGH"]
    med_results   = [r for r in focused if not r.get("web_exposed") and r["level"] == "MEDIUM"]
    low_results   = [r for r in focused if not r.get("web_exposed") and r["level"] == "LOW"]
    display_high = sum(1 for r in focused if r["level"] == "HIGH")
    display_med = sum(1 for r in focused if r["level"] == "MEDIUM")
    display_low = sum(1 for r in focused if r["level"] == "LOW")

    total_shown = len(web_results) + len(high_results) + len(med_results)
    print(f"[DONE]  {len(results)} candidate(s)  "
          f"(web={len(web_results)}  HIGH={display_high}"
          f"  MEDIUM={display_med}  LOW={display_low})",
          flush=True)

    _sec(f"IoT HIGH-PRIORITY TARGETS  ({total_shown})")

    if web_results:
        print("\n  ── Web-exposed ──────────────────────────────────────────", flush=True)
        for r in web_results:
            _print_iot_entry(r, cgi_files=cgi_files)

    if high_results:
        print("\n  ── HIGH (not directly web-exposed) ──────────────────────", flush=True)
        for r in high_results:
            _print_iot_entry(r, cgi_files=cgi_files)

    if med_results:
        print("\n  ── MEDIUM ───────────────────────────────────────────────", flush=True)
        for r in med_results:
            _print_iot_entry(r, cgi_files=cgi_files)

    if show_all and low_results:
        print("\n  ── LOW ──────────────────────────────────────────────────", flush=True)
        for r in low_results:
            _print_iot_entry(r, cgi_files=cgi_files)

    if not (web_results or high_results or med_results):
        print("  (none — the firmware may use stripped binaries or an unsupported format)",
              flush=True)

    # ── Deep flow verification ─────────────────────────���─────────────────────���
    # Run only on top candidates to keep runtime bounded.
    priority_results = web_results + high_results + med_results
    if priority_results:
        _sec("VERIFIED EXPLOITABLE FLOWS  (top candidates only)")
        print("    Running deep argument-taint analysis ...", flush=True)
        sys.stdout.flush()
        _run_deep_verification(priority_results, top_n=10)
        had_flows = _print_verified_flows(priority_results)
        if not had_flows:
            print("  (no confirmed flows — binaries may be stripped or use indirect dispatch)",
                  flush=True)

    # ── Reachability and exploit scenario generation ──────────────────────────
    # Only runs on candidates that have verified CONFIRMED/LIKELY flows.
    exploit_candidates = []
    if priority_results:
        _sec("REMOTELY EXPLOITABLE FLOWS")
        print("    Checking HTTP reachability and authentication ...", flush=True)
        sys.stdout.flush()
        exploit_candidates = analyze_reachability(
            priority_results, cgi_files, SYSTEM_PATH)
        had_exploits = _print_exploit_candidates(exploit_candidates)
        if not had_exploits:
            print("  (no remotely reachable flows confirmed — check verified flows above)",
                  flush=True)

        # Summary count
        unauth_count = sum(1 for e in exploit_candidates
                           if e['reach']['auth_required'] is False)
        if exploit_candidates:
            print(f"\n  Total exploit candidates : {len(exploit_candidates)}", flush=True)
            print(f"  Unauthenticated          : {unauth_count}", flush=True)

    # ── Cryptographic material scan ───────────────────────────────────────────
    crypto_findings = scan_crypto_material(SYSTEM_PATH)
    upgrade_findings = scan_upgrade_scripts(SYSTEM_PATH)

    if crypto_findings or upgrade_findings:
        _sec(f"STATIC SECURITY FINDINGS  "
             f"(crypto={len(crypto_findings)}  upgrade={len(upgrade_findings)})")
        _SEV_MARK = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "~ ", "LOW": "  "}

        if crypto_findings:
            print("\n  ── Cryptographic Material ───────────────────────────────", flush=True)
            for f in crypto_findings:
                mark = _SEV_MARK.get(f.get("severity", "LOW"), "  ")
                print(f"  [{mark}{f['severity']}]  {f['type']}", flush=True)
                print(f"    path:     {f['path']}", flush=True)
                print(f"    evidence: {f['evidence']}", flush=True)
                if f.get("key_size_bits"):
                    print(f"    key size: {f['key_size_bits']} bits", flush=True)
                if f.get("gid"):
                    print(f"    GID:      {f['gid']}  (static={f.get('gid_is_static')})", flush=True)
                if f.get("shared_across_devices"):
                    print(f"    !! Key identical across all devices with same firmware", flush=True)

        if upgrade_findings:
            print("\n  ── Unsigned Firmware Flash ──────────────────────────────", flush=True)
            for f in upgrade_findings:
                mark = _SEV_MARK.get(f.get("severity", "LOW"), "  ")
                print(f"  [{mark}{f['severity']}]  {f['pattern']}", flush=True)
                print(f"    path:     {f['path']}", flush=True)
                print(f"    evidence: {f['evidence']}", flush=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    _sec("SUMMARY")
    print(f"  Candidates analyzed : {len(results)}", flush=True)
    print(f"  Web-exposed         : {len(web_results)}", flush=True)
    print(f"  HIGH                : {display_high}", flush=True)
    print(f"  MEDIUM              : {display_med}", flush=True)
    print(f"  LOW                 : {display_low}", flush=True)
    if crypto_findings:
        crit_count = sum(1 for f in crypto_findings if f.get("severity") == "CRITICAL")
        print(f"  Crypto findings     : {len(crypto_findings)}  (CRITICAL: {crit_count})", flush=True)
    if upgrade_findings:
        crit_u = sum(1 for f in upgrade_findings if f.get("severity") == "CRITICAL")
        print(f"  Upgrade findings    : {len(upgrade_findings)}  (CRITICAL: {crit_u})", flush=True)

    if web_results:
        print(f"\n  Top web-exposed targets:", flush=True)
        for r in web_results[:5]:
            print(f"    ▸ {r['name']:<30}  score={r['score']}  "
                  f"flow={r.get('flow_type') or 'none'}  "
                  f"sinks={','.join((r.get('all_sinks') or [])[:2])}",
                  flush=True)

    print(f"\n{'─' * _W}", flush=True)
    return {
        "mode": "iot_web",
        "remote_count": len(exploit_candidates),
        "results": results,
        "cgi_files": cgi_files,
        "exploit_candidates": exploit_candidates,
        "crypto_findings": crypto_findings,
        "upgrade_findings": upgrade_findings,
        "summary": {
            "candidates_analyzed": len(results),
            "web_exposed": len(web_results),
            "high": display_high,
            "medium": display_med,
            "low": display_low,
            "exploit_candidates": len(exploit_candidates),
            "unauthenticated_exploits": unauth_count if exploit_candidates else 0,
            "crypto_findings": len(crypto_findings),
            "upgrade_findings": len(upgrade_findings),
        },
    }


# ── Main analysis entry point ─────────────────────────────────────────────────

def run_android_analysis(show_all=False):
    if not os.path.exists(SYSTEM_PATH):
        print("[!] .cache/rootfs/system not found — was the extraction step successful?",
              flush=True)
        print(f"    Expected: {SYSTEM_PATH}", flush=True)
        print("    Tip: run without --skip to re-extract, or check .cache/extracted/",
              flush=True)
        return

    # IoT firmware has no Android .rc files — use web-surface-aware analysis.
    if _is_iot_firmware(SYSTEM_PATH):
        return run_iot_analysis(show_all=show_all)

    services = parse_init_services(SYSTEM_PATH)
    if os.path.exists(VENDOR_PATH):
        services += parse_init_services(VENDOR_PATH)

    print(f"    {len(services)} services detected", flush=True)
    print(f"[START] Vulnerability analysis", flush=True)
    sys.stdout.flush()

    results = analyze_services(services, SYSTEM_PATH)
    _, cgi_files = scan_web_surface(SYSTEM_PATH)
    _retune_results(results, cgi_files=cgi_files, strict_high=True)

    high   = [r for r in results if r["level"] == "HIGH"]
    medium = [r for r in results if r["level"] == "MEDIUM"]
    low    = [r for r in results if r["level"] == "LOW"]

    print(f"[DONE]  Analysis complete — {len(results)} candidate(s) found"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)

    print_section("HIGH RISK TARGETS", high)
    print_section("MEDIUM RISK TARGETS", medium)

    if show_all:
        print_section("LOW RISK TARGETS", low)

    print_attack_surface_map(results)

    run_filesystem_checks(results)

    # ── Final summary ─────────────────────────────────────────────────────────
    _sec("SUMMARY")
    print(f"  Services parsed:   {len(services)}", flush=True)
    print(f"  Candidates found:  {len(results)}"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)

    if high:
        print(f"\n  Top targets:", flush=True)
        for r in high[:5]:
            ctrl = r.get("controllability", "?")
            mem  = r.get("memory_impact", "?")
            print(f"    ▸ {r['name']:<30}  score={r['score']}  "
                  f"ctrl={ctrl}  mem={mem}  priv={r['priv']}", flush=True)
    elif medium:
        print(f"\n  No HIGH targets. Top MEDIUM:", flush=True)
        for r in medium[:3]:
            print(f"    ▸ {r['name']:<30}  score={r['score']}  priv={r['priv']}",
                  flush=True)
    else:
        print("\n  No HIGH or MEDIUM candidates found.", flush=True)
        print("  Run with --all to inspect LOW-scored services.", flush=True)

    print(f"\n{'─' * _W}", flush=True)
    return {
        "mode": "android",
        "remote_count": 0,
        "results": results,
        "cgi_files": cgi_files,
        "exploit_candidates": [],
        "summary": {
            "services_parsed": len(services),
            "candidates_found": len(results),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
        },
    }


def run_general_analysis(show_all=False):
    print("\n[*] General mode fallback uses generic firmware blob analysis.",
          flush=True)

    services = _collect_generic_blob_services(SYSTEM_PATH)
    print(f"    {len(services)} blob candidates", flush=True)
    if not services:
        print("    no suitable blobs found under analysis root", flush=True)
        return {
            "mode": "general",
            "remote_count": 0,
            "results": [],
            "cgi_files": [],
            "exploit_candidates": [],
            "summary": {"blob_candidates": 0, "candidates_found": 0},
        }

    print(f"[START] Vulnerability analysis", flush=True)
    sys.stdout.flush()
    results = analyze_services(services, SYSTEM_PATH)
    if not results:
        results = _collect_blob_signal_findings(services, SYSTEM_PATH)
    if not results:
        results = _collect_container_signal_findings(services, SYSTEM_PATH)

    high = [r for r in results if r["level"] == "HIGH"]
    medium = [r for r in results if r["level"] == "MEDIUM"]
    low = [r for r in results if r["level"] == "LOW"]

    print(f"[DONE]  Analysis complete — {len(results)} candidate(s) found"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)

    print_section("HIGH RISK TARGETS", high)
    print_section("MEDIUM RISK TARGETS", medium)
    if show_all:
        print_section("LOW RISK TARGETS", low)

    _sec("SUMMARY")
    print(f"  Blob candidates:   {len(services)}", flush=True)
    print(f"  Candidates found:  {len(results)}"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)
    print(f"\n{'─' * _W}", flush=True)
    return {
        "mode": "general",
        "remote_count": 0,
        "results": results,
        "cgi_files": [],
        "exploit_candidates": [],
        "summary": {
            "blob_candidates": len(services),
            "candidates_found": len(results),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
        },
    }


def run_analysis(show_all=False, output_path=None, dossier_dir=None):
    if not os.path.exists(SYSTEM_PATH):
        print("[!] .cache/rootfs/system not found — was the extraction step successful?",
              flush=True)
        print(f"    Expected: {SYSTEM_PATH}", flush=True)
        print("    Tip: run without --skip to re-extract, or check .cache/extracted/",
              flush=True)
        return

    mode, reason = detect_analysis_mode()
    _sec("ANALYSIS MODE")
    print(f"  selected mode: {mode}", flush=True)
    print(f"  reason: {reason}", flush=True)

    if mode == "iot_web":
        result = run_iot_analysis(show_all=show_all)
        _emit_analysis_bundle(
            "iot_web",
            reason,
            result,
            output_path=output_path,
            dossier_dir=dossier_dir,
            cgi_files=result.get("cgi_files"),
        )
        return result

    if mode == "android":
        result = run_android_analysis(show_all=show_all)
    else:
        result = run_general_analysis(show_all=show_all)

    if result and mode != "general" and result.get("remote_count", 0) == 0:
        _sec("ANALYSIS RETRY")
        print("  selected mode: iot_web", flush=True)
        print("  reason: no remotely exploitable candidates found in initial analysis",
              flush=True)
        result = run_iot_analysis(show_all=show_all)
        _emit_analysis_bundle(
            "iot_web",
            "retry after initial non-remote result set",
            result,
            output_path=output_path,
            dossier_dir=dossier_dir,
            cgi_files=result.get("cgi_files"),
        )
        return result

    if result:
        _emit_analysis_bundle(
            mode,
            reason,
            result,
            output_path=output_path,
            dossier_dir=dossier_dir,
            cgi_files=result.get("cgi_files"),
        )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="show LOW results too")
    parser.add_argument("--output", help="write structured JSON results to this path")
    parser.add_argument("--dossier-dir", help="write candidate dossiers to this directory")
    parser.add_argument("--context", help="optional run context label to embed in output")
    args = parser.parse_args()

    if args.context:
        os.environ["FIRMWARE_RUN_CONTEXT"] = args.context

    run_analysis(
        show_all=args.all,
        output_path=args.output,
        dossier_dir=args.dossier_dir or _DEFAULT_DOSSIER_DIR,
    )
