import os
import sys
import re
import argparse
import json
from datetime import datetime

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


def _collect_iot_services(system_path, web_bins):
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

    return services


def _collect_generic_blob_services(system_path, max_candidates=None):
    """
    Fallback collector for firmware bundles that do not expose a classic
    rootfs layout. Treat interesting blobs as analysis targets and let the
    string-based analyzer rank them.
    """
    exts = {".bin", ".img", ".so", ".elf", ".fw", ".cgi", ".apk"}
    if max_candidates is None:
        root_lower = os.path.abspath(system_path).lower()
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
            if ext not in exts:
                continue

            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size < 4096:
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

    services.sort(key=priority)
    return services[:max_candidates]


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
            or (handler_ref and not _is_generic_shell_utility(r))
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

    for script_path in cgi_files:
        try:
            content = open(script_path, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        lower = content.lower()
        if any(ref in lower for ref in exact_refs):
            return True
        if allow_basename and base_pat.search(content):
            return True
    return False


def _manual_review_hints(result, cgi_files):
    bp = result.get("binary_path", "")
    if not bp or not os.path.isfile(bp):
        return None

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
            strings = extract_strings(bp) if not imports else None
            flows   = verify_exploitable_flows(bp, cg or {},
                                               imports=imports,
                                               strings=strings)
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
    path = _result_path(result)
    steps = [
        f"Open {path} in Ghidra and inspect the path into {', '.join((result.get('all_sinks') or result.get('sinks') or ['?'])[:2])}.",
    ]

    if review and review.get("frontend"):
        steps.append(
            f"Trace request entry from {review['frontend'][0]} into {os.path.basename(path or result.get('name', 'binary'))}."
        )
    if review and review.get("params"):
        steps.append(f"Check whether parameters {', '.join(review['params'][:3])} reach argv/env parsing.")
    if exploit_paths:
        ep = exploit_paths[0].get("endpoint") or "(unknown endpoint)"
        steps.append(f"Validate the reachable endpoint {ep} against the reported flow.")
    elif result.get("web_exposed"):
        steps.append("Confirm handler routing and auth checks from the web entrypoint before sink reachability review.")
    else:
        steps.append("Verify whether the candidate is actually externally reachable before spending time on deep taint review.")
    return steps[:4]


def _build_result_snapshot(result, cgi_files=None, exploit_paths=None):
    review = _manual_review_hints(result, cgi_files or []) if cgi_files is not None else None
    verified = [
        flow for flow in (result.get("verified_flows") or [])
        if flow.get("verdict") != "FALSE_POSITIVE"
    ]
    return {
        "id": _candidate_id(result),
        "name": result.get("name"),
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
        "attack_surface": _json_safe(result.get("attack_surface", {})),
        "fuzzing_hints": list(result.get("fuzzing_hints") or []),
        "manual_review": _json_safe(review),
        "verified_flows": _json_safe(verified),
        "exploit_paths": _json_safe(exploit_paths or []),
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
        lines = [
            f"# {snapshot['name']}",
            "",
            f"- id: `{snapshot['id']}`",
            f"- level: `{snapshot['level']}`",
            f"- score: `{snapshot['score']}`",
            f"- binary: `{snapshot['binary_path']}`",
            f"- flow: `{snapshot['flow_type'] or 'none'}`",
            f"- sinks: `{', '.join(snapshot['all_sinks']) if snapshot['all_sinks'] else 'none'}`",
        ]
        review = snapshot.get("manual_review") or {}
        if review:
            lines.extend([
                "",
                "## Manual Review",
                f"- frontend: `{', '.join(review.get('frontend') or []) or 'none'}`",
                f"- params: `{', '.join(review.get('params') or []) or 'none'}`",
                f"- auth hints: `{', '.join(review.get('auth') or []) or 'none'}`",
                f"- control: `{review.get('control') or 'unknown'}`",
            ])
        if snapshot["verified_flows"]:
            lines.append("")
            lines.append("## Verified Flows")
            for flow in snapshot["verified_flows"][:5]:
                lines.append(
                    f"- `{flow.get('verdict')}` {flow.get('func_sym') or '(heuristic)'} -> {flow.get('sink_sym')} :: {flow.get('flow_str')}"
                )
        if snapshot["exploit_paths"]:
            lines.append("")
            lines.append("## Reachability")
            for exploit in snapshot["exploit_paths"][:5]:
                lines.append(
                    f"- `{exploit.get('verdict')}` endpoint `{exploit.get('endpoint') or '?'}` param `{exploit.get('input_param') or '?'}` auth `{exploit.get('auth_required')}`"
                )
        lines.append("")
        lines.append("## Next Steps")
        for step in snapshot["next_steps"]:
            lines.append(f"- {step}")
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

    bundle = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
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
        "exploit_candidates": [
            _build_exploit_snapshot(entry) for entry in exploit_candidates
        ],
        "dossiers": dossiers,
    }
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

    services = _collect_iot_services(SYSTEM_PATH, web_bins)
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

    # ── Summary ───────────────────────────────────────────────────────────────
    _sec("SUMMARY")
    print(f"  Candidates analyzed : {len(results)}", flush=True)
    print(f"  Web-exposed         : {len(web_results)}", flush=True)
    print(f"  HIGH                : {display_high}", flush=True)
    print(f"  MEDIUM              : {display_med}", flush=True)
    print(f"  LOW                 : {display_low}", flush=True)

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
        "summary": {
            "candidates_analyzed": len(results),
            "web_exposed": len(web_results),
            "high": display_high,
            "medium": display_med,
            "low": display_low,
            "exploit_candidates": len(exploit_candidates),
            "unauthenticated_exploits": unauth_count if exploit_candidates else 0,
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
