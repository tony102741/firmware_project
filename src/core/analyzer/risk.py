import os

from .strings_analyzer import extract_strings, filter_keywords
from .sink_detector import detect_sinks, is_valid_sink
from .input_classifier import classify_input, has_input_handler
from .dataflow import (analyze_dataflow, has_dangerous_memcpy_context,
                       has_dlopen_usage, is_parsing_heavy)
from .scoring import score_sinks, calc_score
from .surface_detector import detect_surface, build_fuzzing_hints


# ── ELF check ──────────────────────────────────────────────────────────────

def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


# ── Path resolution ─────────────────────────────────────────────────────────
# root_path is always rootfs/system; derive rootfs/ from it.

def resolve_path(exec_path, root_path):
    rootfs = os.path.dirname(root_path)  # rootfs/
    if exec_path.startswith("/system/"):
        return os.path.join(root_path, exec_path[len("/system/"):])
    elif exec_path.startswith("/vendor/"):
        return os.path.join(rootfs, "vendor", exec_path[len("/vendor/"):])
    else:
        return os.path.join(root_path, exec_path.lstrip("/"))


# ── Noise services ──────────────────────────────────────────────────────────
# Well-understood system services unlikely to surface novel vulnerabilities.

NOISE_SERVICES = [
    "wpa_supplicant", "hostapd", "vndservicemanager",
    "bcmbtlinux", "btsnoop",
    "netd", "adbd",
    "healthd", "lmkd", "logd", "statsd",
    "tombstoned", "incidentd", "traced",
    "storaged", "installd",
]


def is_noise_service(name):
    n = name.lower()
    return any(noise in n for noise in NOISE_SERVICES)


# ── Confidence label ────────────────────────────────────────────────────────

def _flow_confidence(flow_score):
    """
    Translate a numeric flow_score into a human-readable confidence label.

    HIGH   — controllable input demonstrably reaches a dangerous function
    MEDIUM — parsing stage present between input and sink
    LOW    — weak signal: copy without parse confirmation
    WEAK   — no confirmed dataflow chain
    """
    if flow_score >= 8:
        return "HIGH"
    if flow_score >= 6:
        return "MEDIUM"
    if flow_score >= 3:
        return "LOW"
    return "WEAK"


# ── Main analysis loop ───────────────────────────────────────────────────────

def analyze_services(services, root_path):
    results = []
    seen_exec = set()
    total = len(services)
    scanned = 0

    for svc in services:
        if is_noise_service(svc["name"]):
            continue
        if svc["exec"] in seen_exec:
            continue
        seen_exec.add(svc["exec"])

        path = resolve_path(svc["exec"], root_path)
        if not os.path.exists(path) or not is_elf(path):
            continue

        scanned += 1
        print(f"\r  scanning {scanned}/{total}: {svc['name']:<40}", end="", flush=True)

        strings = extract_strings(path)

        input_type = classify_input(strings)
        if not input_type:
            continue

        if not has_input_handler(strings):
            continue

        raw_sinks = detect_sinks(strings)

        # Validate critical and strong sinks
        filtered = {
            "critical": [s for s in raw_sinks["critical"] if is_valid_sink(s, "critical")],
            "strong":   [s for s in raw_sinks["strong"]   if is_valid_sink(s, "strong")],
            "weak":     [],
        }

        # Dataflow analysis (required before admitting weak sinks)
        flow_score, flow_type = analyze_dataflow(strings)

        # Weak sinks are only admitted when the dataflow chain is confirmed
        # AND the memcpy context is demonstrably dangerous.
        if flow_score >= 3:
            if has_dangerous_memcpy_context(strings):
                filtered["weak"] = [
                    s for s in raw_sinks["weak"]
                    if not is_valid_sink(s, "critical")  # already excluded above
                ]

        all_sinks = filtered["critical"] + filtered["strong"] + filtered["weak"]
        if not all_sinks:
            continue

        # ── New capability: compute additional scoring factors ────────────────

        dlopen   = has_dlopen_usage(strings)
        heavy    = is_parsing_heavy(strings)
        source   = svc.get("source", "system")

        # ── Socket permissions ───────────────────────────────────────────────

        socket_perms = [sock["perm"] for sock in svc.get("socket", [])]
        socket_perm  = socket_perms[0] if socket_perms else None

        # ── Scoring ──────────────────────────────────────────────────────────

        sink_score = score_sinks(filtered)
        score = calc_score(
            input_type, svc["user"], socket_perm, sink_score, flow_score,
            source=source,
            has_dlopen=dlopen,
            is_parsing_heavy=heavy,
        )

        # ── Level classification ─────────────────────────────────────────────

        if score >= 15 and flow_score >= 6:
            level = "HIGH"
        elif score >= 8 and flow_score >= 3:
            level = "MEDIUM"
        elif score >= 5:
            level = "LOW"
        else:
            continue  # Below minimum threshold

        # ── Input surface detection ──────────────────────────────────────────

        surface = detect_surface(strings)

        # ── Fuzzing hints ────────────────────────────────────────────────────

        fuzzing_hints = build_fuzzing_hints(surface, input_type, flow_type, all_sinks)

        # ── Result assembly ──────────────────────────────────────────────────

        results.append({
            # Core identification
            "name":        svc["name"],
            "exec":        svc["exec"],
            "binary_path": path,                       # absolute path on host fs
            "source":      source,                     # "system" or "vendor"

            # Input classification
            "input_type":  input_type,
            "priv":        svc["user"],

            # Dataflow analysis
            "flow_type":   flow_type,
            "confidence":  _flow_confidence(flow_score),

            # Sink evidence — first 2 for compact display, full list for detail
            "sinks":       all_sinks[:2],
            "all_sinks":   all_sinks,

            # Attack surface and fuzzing
            "attack_surface": surface,
            "fuzzing_hints":  fuzzing_hints,

            # Additional evidence strings
            "evidence":    filter_keywords(strings)[:3],

            # Scoring
            "score":       score,
            "level":       level,
        })

    print()   # newline after the \r progress line
    return sorted(results, key=lambda x: x["score"], reverse=True)
