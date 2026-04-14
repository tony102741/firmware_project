import os
import time

from .strings_analyzer import extract_strings, filter_keywords
from .sink_detector import detect_sinks, detect_sinks_from_imports, is_valid_sink
from .input_classifier import (classify_input, has_input_handler,
                                classify_input_from_imports,
                                has_input_handler_from_imports)
from .dataflow import (analyze_dataflow, analyze_dataflow_with_graph,
                       upgrade_taint_confidence,
                       has_dangerous_memcpy_context,
                       has_dlopen_usage, is_parsing_heavy,
                       detect_validation_signals)
from .scoring import score_sinks, calc_score
from .surface_detector import detect_surface, build_fuzzing_hints
from .elf_analyzer import get_imports, build_call_graph, detect_parser_patterns


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

NOISE_BINARIES = {
    "busybox", "[", "[[", "ash", "sh", "false", "true", "cat", "chmod", "chown",
    "cmp", "cp", "cut", "date", "dd", "df", "dirname", "du", "echo", "env",
    "expr", "head", "id", "kill", "killall", "ln", "ls", "mkdir", "mkfifo",
    "mknod", "mktemp", "mv", "nice", "nohup", "od", "paste", "printf", "pwd",
    "readlink", "rm", "rmdir", "sed", "seq", "sleep", "sort", "stat", "stty",
    "sync", "tail", "tee", "test", "timeout", "touch", "tr", "uname", "uniq",
    "unlink", "wc", "which", "whoami", "xargs", "yes", "basename", "find",
    "grep", "egrep", "fgrep", "vi", "mount", "umount",
}


def is_noise_service(name):
    n = name.lower()
    return any(noise in n for noise in NOISE_SERVICES)


def is_noise_binary(name, exec_path):
    names = {
        (name or "").strip().lower(),
        os.path.basename((exec_path or "").strip()).lower(),
    }
    return any(n in NOISE_BINARIES for n in names if n)


def _has_external_network_surface(surface):
    sockets = surface.get("sockets", []) if surface else []
    return any(s.startswith("port:") for s in sockets)


# ── Controllability classification ─────────────────────────────────────────

def _classify_controllability(input_type, user, socket_perm, source):
    """
    Estimate how easily an attacker can reach and control the input surface.

    HIGH   — externally reachable without authentication:
               world-accessible socket (666/777), OR
               network socket run as root (no sandbox), OR
               netlink + root
    MEDIUM — reachable from apps or limited-trust peers:
               standard network socket (non-world, non-root),
               Binder IPC (reachable from any installed app),
               vendor file (OTA/update-modifiable config)
    LOW    — controlled by privileged components only:
               internal system config files, property-gated inputs
    """
    world_socket = bool(
        socket_perm and
        any(p in socket_perm for p in ["666", "777", "0666", "0777"])
    )

    if input_type in ("socket", "netlink"):
        if world_socket or user == "root":
            return "HIGH"
        return "MEDIUM"

    if input_type == "binder":
        return "MEDIUM"   # reachable from any app via Binder IPC

    if input_type == "file":
        if source == "vendor":
            return "MEDIUM"   # vendor configs often updatable via OTA/adb
        return "LOW"

    return "LOW"


# ── Memory impact classification ────────────────────────────────────────────

def _classify_memory_impact(filtered, flow_score, taint_confidence):
    """
    Classify the potential for memory-safety violations (distinct from
    command-injection impact).

    CONFIRMED — strong sinks (strcpy/gets/sprintf) with high taint confidence
                AND a confirmed dataflow chain: likely exploitable overflow
    POSSIBLE  — strong sinks present but chain uncertain, OR weak sinks with
                dangerous context: memory corruption cannot be ruled out
    NONE      — only critical sinks (command execution) with no memory ops:
                injection risk but no classic memory-safety violation
    """
    strong = filtered.get("strong", [])
    weak   = filtered.get("weak",   [])

    if not strong and not weak:
        return "NONE"

    if strong and taint_confidence >= 0.7 and flow_score >= 6:
        return "CONFIRMED"

    if strong or (weak and flow_score >= 3):
        return "POSSIBLE"

    return "NONE"


# ── Confidence label ────────────────────────────────────────────────────────

def _has_argument_level_sink(sinks):
    """
    Return True only for sinks where attacker control of the *argument value*
    materially changes code execution or file-write behavior.
    """
    for sink in sinks:
        l = sink.lower()
        if "system" in l or "popen" in l:
            return True
        if "dlopen" in l or "dlsym" in l:
            return True
        if "exec" in l and "dlsym" not in l and "dlopen" not in l:
            return True
        if any(k in l for k in ("fwrite", "fprintf", "write(", "pwrite", "fputs", "fputc")):
            return True
    return False


def _flow_confidence(flow_score, flow_type=None, sinks=None):
    """
    Translate a numeric flow_score into a human-readable confidence label.

    HIGH   — controllable input demonstrably reaches a dangerous function
    MEDIUM — parsing stage present between input and sink
    LOW    — weak signal: copy without parse confirmation
    WEAK   — no confirmed dataflow chain
    """
    sinks = sinks or []
    arg_sink = _has_argument_level_sink(sinks)

    # Path-only control and UI-only influence should not be promoted as
    # argument-level exploitability.
    if flow_type == "file_path_injection":
        return "LOW" if flow_score >= 3 else "WEAK"
    if not arg_sink:
        if flow_score >= 6:
            return "LOW"
        if flow_score >= 3:
            return "WEAK"
        return "WEAK"

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
    last_print_time = 0.0   # throttle progress output to ~100ms intervals

    for svc in services:
        if is_noise_service(svc["name"]):
            continue
        if is_noise_binary(svc.get("name", ""), svc.get("exec", "")):
            continue
        if svc["exec"] in seen_exec:
            continue
        seen_exec.add(svc["exec"])

        path = resolve_path(svc["exec"], root_path)
        if not os.path.exists(path) or not is_elf(path):
            continue

        scanned += 1
        now = time.time()
        if now - last_print_time >= 0.1:   # at most 10 redraws/second
            last_print_time = now
            pct = scanned * 100 // total if total else 0
            print(f"\r  [SCAN] {scanned}/{total} ({pct:3d}%)  {svc['name']:<40}",
                  end="", flush=True)

        # ── Stage 1: ELF import-based fast filter ────────────────────────────
        # Parse the import table first. This is cheap (pure struct unpacking)
        # and eliminates false positives from string-matched log messages.

        strings = None   # populated lazily; always defined before result assembly
        imports = get_imports(path)   # {sym_name: plt_stub_va}

        if imports:
            input_type = classify_input_from_imports(imports)
            if not input_type:
                # Import table present but no recognized input symbol — skip.
                # Do NOT fall back to strings here: if the ELF has no input
                # import, the binary doesn't receive external data directly.
                continue
            if not has_input_handler_from_imports(imports):
                continue
            raw_sinks = detect_sinks_from_imports(imports)
        else:
            # Non-ELF or stripped with no .dynstr — fall back to strings.
            strings = extract_strings(path)
            input_type = classify_input(strings)
            if not input_type:
                continue
            if not has_input_handler(strings):
                continue
            raw_sinks = detect_sinks(strings)

        # ── Stage 2: sink validation ─────────────────────────────────────────
        # Import-sourced sinks need no is_valid_sink filter (they are exact
        # symbol names); string-sourced sinks still require it.

        if imports:
            filtered = {
                "critical": raw_sinks["critical"],
                "strong":   raw_sinks["strong"],
                "weak":     [],
            }
        else:
            filtered = {
                "critical": [s for s in raw_sinks["critical"] if is_valid_sink(s, "critical")],
                "strong":   [s for s in raw_sinks["strong"]   if is_valid_sink(s, "strong")],
                "weak":     [],
            }

        # ── Stage 3: dataflow / call-graph analysis ───────────────────────────
        # Try graph-based reachability first; fall back to string co-presence.

        graph_path       = None
        cg               = None
        taint_confidence = 0.3   # default: string-based

        if imports:
            cg = build_call_graph(path)
            if cg:
                flow_score, flow_type, path_len, taint_confidence = \
                    analyze_dataflow_with_graph(cg, binary_path=path)
                # Persist path for taint upgrade below
                from .elf_analyzer import find_shortest_path
                graph_path, _, _ = find_shortest_path(cg)

                # Upgrade confidence to 1.0 if bottleneck shows LDRH→MUL→sink
                if taint_confidence >= 0.5 and graph_path:
                    taint_confidence = upgrade_taint_confidence(
                        graph_path, cg, path)

                # If graph found no reachable path (flow_score=0), fall back to
                # string co-presence so we don't silently under-score candidates
                # whose call graph is incomplete (e.g. indirect calls via vtable).
                if flow_score == 0:
                    if strings is None:
                        strings = extract_strings(path)
                    flow_score, flow_type = analyze_dataflow(strings)
                    taint_confidence = 0.3   # string-based confidence
            else:
                # build_call_graph failed (non-AArch64 or too large);
                # fall back to string-based dataflow for this binary.
                if strings is None:
                    strings = extract_strings(path)
                flow_score, flow_type = analyze_dataflow(strings)
        else:
            flow_score, flow_type = analyze_dataflow(strings)

        # Admit weak sinks only when chain is confirmed and memcpy context
        # is dangerous (original guard preserved).
        if flow_score >= 3:
            if imports:
                # For import-based path: weak sinks are present if in import table
                filtered["weak"] = raw_sinks.get("weak", [])
            else:
                if has_dangerous_memcpy_context(strings):
                    filtered["weak"] = [
                        s for s in raw_sinks["weak"]
                        if not is_valid_sink(s, "critical")
                    ]

        all_sinks = filtered["critical"] + filtered["strong"] + filtered["weak"]
        if not all_sinks:
            continue
        flow_confidence = _flow_confidence(flow_score, flow_type, all_sinks)
        taint_for_score = (
            taint_confidence if _has_argument_level_sink(all_sinks)
            else min(taint_confidence, 0.3)
        )

        # ── Stage 4: additional scoring factors ──────────────────────────────

        if imports:
            dlopen = "dlopen" in imports or "dlsym" in imports
            heavy  = is_parsing_heavy(strings) if strings is not None else False
        else:
            dlopen = has_dlopen_usage(strings)
            heavy  = is_parsing_heavy(strings)

        source = svc.get("source", "system")

        # ── Socket permissions ────────────────────────────────────────────────

        socket_perms = [sock["perm"] for sock in svc.get("socket", [])]
        socket_perm  = socket_perms[0] if socket_perms else None

        # ── Validation signals ────────────────────────────────────────────────
        # Detect if the binary uses bounded ops consistently; reduce score but
        # never eliminate the candidate — validation may be partial or bypassed.

        if imports:
            validation_penalty = detect_validation_signals(imports, use_imports=True)
        elif strings is not None:
            validation_penalty = detect_validation_signals(strings, use_imports=False)
        else:
            validation_penalty = 0.0

        # ── Controllability ───────────────────────────────────────────────────

        controllability = _classify_controllability(
            input_type, svc["user"], socket_perm, source)

        # ── Memory impact ─────────────────────────────────────────────────────

        memory_impact = _classify_memory_impact(filtered, flow_score, taint_confidence)

        # ── Scoring ───────────────────────────────────────────────────────────

        sink_score = score_sinks(filtered)
        score = calc_score(
            input_type, svc["user"], socket_perm, sink_score, flow_score,
            source=source,
            has_dlopen=dlopen,
            is_parsing_heavy=heavy,
            taint_confidence=taint_for_score,
            validation_penalty=validation_penalty,
            controllability=controllability,
            flow_confidence=flow_confidence,
            memory_impact=memory_impact,
            flow_type=flow_type,
        )

        # ── Level classification ──────────────────────────────────────────────
        # Hard discard only for truly no-signal cases (score < 2).
        # Validation penalty may push borderline candidates down but not out.

        if score >= 15 and flow_score >= 6:
            level = "HIGH"
        elif score >= 8 and flow_score >= 3:
            level = "MEDIUM"
        elif score >= 2:
            level = "LOW"
        else:
            continue  # No meaningful signal (score < 2)

        # ── Ensure strings are available for surface/evidence output ─────────
        # The ELF import path defers extract_strings; materialise it now.

        if strings is None:
            strings = extract_strings(path)

        # ── Input surface detection ───────────────────────────────────────────

        surface = detect_surface(strings)

        if input_type in ("socket", "netlink") and not _has_external_network_surface(surface):
            continue

        # ── Fuzzing hints ─────────────────────────────────────────────────────

        fuzzing_hints = build_fuzzing_hints(surface, input_type, flow_type, all_sinks)

        # ── Parser pattern detection ──────────────────────────────────────────
        # Best-effort: detect TLV/ASN.1/LPF/SEQOF patterns on confirmed path.
        # Only run when we have a call graph (import-based path); string-based
        # path is too coarse to meaningfully scope the scan.

        parser_hits = {}
        if cg:
            try:
                parser_hits = detect_parser_patterns(path, cg)
            except Exception:
                pass

        # Summarise for result dict: top 3 hits by score, VA as hex string
        top_parser = sorted(
            [{'va': hex(va), **info} for va, info in parser_hits.items()],
            key=lambda x: -x['score']
        )[:3]

        # ── Result assembly ───────────────────────────────────────────────────

        results.append({
            # Core identification
            "name":        svc["name"],
            "exec":        svc["exec"],
            "binary_path": path,
            "source":      source,

            # Input classification
            "input_type":  input_type,
            "priv":        svc["user"],

            # Dataflow analysis
            "flow_type":   flow_type,
            "confidence":  flow_confidence,

            # Taint confidence from ELF analysis (new)
            "taint_confidence": round(taint_confidence, 2),

            # Sink evidence — first 2 for compact display, full list for detail
            "sinks":       all_sinks[:2],
            "all_sinks":   all_sinks,

            # Attack surface and fuzzing
            "attack_surface": surface,
            "fuzzing_hints":  fuzzing_hints,

            # Additional evidence strings
            "evidence":    filter_keywords(strings)[:3],

            # Scoring
            "score":              score,
            "level":              level,

            # Controllability and memory impact
            "controllability":    controllability,
            "memory_impact":      memory_impact,
            "validation_penalty": round(validation_penalty, 2),

            # Parser pattern evidence (TLV/ASN.1/LPF/SEQOF)
            "parser_patterns": len(parser_hits),
            "parser_hits":     top_parser,
        })

    pct = scanned * 100 // total if total else 0
    print(f"\r  [SCAN] {scanned}/{total} ({pct:3d}%)  complete{' ' * 32}", flush=True)
    return sorted(results, key=lambda x: x["score"], reverse=True)
