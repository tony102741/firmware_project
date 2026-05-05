"""
CVE Triage Filter  (cve_triage.py)
===================================
Post-pipeline rescoring layer that replicates how a human / LLM researcher
picks Top-N CVE-quality candidates from the full scored output.

The upstream pipeline (risk.py → scoring.py) measures exploitability magnitude
and chain quality.  This module answers a different question:

    "Which of these would I actually file a CVE for?"

Three things the pipeline does not fully capture that human triage always does:

  1. Noise suppression  — BusyBox applets carry SHELL=/bin/sh / -/bin/sh in
                          every binary; they look like sinks but are not
                          reachable by an attacker.

  2. Auth-bypass elevation — pre-auth (auth_bypass="none") and bypassable-auth
                             are far stronger CVE signals than post-auth,
                             regardless of pipeline score.

  3. Web-exposure gating  — a network-exploitable CVE requires a web-reachable
                            attack surface; internal-only binaries are
                            deprioritised unless they have verified flows.

Integration:
  Called from main.py _emit_analysis_bundle() after snapshots are built.
  Output is added to the results bundle as "cve_candidates".
"""

import re

# ── Noise fingerprints ────────────────────────────────────────────────────────

# BusyBox applet names — every one of these shares the same binary (or symlink)
# and picks up SHELL=/bin/sh from the embedded login shell table.
_BUSYBOX_NAMES = frozenset({
    "addgroup", "adduser", "awk", "bunzip2", "bzcat", "chgrp", "chpasswd",
    "chroot", "delgroup", "deluser", "depmod", "diff", "fdisk", "free",
    "fsck", "ftpget", "ftpput", "fuser", "getty", "halt", "hostname",
    "ifconfig", "init", "insmod", "login", "lsmod", "md5sum", "modprobe",
    "passwd", "ping", "ping6", "poweroff", "ps", "reboot", "renice",
    "rmmod", "route", "start-stop-daemon", "top", "uptime", "vconfig",
    "chown", "chmod", "cmp", "cp", "cut", "date", "dd", "df", "dirname",
    "du", "echo", "env", "expr", "head", "id", "kill", "killall", "ln",
    "ls", "mkdir", "mkfifo", "mknod", "mktemp", "mv", "nice", "nohup",
    "od", "paste", "printf", "pwd", "readlink", "rm", "rmdir", "sed",
    "seq", "sleep", "sort", "stat", "stty", "sync", "tail", "tee", "test",
    "timeout", "touch", "tr", "uname", "uniq", "unlink", "wc", "which",
    "whoami", "xargs", "yes", "basename", "find", "grep", "egrep", "fgrep",
    "vi", "mount", "umount",
})

# Sink strings that are NOT attacker-controlled execution sinks.
# These appear as "sinks" only because they reference /bin/sh in a declarative
# context (environment variable, shebang line, login-shell field).
_DECL_ONLY_SINK_HINTS = frozenset({
    "-/bin/sh",           # busybox login: SHELL field
    "shell=/bin/sh",      # env var assignment
    "#!/bin/sh",          # shebang — not a dangerous call
    "#!/bin/sh /etc/",    # init-script shebang
})

# Strings that look like system() references but are not shell execution sinks.
_PSEUDO_EXEC_SINK_HINTS = frozenset({
    "system(flash)",
    "print mac address in system(flash)",
})

# The generic /vlan/config endpoint appears in every busybox binary in
# TOTOLINK builds because it comes from a shared config-parsing library.
# It is NOT a real attack surface for those binaries.
_BUSYBOX_EP_ARTIFACTS = frozenset({"/vlan/config"})

# ── Real sink fingerprints ────────────────────────────────────────────────────

# Sinks that represent a genuinely dangerous, potentially attacker-controlled
# function call (as opposed to a declaration or environment lookup).
_REAL_EXEC_SINKS = frozenset({
    "popen", "system(", "execl", "execv", "execle", "execve", "execvp",
    "/bin/sh", "sh -c", "do_system", "twsystem",
})

# Memory-corruption / format-string sinks — real sinks for buffer_overflow /
# format_string flow types.  fscanf/sprintf/strcpy are not exec calls but they
# ARE dangerous operations when attacker-controlled data reaches them.
_REAL_MEMORY_SINKS = frozenset({
    "fscanf", "scanf(", "sscanf(", "gets(",
    "sprintf(", "vsprintf(", "strcpy(", "strcat(",
    "snprintf() failed",   # explicit snprintf overflow indicator string
})

# ── High-value endpoint fingerprints ─────────────────────────────────────────

# Endpoint substrings that confirm a specific, named HTTP attack surface.
# These are concrete URLs an attacker would POST to, not generic patterns.
# NOTE: Generic admin paths (/firmware, /administration) are intentionally
# excluded — they appear in nearly every router firmware and do not constitute
# evidence of a specific exploitable handler on their own.
_HV_ENDPOINT_HINTS = frozenset({
    "/goform/", "/cgi-bin/", "/boafrm/",
    "/cstecgi.cgi", "/hnap1/",
    "formupload", "formwanp", "formddns", "formsetwan",
    "formipqos", "formfilter", "formfirewall", "formreboot",
    "formsetwifi", "formsetwlan",
})

_GENERIC_UPGRADE_ENDPOINTS = frozenset({
    "/firmware.bin",
    "/firmware.img",
    "/upgrade",
    "/applyreboot",
    "/firmware",
    "/config",
})

_SOURCE_ARTIFACT_ENDPOINT_HINTS = frozenset({
    ".y",
    ".l",
    ".h",
    "/configparser.y",
})


# ── Strong-unverified escape condition ───────────────────────────────────────

# Score cap for a candidate that passes the escape condition but has no verified
# flows.  Set just above the normal unverified cap (40) but below the floor of
# a typical verified candidate (web_exposed+verified ≥ 50), so the ordering
# remains: verified >> escape >> normal-unverified.
_ESCAPE_CAP = 55
_UNVERIFIED_CAP = 40


def _is_strong_unverified(candidate):
    """
    Return True when a candidate carries strong, converging evidence of
    exploitability even though no verified data-flow has been confirmed yet.

    All five conditions must hold simultaneously:
      1. web_exposed      — directly reachable from the network
      2. handler_surface  — HTTP form-handler strings found in the binary
      3. controllability == "HIGH"  — attacker can influence the input
      4. popen or system() sink     — dangerous exec reachable in principle
      5. plausibility_bonus > 0     — at least one positive direct-path signal

    When this returns True the score cap is raised from 40 → 55 and the
    candidate is tagged "UNVERIFIED_HIGH_VALUE" in the output.
    """
    if not candidate.get("web_exposed"):
        return False
    if not candidate.get("handler_surface"):
        return False
    if candidate.get("controllability") != "HIGH":
        return False
    sinks_lower = [s.lower() for s in (candidate.get("all_sinks") or [])]
    if not any("popen" in s or "system(" in s for s in sinks_lower):
        return False
    if int(candidate.get("plausibility_bonus") or 0) <= 0:
        return False
    return True


# ── Candidate classification helpers ─────────────────────────────────────────

def is_busybox_noise(candidate):
    """
    Return True if this candidate is a BusyBox applet producing false
    positive sinks (SHELL=/bin/sh, -/bin/sh).

    Requires at least 2 of 3 signals to avoid false-positives on
    legitimate binaries that happen to share a name with a BusyBox applet:

      a. Name matches a known BusyBox applet
      b. ALL sinks are declaration-only (no real exec sink present)
      c. Endpoints contain only the generic busybox /vlan/config artifact
    """
    name  = (candidate.get("name") or "").lower().strip()
    sinks = [s.lower() for s in (candidate.get("all_sinks") or [])]
    eps   = [e.lower() for e in (candidate.get("endpoints") or [])]

    a = name in _BUSYBOX_NAMES

    # All sinks are declaration-only when none of them contain a real
    # exec/popen/system call.
    b = bool(sinks) and not any(
        any(h in s for h in _REAL_EXEC_SINKS) for s in sinks
    ) and any(
        any(h in s for h in _DECL_ONLY_SINK_HINTS) for s in sinks
    )

    # Endpoint set is entirely the busybox artifact (empty or only /vlan/config)
    c = bool(eps) and all(any(h in e for h in _BUSYBOX_EP_ARTIFACTS) for e in eps)

    return sum([a, b, c]) >= 2


def _has_real_sink(candidate):
    """Return True if any sink is a genuinely dangerous operation.

    Covers both exec-class sinks (command injection / RCE) and
    memory-class sinks (buffer overflow / format string).  The latter
    are valid only when the candidate's flow_type confirms the context.
    """
    flow = (candidate.get("flow_type") or "").lower()
    is_mem_flow = flow in ("buffer_overflow", "format_string", "heap_overflow")

    for s in (candidate.get("all_sinks") or []):
        sl = s.lower()
        if any(h in sl for h in _DECL_ONLY_SINK_HINTS):
            continue
        if any(h in sl for h in _PSEUDO_EXEC_SINK_HINTS):
            continue
        if any(h in sl for h in _REAL_EXEC_SINKS):
            return True
        if is_mem_flow and any(h in sl for h in _REAL_MEMORY_SINKS):
            return True
    return False


def _has_hv_endpoint(candidate):
    """Return True if any endpoint is a high-value, named attack path."""
    for e in (candidate.get("endpoints") or []):
        el = e.lower()
        if any(h in el for h in _HV_ENDPOINT_HINTS):
            return True
    return False


def _has_only_generic_upgrade_endpoints(candidate):
    eps = [e.lower() for e in (candidate.get("endpoints") or []) if e]
    if not eps:
        return False
    return all(e in _GENERIC_UPGRADE_ENDPOINTS for e in eps)


def _has_only_source_artifact_endpoints(candidate):
    eps = [e.lower() for e in (candidate.get("endpoints") or []) if e]
    if not eps:
        return False
    return all(
        any(e.endswith(h) or h in e for h in _SOURCE_ARTIFACT_ENDPOINT_HINTS)
        for e in eps
    )


def _split_verified_flows(candidate):
    strong = []
    weak = []
    for f in (candidate.get("verified_flows") or []):
        verdict = (f.get("verdict") or "").upper()
        if verdict in ("CONFIRMED", "LIKELY"):
            strong.append(f)
        elif verdict == "UNCERTAIN":
            weak.append(f)
    return strong, weak


# ── CVE triage scoring ────────────────────────────────────────────────────────

def calc_cve_triage_score(candidate):
    """
    Compute a CVE-triage score that reflects a researcher's ranking criteria.

    This is NOT a replacement for the pipeline score.  It is a second-pass
    rescoring that answers: "would I file a CVE report for this?"

    Returns (triage_score: int, discard: bool, discard_reason: str | None)

    ── Score components ──────────────────────────────────────────────────────

    WEB PRESENCE  (primary gate for network-exploitable CVEs)
      +30  web_exposed == True
      +12  web_reachable == True  (not directly exposed but on the attack path)
      +10  handler_surface == True  (HTTP form-handler strings present in binary)

    AUTH QUALITY  (how easily an attacker reaches the vulnerable code)
      +25  auth_bypass == "confirmed"  — explicitly confirmed pre-auth access
      +15  auth_bypass == "bypassable" — explicit bypass hint (HNAP, no-auth)
      +0   auth_bypass == "none"       — absence of evidence ≠ pre-auth
      +0   auth_bypass == "unknown"    — not analysed; treat as required
      +0   auth_bypass == "required"   — auth needed; much harder to exploit

    EVIDENCE QUALITY
      +20  verified_flows not empty  (CONFIRMED or LIKELY flow found)
      +10  confidence == "HIGH"
      +5   confidence == "MEDIUM"

    ENDPOINT CONCRETENESS
      +10  high-value specific endpoint present
           (/firmware, /goform/, /administration, /cstecgi.cgi, ...)

    SINK QUALITY
      +10  popen or system() in sinks  (direct command execution)
      +5   /bin/sh in sinks  (shell invocation without confirmed popen/system)

    PIPELINE SCORE CARRY-OVER  (diminishing — prevents inflation)
      +min(20, int(pipeline_score × 0.08))

    PLAUSIBILITY SIGNAL  (from calc_exploitability_plausibility)
      +plausibility_bonus  (additive; no multiplier — prevents inflation)

    ACTIONABILITY SIGNALS
      +5   handler_symbols not empty  (named function targets for Ghidra)
      +3   injection_templates not empty  (visible %s command templates)

    CONTROLLABILITY
      +5   controllability == "HIGH"

    VERIFIED-FLOWS GATE  (three tiers)
      Uncapped   verified_flows not empty  — confirmed chain evidence
      Cap=55     _is_strong_unverified()   — all 5 escape conditions met;
                                             tagged UNVERIFIED_HIGH_VALUE
      Cap=40     everything else           — insufficient converging evidence

      Tier ordering ensures: verified >> escape >> normal-unverified.

    ── Discard conditions ────────────────────────────────────────────────────

    These are hard-drops regardless of score:
      1. is_busybox_noise()  — SHELL=/bin/sh is not a reachable sink
      2. No real sink         — all sinks are shebangs / env-var declarations
      3. File-input only, not web-reachable
      4. too_many_unknowns + not web-exposed
      5. triage_score < 20 AND not web-exposed AND no verified_flows
    """
    verdict = (candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    confirmed_input = candidate.get("confirmed_input")
    confirmed_sink = candidate.get("confirmed_sink")
    attacker_arg = str(candidate.get("attacker_controlled_argument") or "unconfirmed").lower()
    same_request = str(candidate.get("same_request") or "unknown").lower()
    auth_boundary = str(candidate.get("auth_boundary") or "").lower()
    sanitization = str(candidate.get("sanitization") or "unknown").lower()
    false_positive_risks = set(candidate.get("false_positive_risks") or [])

    # ── Hard discard: explicit reject from conservative readiness model ──────
    if verdict == "reject":
        return 0, True, "conservative readiness model rejected the candidate"

    # ── Hard discard: busybox noise ───────────────────────────────────────────
    if is_busybox_noise(candidate):
        return 0, True, "busybox applet — SHELL=/bin/sh is not a reachable sink"

    # ── Hard discard: no real sink ────────────────────────────────────────────
    sinks = candidate.get("all_sinks") or []
    if sinks and not _has_real_sink(candidate):
        return 0, True, "all sinks are declaration-only (shebang / env-var / SHELL=)"

    # Convenience flags
    web_exposed   = bool(candidate.get("web_exposed"))
    web_reachable = bool(candidate.get("web_reachable"))
    strong_verified, weak_verified = _split_verified_flows(candidate)
    missing = candidate.get("missing_links") or []

    # ── Hard discard: file-input only ─────────────────────────────────────────
    if (candidate.get("input_type") == "file"
            and not web_exposed and not web_reachable):
        return 0, True, "file-input only — not network-exploitable"

    if (
        not web_exposed and not web_reachable and not strong_verified and not weak_verified
        and not candidate.get("handler_surface")
        and _has_only_generic_upgrade_endpoints(candidate)
    ):
        return 0, True, "generic firmware/config artifact without web-reachable handler"

    if (
        _has_only_source_artifact_endpoints(candidate)
        and not candidate.get("handler_surface")
        and not strong_verified
    ):
        return 0, True, "source-artifact endpoint only without strong handler evidence"

    # ── Hard discard: too vague, not reachable ────────────────────────────────
    if "too_many_unknowns" in missing and not web_exposed and not web_reachable:
        return 0, True, "3+ unconfirmed chain elements with no web surface"

    # ── Score computation ─────────────────────────────────────────────────────
    score = 0

    # Web presence
    if web_exposed:
        score += 30
    elif web_reachable:
        score += 12
    if candidate.get("handler_surface"):
        score += 10

    # Auth quality
    # "none" / "unknown" → 0: absence of evidence is not confirmation of pre-auth.
    # Only an explicit "confirmed" or "bypassable" tag earns a bonus.
    auth = candidate.get("auth_bypass") or "unknown"
    if auth == "confirmed":
        score += 25   # explicitly confirmed pre-auth access
    elif auth == "bypassable":
        score += 15   # explicit bypass hint (HNAP, no-auth endpoint)

    # Evidence quality
    if strong_verified:
        score += 20
    elif weak_verified:
        score += 5
    conf = candidate.get("confidence") or "WEAK"
    if conf == "HIGH":
        score += 10
    elif conf == "MEDIUM":
        score += 5

    # Endpoint concreteness
    if _has_hv_endpoint(candidate):
        score += 10
    elif _has_only_generic_upgrade_endpoints(candidate):
        score -= 8
    if _has_only_source_artifact_endpoints(candidate):
        score -= 15

    # Sink quality
    sinks_lower = [s.lower() for s in sinks]
    if any("popen" in s or "system(" in s for s in sinks_lower):
        score += 10
    elif any("/bin/sh" in s for s in sinks_lower):
        score += 5

    # Pipeline score carry-over (capped to prevent inflation)
    pipeline_score = int(candidate.get("score") or 0)
    score += min(20, int(pipeline_score * 0.08))

    # Plausibility signal (from calc_exploitability_plausibility) — additive only
    plaus = int(candidate.get("plausibility_bonus") or 0)
    score += plaus

    # Actionability signals
    if candidate.get("handler_symbols"):
        score += 5
    if candidate.get("injection_templates"):
        score += 3

    # Controllability
    if candidate.get("controllability") == "HIGH":
        score += 5

    # Conservative CVE-readiness structure
    if confirmed_input and confirmed_input != "unconfirmed":
        score += 10
    if confirmed_sink and confirmed_sink != "unconfirmed":
        score += 4

    if attacker_arg == "confirmed":
        score += 18
    elif attacker_arg == "likely":
        score += 8

    if same_request == "confirmed":
        score += 8
    elif same_request == "deferred":
        score -= 6

    if auth_boundary == "pre-auth":
        score += 10
    elif auth_boundary == "bypassable":
        score += 5
    elif auth_boundary == "post-auth":
        score += 1

    if sanitization == "present":
        score -= 10
    elif sanitization == "bounded-or-truncating":
        score -= 8

    if verdict == "cve-ready":
        score += 20
    elif verdict == "promising":
        score += 10
    elif verdict == "needs-reversing":
        score -= 4

    if "constant_sink_argument" in false_positive_risks:
        score -= 25
    if "sink_import_only" in false_positive_risks:
        score -= 20
    if "cross_function_token_contamination" in false_positive_risks:
        score -= 18
    if "literal_logging_sink_only" in false_positive_risks:
        score -= 20
    if "bridge_api_unproven" in false_positive_risks:
        score -= 10
    if "bounded_or_truncated_copy" in false_positive_risks:
        score -= 8
    if "key_gated_protocol_surface" in false_positive_risks:
        score -= 15
    if "rpc_default_validator" in false_positive_risks:
        score -= 18
    if "double_quoted_no_subshell_exec" in false_positive_risks:
        score -= 15
    if "input_to_sink_unproven" in false_positive_risks:
        score -= 14
    if "no_exact_input" in false_positive_risks:
        score -= 8

    # ── Verified-flows gate: cap unverified candidates ───────────────────────
    # Without a confirmed data-flow path apply a score ceiling.
    # Escape condition: all 5 strong signals present → raise cap to 55 and mark
    # the candidate; otherwise hard cap at 40.
    if not strong_verified:
        if _is_strong_unverified(candidate):
            score = min(score, _ESCAPE_CAP)
        else:
            score = min(score, _UNVERIFIED_CAP)

    # ── Late discard: insufficient signal ────────────────────────────────────
    if score < 20 and not web_exposed and not web_reachable and not strong_verified and not weak_verified:
        return score, True, (
            f"triage_score={score} — low signal, not web-reachable, "
            "no verified flows"
        )

    return score, False, None


def select_cve_candidates(candidates, top_n=3):
    """
    Filter and rank candidates for CVE potential.

    Input:  list of candidate dicts from _build_result_snapshot() or
            the raw risk.py result dicts (both are accepted).
    Output: list of up to top_n dicts, ordered by triage_score descending.

    Each output dict contains all original candidate fields plus:
      "triage_score":           int   — CVE triage score (ranking key)
      "discard":                False — always False (discarded items excluded)
      "unverified_high_value":  bool  — True when escape condition fired;
                                        candidate is strong but unconfirmed
    """
    scored = []
    for c in candidates:
        ts, discard, _ = calc_cve_triage_score(c)
        if discard:
            continue
        strong_verified, _ = _split_verified_flows(c)
        entry = dict(c)
        entry["triage_score"] = ts
        entry["discard"] = False
        entry["unverified_high_value"] = (
            not strong_verified and _is_strong_unverified(c)
        )
        scored.append(entry)

    scored.sort(key=lambda x: x["triage_score"], reverse=True)
    return scored[:top_n]


def explain_triage(candidate):
    """
    Return a human-readable string explaining why a candidate was scored
    the way it was.  Useful for the dossier "Triage Notes" section.

    Returns (triage_score: int, lines: list[str])
    """
    ts, discard, reason = calc_cve_triage_score(candidate)
    if discard:
        return 0, [f"DISCARDED: {reason}"]

    lines = [f"triage_score = {ts}"]

    if candidate.get("web_exposed"):
        lines.append("+30  web_exposed")
    elif candidate.get("web_reachable"):
        lines.append("+12  web_reachable")
    if candidate.get("handler_surface"):
        lines.append("+10  handler_surface (HTTP form-handler strings present)")

    auth = candidate.get("auth_bypass") or "unknown"
    if auth == "confirmed":
        lines.append("+25  auth confirmed pre-auth")
    elif auth == "bypassable":
        lines.append("+15  auth bypassable (HNAP / no-auth hint)")

    strong_verified, weak_verified = _split_verified_flows(candidate)
    if strong_verified:
        lines.append(f"+20  {len(strong_verified)} verified flow(s)")
    elif weak_verified:
        lines.append(f"+5   {len(weak_verified)} uncertain flow heuristic(s)")
    conf = candidate.get("confidence") or "WEAK"
    if conf == "HIGH":
        lines.append("+10  confidence HIGH")
    elif conf == "MEDIUM":
        lines.append("+5   confidence MEDIUM")

    if _has_hv_endpoint(candidate):
        eps = [e for e in (candidate.get("endpoints") or [])
               if any(h in e.lower() for h in _HV_ENDPOINT_HINTS)]
        lines.append(f"+10  high-value endpoint: {eps[0] if eps else '?'}")

    sinks_lower = [s.lower() for s in (candidate.get("all_sinks") or [])]
    if any("popen" in s or "system(" in s for s in sinks_lower):
        lines.append("+10  popen/system() sink")
    elif any("/bin/sh" in s for s in sinks_lower):
        lines.append("+5   /bin/sh sink")

    pipeline_score = int(candidate.get("score") or 0)
    carry = min(20, int(pipeline_score * 0.08))
    if carry:
        lines.append(f"+{carry:2d}  pipeline score carry-over (score={pipeline_score})")

    plaus = int(candidate.get("plausibility_bonus") or 0)
    if plaus > 0:
        lines.append(f"+{plaus:2d}  plausibility bonus ({plaus:+d})")
    elif plaus < 0:
        lines.append(f"{plaus:3d}  plausibility penalty ({plaus:+d})")

    if candidate.get("handler_symbols"):
        lines.append("+5   handler symbols present")
    if candidate.get("injection_templates"):
        lines.append("+3   injection templates present")
    if candidate.get("controllability") == "HIGH":
        lines.append("+5   controllability HIGH")

    if candidate.get("confirmed_input") and candidate.get("confirmed_input") != "unconfirmed":
        lines.append(f"+10  confirmed_input ({candidate.get('confirmed_input')})")
    if candidate.get("confirmed_sink") and candidate.get("confirmed_sink") != "unconfirmed":
        lines.append(f"+4   confirmed_sink ({candidate.get('confirmed_sink')})")

    attacker_arg = str(candidate.get("attacker_controlled_argument") or "unconfirmed").lower()
    if attacker_arg == "confirmed":
        lines.append("+18  attacker-controlled sink argument confirmed")
    elif attacker_arg == "likely":
        lines.append("+8   attacker-controlled sink argument likely")

    same_request = str(candidate.get("same_request") or "unknown").lower()
    if same_request == "confirmed":
        lines.append("+8   same-request execution")
    elif same_request == "deferred":
        lines.append("-6   deferred/restart bridge")

    auth_boundary = str(candidate.get("auth_boundary") or "").lower()
    if auth_boundary == "pre-auth":
        lines.append("+10  auth_boundary pre-auth")
    elif auth_boundary == "bypassable":
        lines.append("+5   auth_boundary bypassable")
    elif auth_boundary == "post-auth":
        lines.append("+1   auth_boundary post-auth")

    sanitization = str(candidate.get("sanitization") or "unknown").lower()
    if sanitization == "present":
        lines.append("-10  sanitization present")
    elif sanitization == "bounded-or-truncating":
        lines.append("-8   bounded/truncating copy path")

    verdict = (candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    if verdict == "cve-ready":
        lines.append("+20  conservative verdict cve-ready")
    elif verdict == "promising":
        lines.append("+10  conservative verdict promising")
    elif verdict == "needs-reversing":
        lines.append("-4   conservative verdict needs-reversing")

    for risk in candidate.get("false_positive_risks") or []:
        penalty = {
            "constant_sink_argument": "-25",
            "sink_import_only": "-20",
            "cross_function_token_contamination": "-18",
            "literal_logging_sink_only": "-20",
            "bridge_api_unproven": "-10",
            "bounded_or_truncated_copy": "-8",
            "key_gated_protocol_surface": "-15",
            "rpc_default_validator": "-18",
            "double_quoted_no_subshell_exec": "-15",
            "input_to_sink_unproven": "-14",
            "no_exact_input": "-8",
        }.get(risk)
        if penalty:
            lines.append(f"{penalty}  false_positive_risk {risk}")

    if not strong_verified:
        if _is_strong_unverified(candidate):
            lines.append(
                f"     [cap={_ESCAPE_CAP}] UNVERIFIED_HIGH_VALUE — "
                "escape condition met (web+handler+ctrl+sink+plausibility)"
            )
        else:
            lines.append(
                f"     [cap={_UNVERIFIED_CAP}] no verified flows — score capped at {_UNVERIFIED_CAP}"
            )

    missing = candidate.get("missing_links") or []
    if missing:
        visible = [m for m in missing if m != "too_many_unknowns"]
        if visible:
            lines.append(f"     missing links: {', '.join(visible)}")

    return ts, lines
