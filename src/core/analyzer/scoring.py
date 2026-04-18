import re

# ── Feature-chain keyword sets ────────────────────────────────────────────────
# Used by calc_feature_chain_adjustment() to reward human/LLM-preferred
# attack-chain candidates and penalise generic daemon noise.

# Router feature domains — presence signals a real user-facing attack surface.
_FEATURE_KEYWORDS = {
    "qos", "ddns", "wan", "wlan", "vpn", "parental", "repeater", "survey",
    "upload", "filter", "portmap", "dmz", "upnp", "acl", "vlan", "firewall",
    "schedule", "bandwidth", "iptv", "nat", "dhcpd", "pppoe", "bridge",
}

# Frontend/HTTP-handler signals — suggests the binary processes form or CGI input.
_FRONTEND_KEYWORDS = {
    "action=", "ajax", "formvalue", "form_get", "form_set",
    "cgi_main", "cgi-bin", "handle_request", "process_form",
    "apply_cgi", "save_setting", "do_system", "apply.cgi",
    "submit", "nvram_get", "websGetVar",
}

# Config/nvram/MIB write indicators — data persisted here becomes an indirect
# sink if later reused without sanitisation.
_CONFIG_WRITE_KEYWORDS = {
    "nvram_set", "nvram_commit", "nvram_bufset", "mib_set", "config_set",
    "cfg_set", "apmib_set", "set_config", "write_config", "fwrite",
    "/etc/config", "/tmp/", "nvram_store",
}

# Post-write restart/apply indicators — config becomes active (executed) here.
_RESTART_KEYWORDS = {
    "restart", "reload", "reboot", "kill -", "killall",
    "ifconfig", "iptables", "route add", "service restart", "apply",
}

# Generic daemon noise signals — protocol internals, not feature handlers.
_GENERIC_DAEMON_KEYWORDS = {
    "malformed", "invalid frame", "bad packet", "parse error", "decode error",
    "frame too", "packet too", "unexpected eof", "connection reset",
    "keepalive", "heartbeat",
}

# Auth/session helpers — rarely lead directly to feature-level sinks.
_AUTH_HELPER_KEYWORDS = {
    "session_id", "auth_check", "login_verify", "check_auth", "verify_token",
    "is_authenticated", "cookie_check", "csrf_token",
}


def calc_feature_chain_adjustment(strings, exec_path):
    """
    Compute a score adjustment based on feature-chain vs generic-daemon signals.
    Returns an integer (positive or negative) added to the final score after all
    other factors, so it represents independent ranking priority rather than
    raw exploitability magnitude.

    Positive signals (human/LLM-preferred candidates):
      +3   frontend linkage found (action=, cgi handler, form processor)
      +3/+5 feature keywords present (wan/vpn/qos/ddns…) — +3 for any, +5 for 3+
      +3   config/nvram/MIB write behaviour detected
      +2   restart/rebuild present alongside config write (chain step 3)
      +4   full chain: frontend → config write → restart all co-present

    Negative signals (generic daemon / noise candidates):
      -5   exec path contains 'boa' — generic httpd, known/studied internals
      -3   generic daemon noise keywords with no feature context
      -2   malformed/frame handling with no config-write linkage
      -2   auth/session helper with no frontend or config context
    """
    if not strings:
        return 0

    lower_strings = [s.lower() for s in strings]
    lower_exec = (exec_path or "").lower()

    def hit_set(keyword_set):
        return any(any(k in l for k in keyword_set) for l in lower_strings)

    def count_hits(keyword_set):
        return sum(1 for kw in keyword_set if any(kw in l for l in lower_strings))

    adj = 0

    # ── Positive: frontend/HTTP handler linkage ───────────────────────────────
    # Presence of form-processing or CGI indicators strongly suggests this binary
    # sits on the HTTP→feature boundary that human analysts target first.
    has_frontend = hit_set(_FRONTEND_KEYWORDS)
    if has_frontend:
        adj += 3

    # ── Positive: router feature domain keywords ──────────────────────────────
    # Binaries that handle specific features (WAN, VPN, QoS…) are far more
    # interesting than generic parsing daemons — each keyword is a distinct
    # entry point into a real user-controllable flow.
    feature_count = count_hits(_FEATURE_KEYWORDS)
    if feature_count >= 3:
        adj += 5   # rich multi-feature binary = broad attack surface
    elif feature_count >= 1:
        adj += 3

    # ── Positive: config/nvram/MIB write ─────────────────────────────────────
    # Persistent storage writes create the indirect-sink pattern:
    # attacker-supplied form value → nvram_set → reboot → system(nvram_get(…)).
    has_config_write = hit_set(_CONFIG_WRITE_KEYWORDS)
    if has_config_write:
        adj += 3

    # ── Positive: config write + service restart ──────────────────────────────
    # When config write is followed by a restart/apply action the chain is
    # complete: write-then-execute is the canonical embedded-router RCE pattern.
    has_restart = hit_set(_RESTART_KEYWORDS)
    if has_config_write and has_restart:
        adj += 2

    # ── Positive: full three-stage chain bonus ────────────────────────────────
    # All stages present: frontend input → config write → apply/restart.
    # This precisely matches what human/LLM auditors mark as high-priority.
    if has_frontend and has_config_write and has_restart:
        adj += 4

    # ── Negative: boa / generic httpd internals ───────────────────────────────
    # boa is a well-studied, heavily-fuzzed daemon; core-internal findings
    # there are almost always known or low-novelty.  Penalise to let
    # feature-specific handlers rank above it.
    if "boa" in lower_exec or "/boa" in lower_exec:
        adj -= 5

    # ── Negative: generic noise without any feature context ──────────────────
    # Protocol parsing noise (malformed-frame handling, keepalives) without a
    # single router-feature keyword is almost never a high-priority finding.
    has_noise = hit_set(_GENERIC_DAEMON_KEYWORDS)
    if has_noise and not has_frontend and feature_count == 0:
        adj -= 3

    # ── Negative: malformed/frame handling without config linkage ────────────
    # These code paths are triggered by fuzzers, not realistic attacker-
    # controlled HTTP/form inputs, and are not part of a feature chain.
    if has_noise and not has_config_write:
        adj -= 2

    # ── Negative: auth/session helpers without downstream feature context ─────
    # Auth helpers that don't feed into feature handlers rarely reach
    # interesting sinks; they produce false-positive rankings.
    has_auth_helper = hit_set(_AUTH_HELPER_KEYWORDS)
    if has_auth_helper and not has_frontend and not has_config_write:
        adj -= 2

    return adj


# ── Chain-consistency keyword sets ───────────────────────────────────────────
# Used by calc_chain_consistency_adjustment() to validate that write and sink
# actually share data rather than just co-existing in the same binary.

# Config-read symbols — the "reuse" step that connects storage to execution.
# Presence alongside a sink strongly implies read-then-execute.
_CONFIG_READ_KEYWORDS = {
    "nvram_get", "nvram_bufget", "mib_get", "config_get", "cfg_get",
    "apmib_get", "get_config", "read_config",
}

# Sink context keywords for proximity checks (deliberately broad substrings).
_SINK_CONTEXT_KEYWORDS = {
    "system", "popen", "execl", "execv", "/bin/sh", "sh -c",
}

# How close (in string-table index) two strings must be to count as
# "same function locality".  Strings from the same function are typically
# emitted within a few dozen indices of each other in the binary's rodata.
_PROXIMITY_WINDOW = 30

# Tokens too generic to count as evidence of parameter reuse.
_TRIVIAL_TOKENS = {
    "get", "set", "the", "for", "and", "not", "err", "null", "true",
    "false", "none", "val", "key", "str", "buf", "len", "ret", "tmp",
    "num", "idx", "ptr", "type", "name", "data", "info", "list", "flag",
    "mode", "size", "time", "code", "path", "file", "line", "char",
    "config", "nvram", "value", "result", "error", "status", "argv",
    "read", "write", "open", "close", "load", "save", "init", "exit",
}


def _extract_tokens(string_list, min_len=4):
    """
    Split strings on non-alphanumeric chars and return the set of tokens
    that are long enough and not in the trivial-token stoplist.
    These represent potential variable/parameter/config-key names.
    """
    tokens = set()
    for s in string_list:
        for part in re.split(r'[^a-z0-9_]', s.lower()):
            if len(part) >= min_len and part not in _TRIVIAL_TOKENS:
                tokens.add(part)
    return tokens


def _proximity_hit(lower_strings, set_a, set_b, window=_PROXIMITY_WINDOW):
    """
    Return True if any string matching set_a appears within `window` indices
    of any string matching set_b in the ordered string table.

    String-table order approximates address order: strings from the same
    function tend to cluster, so proximity is a lightweight same-function proxy.
    O(|matches_a| × |matches_b|) — both sets are typically small (< 50).
    """
    idx_a = [i for i, s in enumerate(lower_strings)
             if any(k in s for k in set_a)]
    if not idx_a:
        return False
    idx_b = set(i for i, s in enumerate(lower_strings)
                if any(k in s for k in set_b))
    if not idx_b:
        return False
    return any(
        any(abs(ia - ib) <= window for ib in idx_b)
        for ia in idx_a
    )


def calc_chain_consistency_adjustment(strings):
    """
    Second-pass refinement: reward binaries where config-write and command-sink
    share actual data (key names, proximity), penalise binaries where those
    signals are isolated keyword islands.

    Positive signals (real chain evidence):
      +5  config-read (nvram_get/mib_get) appears within ±30 strings of a
          command sink — same-function locality strongly implies read→execute
      +2  config-read exists anywhere (write→read cycle is present even if
          not provably proximate to the sink)
      +4  ≥2 shared key tokens between config-write strings and sink strings
          (e.g. "wan_ip" appears in both nvram_set context and system() context)
      +2  exactly 1 shared key token (weak but present reuse evidence)
      +3  frontend parameter tokens overlap with config-write tokens —
          form input names reach the storage call

    Negative signals (fake chain penalties):
      -4  config write present but no config-read anywhere — binary only writes,
          never reads back; the stored value is never passed to a sink here
      -3  command sink present with no config context nearby (no nvram_get/
          config string within proximity of system/popen) — sink is called
          with static or non-config-derived arguments
      -2  frontend present but its parameter tokens share nothing with config-
          write or sink tokens — handler and sink are isolated islands
    """
    if not strings:
        return 0

    lower_strings = [s.lower() for s in strings]

    def hit(keyword_set):
        return any(any(k in s for k in keyword_set) for s in lower_strings)

    def matching(keyword_set):
        return [s for s in lower_strings if any(k in s for k in keyword_set)]

    adj = 0

    has_config_write = hit(_CONFIG_WRITE_KEYWORDS)
    has_config_read  = hit(_CONFIG_READ_KEYWORDS)
    has_sink         = hit(_SINK_CONTEXT_KEYWORDS)
    has_frontend     = hit(_FRONTEND_KEYWORDS)

    # ── Positive: config-read proximate to command sink ───────────────────────
    # nvram_get / mib_get appearing within ~30 strings of system() / popen()
    # is the canonical "val = nvram_get(key); system(cmd_with_val)" pattern.
    if has_config_read and has_sink:
        if _proximity_hit(lower_strings, _CONFIG_READ_KEYWORDS,
                          _SINK_CONTEXT_KEYWORDS):
            adj += 5   # proximate: almost certainly same function
        else:
            adj += 2   # exists but not proven near sink; partial credit

    # ── Positive: shared key tokens between write-context and sink-context ─────
    # If "wan_ip" appears in both nvram_set("wan_ip", ...) strings and
    # system("route add ... %s") strings, the same parameter name is reused.
    # This catches the indirect chain even without proximity evidence.
    if has_config_write and has_sink:
        write_toks = _extract_tokens(matching(_CONFIG_WRITE_KEYWORDS))
        sink_toks  = _extract_tokens(matching(_SINK_CONTEXT_KEYWORDS))
        shared     = write_toks & sink_toks
        if len(shared) >= 2:
            adj += 4   # multiple shared names = strong write→execute linkage
        elif len(shared) == 1:
            adj += 2   # single shared name = weak but real reuse signal

    # ── Positive: frontend token overlap with config-write context ────────────
    # Shared tokens between HTTP-handler strings and nvram_set strings prove
    # that form parameter names actually reach the storage call.
    if has_frontend and has_config_write:
        fe_toks    = _extract_tokens(matching(_FRONTEND_KEYWORDS))
        write_toks = _extract_tokens(matching(_CONFIG_WRITE_KEYWORDS))
        if fe_toks & write_toks:
            adj += 3   # form parameter names appear in write calls

    # ── Negative: config write with no config read ────────────────────────────
    # Write-only binary: nvram_set is called but nvram_get never is, so the
    # stored value is never read back into a command — chain is incomplete here.
    if has_config_write and not has_config_read:
        adj -= 4

    # ── Negative: sink present but no config context nearby ──────────────────
    # system()/popen() exists but nothing config-related appears near it.
    # The command arguments are almost certainly static or come from a
    # non-config source that was not attacker-influenced via this binary.
    if has_sink and not _proximity_hit(lower_strings,
                                       _CONFIG_READ_KEYWORDS | _CONFIG_WRITE_KEYWORDS,
                                       _SINK_CONTEXT_KEYWORDS):
        adj -= 3

    # ── Negative: frontend with no parameter reuse in write or sink context ───
    # Frontend handler exists but its parameter names appear in neither the
    # nvram_set strings nor the system() strings — it may only display data.
    if has_frontend and not has_config_write and not has_config_read:
        adj -= 2

    return adj


# ── Cross-binary chain correlation ───────────────────────────────────────────
# These functions are called from risk.py in a second pass after all binaries
# have been scored.  The pattern detected is:
#   Binary A (writer):  nvram_set("wan_ip", user_input)
#   Binary B (reader):  nvram_get("wan_ip") → system(cmd)
# Such chains span component boundaries and are invisible to single-binary
# analysis; they represent the canonical embedded-router indirect RCE pattern.


def extract_config_key_tokens(strings):
    """
    Return (write_tokens, read_tokens) for a binary's config key usage.

    Splits strings near config-write / config-read keywords and returns the
    non-trivial token sets.  These fingerprints are used by
    build_config_key_index() to find shared key names across binaries.
    """
    if not strings:
        return set(), set()
    lower_strings = [s.lower() for s in strings]

    def matching(kw_set):
        return [s for s in lower_strings if any(k in s for k in kw_set)]

    return (
        _extract_tokens(matching(_CONFIG_WRITE_KEYWORDS)),
        _extract_tokens(matching(_CONFIG_READ_KEYWORDS)),
    )


def has_frontend_linkage(strings):
    """Return True if the binary's strings indicate a frontend/HTTP handler."""
    if not strings:
        return False
    return any(any(k in s.lower() for k in _FRONTEND_KEYWORDS) for s in strings)


def build_config_key_index(binary_token_map):
    """
    Build a global config-key token index from per-binary token fingerprints.

    binary_token_map: {binary_path: {'write': set, 'read': set,
                                     'has_sink': bool, 'has_frontend': bool}}
    Returns: {token: {'writers': [path, ...], 'readers': [path, ...]}}

    Called once after all binaries have been analysed; O(N × |tokens|).
    """
    index = {}
    for path, info in binary_token_map.items():
        for tok in info.get('write', set()):
            index.setdefault(tok, {'writers': [], 'readers': []})['writers'].append(path)
        for tok in info.get('read', set()):
            index.setdefault(tok, {'writers': [], 'readers': []})['readers'].append(path)
    return index


def calc_cross_binary_bonus(binary_path, binary_token_map, key_index):
    """
    Compute a cross-binary write→read→sink chain bonus for a single binary.

    A binary earns this bonus when it plays the reader+sink role:
      - it calls config-read functions (nvram_get / mib_get / …)
      - it has at least one dangerous sink (system / popen / exec)
      - at least one of its read-side tokens is written by a *different* binary

    Positive signals:
      +6  cross-binary chain confirmed (writer binary identified)
      +3  extra if the writer has frontend linkage — full 4-stage chain:
          HTTP form → writer binary → config store → reader binary → sink

    Returns: (bonus: int, chain_info: dict | None)
      chain_info = {'writer': path, 'reader': path, 'shared_keys': [token, ...]}
      chain_info is None when no cross-binary chain is found.
    """
    info      = binary_token_map.get(binary_path, {})
    read_toks = info.get('read', set())
    has_sink  = info.get('has_sink', False)

    if not read_toks or not has_sink:
        return 0, None

    # Map each read-side token to external binaries that write it.
    shared_by_writer = {}   # writer_path → [shared_token, ...]
    for tok in read_toks:
        for writer in key_index.get(tok, {}).get('writers', []):
            if writer == binary_path:
                continue   # same-binary reuse is already covered by chain_consistency
            shared_by_writer.setdefault(writer, []).append(tok)

    if not shared_by_writer:
        return 0, None

    # Pick the writer that shares the most key tokens (strongest evidence).
    best_writer = max(shared_by_writer, key=lambda w: len(shared_by_writer[w]))
    shared_keys = shared_by_writer[best_writer]

    bonus = 6
    # If the writer binary handles HTTP/CGI input, the chain starts at the
    # user-visible attack surface — maximum attacker reach.
    if binary_token_map.get(best_writer, {}).get('has_frontend', False):
        bonus += 3

    chain_info = {
        'writer':      best_writer,
        'reader':      binary_path,
        'shared_keys': shared_keys[:5],   # cap for display
    }
    return bonus, chain_info


# ── Exploit context signals (Gaps 1–5) ───────────────────────────────────────
# These signals answer the question an LLM/human analyst asks after seeing a
# sink: "how easy is this to actually exploit?"
#
#  Gap 1  calc_hardening_bonus()         — absent stack canary / PIE / RELRO
#  Gap 2  detect_injection_templates()   — visible %s in shell command strings
#  Gap 3  extract_endpoints()            — named /goform/ or /cgi-bin/ URLs
#  Gap 4  calc_symbol_bonus()            — internal function names from .symtab
#  Gap 5  assess_auth_bypass()           — frontend with no auth guard detected
#
#  calc_exploit_context_bonus() aggregates all five into one additive bonus
#  that is passed to calc_score() as exploit_signal_bonus.


# Shell command verbs that commonly appear in injectable template strings.
_SHELL_CMD_HINTS = {
    "wget ", "curl ", "iptables ", "ip6tables ", "ebtables ",
    "route add", "route del", "ifconfig ", "uci set", "uci commit",
    "nvram set", "killall ", "ping ", "chmod ", "mkdir ",
    "echo ", "telnet ", "nc ", "/bin/sh", "sh -c",
    "cmd=", "command=", "do_system",
}

# Format specifiers that indicate user-supplied value substitution.
_FORMAT_SPECS = {"%s", "%d", "%i", "%u", "%x", "%02x", "$(", "`"}


def detect_injection_templates(strings):
    """
    Find strings that pair a shell command verb with a format specifier.

    A match like "iptables -I INPUT -s %s -j DROP" is smoking-gun evidence:
    the attacker-supplied value is literally visible in the binary's string
    table as the argument to a shell command.

    Returns list of up to 5 matching template strings (capped at 120 chars).
    """
    templates = []
    for s in strings:
        l = s.lower()
        if (any(c in l for c in _SHELL_CMD_HINTS) and
                any(f in s for f in _FORMAT_SPECS) and
                len(s) >= 6):
            templates.append(s[:120])
            if len(templates) >= 5:
                break
    return templates


# Regex for named HTTP endpoint paths embedded in binary strings.
# Covers the most common CGI/API namespaces found in embedded router firmware.
_ENDPOINT_RE = re.compile(
    r'(/(?:goform|cgi-bin|cgi|HNAP1|api|admin|apply|setup|wan|wlan|'
    r'wireless|network|firewall|vpn|ddns|nat|qos|upnp|parental|acl|vlan|'
    r'upgrade|firmware|diagnostic|management|config)[^\s"\'<>\x00]{0,80})',
    re.IGNORECASE,
)


def extract_endpoints(strings):
    """
    Extract named HTTP endpoint paths embedded in binary strings.

    Paths like "/goform/SetWanInfo" or "/cgi-bin/apply_setting.cgi" are the
    specific URLs an attacker would submit a crafted request to — far more
    actionable than a generic "socket input" classification.

    Returns sorted list of up to 10 unique endpoint paths (≥ 5 chars).
    """
    endpoints = set()
    for s in strings:
        for m in _ENDPOINT_RE.finditer(s):
            ep = m.group(1).rstrip('/')
            if len(ep) >= 5:
                endpoints.add(ep)
    return sorted(endpoints)[:10]


# Auth guard symbols — presence indicates the handler enforces credentials.
_AUTH_GUARD_KEYWORDS = {
    "check_login", "verify_session", "is_admin", "auth_check",
    "session_valid", "check_auth", "login_check", "authenticate",
    "verify_password", "check_user", "is_logged_in", "check_privilege",
    "require_auth", "need_login",
}

# Known authentication-bypass patterns in embedded routers.
_AUTH_BYPASS_HINTS = {
    "soapaction",   # HNAP SOAPAction: many methods reachable unauthenticated
    "urn:hnap1",    # HNAP unauthenticated service exposure
    "no-auth",
    "noauth",
}


def assess_auth_bypass(strings, has_frontend):
    """
    Estimate whether frontend handlers can be reached without authentication.

    Only meaningful for frontend-linked binaries; returns ('required', 0)
    immediately for non-frontend binaries to avoid false positives.

    Returns: (status: str, bonus: int)
      ('none',       +3)  — frontend found, zero auth-guard keywords present
      ('bypassable', +2)  — explicit bypass hint (HNAP SOAPAction, no-auth)
      ('required',    0)  — at least one auth-guard keyword detected
    """
    if not has_frontend:
        return 'required', 0

    lower = [s.lower() for s in strings]

    if any(any(k in l for k in _AUTH_BYPASS_HINTS) for l in lower):
        return 'bypassable', 2
    if not any(any(k in l for k in _AUTH_GUARD_KEYWORDS) for l in lower):
        return 'none', 3
    return 'required', 0


# Internal symbol name patterns for Gap 4 (calc_symbol_bonus).

# Prefixes/substrings that identify user-input handler functions.
_HANDLER_SYM_HINTS = {
    "handle_", "apply_", "process_", "do_cgi", "do_apply",
    "set_wan", "set_ddns", "set_wlan", "set_vpn", "set_nat",
    "set_qos", "set_upnp", "set_acl", "set_vlan", "set_firewall",
    "save_setting", "config_save", "apply_setting", "websform",
    "cgi_handle", "form_handle",
}

# Substrings that identify command-execution wrapper functions.
_SINK_SYM_HINTS = {
    "do_system", "exec_cmd", "run_cmd", "run_command",
    "exec_shell", "system_cmd", "popen_cmd", "shell_cmd",
    "do_exec", "call_system",
}


def calc_symbol_bonus(symbol_names):
    """
    Bonus from internal function symbol names (.symtab, via get_internal_symbols).

    Symbol names are higher-confidence evidence than string co-presence:
    handle_wan_setting() directly names the feature attacked, not just a log.

    +4  handler-pattern names found (handle_*, apply_*, set_wan*, …)
    +2  sink-wrapper names found (do_system*, exec_cmd*, …)
    """
    if not symbol_names:
        return 0
    bonus = 0
    if any(any(h in n for h in _HANDLER_SYM_HINTS) for n in symbol_names):
        bonus += 4
    if any(any(h in n for h in _SINK_SYM_HINTS) for n in symbol_names):
        bonus += 2
    return bonus


def calc_hardening_bonus(hardening):
    """
    Score bonus for absent compile-time security mitigations.

    Absent hardening directly lowers the bar for exploitation: no stack canary
    means a simple overflow controls EIP/PC; no PIE means ROP addresses are
    static.  Scored separately from exploitability factors to reflect
    how easy a discovered vulnerability is to actually weaponise.

    +5  no canary AND no PIE  — classic unprotected embedded binary
    +3  no canary only        — stack overflows have no protection
    +2  no PIE only           — fixed addresses ease ROP chain construction
    +1  no RELRO              — GOT overwrite remains viable
    -1  all mitigations present — exploitation materially harder

    Returns 0 on empty input (fail-open: unknown hardening ≠ penalty).
    """
    if not hardening:
        return 0

    no_canary = not hardening.get('canary', True)
    no_pie    = not hardening.get('pie',    True)
    no_relro  = not hardening.get('relro',  True)

    bonus = 0
    if no_canary and no_pie:
        bonus += 5
    elif no_canary:
        bonus += 3
    elif no_pie:
        bonus += 2

    if no_relro:
        bonus += 1

    all_hardened = (
        hardening.get('canary') and hardening.get('pie') and
        hardening.get('relro') and hardening.get('nx', True)
    )
    if all_hardened:
        bonus -= 1   # full hardening: exploitation materially harder

    return bonus


# TOCTOU race-condition indicators.
# Pattern: check (access/stat) on a path → use (open/fopen/unlink) on same path.
# Classic /tmp symlink race or file-existence TOCTOU.
_TOCTOU_CHECK_KEYWORDS = {
    "access(", "stat(", "lstat(", "faccessat",
    "/tmp/", "tmpfile", "mktemp(", "tempnam(",
}
_TOCTOU_USE_KEYWORDS = {
    "open(", "fopen(", "unlink(", "rename(", "chmod(",
    "chown(", "execve(", "dlopen(",
}


def detect_toctou_risk(strings):
    """
    Detect potential TOCTOU (time-of-check-to-time-of-use) race conditions.

    Heuristic: a binary that both checks a path (access/stat) AND then uses it
    (open/fopen/unlink) on what appears to be a /tmp or user-supplied path has
    the classic race-condition structure.  Not a confirmed vulnerability, but
    worth flagging as a secondary signal for the Stage-2 analyst.

    Returns True if the pattern is present.
    """
    lower = [s.lower() for s in strings]
    has_check = any(any(k in l for k in _TOCTOU_CHECK_KEYWORDS) for l in lower)
    has_use   = any(any(k in l for k in _TOCTOU_USE_KEYWORDS)   for l in lower)
    return has_check and has_use


def generate_vuln_summary(result):
    """
    Generate a one-line CVE-style vulnerability description.

    Combines: auth requirement + input type + vulnerability class + entry point
    + sink.  Produces output comparable to what an LLM analyst would write as
    the first line of a vulnerability report.

    Example: "pre-auth HTTP Command Injection via /goform/SetWanInfo → system()"
    """
    flow       = result.get('flow_type') or ''
    input_type = result.get('input_type') or 'unknown'
    sinks      = (result.get('all_sinks') or result.get('sinks') or [])[:1]
    sink       = sinks[0] if sinks else 'dangerous function'
    auth       = result.get('auth_bypass', 'required')
    endpoints  = result.get('endpoints') or []

    _FLOW_NAME = {
        'cmd_injection':       'Command Injection',
        'bof+net_length':      'Network-Length Buffer Overflow',
        'buffer_overflow':     'Stack Buffer Overflow',
        'net_copy_partial':    'Partial Network Buffer Copy',
        'dlopen_injection':    'Dynamic Library Injection',
        'file_path_injection': 'File Path Injection',
        'file_cmd_injection':  'File-based Command Injection',
        'config_injection':    'Config-File Buffer Overflow',
    }
    vuln_type  = _FLOW_NAME.get(flow, 'Memory/Command Vulnerability')
    auth_str   = 'pre-auth' if auth in ('none', 'bypassable') else 'post-auth'
    input_str  = 'HTTP'     if input_type == 'socket' else input_type.upper()

    import os as _os
    ep       = next((_os.path.basename(e) for e in endpoints if e), None)
    via_str  = f' via {ep}' if ep else ''

    return f"{auth_str} {input_str} {vuln_type}{via_str} → {sink}"


def calc_exploit_context_bonus(hardening, symbol_names,
                                injection_templates, endpoints,
                                auth_bypass_bonus, has_toctou=False):
    """
    Aggregate all exploit-context signals (Gaps 1–5) into a single bonus.

    Called from risk.py after per-binary signals are collected; passed to
    calc_score() as exploit_signal_bonus.  Applied after all multipliers so
    it shifts rank independently of raw exploitability magnitude.

    Gap 1  hardening absence  : calc_hardening_bonus()           up to +6
    Gap 2  injection templates: +4 (one) or +5 (two or more)     up to +5
    Gap 3  named endpoints    : +2 (any) or +4 (three or more)   up to +4
    Gap 4  symbol names       : calc_symbol_bonus()              up to +6
    Gap 5  auth bypass        : auth_bypass_bonus (0 / +2 / +3)  up to +3
    """
    bonus = 0
    bonus += calc_hardening_bonus(hardening)
    bonus += calc_symbol_bonus(symbol_names)

    # Injection templates: each one is a directly visible attack point.
    if len(injection_templates) >= 2:
        bonus += 5   # multiple explicit injection strings
    elif injection_templates:
        bonus += 4   # one visible injection template

    # Named endpoints: specific URLs beat a generic "socket" classification.
    if len(endpoints) >= 3:
        bonus += 4   # rich endpoint set → broad, specific attack surface
    elif endpoints:
        bonus += 2   # at least one named target URL

    bonus += auth_bypass_bonus   # 0 / +2 / +3

    # TOCTOU race condition: /tmp check-then-use pattern.
    # Lower bonus than direct injection — race conditions require more setup.
    if has_toctou:
        bonus += 2

    return bonus


# ── Vendor-specific API pattern detection ────────────────────────────────────
# Vendor-specific APIs are typically less-audited than standard libc and are
# more likely to harbour novel vulnerabilities.  Each weight reflects how
# directly the API name signals an attacker-controllable sink or entry point.

_VENDOR_API_WEIGHTS = {
    "websgetvar":   5,   # Netgear/GoAhead: reads HTTP form variable → sink
    "webswrite":    4,   # Netgear: HTTP response writer (XSS / injection surface)
    "hnap":         4,   # D-Link HNAP: unauthenticated SOAP service methods
    "cstecgi.cgi":  5,   # TP-Link: main CGI dispatcher (all form traffic)
    "tddp":         4,   # TP-Link TDDP: LAN-side debug protocol, pre-auth
    "apmib_":       4,   # Realtek AP-MIB: widely used in D-Link/Tenda/Edimax
    "nvram_bufset": 3,   # Broadcom bulk nvram write (Netgear/Linksys/Asus)
    "twsystem":     3,   # Trendnet system() wrapper
    "bcm_nvram":    3,   # Broadcom nvram variant
    "formsetwan":   5,   # Tenda: WAN form handler, historically cmd-injection prone
    "goahead":      3,   # GoAhead web server (very common in budget routers)
    "ej_":          3,   # Asus httpd template handler prefix (ej_completion etc.)
    "do_cgi":       4,   # Generic CGI dispatcher (Asus / various)
    "httpd_":       3,   # Generic httpd symbol prefix
    "set_pppoe":    4,   # PPPoE setter — user-supplied credentials pass through
    "set_pptp":     4,   # PPTP setter — similar credential/cmd risk
    "formwizard":   4,   # Tenda setup wizard forms
    "set_ddns":     4,   # DDNS handler — hostname parameter often injected
}


def calc_vendor_pattern_bonus(strings):
    """
    Bonus for vendor-specific API patterns found in binary strings.

    Each vendor API hit raises the confidence that this binary handles
    real user input via a less-audited, vendor-specific code path.
    The highest single-pattern weight wins (patterns don't stack) to prevent
    accidental inflation on binaries that merely reference the API in strings.

    Returns an integer bonus in [0, 8].
    """
    if not strings:
        return 0
    lower = [s.lower() for s in strings]
    best  = 0
    for pattern, weight in _VENDOR_API_WEIGHTS.items():
        if any(pattern in l for l in lower):
            best = max(best, weight)
    return min(8, best)


# ── Logging-only sink detection ───────────────────────────────────────────────
# When the only "sinks" present are logging functions (printf/syslog/fprintf)
# and there are no exec or memory-corruption sinks, the binary should be
# deprioritised because the actual exploitation surface is much narrower
# (format-string bugs only, typically harder to weaponise).

_EXEC_SINK_KEYS = {
    "system", "popen", "execl", "execv", "execle", "execve",
    "execvp", "execlp", "dlopen", "dlsym",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "memcpy", "__memcpy_chk", "read(", "fwrite", "write(",
}


def is_logging_only_sink(all_sinks):
    """
    Return True if all detected sinks are logging functions with no exec or
    memory-corruption operations present.

    printf / fprintf / syslog are only dangerous for format-string bugs — a
    much narrower attack surface than command execution or stack overflows.
    When every sink is a logging call, the binary is deprioritised (~50% score
    reduction) so higher-severity candidates rank above it.

    Returns False (safe to keep) when all_sinks is empty — no sinks means the
    binary already filtered out before this check.
    """
    if not all_sinks:
        return False
    for sink in all_sinks:
        l = sink.lower()
        if any(k in l for k in _EXEC_SINK_KEYS):
            return False   # at least one exec / memory sink found
    return True


# ── Integer overflow → heap overflow detection ────────────────────────────────
# Pattern: heap allocation (malloc/calloc) whose size comes from a network
# byte-order conversion (ntohl/ntohs) without an intervening size check.
# This is the canonical integer-overflow → heap-overflow pattern in embedded
# network daemons (e.g. length field in TLV read directly into malloc arg).

_HEAP_ALLOC_KEYS = {
    "malloc", "calloc", "realloc", "valloc", "memalign", "mmap",
    "posix_memalign",
}
_NETWORK_LEN_KEYS = {
    "ntohl", "ntohs", "htonl", "htons",
    "recvfrom", "recvmsg", "recv(",
}


def detect_heap_overflow_risk(strings, imports=None):
    """
    Detect potential integer-overflow → heap-overflow vulnerability pattern.

    Criteria (either branch sufficient):
      Import-based: malloc/calloc AND (ntohl/ntohs/recvfrom/recvmsg) both
                    appear in the PLT import table.
      String-based: same keywords appear together in the string table.

    Import-based detection is preferred (more precise); string-based is the
    fallback for stripped or non-ELF binaries.

    Returns True if the pattern is present, False otherwise.
    """
    if imports is not None:
        names = set(imports.keys())
        if (names & _HEAP_ALLOC_KEYS) and (names & _NETWORK_LEN_KEYS):
            return True

    if strings:
        lower = [s.lower() for s in strings]
        has_alloc   = any(any(k in l for k in _HEAP_ALLOC_KEYS)   for l in lower)
        has_net_len = any(any(k in l for k in _NETWORK_LEN_KEYS) for l in lower)
        return has_alloc and has_net_len

    return False


# ── Candidate actionability scoring ──────────────────────────────────────────
# These functions reward candidates that match how Claude / human analysts
# actually triage: concrete names, explicit chains, specific start points.
#
# They answer a different question than the existing scoring:
#   existing scoring → "how exploitable is this?"
#   actionability   → "how easy is this to reason about and reverse?"
#
# A candidate can be highly exploitable but vague (generic /bin/sh presence in
# a monolithic daemon), or moderately scored but extremely actionable (named
# function with popen error string and specific form endpoint). Actionability
# moves the second class up in ranking so it surfaces in Top-N ahead of noise.

# camelCase function names: ≥2 humps, ≥7 total chars.
# Matches GetMacByIp, HandleWanSetting, ApplyDdnsConfig, FormUploadConfig, etc.
_NAMED_FN_RE = re.compile(
    r'\b([A-Z][a-z]{1,20}(?:[A-Z][a-zA-Z]{1,20})+)\b'
)

# Keywords that, when co-occurring with a camelCase name, confirm it is a
# function referenced in an error/log string near a dangerous call.
_SINK_COOCCUR_HINTS = frozenset({
    "popen", "system(", "exec(", "fail", "error", "from popen",
    "from system", "in get", "in handle", "in apply", "in set_", "in form",
})

# High-information sink artifacts: strings that reveal *what the operation does*,
# not just which function is called. These are the strings Claude elevates.
_HIGH_INFO_SINK_HINTS = frozenset({
    "/var/passwd", "/etc/passwd", "/etc/shadow",
    ">> /var/", ">> /etc/",
    ":x:0:0:", ":/bin/sh",          # /etc/passwd line structure
    "fail from popen", "fail from system",
    " in get", " in handle", " in apply",
})

# Named shell scripts: concrete intermediate chain steps
_SCRIPT_HELPER_RE = re.compile(
    r'/(?:usr/|var/|tmp/)?(?:bin|sbin|lib|etc|scripts?|usr/share)'
    r'/[A-Za-z0-9_.-]{3,}\.sh',
    re.IGNORECASE,
)

# Specific high-value form handler patterns — more concrete than generic /cgi-bin/
_FORM_HANDLER_RE = re.compile(
    r'/boafrm/form[A-Za-z0-9_]+'       # TOTOLINK boa form handlers
    r'|/cstecgi\.cgi'                   # TP-Link / TOTOLINK CGI dispatcher
    r'|/goform/[A-Za-z0-9_]+'          # Tenda goform handlers
    r'|/HNAP1/[A-Za-z0-9]+'            # D-Link HNAP
    r'|formUpload[A-Za-z]*'            # upload form handlers
    r'|formIpQoS|formWan|formDDNS'
    r'|formFilter|formFirewall'
    r'|formUpgrade|formReboot'
    r'|formSetWifi|formSetWlan',
    re.IGNORECASE,
)


def has_named_function_evidence(strings, all_sinks=None):
    """
    Return True if any string pairs a camelCase function name (≥7 chars,
    ≥2 humps) with a sink-or-error context keyword.

    This is the strongest actionability signal: a named, searchable function
    is the vulnerability site — Ghidra can find it by name in one step.

    Examples that match:
      "error: get mac  fail from popen() in GetMacByIp() !"  → GetMacByIp
      "HandleWanSetting: system() call failed"                → HandleWanSetting

    Checks all_sinks first (pre-filtered, highest quality), then a sample of
    the full string table (capped at 1 000 to stay fast).
    """
    candidates = list(all_sinks or []) + list(strings or [])[:1000]
    for s in candidates:
        for m in _NAMED_FN_RE.finditer(s):
            fn = m.group(1)
            if len(fn) < 7:
                continue
            sl = s.lower()
            if any(k in sl for k in _SINK_COOCCUR_HINTS):
                return True
    return False


def calc_candidate_actionability_bonus(strings, endpoints=None,
                                        all_sinks=None, handler_symbols=None):
    """
    Reward candidates whose evidence is specific, named, and directly traceable.

    Claude / human analysts elevate these properties:

      +8  named function co-occurring with sink/error context
          e.g. "popen() in GetMacByIp()" — exact Ghidra search target
      +6  high-information sink artifact revealing the concrete operation
          e.g. "echo %s:x:0:0:%s:/:/bin/sh >> /var/passwd"
      +5  specific form-handler endpoint (beyond generic /cgi-bin/)
          e.g. "/boafrm/formIpQoS", "/goform/SetWanInfo", "/cstecgi.cgi"
      +4  named shell script in strings (concrete chain intermediate step)
          e.g. "/usr/sbin/ip_qos.sh", "/etc/scripts/firewall.sh"

    Returns int in [0, 15].  Cap prevents one dimension from dominating.
    """
    if not strings:
        return 0

    bonus = 0

    # ── +8: named function evidence ───────────────────────────────────────────
    if has_named_function_evidence(strings, all_sinks):
        bonus += 8

    # ── +6: high-information sink artifact ───────────────────────────────────
    # Check all_sinks first (pre-filtered), then raw strings as fallback.
    for s in (list(all_sinks or []) + list(strings)[:500]):
        sl = s.lower()
        if any(h in sl for h in _HIGH_INFO_SINK_HINTS):
            bonus += 6
            break

    # ── +5: specific form handler endpoint ───────────────────────────────────
    ep_text = " ".join(endpoints or []) + " " + " ".join(strings[:500])
    if _FORM_HANDLER_RE.search(ep_text):
        bonus += 5

    # ── +4: named shell script (concrete chain intermediate step) ─────────────
    for s in strings[:500]:
        if _SCRIPT_HELPER_RE.search(s):
            bonus += 4
            break

    return min(15, bonus)


def assess_missing_links(all_sinks, endpoints, templates, config_keys,
                          auth_status, taint_confidence,
                          handler_symbols=None, has_named_fn=False):
    """
    Identify which critical chain elements are still unconfirmed.

    Called from risk.py after per-binary signals are collected.  The returned
    list drives two things:
      1. A score penalty when "too_many_unknowns" is present (vague candidates
         should not outrank specific, explainable ones).
      2. Targeted "what is still missing" steps in the dossier next-steps.

    Tokens returned:
      exact_input_unknown    — no specific form param or injection template
                               names the attacker-controlled field
      auth_boundary_unknown  — auth requirement ambiguous (required, no evidence)
      dispatch_unknown       — no named endpoint and no named-function evidence
      chain_gap_unknown      — no NVRAM/config key and no direct handler evidence:
                               the intermediate hop is entirely inferred
      too_many_unknowns      — 3+ unknowns (broad suppression flag)
    """
    unknowns = []

    # ── exact_input_unknown ───────────────────────────────────────────────────
    # A specific field name is "known" when there is an injection template
    # (format string reveals the field), a handler symbol (named function),
    # named function evidence in strings, or a specific form handler endpoint.
    has_specific_input = (
        bool(templates) or
        bool(handler_symbols) or
        has_named_fn or
        any(
            "/boafrm/" in (e or "").lower()
            or "/goform/" in (e or "").lower()
            or "cstecgi" in (e or "").lower()
            or "hnap1" in (e or "").lower()
            for e in (endpoints or [])
        )
    )
    if not has_specific_input:
        unknowns.append("exact_input_unknown")

    # ── auth_boundary_unknown ─────────────────────────────────────────────────
    # Only flag when "required" AND taint_confidence is low (chain unconfirmed).
    # Bypassable / none are already a positive signal — don't penalise them.
    if auth_status == "required" and taint_confidence <= 0.3:
        unknowns.append("auth_boundary_unknown")

    # ── dispatch_unknown ─────────────────────────────────────────────────────
    # No endpoint at all AND no named-function evidence — we don't know how
    # to reach this code path from the network.
    if not endpoints and not has_named_fn:
        unknowns.append("dispatch_unknown")

    # ── chain_gap_unknown ─────────────────────────────────────────────────────
    # No NVRAM/config key (no intermediate storage step) AND no direct handler
    # evidence (symbols) AND chain not confirmed by taint analysis.
    if not config_keys and not handler_symbols and taint_confidence < 0.5:
        unknowns.append("chain_gap_unknown")

    if len(unknowns) >= 3:
        unknowns.append("too_many_unknowns")

    return unknowns


# ── Exploitability plausibility scoring ──────────────────────────────────────
# Answers: "is attacker input realistically reaching the sink?"
# Distinct from actionability ("easy to reason about") — a candidate can be
# highly actionable (named function, specific endpoint) yet low plausibility
# (all evidence from error-handler crash strings, sanitization imports present).
#
# Prevents over-fitting to actionability: the boa GetMacByIp case has high
# actionability (named function in strings) but all evidence is in error/crash
# paths, not attacker-reachable execution paths.

# Error/crash handler path indicators — strings here are diagnostic noise,
# not normal-execution paths reachable by attacker-controlled input.
_ERROR_PATH_INDICATORS = frozenset({
    "error:", "warning:", "fatal:", "fail from ",
    "failed in ", "cannot ", "failed to ",
    "sigsegv", "sigbus", "dumping core",
    "assertion ", "assert(", "catch(",
    "exception:", "panic:",
})

# Normal execution path indicators — format strings here ARE on reachable paths
# and confirm attacker input reaches a real operation.
_NORMAL_EXEC_INDICATORS = frozenset({
    "iptables", "route ", "ifconfig ",
    "echo ", "wget ", "curl ",
    "nvram set", "uci set", "killall ",
    "ping -", "chmod ", "mkdir ",
    "/bin/iptables", "/sbin/route",
    ">> /var/", ">> /etc/",
})

# Sanitization imports — presence suggests the binary validates input before use.
_SANITIZATION_IMPORTS = frozenset({
    "inet_aton", "inet_pton", "inet_addr",
    "regcomp", "regexec", "fnmatch",
    "atoi", "strtol", "strtoul",
    "getaddrinfo", "inet_ntop",
})

# Sanitization string hints — developer error messages or explicit validation
# function names that appear in the string table.
_SANITIZATION_STRING_HINTS = frozenset({
    "inet_aton", "inet_pton", "validate", "sanitize", "sanitise",
    "whitelist", "blacklist", "check_input", "filter_input",
    "isdigit", "isalpha", "strtol(", "strtoul(",
})


def _classify_template_quality(templates):
    """
    Classify injection templates by execution-path certainty.

    Returns 'direct'   — any template is on a normal execution path:
                         shell command verb + format spec = attacker value
                         is substituted in a genuinely reachable path.
            'indirect' — all templates are in error/crash handler contexts:
                         evidence is diagnostic noise, not a reachable attack
                         path.
            'none'     — no templates present.
    """
    if not templates:
        return 'none'
    direct   = 0
    indirect = 0
    for t in templates:
        tl = t.lower()
        if any(k in tl for k in _ERROR_PATH_INDICATORS):
            indirect += 1
        elif any(k in tl for k in _NORMAL_EXEC_INDICATORS) or '%s' in t or '%d' in t:
            direct += 1
    if direct > 0:
        return 'direct'
    if indirect > 0:
        return 'indirect'
    return 'none'


def calc_exploitability_plausibility(strings, all_sinks=None, imports=None,
                                      endpoints=None, templates=None,
                                      missing_links=None):
    """
    Estimate how plausibly attacker input reaches the sink in practice.

    Complements actionability: actionability measures explainability /
    reversibility; plausibility measures whether the chain is realistically
    reachable.  A candidate should not rank high solely because its evidence
    is easy to name.

    Returns int in [-10, +8].  Applied additively after all other scoring.

    Signal 1 — Template quality         (-3 / 0 / +3)
      'direct'   templates contain real shell commands with %s — execution path
                 confirmed by visible format string.
      'indirect' all templates are in error/crash handlers — execution
                 certainty LOW.
      'none'     no templates — no evidence either way.

    Signal 2 — Sanitization likelihood  (0 / -3)
      Known validation imports (inet_aton, regcomp, strtol) OR validation
      string hints present — input is likely checked before the sink is reached.

    Signal 3 — Error-path sink evidence (0 / -2 / -4)
      Only applied to long sinks (len > 15) — short sinks like "/bin/sh" are
      genuine function names, not error-path strings.
      -4: all long sinks are error-path AND templates are 'indirect' or 'none'
      -2: some long sinks are error-path AND templates are 'indirect'

    Signal 4 — Input-to-sink token coupling (+0 / +1 / +2)
      Tokens shared between injection templates/endpoints (input side) and
      sinks/config strings (sink side) confirm the same named parameter
      appears at both ends of the chain.
      +2: 2+ shared tokens (strong coupling)
      +1: 1 shared token (weak coupling)

    Signal 5 — Over-inference penalty   (0 / -1 / -2 / -3)
      Each missing link beyond the first contributes -1 (max -3).
      A chain with 3+ unknowns is speculative regardless of actionability.
    """
    strings  = strings   or []
    sinks    = all_sinks or []
    imps     = imports   or {}
    eps      = endpoints or []
    tmps     = templates or []
    links    = missing_links or []

    adj = 0

    # ── Signal 1: Template quality ────────────────────────────────────────────
    tq = _classify_template_quality(tmps)
    if tq == 'direct':
        adj += 3
    elif tq == 'indirect':
        adj -= 3

    # ── Signal 2: Sanitization likelihood ────────────────────────────────────
    # Check both import table (precise) and string table (fallback for stripped).
    import_names = set(imps.keys()) if isinstance(imps, dict) else set()
    has_san_import = bool(import_names & _SANITIZATION_IMPORTS)
    has_san_string = any(
        any(h in s.lower() for h in _SANITIZATION_STRING_HINTS)
        for s in strings[:800]
    )
    if has_san_import or has_san_string:
        adj -= 3

    # ── Signal 3: Error-path sink evidence ───────────────────────────────────
    # Only apply to "long" sinks (len > 15) — short sinks like "/bin/sh" are
    # genuine function names, not necessarily error-path strings.
    long_sinks = [s for s in sinks if len(s) > 15]
    if long_sinks:
        error_count = sum(
            1 for s in long_sinks
            if any(k in s.lower() for k in _ERROR_PATH_INDICATORS)
        )
        all_error  = (error_count == len(long_sinks))
        some_error = (error_count > 0)

        if all_error and tq != 'direct':
            adj -= 4   # every concrete sink reference is error-path only
        elif some_error and tq == 'indirect':
            adj -= 2   # partial error-path with no direct-path templates

    # ── Signal 4: Input-to-sink token coupling ────────────────────────────────
    # Build token sets from the input side (templates + endpoints) and sink side
    # (sinks + nearby config-read strings).  Shared non-trivial tokens confirm
    # the same named parameter appears at both ends of the chain.
    input_side = list(tmps) + list(eps)
    sink_side  = list(sinks) + [
        s for s in strings[:500]
        if any(k in s.lower() for k in _CONFIG_READ_KEYWORDS)
    ]
    shared = _extract_tokens(input_side) & _extract_tokens(sink_side)
    if len(shared) >= 2:
        adj += 2
    elif len(shared) == 1:
        adj += 1

    # ── Signal 5: Over-inference penalty ─────────────────────────────────────
    # Every missing link beyond the first is a speculative inference step.
    # Exclude the "too_many_unknowns" sentinel — it's a derived flag, not a
    # distinct unknown.  Cap at -3 so a legitimate finding with gaps can
    # still surface.
    n_links = len([lk for lk in links if lk != "too_many_unknowns"])
    if n_links > 1:
        adj -= min(3, n_links - 1)

    return max(-10, min(8, adj))


def score_sinks(sinks_by_tier):
    """
    Assign a numeric score based on sink tier and specific function.

    critical: command execution / dynamic loading — highest severity
    strong:   unchecked memory/string ops
    weak:     compiler-added checked variants; 1 pt each, only admitted
              after dataflow confirmation (see analyze_services in risk.py)
    """
    score = 0

    for s in sinks_by_tier.get("critical", []):
        l = s.lower()
        if "system(" in l or "popen(" in l:
            score += 8
        elif "exec" in l:
            score += 7
        elif "dlopen(" in l or "dlsym(" in l:
            score += 6   # dynamic loading = conditional code execution
        else:
            score += 5   # /bin/sh, sh -c

    for s in sinks_by_tier.get("strong", []):
        l = s.lower()
        if "gets(" in l:
            score += 5
        elif "strcpy(" in l or "strcat(" in l:
            score += 4
        elif "sprintf(" in l or "vsprintf(" in l:
            score += 3
        elif "printf(" in l:
            score += 2   # format string risk when arg is user-controlled
        else:
            score += 2

    for _ in sinks_by_tier.get("weak", []):
        score += 1

    return score


def calc_score(input_type, user, socket_perm, sink_score, flow_score,
               source="system", has_dlopen=False, is_parsing_heavy=False,
               taint_confidence=0.3, validation_penalty=0.0,
               controllability="MEDIUM", flow_confidence="WEAK",
               memory_impact="NONE", flow_type=None,
               feature_chain_bonus=0, chain_consistency_bonus=0,
               cross_binary_bonus=0, exploit_signal_bonus=0):
    """
    Aggregate all scoring factors into a single exploitability score.

    Base factors (preserved):
      input_type   : socket/netlink +3, binder +2, file +2
      user         : root +4, system/radio/media +2, bt/wifi/nfc +1
      socket_perm  : world-accessible (666/777) +2
      sink_score   : from score_sinks()
      flow_score   : from analyze_dataflow()

    Bonus factors:
      socket+root  : combo bonus +2  (externally reachable AND maximally privileged)
      vendor source: +2              (vendor services are less audited / hardened)
      has_dlopen   : +3              (dynamic loading widens the attack surface)
      parsing_heavy: +1              (more parsing code → more parser bugs)

    Cap raised to 35 to preserve ranking fidelity when multiple bonuses apply.

    taint_confidence: float 0.0–1.0 from elf_analyzer / dataflow graph.
      1.0  LDRH→MUL→sink taint confirmed in function body
      0.7  BFS path confirmed, short chain (≤3 hops)
      0.5  BFS path confirmed, longer chain
      0.3  string co-presence only (original pipeline default)
      0.0  no evidence — sink_score contributes nothing

    validation_penalty: float 0.0–0.40 from detect_validation_signals().
      Applied as a proportional reduction to the final score.
      0.0  — no safe-variant evidence detected (no reduction)
      0.40 — binary exclusively uses bounded ops (max ~40% reduction)

      Penalty NEVER eliminates a candidate — it only reduces its rank.
      Minimum post-penalty score is 1 (if pre-penalty score > 0).
    """
    score = 0

    # ── Input type ────────────────────────────────────────────────────────────

    if input_type == "socket":
        score += 3
    elif input_type == "binder":
        score += 2
    elif input_type == "netlink":
        score += 3    # kernel netlink = privileged but reachable from unprivileged
    elif input_type == "file":
        score += 2

    # ── Privilege ─────────────────────────────────────────────────────────────

    if user == "root":
        score += 4
    elif user in ["system", "radio", "media"]:
        score += 2
    elif user in ["bluetooth", "wifi", "nfc", "secure_element"]:
        score += 1

    # ── Combo bonus: network-exposed AND maximally privileged ─────────────────

    if input_type in ("socket", "netlink") and user == "root":
        score += 2

    # ── World-accessible socket ───────────────────────────────────────────────

    if socket_perm and any(p in socket_perm for p in ["666", "777", "0666", "0777"]):
        score += 2

    # ── Vendor source: less audited, often missing compile-time hardening ─────

    if source == "vendor":
        score += 2

    # ── Dynamic loading: dlopen/dlsym widens the exploitable surface ──────────

    if has_dlopen:
        score += 3

    # ── Parsing-heavy binary: more code means more parser bugs ────────────────

    if is_parsing_heavy:
        score += 1

    # ── Sink and dataflow scores ──────────────────────────────────────────────
    # Sink contribution is gated by taint_confidence to suppress false positives.
    # flow_score is not gated — it reflects chain structure, not sink reachability.

    score += int(round(sink_score * taint_confidence))
    score += flow_score

    score = min(score, 35)   # Raised from 25 to preserve ranking at the top

    # ── Validation penalty ────────────────────────────────────────────────────
    # Proportional reduction — never eliminates; floor of 1 for any non-zero score.

    if validation_penalty > 0.0 and score > 0:
        score = max(1, int(round(score * (1.0 - validation_penalty))))

    # ── Controllability multiplier ────────────────────────────────────────────
    # HIGH  — attacker-reachable without privilege: boost ranking
    # MEDIUM — default: no change
    # LOW   — requires privileged writer or internal-only path: strong penalty

    if controllability == "HIGH":
        score = int(round(score * 1.3))
    elif controllability == "LOW":
        score = max(1, int(round(score * 0.4)))
    # MEDIUM: multiplier 1.0 — no operation needed

    # ── Flow confidence multiplier ────────────────────────────────────────────
    # Penalise weak chains to reduce MEDIUM noise; reward confirmed chains.

    if flow_confidence == "LOW":
        score = int(round(score * 0.7))
    elif flow_confidence == "HIGH":
        score = int(round(score * 1.2))
    # MEDIUM: multiplier 1.0 — no operation needed

    # ── Memory impact boost ───────────────────────────────────────────────────
    # CONFIRMED overflow chain elevates urgency independent of other factors.

    if memory_impact == "CONFIRMED":
        score = int(round(score * 1.3))

    # ── High-severity flow type boost ─────────────────────────────────────────
    # Command execution and dynamic loading represent highest-impact primitives.

    if flow_type in ("cmd_injection", "dlopen_injection"):
        score = int(round(score * 1.2))

    # ── Feature-chain adjustment ───────────────────────────────────────────────
    # Applied last so it shifts rank independently of exploitability magnitude.
    # Positive values reward frontend→config→restart chains; negative values
    # suppress generic daemon internals and noise-only findings.

    score += feature_chain_bonus

    # ── Chain consistency adjustment ──────────────────────────────────────────
    # Second-pass refinement on top of the feature-chain bonus.
    # Rewards binaries where config-write and sink share key tokens or appear
    # proximate in the string table (real reuse evidence).
    # Penalises binaries where those signals are isolated keyword islands
    # (write-only, sink-only, or frontend with no parameter reuse).

    score += chain_consistency_bonus

    # ── Cross-binary chain bonus ──────────────────────────────────────────────
    # Applied after all single-binary multipliers.  When non-zero this means a
    # separate writer binary was identified at post-analysis time; the score is
    # normally injected directly by analyze_services() rather than passed here,
    # but the parameter exists for unit-testing and future pipeline use.

    score += cross_binary_bonus

    # ── Exploit context bonus (Gaps 1–5) ──────────────────────────────────────
    # Aggregates hardening absence, injection templates, named endpoints,
    # symbol intelligence, and auth-bypass evidence.  Applied last so it shifts
    # exploit-readiness rank independently of raw exploitability magnitude.

    score += exploit_signal_bonus
    score = max(0, score)   # no adjustment may drive score below zero

    return score
