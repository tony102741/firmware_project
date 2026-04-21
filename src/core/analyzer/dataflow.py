# Pattern sets for dataflow chain detection.
# Each set contains lowercase substrings matched against strings(1) output.

import re

# ── Existing pattern sets (preserved) ────────────────────────────────────────

_NET_INPUT = {
    "recv", "recvfrom", "recvmsg", "recvmmsg", "accept(", "read(",
    "luci.http.formvalue", "luci.http.content", "luci.http.getenv",
    "query_string", "request_method", "content_length",
    "cgi-bin", "uhttpd", "rpcd", "ubus",
}
_PARSE_OPS = {"sscanf", "strtol", "strtoul", "atoi", "atol",
              "json", "xml", "parse", "packet", "deserializ", "decode"}
_COPY_OPS  = {"strcpy", "strcat", "sprintf", "vsprintf", "memcpy",
              "__strcpy_chk", "__memcpy_chk"}
_CMD_OPS   = {
    "system(", "popen(", "exec(", "execl(", "execv(",
    "os.execute", "io.popen", "luci.sys.call", "luci.sys.exec", "nixio.exec",
    "/bin/sh", "sh -c", "sh\"",
}
_NTOH_OPS  = {"ntohl", "ntohs", "htonl", "htons"}

# ── New pattern sets ──────────────────────────────────────────────────────────

# File-based input indicators
_FILE_INPUT = {"fopen", "fopen64", ".conf", ".json", ".xml", ".cfg",
               "/etc/", "/data/", "/system/etc", "/vendor/etc"}

# User-controllable path patterns
_PATH_OPS   = {"filename", "filepath", "getenv", "argv", "realpath", "readlink"}

# Dynamic library loading
_DLOPEN_OPS = {"dlopen", "dlsym", "dlclose"}

# Heavy parsing indicators (used by is_parsing_heavy)
_PARSE_HEAVY_KEYWORDS = {
    "json", "xml", "parse", "decode", "sscanf", "strtol",
    "deserializ", "packet", "tlv", "asn1", "protobuf", "flatbuffer",
}


# ── Context helpers ───────────────────────────────────────────────────────────

def has_dangerous_memcpy_context(strings):
    """
    __memcpy_chk / memcpy is dangerous only when the copy length plausibly
    originates from external data.  Indicators:
      - Network byte-order conversions (ntohl/ntohs) → length from network
      - parse+len/size co-occurrence → variable-length protocol field
    """
    has_memcpy = any(
        "__memcpy_chk" in s.lower() or "memcpy(" in s.lower()
        for s in strings
    )
    if not has_memcpy:
        return False

    for s in strings:
        l = s.lower()
        if any(k in l for k in ["ntohl", "ntohs", "htonl", "htons"]):
            return True
        if "parse" in l and any(k in l for k in ["len", "size", "length"]):
            return True
        if any(k in l for k in ["packet", "payload"]) and any(k in l for k in ["len", "size"]):
            return True

    return False


def has_dlopen_usage(strings):
    """Return True if the binary uses dynamic library loading (dlopen/dlsym)."""
    return any(
        "dlopen" in s.lower() or "dlsym" in s.lower()
        for s in strings
    )


def is_parsing_heavy(strings):
    """
    Return True if the binary performs significant parsing work.

    Heuristic: ≥ 3 distinct strings containing parsing-related keywords
    indicates non-trivial protocol / format handling and a broader attack
    surface for malformed-input bugs.
    """
    count = sum(
        1 for s in strings
        if any(k in s.lower() for k in _PARSE_HEAVY_KEYWORDS)
    )
    return count >= 3


# ── Main dataflow analysis ────────────────────────────────────────────────────

def analyze_dataflow(strings):
    """
    Detect input → parse → sink chains at the symbol / string level.
    Returns (flow_score, flow_type).

    Patterns ranked by confidence (highest wins):

    Existing patterns (preserved):
      cmd_injection    : net_input + cmd_ops           → score 10
      bof+net_length   : net + parse + copy + ntoh     → score 8
      buffer_overflow  : net + parse + copy            → score 6
      net_copy_partial : net + copy (no parse)         → score 3

    New patterns:
      dlopen_injection   : dlopen + (net or file input) → score 9
      file_path_injection: file + path_ops + cmd_ops    → score 8
      file_cmd_injection : file + cmd_ops               → score 7
      config_injection   : file + parse + copy          → score 5
    """
    lower_strings = [s.lower() for s in strings]

    def hit(keywords):
        return any(any(k in l for k in keywords) for l in lower_strings)

    h_net    = hit(_NET_INPUT)
    h_parse  = hit(_PARSE_OPS)
    h_copy   = hit(_COPY_OPS)
    h_cmd    = hit(_CMD_OPS)
    h_ntoh   = hit(_NTOH_OPS)
    h_file   = hit(_FILE_INPUT)
    h_path   = hit(_PATH_OPS)
    h_dlopen = hit(_DLOPEN_OPS)

    # ── Existing patterns (order preserved) ──────────────────────────────────

    if h_net and h_cmd:
        return 10, "cmd_injection"

    if h_net and h_parse and h_copy:
        if h_ntoh:
            return 8, "bof+net_length"
        return 6, "buffer_overflow"

    if h_net and h_copy:
        return 3, "net_copy_partial"

    # ── New patterns ─────────────────────────────────────────────────────────

    # dlopen with any external input → arbitrary code execution risk
    if h_dlopen and (h_net or h_file):
        return 9, "dlopen_injection"

    # File path reaches a command sink via controllable path
    if h_file and h_path and h_cmd:
        return 8, "file_path_injection"

    # File input reaches a command sink (no explicit path evidence)
    if h_file and h_cmd:
        return 7, "file_cmd_injection"

    # File input → parse → copy: classic config-file buffer overflow
    if h_file and h_parse and h_copy:
        return 5, "config_injection"

    return 0, None


# ── Graph-based dataflow analysis ─────────────────────────────────────────────

def analyze_dataflow_with_graph(cg, binary_path=None):
    """
    Dataflow analysis using the call graph built by elf_analyzer.build_call_graph().

    Replaces the co-presence heuristic with actual reachability: a source→sink
    chain is only reported when a BFS path exists in the call graph.

    Returns: (flow_score, flow_type, path_len, taint_confidence)

      flow_score       — same scale as analyze_dataflow() for scoring compat.
      flow_type        — string label matching existing categories.
      path_len         — hop count source→sink; shorter = higher confidence.
      taint_confidence — float 0.0–1.0:
                           1.0  path confirmed + LDRH/MUL taint in bottleneck
                           0.7  path confirmed, short (≤3 hops)
                           0.5  path confirmed, longer (4–7 hops)
                           0.3  path confirmed, long chain (>7 hops)
                           0.0  no path found (falls back to string analysis)

    Parser-pattern boost: if binary_path is supplied, detect_parser_patterns()
    is called to identify TLV/ASN.1/LPF/SEQOF functions on the confirmed path.
    Any high-scoring (≥3) parser hit on the path raises taint_conf by 0.2
    (capped at 1.0), reflecting elevated confidence that the length field is
    actually network-controlled.
    """
    from .elf_analyzer import find_shortest_path, SINK_IMPORTS

    source_fns = cg.get('_source_fns', set())
    sink_fns   = cg.get('_sink_fns',   {})

    if not source_fns or not sink_fns:
        return 0, None, 999, 0.0

    path, sink_sym, sink_tier = find_shortest_path(cg)

    if path is None:
        return 0, None, 999, 0.0

    path_len = len(path)

    # Map sink tier to flow primitives used by the rest of the pipeline
    if sink_tier == "critical":
        flow_type  = "cmd_injection"
        flow_score = 10
    elif sink_tier == "strong":
        flow_type  = "buffer_overflow"
        flow_score = 6
    else:
        flow_type  = "net_copy_partial"
        flow_score = 3

    # Base confidence from path length
    if path_len <= 3:
        taint_conf = 0.7
    elif path_len <= 7:
        taint_conf = 0.5
    else:
        taint_conf = 0.3

    # Parser-pattern boost: network-controlled length confirmed on path
    if binary_path is not None:
        try:
            from .elf_analyzer import detect_parser_patterns
            parser_hits = detect_parser_patterns(binary_path, cg)
            path_set = set(n for n in path if isinstance(n, int))
            if any(parser_hits.get(va, {}).get('score', 0) >= 3 for va in path_set):
                taint_conf = min(taint_conf + 0.2, 1.0)
        except Exception:
            pass  # parser scan is best-effort; never block scoring

    return flow_score, flow_type, path_len, taint_conf


def count_validation_messages(strings):
    """
    Count strings that look like input validation error messages.

    Patterns like "invalid IP address", "value out of range", or "bad parameter"
    indicate the binary actively validates inputs before processing them.
    High counts are a secondary sanitization signal used to boost the validation
    penalty in risk.py — they show the developer was thinking about bad input.

    Returns an int count of distinct validation message strings found.
    """
    _VALIDATION_MSG_HINTS = {
        "invalid", "out of range", "bad value", "illegal",
        "not valid", "must be", "too long", "too short",
        "out of bound", "exceeds", "check fail", "validation fail",
        "invalid input", "invalid param", "invalid value", "invalid format",
        "invalid ip", "invalid address", "address format",
        "parameter error", "param error", "bad param", "wrong format",
    }
    count = 0
    for s in strings:
        l = s.lower()
        if any(h in l for h in _VALIDATION_MSG_HINTS):
            count += 1
    return count


def detect_validation_signals(imports_or_strings, use_imports=True):
    """
    Detect bounds-checking / validation discipline.

    Returns a penalty float in [0.0, 0.40]:
      0.0  — no safe-variant evidence; do not penalise
      0.40 — binary exclusively uses bounded ops; likely defensive code

    Logic
    -----
    Bounded copy (strncpy/strncat/__chk) present WITHOUT unsafe (strcpy/strcat)
    → the binary was written to avoid the classic overflow pattern (+0.20).

    Bounded format (snprintf/vsnprintf) WITHOUT unsafe (sprintf/vsprintf)
    → format string overflow unlikely (+0.15).

    Mixed (both safe and unsafe present) → partial credit (+0.08 / +0.05).

    IP/network validation imports (inet_aton/inet_pton/regcomp) present
    → binary validates IP addresses or applies regex checks (+0.10).

    Presence of gets() WITHOUT any fgets() → no validation, subtract 0.05
    so penalty cannot accidentally inflate on obviously dangerous binaries.

    The returned value is passed to calc_score() as `validation_penalty`.
    It reduces score proportionally but never eliminates a candidate.
    """
    if use_imports:
        names = set(imports_or_strings.keys())
        has_safe_copy   = bool(names & {"strncpy", "__strncpy_chk",
                                        "strncat", "__strncat_chk"})
        has_unsafe_copy = bool(names & {"strcpy", "strcat"})
        has_safe_fmt    = bool(names & {"snprintf", "__snprintf_chk",
                                        "vsnprintf", "__vsnprintf_chk"})
        has_unsafe_fmt  = bool(names & {"sprintf", "vsprintf"})
        has_safe_read   = bool(names & {"fgets", "__fgets_chk"})
        has_unsafe_read = bool(names & {"gets"})
        # IP/network/regex validation imports — developer is checking values
        has_ip_valid    = bool(names & {"inet_aton", "inet_pton", "inet_addr",
                                        "regcomp", "regexec", "fnmatch",
                                        "getaddrinfo", "inet_ntop"})
    else:
        lower = [s.lower() for s in imports_or_strings]
        has_safe_copy   = any("strncpy" in l or "strncat" in l for l in lower)
        has_unsafe_copy = any("strcpy(" in l or "strcat(" in l for l in lower)
        has_safe_fmt    = any("snprintf" in l or "vsnprintf" in l for l in lower)
        has_unsafe_fmt  = any("sprintf(" in l or "vsprintf(" in l for l in lower)
        has_safe_read   = any("fgets" in l for l in lower)
        has_unsafe_read = any("gets(" in l for l in lower)
        has_ip_valid    = any(
            k in l for l in lower
            for k in ("inet_aton", "inet_pton", "regcomp", "fnmatch",
                      "getaddrinfo", "inet_ntop")
        )

    penalty = 0.0

    if has_safe_copy and not has_unsafe_copy:
        penalty += 0.20
    elif has_safe_copy and has_unsafe_copy:
        penalty += 0.08

    if has_safe_fmt and not has_unsafe_fmt:
        penalty += 0.15
    elif has_safe_fmt and has_unsafe_fmt:
        penalty += 0.05

    # IP/address validation functions indicate input sanitization for network data.
    # Only credit if not offset by clearly unsafe copy/format patterns.
    if has_ip_valid and not (has_unsafe_copy and has_unsafe_fmt):
        penalty += 0.10

    if has_unsafe_read and not has_safe_read:
        penalty -= 0.05   # gets() present: actively dangerous, reduce penalty

    return max(0.0, min(0.40, penalty))


def detect_arg_level_injection(strings):
    """
    Detect argument-level command injection evidence.

    Returns a dict with:
      detected       - bool: True if argument-level control confirmed
      templates      - list of matching format strings (up to 3)
      confidence     - float upgrade amount (0.0–0.25)

    Argument-level means the attacker controls the actual value passed to
    system()/popen(), not just that both are present in the same binary.

    Patterns:
      1. sprintf/snprintf format string with %s/%d adjacent to system/popen
         (the format string constructs the command argument)
      2. system/popen called with a buffer that was filled by sprintf
         (inferred from: sprintf present + /bin/sh or shell metachar template)
      3. iwpriv/iptables/nft template with %s parameter placeholder
         (router-specific command injection pattern)
    """
    _CMD_TEMPLATE_RE = re.compile(
        r'(?:sprintf|snprintf|printf)\s*\([^)]*%[sdi][^)]*\)',
        re.IGNORECASE,
    )
    _ROUTER_CMD_TEMPLATE_RE = re.compile(
        r'(?:iwpriv|iptables|ip6tables|nft|uci|nvram)\s[^\n]*%[sdi]',
        re.IGNORECASE,
    )
    _SHELL_META_TEMPLATE_RE = re.compile(
        r'(?:echo\s+%s|sh\s+-c\s+|system\s*\()\s*[^;\n]*%[sdi]',
        re.IGNORECASE,
    )

    templates = []
    seen = set()

    for s in strings:
        stripped = s.strip()
        if not stripped or stripped in seen:
            continue
        # Look for format strings that will become command arguments
        for pat in (_CMD_TEMPLATE_RE, _ROUTER_CMD_TEMPLATE_RE,
                    _SHELL_META_TEMPLATE_RE):
            if pat.search(stripped):
                if len(stripped) <= 150:
                    templates.append(stripped)
                    seen.add(stripped)
                break

    if not templates:
        return {"detected": False, "templates": [], "confidence": 0.0}

    # Confidence upgrade based on template count and specificity
    n = len(templates)
    has_router_cmd = any(
        any(k in t.lower() for k in ("iwpriv", "iptables", "nft ", "uci "))
        for t in templates
    )
    conf_bump = min(0.25, 0.10 * n + (0.05 if has_router_cmd else 0.0))

    return {
        "detected": True,
        "templates": templates[:3],
        "confidence": conf_bump,
    }


def upgrade_taint_confidence(path, cg, binary_path):
    """
    Attempt to upgrade taint_confidence to 1.0 by running check_length_taint_deep
    (inter-procedural) on the function immediately before the sink in the
    confirmed path.

    Called lazily from risk.py only when the graph path was already confirmed
    (taint_conf >= 0.5) to avoid expensive scans on unconfirmed chains.

    Returns: updated taint_confidence (original value if upgrade fails).
    """
    from .elf_analyzer import check_length_taint_deep

    if not path or len(path) < 2:
        return 0.5

    # Check the penultimate function (direct caller of the sink)
    candidate = path[-2]
    if not isinstance(candidate, int):
        return 0.5

    vulnerable, _evidence = check_length_taint_deep(binary_path, candidate, cg)
    return 1.0 if vulnerable else 0.5
