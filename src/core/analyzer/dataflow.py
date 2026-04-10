# Pattern sets for dataflow chain detection.
# Each set contains lowercase substrings matched against strings(1) output.

# ── Existing pattern sets (preserved) ────────────────────────────────────────

_NET_INPUT = {"recv", "recvfrom", "recvmsg", "recvmmsg", "accept(", "read("}
_PARSE_OPS = {"sscanf", "strtol", "strtoul", "atoi", "atol",
              "json", "xml", "parse", "packet", "deserializ", "decode"}
_COPY_OPS  = {"strcpy", "strcat", "sprintf", "vsprintf", "memcpy",
              "__strcpy_chk", "__memcpy_chk"}
_CMD_OPS   = {"system(", "popen(", "exec(", "execl(", "execv(",
              "/bin/sh", "sh -c", "sh\""}
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
