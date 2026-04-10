# Pattern sets for dataflow chain detection.
# Each set contains lowercase substrings matched against strings(1) output.

_NET_INPUT = {"recv", "recvfrom", "recvmsg", "recvmmsg", "accept(", "read("}
_PARSE_OPS = {"sscanf", "strtol", "strtoul", "atoi", "atol",
              "json", "xml", "parse", "packet", "deserializ", "decode"}
_COPY_OPS  = {"strcpy", "strcat", "sprintf", "vsprintf", "memcpy",
              "__strcpy_chk", "__memcpy_chk"}
_CMD_OPS   = {"system(", "popen(", "exec(", "execl(", "execv(",
              "/bin/sh", "sh -c", "sh\""}
_NTOH_OPS  = {"ntohl", "ntohs", "htonl", "htons"}


def has_dangerous_memcpy_context(strings):
    """
    __memcpy_chk / memcpy is dangerous only when the copy length plausibly
    originates from external data. Indicators:
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


def analyze_dataflow(strings):
    """
    Detect net_input → parse → copy/exec chains at the symbol/string level.
    Returns (flow_score, flow_type).

    Patterns ranked by confidence:
      cmd_injection   : net_input + cmd_ops           → score 10
      bof+net_length  : net + parse + copy + ntoh     → score 8
      buffer_overflow : net + parse + copy            → score 6
      net_copy_partial: net + copy (no parse)         → score 3
    """
    lower_strings = [s.lower() for s in strings]

    def hit(keywords):
        return any(any(k in l for k in keywords) for l in lower_strings)

    h_net   = hit(_NET_INPUT)
    h_parse = hit(_PARSE_OPS)
    h_copy  = hit(_COPY_OPS)
    h_cmd   = hit(_CMD_OPS)
    h_ntoh  = hit(_NTOH_OPS)

    if h_net and h_cmd:
        return 10, "cmd_injection"

    if h_net and h_parse and h_copy:
        if h_ntoh:
            return 8, "bof+net_length"
        return 6, "buffer_overflow"

    if h_net and h_copy:
        return 3, "net_copy_partial"

    return 0, None
