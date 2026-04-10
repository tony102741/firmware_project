# Keyword sets for input surface classification.
# Priority during classification: binder > socket > netlink > file > None

_NETLINK_KEYWORDS = {"netlink", "af_netlink", "nl_socket", "rtnetlink", "nlmsg"}

# File input is inferred from fopen/fopen64 usage combined with a recognisable
# config / data path or extension.
_FILE_EXT_HINTS  = {".conf", ".json", ".xml", ".cfg", ".ini", ".prop", ".yaml"}
_FILE_PATH_HINTS = {"/etc/", "/data/", "/sdcard/", "/system/etc", "/vendor/etc"}


def classify_input(strings):
    """
    Classify the primary input surface of a binary from its string literals.

    Detection priority (first match wins):
      1. binder   — onTransact present          (Binder IPC)
      2. socket   — recvfrom / recvmsg / accept (network/UNIX socket)
      3. netlink  — netlink / AF_NETLINK        (kernel netlink socket)
      4. file     — fopen + config extension/path hint
      5. None     — no recognisable input handler
    """
    for s in strings:
        l = s.lower()
        if "ontransact" in l:
            return "binder"
        if "recvfrom" in l or "recvmsg" in l or "accept(" in l:
            return "socket"
        if "recv" in l or "accept" in l:
            return "socket"

    for s in strings:
        l = s.lower()
        if any(k in l for k in _NETLINK_KEYWORDS):
            return "netlink"

    # File input: require fopen/open AND a config path or extension clue
    _has_fopen = any("fopen" in s.lower() for s in strings)
    if _has_fopen:
        for s in strings:
            l = s.lower()
            if any(ext in l for ext in _FILE_EXT_HINTS):
                return "file"
            if any(path in l for path in _FILE_PATH_HINTS):
                return "file"

    return None


def has_input_handler(strings):
    """
    Return True if the binary contains any form of input-reading construct.
    Used as a coarse pre-filter before deeper analysis.
    """
    return any(
        "recv" in s.lower()
        or "read(" in s.lower()
        or "accept(" in s.lower()
        or "fopen" in s.lower()
        or "netlink" in s.lower()
        for s in strings
    )
