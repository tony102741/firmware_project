# Keyword sets for input surface classification.
# Priority during classification: binder > socket > netlink > file > None

_NETLINK_KEYWORDS = {"netlink", "af_netlink", "nl_socket", "rtnetlink", "nlmsg"}

_WEB_INPUT_HINTS = {
    "luci.http.formvalue",
    "luci.http.content",
    "luci.http.getenv",
    "luci.dispatcher",
    "query_string",
    "request_method",
    "content_length",
    "content_type",
    "cgi-bin",
    "uhttpd",
    "rpcd",
    "ubus",
}

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
        if any(k in l for k in _WEB_INPUT_HINTS):
            return "socket"
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
        or any(k in s.lower() for k in _WEB_INPUT_HINTS)
        for s in strings
    )


def classify_input_from_imports(imports_dict):
    """
    Exact input surface classification from ELF import table.

    Priority mirrors classify_input() but uses symbol names instead of
    substrings, eliminating matches against log strings like "recvfailed".

    imports_dict: {sym_name: plt_va} from elf_analyzer.get_imports()
    Returns: "binder" | "socket" | "netlink" | "file" | None
    """
    from .elf_analyzer import INPUT_IMPORTS
    names = set(imports_dict.keys())

    # Binder: onTransact is a vtable symbol, not a PLT import — keep string path
    # for binder detection; import table alone is insufficient.

    # Network socket: these are the canonical recv-family imports
    if names & {"SSL_read", "recvfrom", "recvmsg", "recvmmsg", "accept", "accept4"}:
        return "socket"
    if names & {"recv"}:
        return "socket"
    if names & {"cgi_main", "uh_cgi_request", "rpc_handle_request"}:
        return "socket"

    # Netlink: raw read() with netlink strings is handled by the string path;
    # no distinctive PLT import exists, so fall through to string classifier.

    # File input
    if names & {"fread", "fgets", "__fgets_chk"}:
        return "file"

    # Generic read() — could be socket or file; defer to string classifier
    if "read" in names or "__read_chk" in names:
        return "socket"   # conservative: treat raw read() as socket surface

    return None


def has_input_handler_from_imports(imports_dict):
    """
    Import-based equivalent of has_input_handler().
    Returns True if any known input symbol is present in the import table.
    """
    from .elf_analyzer import INPUT_IMPORTS
    return bool(set(imports_dict.keys()) & INPUT_IMPORTS)
