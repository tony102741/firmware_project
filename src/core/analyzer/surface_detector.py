"""
Input surface detection module.

Scans binary strings output for evidence of:
  - Socket endpoints  (AF_UNIX paths, abstract namespace, TCP/UDP port hints)
  - Config file paths (/etc/*.conf, *.json, *.xml, /data/…)
  - IPC interfaces    (HIDL service names, AIDL, Binder service descriptors)
  - Environment vars  (getenv() usage as an untrusted-input source)

Produces the [input] → [service] → [binary] surface map used by risk.py and
the fuzzing hint generator.
"""

import re

# ── Regex patterns ────────────────────────────────────────────────────────────

# AF_UNIX paths: /dev/socket/*, abstract @*, /run/*.sock
_SOCKET_PATH_RE = re.compile(
    r'(/dev/socket/[\w.\-]+|@[\w./\-]+|/run/[\w./\-]+\.sock(?:et)?)',
    re.IGNORECASE,
)

# Port hints: "port 1234", ":8080", "PORT=443"
_PORT_RE = re.compile(
    r'(?:port[= :]|:)(\d{2,5})\b',
    re.IGNORECASE,
)

# Config / data file paths
_CONFIG_FILE_RE = re.compile(
    r'(/[\w./\-]+\.(?:conf|json|xml|cfg|ini|prop|rc|yaml|toml))',
    re.IGNORECASE,
)

# HIDL / AIDL / Binder service descriptors
#   android.hardware.radio@1.0::IRadio
#   com.vendor.service.IFoo
_IPC_DESCRIPTOR_RE = re.compile(
    r'(android\.[\w]+(?:\.[\w]+)+(?:@[\d.]+)?(?:::[\w]+)?'
    r'|com\.[\w]+(?:\.[\w]+){2,}'
    r'|vendor\.[\w]+(?:\.[\w]+)+(?:@[\d.]+)?(?:::[\w]+)?)',
)

# Binder service names: "RadioService", "WifiManager" etc.
_BINDER_SERVICE_RE = re.compile(
    r'\b([\w]{4,}(?:Service|Manager|Provider|Controller|Daemon|Handler))\b',
)


# ── Public API ────────────────────────────────────────────────────────────────

def detect_surface(strings):
    """
    Scan a list of strings extracted from a binary and return structured
    input surface evidence.

    Returns:
    {
        "sockets":      list[str]  – socket path or "port:NNNN" entries
        "config_files": list[str]  – detected config / data file paths
        "ipc":          list[str]  – IPC interface / service descriptors
        "env_vars":     list[str]  – raw strings containing getenv calls
    }
    """
    sockets      = []
    config_files = []
    ipc          = []
    env_vars     = []
    seen_raw     = set()

    for s in strings:
        stripped = s.strip()
        if not stripped or stripped in seen_raw:
            continue
        seen_raw.add(stripped)
        lower = stripped.lower()

        # Socket paths
        for m in _SOCKET_PATH_RE.findall(stripped):
            if m not in sockets:
                sockets.append(m)

        # Port numbers
        for m in _PORT_RE.findall(stripped):
            entry = f"port:{m}"
            if entry not in sockets:
                sockets.append(entry)

        # Config / data files
        for m in _CONFIG_FILE_RE.findall(stripped):
            # Filter out obviously irrelevant matches (source file paths, etc.)
            if not any(skip in m for skip in ["/usr/include", "/usr/lib", ".cpp", ".h"]):
                if m not in config_files:
                    config_files.append(m)

        # HIDL / AIDL descriptors
        for m in _IPC_DESCRIPTOR_RE.findall(stripped):
            if m not in ipc:
                ipc.append(m)

        # Binder service names (only when not already captured via descriptor)
        for m in _BINDER_SERVICE_RE.findall(stripped):
            if len(m) > 5 and m not in ipc:
                ipc.append(m)

        # Environment variable usage
        if "getenv" in lower and stripped not in env_vars:
            env_vars.append(stripped)

    return {
        "sockets":      sockets[:10],
        "config_files": config_files[:10],
        "ipc":          ipc[:8],
        "env_vars":     env_vars[:5],
    }


def build_fuzzing_hints(surface, input_type, flow_type, sinks):
    """
    Generate actionable fuzzing suggestions from the detected surface.

    Args:
        surface:    dict returned by detect_surface()
        input_type: "socket" | "netlink" | "file" | "binder" | None
        flow_type:  dataflow pattern label or None
        sinks:      list of sink strings from the binary

    Returns:
        list[str] of human-readable fuzzing hints (≤ 6 items)
    """
    hints = []

    # ── Input-surface–specific hints ──────────────────────────────────────────

    if input_type in ("socket", "netlink"):
        for sock in surface.get("sockets", []):
            if sock.startswith("port:"):
                port = sock.split(":")[1]
                hints.append(
                    f"TCP/UDP → connect to port {port}; send oversized / malformed binary frames"
                )
            elif "/" in sock or sock.startswith("@"):
                hints.append(
                    f"AF_UNIX → connect to {sock}; send malformed protocol messages"
                )
        if not hints:
            hints.append(
                "Socket input: send binary packets with controlled length fields and boundary values"
            )

    if input_type == "netlink":
        hints.append(
            "Netlink: craft RTM_* / NLMSG_* messages with oversized attr payloads"
        )

    if input_type == "file":
        for cfg in surface.get("config_files", []):
            hints.append(f"Config injection → replace {cfg} with crafted key/value pairs")
        if not surface.get("config_files"):
            hints.append(
                "File input: replace config with long strings, format specifiers (%s/%n), and path traversal (../../)"
            )

    if input_type == "binder":
        for iface in surface.get("ipc", [])[:2]:
            hints.append(f"Binder fuzz → send malformed parcels to {iface}")
        if not surface.get("ipc"):
            hints.append("Binder input: fuzz onTransact() with all parcel types and invalid sizes")

    # ── Dataflow–specific hints ───────────────────────────────────────────────

    if flow_type == "cmd_injection":
        hints.append(
            "Command injection: inject shell metacharacters (; | ` $() \\n) into string fields"
        )
    elif flow_type in ("buffer_overflow", "bof+net_length"):
        hints.append(
            "Buffer overflow: send payload ≫ expected size; fuzz length fields near 0, MAX_INT, MAX_INT/2"
        )
    elif flow_type == "dlopen_injection":
        hints.append(
            "DL injection: if library path is config-driven, replace with attacker-controlled .so"
        )
    elif flow_type == "file_path_injection":
        hints.append(
            "Path traversal: inject ../../ sequences and symlinks in file path inputs"
        )
    elif flow_type == "file_cmd_injection":
        hints.append(
            "File cmd: inject shell metacharacters into config values that reach system()/popen()"
        )
    elif flow_type == "config_injection":
        hints.append(
            "Config overflow: supply config values longer than fixed stack/heap buffers"
        )

    # ── Sink–specific hints ───────────────────────────────────────────────────

    has_exec = any("system(" in s or "popen(" in s or "execv" in s for s in sinks)
    has_str  = any("strcpy(" in s or "sprintf(" in s or "gets(" in s for s in sinks)
    has_dl   = any("dlopen(" in s or "dlsym(" in s for s in sinks)

    if has_exec:
        hints.append("Exec sink: target arguments to system()/popen() for OS command injection")
    if has_str:
        hints.append("String sink: fuzz input length past stack buffer; look for off-by-one on strcat/sprintf")
    if has_dl:
        hints.append("dlopen sink: if the .so path is controllable, plant a rogue library in that directory")

    return hints[:6]
