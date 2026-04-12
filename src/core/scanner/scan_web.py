"""
IoT web surface scanner.

Identifies binaries reachable from the HTTP attack surface in a firmware
rootfs:
  1. HTTP server executables (uhttpd, httpd, lighttpd, boa, …)
  2. CGI/Lua/shell scripts under any web-root directory
  3. Binaries explicitly invoked from those scripts via os.execute / popen /
     system() / exec*() calls or bare absolute-path references

Returns a (web_bins, cgi_files) pair:
  web_bins  — set of absolute paths that are web-reachable
  cgi_files — list of script paths found under web roots (evidence)
"""

import os
import re

# Known HTTP server binary names (case-insensitive match on basename)
_WEB_SERVERS = {
    "httpd", "uhttpd", "lighttpd", "nginx", "mini_httpd",
    "thttpd", "mongoose", "boa", "mathopd", "shttpd",
    "hiawatha", "cherokee",
}

# Directory names that indicate web content roots
_WWW_NAMES = {"www", "webroot", "web", "htdocs", "cgi-bin", "cgi", "html"}

# Script extensions whose content should be parsed for binary references
_SCRIPT_EXTS = {".cgi", ".lua", ".sh", ".pl", ".py"}

# Matches invocation of a path string via common exec wrappers:
#   os.execute("/usr/sbin/foo")   io.popen("/bin/bar")
#   system("/sbin/baz")           exec("/usr/bin/qux")
_INVOKE_RE = re.compile(
    r'(?:os\.execute|io\.popen|popen|system|exec[vlpe]*)\s*\(\s*["\']?'
    r'(/[a-zA-Z0-9_./%\-]+)',
    re.IGNORECASE,
)

# Bare absolute paths that look like binaries: /bin/x  /sbin/x  /usr/sbin/x
_PATH_RE = re.compile(r'(/(?:usr/)?s?bin/[a-zA-Z0-9_.\-]+)')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_www_roots(rootfs):
    """Return directories whose basename matches a known web-root name."""
    found = []
    for dirpath, dirnames, _ in os.walk(rootfs):
        depth = dirpath[len(rootfs):].count(os.sep)
        if depth >= 5:
            dirnames.clear()
            continue
        for d in list(dirnames):
            if d.lower() in _WWW_NAMES:
                found.append(os.path.join(dirpath, d))
    return found


def _extract_refs(script_path, rootfs):
    """
    Parse a CGI/Lua/shell script for binary paths it invokes.
    Returns a set of absolute paths that exist and are executable in rootfs.
    """
    refs = set()
    try:
        with open(script_path, "rb") as f:
            content = f.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return refs

    for pattern in (_INVOKE_RE, _PATH_RE):
        for m in pattern.finditer(content):
            rel = m.group(1).lstrip("/")
            candidate = os.path.join(rootfs, rel)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                refs.add(os.path.normpath(candidate))

    return refs


# ── Public API ────────────────────────────────────────────────────────────────

def scan_web_surface(rootfs):
    """
    Identify web-exposed binaries in a firmware rootfs.

    Parameters
    ----------
    rootfs : str
        Absolute path to the extracted rootfs (e.g. data/rootfs/system).

    Returns
    -------
    web_bins  : set[str]   — normalised absolute paths reachable from HTTP
    cgi_files : list[str]  — script paths found under web roots
    """
    web_bins  = set()
    cgi_files = []

    # ── 1. HTTP server executables ────────────────────────────────────────────
    for dirpath, _, files in os.walk(rootfs):
        for f in files:
            if f.lower() in _WEB_SERVERS:
                fpath = os.path.normpath(os.path.join(dirpath, f))
                if os.path.isfile(fpath):
                    web_bins.add(fpath)

    # ── 2. Scripts under web roots → parse for binary invocations ────────────
    for www in _find_www_roots(rootfs):
        for dirpath, _, files in os.walk(www):
            for f in files:
                fpath = os.path.join(dirpath, f)
                ext   = os.path.splitext(f)[1].lower()

                if ext in _SCRIPT_EXTS:
                    cgi_files.append(fpath)
                    web_bins.update(_extract_refs(fpath, rootfs))
                    # CGI binary itself counts as web-exposed
                    if os.access(fpath, os.X_OK):
                        web_bins.add(os.path.normpath(fpath))

    return web_bins, cgi_files
