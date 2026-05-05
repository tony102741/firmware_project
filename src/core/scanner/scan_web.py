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

# Frontend and handler files worth tracking as web-surface evidence
_FRONTEND_EXTS = {".asp", ".htm", ".html", ".cgi", ".lua", ".json", ".js"}

# Script extensions whose content should be parsed for binary references
_SCRIPT_EXTS = {".cgi", ".lua", ".sh", ".pl", ".py"}

_WEB_ENTRY_NAMES = {"luci"}

_WEB_ROOT_REL_HINTS = (
    "web",
    "web/cgi-bin",
    "var/web",
    "www/webpages",
    "etc/wifidog",
    "usr/lib/lua/luci",
    "usr/lib/oui-httpd/rpc",
    "usr/libexec/rpcd",
)

_TP_LINK_WEB_FILES = {
    "login.html", "portal.html", "portalpreview.html", "wifidog-msg.html",
    "tpencrypt.js", "navigator.json", "modules.json",
}

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

_WEB_CONFIGS = (
    "etc/boa.org/boa.conf",
    "etc/config/uhttpd",
    "etc/uhttpd.conf",
    "etc/lighttpd/lighttpd.conf",
    "etc/lighttpd.conf",
    "etc/httpd.conf",
)

_WEB_LAUNCH_DIRS = (
    "etc/init.d",
    "etc/rc.d",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_www_roots(rootfs):
    """Return directories that look like active web roots."""
    found = []
    seen = set()

    for rel in _WEB_ROOT_REL_HINTS:
        path = os.path.join(rootfs, rel)
        if os.path.isdir(path):
            norm = os.path.normpath(path)
            found.append(norm)
            seen.add(norm)

    for path in _configured_web_roots(rootfs):
        norm = os.path.normpath(path)
        if norm not in seen:
            found.append(norm)
            seen.add(norm)

    for dirpath, dirnames, _ in os.walk(rootfs):
        depth = dirpath[len(rootfs):].count(os.sep)
        if depth >= 5:
            dirnames.clear()
            continue
        for d in list(dirnames):
            candidate = os.path.normpath(os.path.join(dirpath, d))
            if candidate in seen:
                continue
            if d.lower() in _WWW_NAMES or _looks_like_tp_link_web_root(candidate):
                found.append(candidate)
                seen.add(candidate)
    return found


def _configured_web_roots(rootfs):
    roots = []

    cfg = os.path.join(rootfs, "etc/config/uhttpd")
    if os.path.isfile(cfg):
        try:
            with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            content = ""

        for rel in re.findall(r'^\s*option\s+home\s+([^\s#]+)', content, re.MULTILINE):
            path = os.path.join(rootfs, rel.strip('\'"').lstrip("/"))
            if os.path.isdir(path):
                roots.append(path)

        for rel in re.findall(r'^\s*option\s+(?:cgi_prefix|lua_prefix)\s+([^\s#]+)', content, re.MULTILINE):
            path = os.path.join(rootfs, rel.strip('\'"').lstrip("/"))
            if os.path.isdir(path):
                roots.append(path)
            else:
                docroot = os.path.join(rootfs, "www", rel.strip('\'"').lstrip("/"))
                if os.path.isdir(docroot):
                    roots.append(docroot)

    return roots


def _looks_like_tp_link_web_root(path):
    base = os.path.basename(path).lower()
    if base in {"webpages", "wifidog"}:
        return True
    try:
        entries = {name.lower() for name in os.listdir(path)[:64]}
    except Exception:
        return False
    return bool(entries & _TP_LINK_WEB_FILES)


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


def _extract_refs_from_text_file(path, rootfs):
    refs = set()
    try:
        with open(path, "rb") as f:
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


def _is_web_handler_file(rel, name, ext):
    rel = rel.replace("\\", "/").lower()
    name = name.lower()
    if ext in _SCRIPT_EXTS or ext in _FRONTEND_EXTS or name in _WEB_ENTRY_NAMES:
        return True
    return (
        rel.startswith("usr/libexec/rpcd/")
        or rel.startswith("usr/lib/oui-httpd/rpc/")
        or rel.startswith("usr/lib/lua/luci/controller/")
        or rel.startswith("usr/lib/lua/luci/apprpc/")
        or rel.startswith("usr/lib/lua/luci/jsonrpcbind/")
    )


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
                fpath = os.path.normpath(os.path.join(dirpath, f))
                ext   = os.path.splitext(f)[1].lower()
                rel   = os.path.relpath(fpath, rootfs).replace("\\", "/").lower()

                if _is_web_handler_file(rel, f, ext):
                    cgi_files.append(fpath)

                if _is_web_handler_file(rel, f, ext):
                    web_bins.update(_extract_refs(fpath, rootfs))
                    # CGI binary itself counts as web-exposed
                    if (
                        os.access(fpath, os.X_OK)
                        or "/cgi-bin/" in rel
                        or rel.startswith("usr/libexec/rpcd/")
                        or rel.startswith("usr/lib/oui-httpd/rpc/")
                    ):
                        web_bins.add(os.path.normpath(fpath))

    # ── 3. Web server configs / launch scripts → parse for routed binaries ───
    for rel in _WEB_CONFIGS:
        cfg = os.path.join(rootfs, rel)
        if os.path.isfile(cfg):
            web_bins.update(_extract_refs_from_text_file(cfg, rootfs))

    for rel_dir in _WEB_LAUNCH_DIRS:
        base = os.path.join(rootfs, rel_dir)
        if not os.path.isdir(base):
            continue
        for dirpath, _, files in os.walk(base):
            for name in files:
                path = os.path.join(dirpath, name)
                if name.lower() in _WEB_SERVERS or "http" in name.lower() or "cgi" in name.lower():
                    web_bins.update(_extract_refs_from_text_file(path, rootfs))
                    if os.access(path, os.X_OK):
                        web_bins.add(os.path.normpath(path))

    return web_bins, cgi_files
