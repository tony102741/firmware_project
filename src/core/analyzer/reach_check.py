"""
Reachability and authentication analysis for confirmed injection flows.

For each binary that has a CONFIRMED or LIKELY flow, this module answers:
  1. Which HTTP endpoint (URL path / CGI script) invokes it?
  2. Is authentication required to reach that endpoint?
  3. What HTTP parameter name maps to the tainted env var?
  4. Is input fully attacker-controlled, or constrained?

Produces a list of exploit candidates ranked by:
  unauthenticated remote > authenticated remote > unclear

Each candidate includes a 1–2 line exploit scenario suitable for direct
reproduction.
"""

import os
import re

# ── Authentication signal patterns ───────────────────────────────────────────

# Presence of ANY of these → auth likely required
_AUTH_STRONG = re.compile(
    r'(?:'
    r'luci\.dispatcher'                     # LuCI auth middleware
    r'|require\s+["\']luci\..*(?:auth|session|user)'
    r'|check_login\s*\('
    r'|auth_check\s*\('
    r'|verify_token\s*\('
    r'|HTTP_COOKIE.*(?:session|token|auth)'
    r'|compare.*passw|passw.*compare'
    r'|/etc/shadow'
    r')',
    re.IGNORECASE | re.DOTALL,
)

# Session / cookie pattern without strong verification:
# cookie present and read but may not be cryptographically checked
_AUTH_WEAK = re.compile(
    r'(?:HTTP_COOKIE|COOKIE|session_id|SESSION)',
    re.IGNORECASE,
)

# These indicate no auth: bare CGI that directly reads QUERY_STRING or env vars
# and feeds them to a command without any check block
_NO_AUTH = re.compile(
    r'(?:QUERY_STRING|CONTENT_LENGTH|REQUEST_METHOD)',
    re.IGNORECASE,
)

# ── HTTP parameter extraction patterns ───────────────────────────────────────

# Lua LuCI: luci.http.formvalue("param") or luci.http.get("param")
_LUA_PARAM = re.compile(
    r'(?:formvalue|http\.get|http\.post|cgi_get|cgi_post)\s*\(\s*["\'](\w+)["\']',
    re.IGNORECASE,
)

# Shell: ${QUERY_STRING##*param=} or cut/awk parsing
_SH_PARAM_AWK = re.compile(
    r'-F\s*["\']?(\w+)=',
)
_SH_PARAM_CUT = re.compile(
    r'(\w+)=.*QUERY_STRING|QUERY_STRING.*?(\w+)=',
)
_SH_PARAM_HASH = re.compile(
    r'\$\{QUERY_STRING[#%]+[*]?(\w+)=',
)

# Common dangerous parameter names seen in router firmware
_DANGEROUS_PARAMS = [
    'cmd', 'command', 'exec', 'run', 'action', 'target', 'host',
    'ip', 'addr', 'url', 'path', 'file', 'name', 'value',
    'dns1', 'dns2', 'ping_addr', 'tracert_addr', 'nslookup_host',
    'sys_cmd', 'shell_cmd', 'wan_ip', 'lan_ip',
]

# ── Web root mappings (filesystem path prefix → URL prefix) ──────────────────

_WEB_ROOTS = [
    ('usr/share/uhttpd',    ''),
    ('usr/lib/lua/luci',    '/cgi-bin/luci'),
    ('usr/lib/cgi-bin',     '/cgi-bin'),
    ('srv/www',             ''),
    ('usr/www',             ''),
    ('www',                 ''),
    ('webroot',             ''),
    ('htdocs',              ''),
]

# ── Known web server binary names ─────────────────────────────────────────────

_WEB_SERVER_NAMES = {
    'httpd', 'uhttpd', 'lighttpd', 'nginx', 'mini_httpd',
    'thttpd', 'boa', 'mongoose', 'shttpd',
}

# ── Web config file candidates ────────────────────────────────────────────────

_WEB_CONFIG_PATHS = [
    'etc/config/uhttpd',
    'etc/uhttpd.conf',
    'etc/lighttpd/lighttpd.conf',
    'etc/lighttpd.conf',
    'etc/httpd.conf',
    'etc/nginx/nginx.conf',
    'etc/config/rpcd',       # OpenWrt RPC daemon (often has auth)
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_text(path, max_bytes=65536):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes).decode('utf-8', errors='replace')
    except Exception:
        return ''


def _script_to_url(script_path, rootfs):
    """
    Map a filesystem path to a URL path using common web-root conventions.
    Falls back to '/<basename>' if no known mapping found.
    """
    rel = os.path.relpath(script_path, rootfs).replace('\\', '/')

    for fs_prefix, url_prefix in _WEB_ROOTS:
        if rel.startswith(fs_prefix + '/') or rel == fs_prefix:
            suffix = rel[len(fs_prefix):].lstrip('/')
            return (url_prefix + '/' + suffix).rstrip('/')

    # CGI path heuristic: any path containing cgi-bin
    m = re.search(r'(cgi-bin/.+)', rel)
    if m:
        return '/' + m.group(1)

    return '/' + os.path.basename(script_path)


def _detect_auth(content):
    """
    Classify authentication requirement from script source.

    Returns (required, strength, evidence) where:
      required : True | False | None (unknown)
      strength : 'strong' | 'weak' | 'none' | 'unknown'
      evidence : human-readable reason
    """
    if _AUTH_STRONG.search(content):
        # Find the matching pattern for evidence
        m = _AUTH_STRONG.search(content)
        snippet = content[max(0, m.start()-20):m.end()+20].strip()
        return True, 'strong', f"auth call: {snippet!r}"

    has_weak  = bool(_AUTH_WEAK.search(content))
    has_noauth = bool(_NO_AUTH.search(content))

    if has_weak and not has_noauth:
        m = _AUTH_WEAK.search(content)
        snippet = content[max(0, m.start()-10):m.end()+20].strip()
        return True, 'weak', f"cookie/session reference: {snippet!r}"

    if has_noauth and not has_weak:
        return False, 'none', "direct QUERY_STRING access, no session/cookie check"

    if has_weak and has_noauth:
        return None, 'weak', "cookie present but QUERY_STRING also directly used — verify"

    return None, 'unknown', "no clear auth signal"


def _extract_param(content, env_var):
    """
    Try to find the HTTP parameter name that populates env_var.

    env_var  — e.g. 'QUERY_STRING', 'HTTP_X_CUSTOM_HEADER'
    Returns  (param_name: str | None, method: str)
    """
    # Lua formvalue
    m = _LUA_PARAM.search(content)
    if m:
        return m.group(1), 'GET/POST'

    # Shell awk parsing: -F 'key='
    m = _SH_PARAM_AWK.search(content)
    if m:
        return m.group(1), 'GET'

    # Shell ${QUERY_STRING##*key=}
    m = _SH_PARAM_HASH.search(content)
    if m:
        return m.group(1), 'GET'

    # Look for dangerous parameter names literally in the script
    content_lower = content.lower()
    for p in _DANGEROUS_PARAMS:
        if p in content_lower:
            # Verify it looks like a param extraction, not just a comment
            pat = re.compile(
                r'(?:' + re.escape(p) + r'\s*=|["\']' + re.escape(p) + r'["\'])',
                re.IGNORECASE,
            )
            if pat.search(content):
                return p, 'GET/POST'

    # If QUERY_STRING is used directly, whole string is the input
    if 'QUERY_STRING' in content.upper():
        return 'QUERY_STRING (raw)', 'GET'

    return None, 'unknown'


def _parse_web_config(rootfs):
    """
    Parse web server configuration for auth settings.

    Returns dict:
      listen_ports      : list[int]
      has_auth_config   : bool
      auth_paths        : list[str]  — URL prefixes that require auth
      no_auth_paths     : list[str]  — explicitly public paths
      config_file       : str | None
    """
    info = {
        'listen_ports': [],
        'has_auth_config': False,
        'auth_paths': [],
        'no_auth_paths': [],
        'config_file': None,
    }

    for cfg_rel in _WEB_CONFIG_PATHS:
        cfg_path = os.path.join(rootfs, cfg_rel)
        if not os.path.isfile(cfg_path):
            continue

        content = _read_text(cfg_path)
        info['config_file'] = cfg_rel

        # Ports
        for m in re.finditer(r'(?:listen|port)[_\s:=]+(\d{2,5})', content, re.I):
            try:
                info['listen_ports'].append(int(m.group(1)))
            except ValueError:
                pass

        # Auth indicators
        if re.search(r'(?:auth|passwd|realm|password)', content, re.I):
            info['has_auth_config'] = True

        # uhttpd: list auth_script → requires auth
        for m in re.finditer(r'(?:auth_script|option\s+realm)\s+(.+)', content, re.I):
            info['auth_paths'].append(m.group(1).strip().strip('"\''))

        # Paths explicitly NOT requiring auth (uhttpd: no_auth)
        for m in re.finditer(r'no_auth\s+(.+)', content, re.I):
            info['no_auth_paths'].append(m.group(1).strip().strip('"\''))

        break   # use first config found

    # Default web ports if none found in config
    if not info['listen_ports']:
        info['listen_ports'] = [80, 443]

    return info


# ── Per-flow reachability check ───────────────────────────────────────────────

def _find_invoking_scripts(binary_name, cgi_files, rootfs):
    """
    Find CGI/Lua/shell scripts that invoke `binary_name`.

    Returns list of (script_path, url, invocation_line).
    """
    name    = os.path.basename(binary_name)
    pattern = re.compile(
        r'(?:^|[\s\'"(/])' + re.escape(name) + r'(?:\s|["\'\);]|$)',
        re.IGNORECASE,
    )
    found = []

    for script_path in cgi_files:
        content = _read_text(script_path)
        if not content:
            continue
        for line in content.splitlines():
            if pattern.search(line) or name in line:
                url = _script_to_url(script_path, rootfs)
                found.append((script_path, url, line.strip()))
                break   # one match per script

    return found


def check_flow_reachability(binary_path, flow, cgi_files, rootfs, web_config):
    """
    Determine if a single confirmed flow is remotely reachable.

    Parameters
    ----------
    binary_path : str   — absolute path to the binary
    flow        : dict  — VerifiedFlow result from verify_flow.py
    cgi_files   : list  — CGI/Lua/shell scripts from scan_web_surface()
    rootfs      : str   — rootfs root (data/rootfs/system)
    web_config  : dict  — from _parse_web_config()

    Returns
    -------
    dict with keys:
      remotely_reachable, endpoint, handler, auth_required, auth_strength,
      auth_evidence, input_param, input_method, exploit_scenario, keep
    """
    binary_name = os.path.basename(binary_path)
    is_webserver = binary_name.lower() in _WEB_SERVER_NAMES

    # ── 1. Find the HTTP handler ──────────────────────────────────────────────

    invokers = _find_invoking_scripts(binary_path, cgi_files, rootfs)

    if invokers:
        # Use first invoking script as representative
        handler_path, url, inv_line = invokers[0]
        content  = _read_text(handler_path)
        env_var  = flow.get('env_var') or 'QUERY_STRING'

        auth_required, auth_strength, auth_evidence = _detect_auth(content)
        param_name, param_method = _extract_param(content, env_var)
        handler_rel = os.path.relpath(handler_path, rootfs)

    elif is_webserver:
        # Binary IS the web server; it handles HTTP directly
        url            = f"port:{web_config['listen_ports'][0]}"
        handler_path   = binary_path
        handler_rel    = os.path.relpath(binary_path, rootfs)
        env_var        = flow.get('env_var') or 'QUERY_STRING'
        param_name     = flow.get('env_var') or 'HTTP_REQUEST'
        param_method   = 'GET/POST'
        # Auth check: web config or binary own auth logic
        if web_config.get('has_auth_config'):
            auth_required, auth_strength, auth_evidence = (
                None, 'weak',
                f"web server config has auth settings ({web_config['config_file']})"
            )
        else:
            auth_required, auth_strength, auth_evidence = (
                False, 'none', "no auth config found"
            )
    else:
        # Binary is not a web server and no invoking scripts found
        return {
            'remotely_reachable': False,
            'endpoint':           None,
            'handler':            None,
            'auth_required':      None,
            'auth_strength':      'unknown',
            'auth_evidence':      'no invoking web script found',
            'input_param':        flow.get('env_var'),
            'input_method':       'unknown',
            'exploit_scenario':   None,
            'keep':               False,
        }

    # ── 2. Build exploit scenario ─────────────────────────────────────────────

    port   = web_config['listen_ports'][0] if web_config['listen_ports'] else 80
    sink   = flow.get('sink_sym', 'system')
    origin = flow.get('origin', 'unknown')

    # Construct the HTTP request line
    if param_name and 'QUERY_STRING' not in param_name:
        payload_param = param_name
    elif flow.get('env_var') and flow['env_var'] in ('QUERY_STRING',):
        payload_param = 'cmd'   # generic, attacker-chosen name
    else:
        payload_param = param_name or 'param'

    if url.startswith('port:'):
        endpoint_str = f"http://device:{port}/ (direct)"
        request_line = f"GET /?{payload_param}=id%3Bwhoami HTTP/1.1"
    else:
        endpoint_str = f"http://device:{port}{url}"
        request_line = f"GET {url}?{payload_param}=id%3Bwhoami HTTP/1.1"

    auth_note = ""
    if auth_required is True:
        auth_note = f" — requires auth ({auth_strength})"
    elif auth_required is False:
        auth_note = " — unauthenticated"
    else:
        auth_note = " — auth unknown"

    scenario = (
        f"{request_line}\n"
        f"      → {sink}(\"id;whoami\") as root{auth_note}"
    )

    # ── 3. Decide whether to keep ─────────────────────────────────────────────

    verdict = flow.get('verdict', 'UNCERTAIN')
    keep = (
        verdict in ('CONFIRMED', 'LIKELY')
        and (auth_required is False or auth_required is None)
    )

    # Keep authenticated flows too, just ranked lower
    if not keep and verdict in ('CONFIRMED', 'LIKELY') and auth_required is True:
        keep = True

    return {
        'remotely_reachable': True,
        'endpoint':           endpoint_str,
        'handler':            handler_rel,
        'auth_required':      auth_required,
        'auth_strength':      auth_strength,
        'auth_evidence':      auth_evidence,
        'input_param':        payload_param,
        'input_method':       param_method,
        'exploit_scenario':   scenario,
        'keep':               keep,
        'all_invokers':       [(os.path.relpath(s, rootfs), u)
                               for s, u, _ in invokers],
    }


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_reachability(results, cgi_files, rootfs):
    """
    Run reachability analysis for every CONFIRMED/LIKELY flow in results.

    Attaches 'exploit_candidates' list to each result dict.
    Returns a flat list of (result, reach_info) tuples, sorted:
      unauthenticated CONFIRMED first, then LIKELY, then authenticated.
    """
    web_config = _parse_web_config(rootfs)
    all_candidates = []

    for r in results:
        r['exploit_candidates'] = []
        bp    = r.get('binary_path', '')
        flows = r.get('verified_flows', [])
        if not bp or not flows:
            continue

        seen_flows = set()
        for flow in flows:
            if flow['verdict'] in ('FALSE_POSITIVE', 'UNCERTAIN'):
                continue
            # Deduplicate by (sink, origin)
            key = (flow.get('sink_sym'), flow.get('origin'))
            if key in seen_flows:
                continue
            seen_flows.add(key)

            reach = check_flow_reachability(bp, flow, cgi_files, rootfs, web_config)
            if not reach['keep'] and not reach['remotely_reachable']:
                continue

            entry = {
                'result':      r,
                'flow':        flow,
                'reach':       reach,
                # Sort key: unauthenticated CONFIRMED best
                '_rank': (
                    0 if (flow['verdict'] == 'CONFIRMED'
                          and reach['auth_required'] is False) else
                    1 if (flow['verdict'] == 'CONFIRMED'
                          and reach['auth_required'] is None) else
                    2 if (flow['verdict'] == 'LIKELY'
                          and reach['auth_required'] is False) else
                    3 if flow['verdict'] == 'LIKELY' else
                    4
                ),
            }
            r['exploit_candidates'].append(entry)
            all_candidates.append(entry)

    all_candidates.sort(key=lambda x: x['_rank'])
    return all_candidates
