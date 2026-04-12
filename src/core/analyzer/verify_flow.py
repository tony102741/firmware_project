"""
Deep flow verifier for confirmed source→sink candidates.

Takes the top-ranked results from the pipeline and performs per-callsite
argument origin analysis to separate real injection vectors from false
positives (constant command execution, unreachable paths, etc.).

AArch64 path (primary)
──────────────────────
For each function that directly calls system/popen/exec*:
  1. Scan forward through the function, tracking what writes X0.
  2. At the BL-to-sink, classify X0's state:
       CONST_CMD  — ADRP+ADD → static string in .rodata → discard
       GETENV     — return value of getenv() → CONFIRMED (CGI param injection)
       NET_INPUT  — return path from recv/read/fgets → CONFIRMED
       FMT_BUF    — snprintf/sprintf destination → LIKELY (check format string)
       STACK_ADDR — ADD X0, sp, #N before sink → UNCERTAIN (may be from sprintf)
       ARG_PASS   — X0 never set in function (caller's responsibility) → PASSTHROUGH
  3. Check for sanitisation calls (strcmp / strncmp / strchr / strstr)
     on X0 between the last input write and the sink call.

Heuristic path (non-AArch64 fallback)
──────────────────────────────────────
Uses import names + strings extracted from the binary:
  getenv + system with no strncmp/strcmp  →  HEURISTIC_LIKELY
  getenv + format string with %s + system →  HEURISTIC_LIKELY
  No getenv / recv anywhere               →  UNCERTAIN

Output per result
─────────────────
  verdict  : CONFIRMED | LIKELY | UNCERTAIN | FALSE_POSITIVE
  origin   : human-readable input source description
  flow_str : "getenv(QUERY_STRING) → snprintf(cmd) → system(cmd)"
  reason   : one-line exploitability justification
"""

import struct

from .elf_analyzer import (
    _read_header,
    _parse_load_segments,
    _parse_sections,
    _v2f,
    ARCH_AARCH64,
    get_imports,
)

# ── Constant tables ───────────────────────────────────────────────────────────

_INPUT_SYMS = frozenset({
    "getenv",
    "recv", "recvfrom", "recvmsg",
    "read", "__read_chk",
    "fread", "fgets", "__fgets_chk",
    "SSL_read",
})

_CMD_SINKS = frozenset({
    "system", "popen",
    "execv", "execve", "execvp", "execvpe",
    "execl", "execle", "execlp",
})

_FMT_SYMS = frozenset({
    "snprintf", "__snprintf_chk",
    "sprintf", "__sprintf_chk",
    "vsnprintf", "vsprintf",
})

_SANITISE_SYMS = frozenset({
    "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "strchr", "strrchr", "strstr",
    "strpbrk", "strtok", "strtok_r",
    # common firmware sanitisation function substrings (checked via .lower())
})
_SANITISE_KEYWORDS = {"sanitize", "escape", "filter", "validate", "check", "allow"}

# CGI environment variables whose presence confirms web-controlled input
_CGI_ENV_VARS = {
    "QUERY_STRING", "CONTENT_LENGTH", "CONTENT_TYPE",
    "HTTP_COOKIE", "HTTP_HOST", "HTTP_USER_AGENT",
    "REQUEST_METHOD", "PATH_INFO", "REMOTE_ADDR",
}


# ── ELF string helper ─────────────────────────────────────────────────────────

def _read_cstr(data, file_off, max_len=128):
    """Read a null-terminated C string from file_off in data."""
    if file_off is None or file_off >= len(data):
        return None
    end = data.find(b'\x00', file_off, file_off + max_len)
    if end < 0:
        end = file_off + max_len
    try:
        return data[file_off:end].decode('ascii', errors='replace')
    except Exception:
        return None


def _read_va_cstr(data, segments, va, max_len=128):
    """Read a C string from a virtual address."""
    fo = _v2f(segments, va)
    return _read_cstr(data, fo, max_len)


# ── AArch64 X0-origin classifier ─────────────────────────────────────────────

def _classify_x0_at_sink(data, segments, func_va, sink_call_idx,
                          plt_reverse, max_scan=400):
    """
    Scan the function body [0..sink_call_idx] and classify what X0 holds
    at the sink call instruction.

    Returns a dict:
      x0_type    : str — see module docstring
      detail     : str — specific evidence string
      sanitized  : bool
      env_var    : str | None  — env-var name if x0_type == 'getenv'
      fmt_str    : str | None  — format string if x0_type == 'fmt_buf'
    """
    foff = _v2f(segments, func_va)
    if foff is None:
        return {'x0_type': 'unknown', 'detail': '', 'sanitized': False,
                'env_var': None, 'fmt_str': None}

    # Register state we track
    adrp_page   = {}          # reg → resolved page VA (from ADRP)
    x0_type     = 'arg_pass'  # assume X0 comes from caller unless we see a setter
    x0_detail   = ''
    sanitized   = False
    env_var     = None
    fmt_str     = None
    last_bl_sym = None
    x0_bl_arg   = None        # X0 value before the last BL (for getenv arg)

    limit = min(sink_call_idx, max_scan)

    for i in range(limit):
        off = foff + i * 4
        if off + 4 > len(data):
            break
        w  = struct.unpack_from('<I', data, off)[0]
        va = func_va + i * 4

        if w == 0xD65F03C0:   # RET — should not appear before sink, but guard
            break

        # ── ADRP Rd, label ────────────────────────────────────────────────────
        if (w & 0x9F000000) == 0x90000000:
            Rd    = w & 0x1F
            immlo = (w >> 29) & 0x3
            immhi = (w >> 5)  & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            adrp_page[Rd] = (va & ~0xFFF) + imm21 * 0x1000
            continue

        # ── ADD Xd, Xn, #imm12  (sf=1, opc=01, shift=0) ────────────────────
        if (w >> 22) == 0b1001000100:
            Rd    = w & 0x1F
            Rn    = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if Rn in adrp_page:
                resolved = adrp_page[Rn] + imm12
                if Rd == 0:   # ADD X0, Xn, #imm → X0 = static string pointer
                    s = _read_va_cstr(data, segments, resolved)
                    x0_bl_arg  = s        # record for getenv arg detection
                    x0_type    = 'const_cmd'
                    x0_detail  = repr(s) if s else hex(resolved)
            # Clear stale ADRP entries when Rd is overwritten by another ADD
            if Rd in adrp_page and Rd != Rn:
                del adrp_page[Rd]
            continue

        # ── ADD X0, sp, #imm → stack buffer address ───────────────────────────
        if (w >> 22) == 0b1001000100:
            pass  # handled above; separate check:

        # Inline: ADD Xd, sp, #N → Xd = stack buffer pointer
        if ((w >> 22) == 0b1001000100 and ((w >> 5) & 0x1F) == 31
                and (w & 0x1F) == 0):
            x0_type   = 'stack_addr'
            x0_detail = f"sp+{((w >> 10) & 0xFFF):#x}"

        # ── MOV X0, Xn  (ORR shift-reg form) ─────────────────────────────────
        if (w & 0xFFE0FFE0) == 0xAA0003E0:
            Rd = w & 0x1F
            Rn = (w >> 16) & 0x1F
            if Rd == 0 and Rn != 0:
                # X0 = Xn — inherit state if Xn had a known role
                # For now: mark as derived from another register
                if x0_type in ('const_cmd', 'getenv', 'net_input', 'fmt_buf'):
                    pass   # already known; MOV just copies the value
            continue

        # ── LDR X0, [Xn, #off] ────────────────────────────────────────────────
        if (w >> 24) == 0xF9 and ((w >> 22) & 3) == 1 and (w & 0x1F) == 0:
            # Load into X0; we lose static knowledge of the value
            Rn = (w >> 5) & 0x1F
            if Rn == 31:                    # [sp, #N]
                x0_type   = 'stack_load'
                x0_detail = f"[sp+{((w >> 10) & 0xFFF) * 8:#x}]"
            else:
                x0_type   = 'indirect_load'
                x0_detail = f"[X{Rn}+{((w >> 10) & 0xFFF) * 8:#x}]"
            continue

        # ── BL target ─────────────────────────────────────────────────────────
        if (w >> 26) == 0x25:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            target = va + imm26 * 4
            sym    = plt_reverse.get(target, '')
            last_bl_sym = sym

            if sym == 'getenv':
                # X0 before this BL was the env-var name
                env_var   = x0_bl_arg if isinstance(x0_bl_arg, str) else None
                x0_type   = 'getenv'
                x0_detail = f"getenv({repr(env_var) if env_var else '?'})"
            elif sym in ('recv', 'recvfrom', 'read', '__read_chk',
                         'fgets', '__fgets_chk', 'fread', 'SSL_read'):
                x0_type   = 'net_input'
                x0_detail = f"{sym}()"
            elif sym in _FMT_SYMS:
                # After snprintf, X0 still points to the destination buffer.
                # Look for an ADRP+ADD that loaded X1 (format string) before this BL.
                x0_type   = 'fmt_buf'
                x0_detail = f"{sym}(buf, ...)"
                # Try to recover format string from X1 (already resolved via adrp_page)
                # We track it via x0_bl_arg only if X1 was set via ADRP+ADD above.
                # Simple approximation: fmt_str left as None unless we found it.
            elif sym:
                sl = sym.lower()
                is_sanitize = (sym in _SANITISE_SYMS or
                               any(k in sl for k in _SANITISE_KEYWORDS))
                if is_sanitize and x0_type in ('getenv', 'net_input',
                                               'fmt_buf', 'stack_addr',
                                               'stack_load', 'indirect_load'):
                    sanitized = True

            # After any BL, X0 = return value — capture for next iteration
            if sym and sym != 'getenv':
                # Record sym so next ADRP+ADD→X0 captures the context
                pass
            x0_bl_arg = None   # reset "arg to next BL" tracker
            continue

    return {
        'x0_type':  x0_type,
        'detail':   x0_detail,
        'sanitized': sanitized,
        'env_var':  env_var,
        'fmt_str':  fmt_str,
    }


def _find_sink_callsites_in_func(data, segments, func_va, sink_va_set,
                                  max_insns=500):
    """
    Return list of (instruction_index, target_va, sink_sym) for every
    BL inside func_va that targets one of the sink VAs.
    """
    foff = _v2f(segments, func_va)
    if foff is None:
        return []
    hits = []
    for i in range(max_insns):
        off = foff + i * 4
        if off + 4 > len(data):
            break
        w  = struct.unpack_from('<I', data, off)[0]
        va = func_va + i * 4
        if w == 0xD65F03C0:   # RET
            break
        if (w >> 26) == 0x25:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            target = va + imm26 * 4
            if target in sink_va_set:
                hits.append((i, target))
    return hits


def _verdict_from_x0(x0_info, has_input_import):
    """
    Translate x0 classification into a verdict.

    Returns (verdict: str, flow_str: str, reason: str)
    """
    t    = x0_info['x0_type']
    det  = x0_info['detail']
    sanit = x0_info['sanitized']

    if t == 'const_cmd':
        s = x0_info['detail']
        # Heuristic: if the constant is a shell invocation with metacharacters, keep
        if s and any(c in s for c in ('%', '$', '`', '|', '&', ';')):
            return ('LIKELY',
                    f"const fmt-like → system({s!r})",
                    "constant with shell metacharacters — format injection possible")
        return ('FALSE_POSITIVE',
                f"system({s!r})",
                "constant command argument — no user input reaches sink")

    if t == 'getenv':
        ev = x0_info['env_var'] or 'UNKNOWN_VAR'
        if sanit:
            return ('UNCERTAIN',
                    f"getenv({ev!r}) → [sanitized] → system()",
                    f"getenv({ev!r}) reaches system() but sanitization observed — verify bypass")
        if ev in _CGI_ENV_VARS or 'HTTP_' in ev or 'QUERY' in ev:
            return ('CONFIRMED',
                    f"getenv({ev!r}) → system()",
                    f"HTTP parameter {ev!r} flows directly to system() with no observed sanitization")
        return ('CONFIRMED',
                f"getenv({ev!r}) → system()",
                f"env var {ev!r} flows directly to system() — user-controlled in CGI context")

    if t == 'net_input':
        src = x0_info['detail']
        if sanit:
            return ('UNCERTAIN',
                    f"{src} → [sanitized] → system()",
                    f"network input via {src} reaches system() but sanitization call observed")
        return ('CONFIRMED',
                f"{src} → system()",
                f"network-sourced buffer from {src} reaches system() unsanitized")

    if t == 'fmt_buf':
        if sanit:
            return ('UNCERTAIN',
                    f"snprintf(cmd, ...) → [sanitized] → system(cmd)",
                    "formatted command buffer reaches system() — sanitization observed, verify completeness")
        if has_input_import:
            return ('LIKELY',
                    f"snprintf(cmd, fmt, input) → system(cmd)",
                    "formatted command passed to system(); function also receives external input — format arg likely tainted")
        return ('UNCERTAIN',
                f"snprintf(cmd, ...) → system(cmd)",
                "formatted command passed to system(); format arg taint unclear")

    if t in ('stack_addr', 'stack_load', 'indirect_load'):
        if has_input_import and not sanit:
            return ('LIKELY',
                    f"buf[stack] → system(buf)",
                    "stack buffer reaches system(); function receives external input — buffer likely filled from user data")
        if sanit:
            return ('UNCERTAIN',
                    f"buf[stack] → [sanitized] → system(buf)",
                    "stack buffer with sanitization — trace sanitization completeness")
        return ('UNCERTAIN',
                f"buf[stack] → system(buf)",
                "stack buffer reaches system(); input origin unclear")

    if t == 'arg_pass':
        if has_input_import:
            return ('LIKELY',
                    "arg(X0) → system(X0)",
                    "command string passed as argument; function also handles external input")
        return ('UNCERTAIN',
                "arg(X0) → system(X0)",
                "command string is a parameter — trace callers for taint origin")

    return ('UNCERTAIN',
            f"X0[{t}] → system()",
            f"sink argument origin is {t!r} — manual confirmation needed")


# ── AArch64 verification ──────────────────────────────────────────────────────

def _verify_aarch64(binary_path, cg):
    """
    Per-callsite X0 origin analysis for AArch64 binaries.
    Returns list of flow dicts.
    """
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
    except OSError:
        return []

    hdr = _read_header(data)
    if hdr is None:
        return []
    _, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx = hdr
    segments = _parse_load_segments(data, e_phoff, e_phnum)
    plt      = cg.get('_plt', {})
    plt_rev  = {v: k for k, v in plt.items()}   # va → sym_name

    # VA set for every critical sink PLT stub
    sink_vas = {va for sym, va in plt.items() if sym in _CMD_SINKS}
    if not sink_vas:
        return []

    sink_fns   = cg.get('_sink_fns', {})
    source_fns = cg.get('_source_fns', set())

    results = []

    for func_va, (sink_sym, tier) in sink_fns.items():
        if tier != 'critical':
            continue

        sink_va = plt.get(sink_sym)
        if sink_va is None:
            continue

        callsites = _find_sink_callsites_in_func(
            data, segments, func_va, {sink_va})

        if not callsites:
            continue

        # Does this function directly call any input import?
        node           = cg.get(func_va, {})
        callee_syms    = {sym for _, sym in node.get('callees', set()) if sym}
        has_input      = bool(callee_syms & _INPUT_SYMS)
        has_sanitise   = bool(callee_syms & _SANITISE_SYMS or
                              any(any(k in s.lower()
                                      for k in _SANITISE_KEYWORDS)
                                  for s in callee_syms))

        for call_idx, target_va in callsites:
            x0_info = _classify_x0_at_sink(
                data, segments, func_va, call_idx, plt_rev)

            verdict, flow_str, reason = _verdict_from_x0(x0_info, has_input)

            results.append({
                'func_va':   func_va,
                'func_sym':  cg.get(func_va, {}).get('sym') or hex(func_va),
                'sink_sym':  sink_sym,
                'sink_va':   target_va,
                'origin':    x0_info['x0_type'],
                'sanitized': x0_info['sanitized'],
                'flow_str':  flow_str,
                'reason':    reason,
                'verdict':   verdict,
            })

    return results


# ── Heuristic fallback (non-AArch64) ─────────────────────────────────────────

def _verify_heuristic(binary_path, imports, strings=None):
    """
    Import + string based taint narrowing for non-AArch64 architectures.
    Returns list of flow dicts.
    """
    results = []
    imp_set = set(imports.keys()) if imports else set()

    has_cmd_sink  = bool(imp_set & _CMD_SINKS)
    has_getenv    = 'getenv' in imp_set
    has_net       = bool(imp_set & _INPUT_SYMS - {'getenv'})
    has_sanitise  = bool(imp_set & _SANITISE_SYMS)
    has_fmt       = bool(imp_set & _FMT_SYMS)

    if not has_cmd_sink:
        return []

    # Detect CGI context from environment variable references in strings
    cgi_vars = set()
    fmt_templates = []
    if strings:
        for s in strings:
            su = s.upper()
            for v in _CGI_ENV_VARS:
                if v in su:
                    cgi_vars.add(v)
            # Collect strings that look like shell command templates
            if ('%s' in s or '%d' in s) and any(
                    c in s for c in ('/', ' ', '-')):
                fmt_templates.append(s)

    sink_sym = next(iter(imp_set & _CMD_SINKS))  # pick one representative

    if has_getenv and cgi_vars and not has_sanitise:
        ev   = sorted(cgi_vars)[0]
        flow = (f"getenv({ev!r}) → "
                + (f"snprintf(cmd, fmt, input) → " if has_fmt else "")
                + f"{sink_sym}(cmd)")
        results.append({
            'func_va':   None,
            'func_sym':  '(heuristic)',
            'sink_sym':  sink_sym,
            'sink_va':   None,
            'origin':    'getenv',
            'sanitized': False,
            'flow_str':  flow,
            'reason':    (f"CGI env var {ev!r} flows to {sink_sym}() "
                          f"with no observed sanitization — confirmed CGI injection surface"),
            'verdict':   'LIKELY',
        })
    elif has_getenv and cgi_vars and has_sanitise:
        ev = sorted(cgi_vars)[0]
        results.append({
            'func_va':   None,
            'func_sym':  '(heuristic)',
            'sink_sym':  sink_sym,
            'sink_va':   None,
            'origin':    'getenv',
            'sanitized': True,
            'flow_str':  f"getenv({ev!r}) → [sanitized?] → {sink_sym}()",
            'reason':    (f"CGI env var {ev!r} reaches {sink_sym}() with possible "
                          f"sanitization — verify sanitization is complete"),
            'verdict':   'UNCERTAIN',
        })
    elif has_net and not has_sanitise:
        results.append({
            'func_va':   None,
            'func_sym':  '(heuristic)',
            'sink_sym':  sink_sym,
            'sink_va':   None,
            'origin':    'net_input',
            'sanitized': False,
            'flow_str':  f"network_input() → {sink_sym}()",
            'reason':    (f"binary reads from network and calls {sink_sym}() "
                          f"with no observed sanitization — likely exploitable"),
            'verdict':   'LIKELY',
        })
    elif has_cmd_sink:
        # Check for format-string templates that look injectable
        injectable = [t for t in fmt_templates
                      if '%s' in t and ('cmd' in t.lower() or
                                        '/bin' in t or '/sbin' in t or
                                        len(t) < 64)]
        if injectable:
            results.append({
                'func_va':   None,
                'func_sym':  '(heuristic)',
                'sink_sym':  sink_sym,
                'sink_va':   None,
                'origin':    'fmt_template',
                'sanitized': has_sanitise,
                'flow_str':  f"fmt({injectable[0]!r}) → {sink_sym}()",
                'reason':    (f"format string with %s feeds {sink_sym}() "
                              f"— confirm format argument is attacker-controlled"),
                'verdict':   'UNCERTAIN',
            })

    return results


# ── Public API ────────────────────────────────────────────────────────────────

def verify_exploitable_flows(binary_path, cg, imports=None, strings=None):
    """
    Run deep flow verification on a top candidate binary.

    Parameters
    ----------
    binary_path : str  — absolute path to the binary
    cg          : dict — call graph from build_call_graph(); {} triggers heuristic
    imports     : dict | None — from get_imports(); inferred from cg if None
    strings     : list | None — from extract_strings(); for heuristic path

    Returns
    -------
    List of flow dicts. Each has the keys:
        func_va, func_sym, sink_sym, sink_va,
        origin, sanitized, flow_str, reason, verdict

    Flows with verdict == 'FALSE_POSITIVE' should be discarded by the caller.
    Results are sorted: CONFIRMED first, then LIKELY, then UNCERTAIN.
    """
    if imports is None:
        imports = get_imports(binary_path)

    # Determine architecture
    try:
        with open(binary_path, 'rb') as f:
            raw = f.read(20)
        is_aarch64 = (len(raw) >= 20 and raw[:4] == b'\x7fELF'
                      and raw[4] == 2 and raw[5] == 1
                      and struct.unpack_from('<H', raw, 18)[0] == ARCH_AARCH64)
    except OSError:
        is_aarch64 = False

    if is_aarch64 and cg:
        flows = _verify_aarch64(binary_path, cg)
        # Supplement with heuristic if deep analysis found nothing
        if not flows:
            flows = _verify_heuristic(binary_path, imports, strings)
    else:
        flows = _verify_heuristic(binary_path, imports, strings)

    # Sort: CONFIRMED > LIKELY > UNCERTAIN > FALSE_POSITIVE
    _order = {'CONFIRMED': 0, 'LIKELY': 1, 'UNCERTAIN': 2, 'FALSE_POSITIVE': 3}
    flows.sort(key=lambda f: _order.get(f['verdict'], 4))

    return flows
