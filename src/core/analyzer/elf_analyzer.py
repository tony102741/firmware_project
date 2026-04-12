"""
ELF-level binary analysis for the firmware vulnerability pipeline.

Provides three capabilities that replace or augment string-based heuristics:

  get_imports(path)         — exact PLT/dynsym import enumeration; no false
                              positives from log strings that mention strcpy etc.

  build_call_graph(path)    — lightweight AArch64 call graph via BL decoding +
                              STP-prologue function boundary detection; single
                              O(n) pass over .text with no disassembler dependency.

  check_length_taint(...)   — per-function scan: LDRH/REV → [MUL] → BL-to-sink
                              without intervening CMP; detects the integer-overflow
                              pattern observed in the ASN.1 UMULL case.

  find_shortest_path(...)   — BFS over the call graph to confirm a reachable
                              source → sink chain and return its length.

All functions return empty/False on non-ELF input, wrong arch, or parse errors.
Only 64-bit AArch64 ELFs are supported for call-graph analysis; other
architectures fall back to string-based analysis in risk.py.
"""

import struct
from collections import deque


# ── Lightweight AArch64 register value tracker ────────────────────────────────

class _RegTracker:
    """
    Track register values through a limited set of AArch64 instructions to
    resolve BLR targets (vtable dispatch) and ADRP-derived static addresses.

    Handles: ADRP, ADD(imm12), LDR(Xt,[Xn,#imm]), MOV(Xd,Xn).
    Not a symbolic executor — just enough to resolve 1–2 level pointer chains
    originating from static (.rodata / .data) addresses.

    State per register: ('page', va) | ('imm', va) | ('deref', base_va, off)
    """

    __slots__ = ('_data', '_segs', '_r')

    def __init__(self, data, segments):
        self._data = data
        self._segs = segments
        self._r    = {}   # reg_num → state tuple

    def reset(self):
        self._r.clear()

    def _read64(self, va):
        f = _v2f(self._segs, va)
        if f is not None and f + 8 <= len(self._data):
            return struct.unpack_from('<Q', self._data, f)[0]
        return None

    def update(self, va, w):
        r = self._r

        # ADRP Rd, label
        if (w & 0x9F000000) == 0x90000000:
            Rd = w & 0x1F
            immlo = (w >> 29) & 0x3
            immhi = (w >> 5)  & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            r[Rd] = ('page', (va & ~0xFFF) + imm21 * 0x1000)
            return

        # ADD Xd, Xn, #imm12  (sf=1, opc=01, sh=0)
        if (w >> 22) == 0b1001000100:
            Rd, Rn = w & 0x1F, (w >> 5) & 0x1F
            imm12  = (w >> 10) & 0xFFF
            prev   = r.get(Rn)
            if prev and prev[0] in ('page', 'imm'):
                r[Rd] = ('imm', prev[1] + imm12)
            else:
                r.pop(Rd, None)
            return

        # LDR Xt, [Xn, #imm12*8]
        if (w >> 24) == 0xF9 and ((w >> 22) & 3) == 1:
            Rt, Rn = w & 0x1F, (w >> 5) & 0x1F
            imm    = ((w >> 10) & 0xFFF) * 8
            prev   = r.get(Rn)
            if prev:
                if prev[0] == 'imm':
                    val = self._read64(prev[1] + imm)
                    r[Rt] = ('imm', val) if val else ('deref', prev[1], imm)
                elif prev[0] == 'deref':
                    # Two-level deref: [*[base+off1] + imm]
                    r[Rt] = ('deref2', prev, imm)
                else:
                    r.pop(Rt, None)
            else:
                r.pop(Rt, None)
            return

        # MOV Xd, Xn  (ORR shifted-reg, Rn=XZR special case handled elsewhere)
        if (w & 0xFFE0FFE0) == 0xAA0003E0:
            Rd, Rn = w & 0x1F, (w >> 16) & 0x1F
            r[Rd]  = r.get(Rn, ('unknown',))
            return

        # Any write to a register we don't handle — invalidate it
        Rd = w & 0x1F
        if Rd != 31 and (w >> 29) in (0b000, 0b001, 0b010, 0b100, 0b101):
            # Very conservative: only clear if the encoding suggests a write
            # to a general-purpose register we're tracking.
            if Rd in self._r:
                r.pop(Rd, None)

    def resolve(self, reg_num):
        """
        Attempt to resolve reg_num to a concrete virtual address.
        Returns int VA or None.
        """
        state = self._r.get(reg_num)
        if state is None:
            return None
        if state[0] == 'imm':
            return state[1]
        if state[0] == 'deref':
            val = self._read64(state[1] + state[2])
            return val
        if state[0] == 'deref2':
            # state = ('deref2', ('deref', base, off1), off2)
            inner = state[1]
            mid = self._read64(inner[1] + inner[2])
            if mid:
                return self._read64(mid + state[2])
        return None

# ── Architecture constants ────────────────────────────────────────────────────

ARCH_AARCH64 = 0xB7

# ── Import classification sets ────────────────────────────────────────────────
# Used both here (to annotate the call graph) and exported to other modules.

INPUT_IMPORTS = frozenset({
    "SSL_read", "recv", "recvfrom", "recvmsg", "recvmmsg",
    "accept", "accept4", "read", "__read_chk",
    "fread", "fgets", "__fgets_chk",
    "getmsg", "t_rcv",
})

SINK_IMPORTS = {
    "critical": frozenset({
        "execv", "execve", "execvp", "execvpe",
        "execl", "execle", "execlp",
        "system", "popen",
    }),
    "strong": frozenset({
        "strcpy", "strcat", "sprintf", "vsprintf",
        "gets", "scanf", "sscanf",
    }),
    "weak": frozenset({
        "memcpy", "memmove",
        "__memcpy_chk", "__memmove_chk",
        "__strcpy_chk", "__strcat_chk",
    }),
}

ALLOC_IMPORTS = frozenset({
    "malloc", "calloc", "realloc",
    "_Znwm", "_Znam", "_Znwj", "_Znaj",   # operator new variants
})

# Flat set for quick membership test
_ALL_SINK_SYMS = frozenset().union(*SINK_IMPORTS.values())


# ── ELF parsing helpers ───────────────────────────────────────────────────────

def _read_header(data):
    """
    Parse ELF64 header fields needed by this module.
    Returns (e_machine, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx)
    or None if the file is not a valid 64-bit ELF.
    """
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    if data[4] != 2:   # EI_CLASS: 2 = ELFCLASS64
        return None
    if data[5] != 1:   # EI_DATA:  1 = little-endian
        return None
    e_machine  = struct.unpack_from('<H', data, 18)[0]
    e_phoff    = struct.unpack_from('<Q', data, 32)[0]
    e_phnum    = struct.unpack_from('<H', data, 56)[0]
    e_shoff    = struct.unpack_from('<Q', data, 40)[0]
    e_shnum    = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]
    return e_machine, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx


def _parse_load_segments(data, e_phoff, e_phnum):
    """Return list of (vaddr, vaddr_end, file_offset) for PT_LOAD segments."""
    segs = []
    for i in range(e_phnum):
        base = e_phoff + i * 56
        p_type   = struct.unpack_from('<I', data, base)[0]
        p_offset = struct.unpack_from('<Q', data, base + 8)[0]
        p_vaddr  = struct.unpack_from('<Q', data, base + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, base + 32)[0]
        if p_type == 1 and p_filesz > 0:   # PT_LOAD
            segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))
    return segs


def _v2f(segments, va):
    """Virtual address → file offset; returns None if unmapped."""
    for s, e, o in segments:
        if s <= va < e:
            return o + (va - s)
    return None


def _parse_sections(data, e_shoff, e_shnum, e_shstrndx):
    """
    Return dict {name: (sh_type, sh_addr, sh_offset, sh_size, sh_entsize)}.
    Returns {} on any parse error.
    """
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        return {}
    try:
        shstr_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * 64 + 24)[0]
        sections = {}
        for i in range(e_shnum):
            sh       = e_shoff + i * 64
            name_off = struct.unpack_from('<I', data, sh)[0]
            sh_type  = struct.unpack_from('<I', data, sh + 4)[0]
            sh_addr  = struct.unpack_from('<Q', data, sh + 16)[0]
            sh_off   = struct.unpack_from('<Q', data, sh + 24)[0]
            sh_size  = struct.unpack_from('<Q', data, sh + 32)[0]
            sh_ent   = struct.unpack_from('<Q', data, sh + 56)[0]
            raw = data[shstr_off + name_off: shstr_off + name_off + 64]
            try:
                name = raw[:raw.index(b'\x00')].decode('ascii', 'replace')
            except ValueError:
                name = raw.decode('ascii', 'replace').rstrip('\x00')
            sections[name] = (sh_type, sh_addr, sh_off, sh_size, sh_ent)
        return sections
    except Exception:
        return {}


# ── Public API ────────────────────────────────────────────────────────────────

def get_imports(path):
    """
    Parse ELF .dynsym + .rela.plt to return exact imported symbol names
    mapped to their PLT stub virtual addresses.

    Returns: dict {sym_name: plt_stub_va}
    Empty dict on failure or non-ELF input.

    This is the primary replacement for string-based sink/input detection:
    every name here is a real dynamic linker symbol, not a substring of a
    log message or comment.
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return {}

    hdr = _read_header(data)
    if hdr is None:
        return {}
    _, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx = hdr

    sections = _parse_sections(data, e_shoff, e_shnum, e_shstrndx)
    if not sections or '.dynstr' not in sections:
        return {}

    _, _, dynstr_off, dynstr_sz, _ = sections['.dynstr']

    def _sym_name(name_off):
        if name_off >= dynstr_sz:
            return ''
        end = data.find(b'\x00', dynstr_off + name_off,
                        dynstr_off + name_off + 256)
        if end < 0:
            return ''
        return data[dynstr_off + name_off: end].decode('ascii', 'replace')

    # Build {sym_index: sym_name} from .dynsym
    sym_names = {}
    if '.dynsym' in sections:
        _, _, dynsym_off, dynsym_sz, dynsym_ent = sections['.dynsym']
        ent = max(int(dynsym_ent), 24)
        for i in range(dynsym_sz // ent):
            name_off = struct.unpack_from('<I', data,
                                          dynsym_off + i * ent)[0]
            sym_names[i] = _sym_name(name_off)

    # .plt geometry
    plt_base = sections['.plt'][1] if '.plt' in sections else 0
    plt_ent  = int(sections['.plt'][4]) if '.plt' in sections else 16
    if plt_ent == 0:
        plt_ent = 16

    # Map each RELA.PLT entry → (sym_name, PLT stub VA)
    result = {}
    if '.rela.plt' in sections:
        _, _, rela_off, rela_sz, _ = sections['.rela.plt']
        n = rela_sz // 24
        for i in range(n):
            r_info  = struct.unpack_from('<Q', data, rela_off + i * 24 + 8)[0]
            sym_idx = r_info >> 32
            name    = sym_names.get(sym_idx, '')
            if name:
                plt_stub_va = plt_base + (i + 1) * plt_ent
                result[name] = plt_stub_va

    return result


def build_call_graph(path, max_text_mb=12):
    """
    Build a lightweight call graph for AArch64 ELF binaries.

    Algorithm (single O(n) pass over .text):
      1. Detect function boundaries via STP X29,X30,[SP,#-N]! prologue
         (bits[31:22]=1010_1001_10, Rt=X29, Rt2=X30, Rn=SP, pre-indexed)
      2. Track the current function while scanning forward
      3. For each BL instruction, compute target and record the call edge
      4. Resolve BL targets that hit PLT stubs to their symbol names

    Returns a dict with the following structure:
      {
        func_va (int): {
            'sym':     str | None,     # symbol name if this VA is a PLT stub
            'callees': set of (va, sym_or_None),
        },
        '_plt':        {sym_name: plt_va},   # PLT reverse map
        '_source_fns': set of func_va,       # functions that call INPUT_IMPORTS
        '_sink_fns':   {func_va: (sym, tier)},
        '_alloc_fns':  set of func_va,       # functions that call allocators
      }

    Returns {} for non-AArch64, missing .text, or binaries larger than
    max_text_mb in their .text section (prevents hanging on huge binaries).
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return {}

    hdr = _read_header(data)
    if hdr is None:
        return {}
    e_machine, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx = hdr

    if e_machine != ARCH_AARCH64:
        return {}

    sections = _parse_sections(data, e_shoff, e_shnum, e_shstrndx)
    if '.text' not in sections:
        return {}

    _, text_va, text_foff, text_sz, _ = sections['.text']
    if text_sz > max_text_mb * 1024 * 1024:
        return {}   # too large; skip to avoid hanging

    segments    = _parse_load_segments(data, e_phoff, e_phnum)
    imports     = get_imports(path)
    plt_reverse = {v: k for k, v in imports.items()}   # va → sym_name

    # AArch64 STP X29,X30,[SP,#-N]! prologue mask
    # Fixed bits: size=10, V=0, opc=10, L=0, Rt2=X30(30), Rn=SP(31), Rt=X29(29)
    # Variable: simm7 (must be negative → bit[21]=1 for pre-indexed stack push)
    PROLOGUE_MASK = 0xFFC07FFF
    PROLOGUE_VAL  = 0xA9807BFD

    cg           = {}        # func_va → node
    current_func = None
    tracker      = _RegTracker(data, segments)

    # Single sequential pass
    chunk = data[text_foff: text_foff + text_sz]
    n_words = len(chunk) // 4

    for i in range(n_words):
        va = text_va + i * 4
        w  = struct.unpack_from('<I', chunk, i * 4)[0]

        # ── Function boundary detection ───────────────────────────────────────
        if (w & PROLOGUE_MASK) == PROLOGUE_VAL:
            current_func = va
            tracker.reset()
            if current_func not in cg:
                cg[current_func] = {
                    'sym':     plt_reverse.get(current_func),
                    'callees': set(),
                }

        if current_func is None:
            continue

        # ── Update register tracker for vtable/indirect resolution ────────────
        tracker.update(va, w)

        # ── BL: direct call ───────────────────────────────────────────────────
        if (w >> 26) == 0x25:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            target = va + imm26 * 4
            sym    = plt_reverse.get(target)
            cg[current_func]['callees'].add((target, sym))

        # ── BLR Xn: indirect call — attempt vtable resolution ─────────────────
        # Encoding: 1101011000111111000000 Rn 00000
        elif (w & 0xFFFFFC1F) == 0xD63F0000:
            Rn     = (w >> 5) & 0x1F
            target = tracker.resolve(Rn)
            if target and text_va <= target < text_va + text_sz:
                sym = plt_reverse.get(target)
                cg[current_func]['callees'].add((target, sym))

    if not cg:
        return {}

    # ── Annotate source / sink / alloc functions ──────────────────────────────
    # A "source function" is one that directly calls an input import.
    # A "sink function" is one that directly calls a sink import.
    source_fns = set()
    sink_fns   = {}    # func_va → (sym_name, tier)
    alloc_fns  = set()

    for func_va, node in cg.items():
        for target_va, sym in node['callees']:
            if sym is None:
                continue
            if sym in INPUT_IMPORTS:
                source_fns.add(func_va)
            if sym in _ALL_SINK_SYMS:
                tier = next(t for t, s in SINK_IMPORTS.items() if sym in s)
                # Keep the highest-tier hit for this function
                prev = sink_fns.get(func_va)
                tier_rank = {"critical": 3, "strong": 2, "weak": 1}
                if prev is None or tier_rank[tier] > tier_rank[prev[1]]:
                    sink_fns[func_va] = (sym, tier)
            if sym in ALLOC_IMPORTS:
                alloc_fns.add(func_va)

    cg['_plt']        = imports
    cg['_source_fns'] = source_fns
    cg['_sink_fns']   = sink_fns
    cg['_alloc_fns']  = alloc_fns

    return cg


def find_shortest_path(cg, max_depth=10, max_visited=50_000):
    """
    BFS from source functions to sink functions in the call graph.

    Starts from all source functions simultaneously (multi-source BFS) to
    find the shortest chain: input_function → ... → sink_function.

    Returns: (path: list[int], sink_sym: str, sink_tier: str)
             or (None, None, None) if no reachable path found.
    """
    source_fns = cg.get('_source_fns', set())
    sink_fns   = cg.get('_sink_fns',   {})

    if not source_fns or not sink_fns:
        return None, None, None

    # Check direct hits first (depth=1)
    for src in source_fns:
        if src in sink_fns:
            sym, tier = sink_fns[src]
            return [src], sym, tier

    visited = set(source_fns)
    # Queue: (func_va, path_so_far)
    queue = deque((src, [src]) for src in source_fns)

    while queue:
        va, path = queue.popleft()
        if len(path) >= max_depth:
            continue
        if len(visited) >= max_visited:
            break

        node = cg.get(va)
        if node is None or isinstance(node, (set, dict)) and 'callees' not in node:
            continue

        for target_va, _sym in node.get('callees', ()):
            # Direct sink hit
            if target_va in sink_fns:
                sym, tier = sink_fns[target_va]
                return path + [target_va], sym, tier

            if target_va in visited or target_va not in cg:
                continue
            visited.add(target_va)
            queue.append((target_va, path + [target_va]))

    return None, None, None


def _scan_taint(data, segments, func_va, tainted_entry=None, max_insns=300):
    """
    Internal taint scanner.  Called by check_length_taint and
    check_length_taint_deep.

    tainted_entry: set of register indices pre-tainted at function entry
                   (used when a caller passed a length value in an argument).

    Returns:
      (vulnerable: bool,
       evidence: str,
       call_sites: list of (target_va: int, tainted_args: frozenset))

    call_sites lists every BL where at least one unchecked length register
    was in an argument position — used by check_length_taint_deep to recurse.
    """
    foff = _v2f(segments, func_va)
    if foff is None:
        return False, "", []

    length_regs  = set(tainted_entry or ())
    checked_regs = set()
    evidence     = []
    call_sites   = []

    for i in range(max_insns):
        off = foff + i * 4
        if off + 4 > len(data):
            break
        w  = struct.unpack_from('<I', data, off)[0]
        va = func_va + i * 4

        if w == 0xD65F03C0:  # RET
            break

        # ── LDRH: 16-bit load → likely a length/size field ───────────────────
        if (w >> 24) == 0x79 and ((w >> 22) & 3) == 1:
            Rt = w & 0x1F
            length_regs.add(Rt)
            evidence.append(f"LDRH W{Rt}@{va:#x}")
            continue

        # ── LDRB: 8-bit load → tag or short length field ─────────────────────
        if (w >> 24) == 0x39 and ((w >> 22) & 3) == 1:
            Rt = w & 0x1F
            length_regs.add(Rt)
            continue

        # ── REV/REV16/REV32: ntohl/ntohs on network field ────────────────────
        if (w & 0xFFFFFC00) in (0x5AC00400, 0x5AC00800, 0x5AC00C00):
            Rd = w & 0x1F
            length_regs.add(Rd)
            evidence.append(f"REV W{Rd}@{va:#x}")
            continue

        # ── UMULL/SMULL/MUL: propagate length through multiply ────────────────
        if (w >> 29) == 0b100 and ((w >> 24) & 0xF) == 0xB:
            Rd = w & 0x1F
            Rn = (w >> 5)  & 0x1F
            Rm = (w >> 16) & 0x1F
            if Rn in length_regs or Rm in length_regs:
                length_regs.add(Rd)
                unchecked = ({Rn, Rm} & length_regs) - checked_regs
                if unchecked:
                    r = min(unchecked)
                    evidence.append(f"MUL/UMULL W{r}→X{Rd} unchecked@{va:#x}")
            continue

        # ── MOV Xd, Xn: propagate taint through register moves ───────────────
        if (w & 0xFFE0FFE0) == 0xAA0003E0:
            Rd = w & 0x1F
            Rn = (w >> 16) & 0x1F
            if Rn in length_regs:
                length_regs.add(Rd)
            elif Rd in length_regs:
                length_regs.discard(Rd)   # clobbered by untainted value
            continue

        # ── CMP / SUBS: bounds check on length register ───────────────────────
        if (w >> 24) in (0x71, 0x6B, 0xEB, 0xF1, 0x6A, 0xEA):
            Rn = (w >> 5) & 0x1F
            if Rn in length_regs:
                checked_regs.add(Rn)
            continue

        # ── CBZ / CBNZ: null-check on length register ─────────────────────────
        if (w >> 25) in (0b0110100, 0b0110101):
            Rt = w & 0x1F
            if Rt in length_regs:
                checked_regs.add(Rt)
            continue

        # ── BL: direct call ───────────────────────────────────────────────────
        if (w >> 26) == 0x25:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            target = va + imm26 * 4

            unchecked_args = (length_regs & set(range(8))) - checked_regs
            if unchecked_args:
                if evidence:
                    r      = min(unchecked_args)
                    ev_str = "; ".join(evidence[-4:])
                    return True, f"W{r} → BL {target:#x} unchecked [{ev_str}]", call_sites
                # Length in args but no LDRH/REV evidence yet — still record
                # for inter-procedural propagation (pre-tainted entry case).
                call_sites.append((target, frozenset(unchecked_args)))

    return False, "", call_sites


def check_length_taint(path, func_va, max_insns=300):
    """
    Scan a single function for the length-field taint pattern:
        LDRH/LDRB/REV → [MUL] → BL with unchecked length in arg registers.

    Returns: (vulnerable: bool, evidence: str)
    Public API — signature unchanged from previous version.
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return False, ""

    hdr = _read_header(data)
    if hdr is None:
        return False, ""
    _, e_phoff, e_phnum, _, _, _ = hdr
    segments = _parse_load_segments(data, e_phoff, e_phnum)

    vuln, ev, _ = _scan_taint(data, segments, func_va, max_insns=max_insns)
    return vuln, ev


def check_length_taint_deep(path, func_va, cg, max_depth=2, max_insns=200):
    """
    Inter-procedural taint: follows length registers through BL argument passing.

    When _scan_taint finds that a length register is passed as an argument to a
    callee (without a prior bounds check), this function recurses into that
    callee with the relevant argument registers pre-marked as tainted.

    Stops at max_depth levels to keep analysis O(n·d) in call-graph size.

    Returns: (vulnerable: bool, evidence: str)
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return False, ""

    hdr = _read_header(data)
    if hdr is None:
        return False, ""
    _, e_phoff, e_phnum, _, _, _ = hdr
    segments = _parse_load_segments(data, e_phoff, e_phnum)

    def _recurse(fva, tainted_entry, depth, visited):
        if fva in visited or depth < 0:
            return False, ""
        visited.add(fva)

        vuln, ev, call_sites = _scan_taint(
            data, segments, fva,
            tainted_entry=tainted_entry,
            max_insns=max_insns,
        )
        if vuln:
            return True, ev

        if depth == 0:
            return False, ""

        for target_va, tainted_args in call_sites:
            # Only recurse into functions the call graph knows about, to avoid
            # chasing into library stubs that are not in the binary.
            if target_va not in cg:
                continue
            ok, ev2 = _recurse(target_va, tainted_args, depth - 1, visited)
            if ok:
                return True, f"[via {fva:#x}] {ev2}"

        return False, ""

    vuln, ev = _recurse(func_va, None, max_depth, set())
    return vuln, ev


def detect_parser_patterns(path, cg=None, max_funcs=2000, max_insns=200):
    """
    Scan functions for characteristic protocol-parser patterns that indicate
    network-controlled length fields feeding allocation or copy operations.

    Detected patterns
    -----------------
    tlv   — Tag-Length-Value triple: LDRB(tag) followed by LDRB/LDRH(length)
            within 8 instructions, with length register unchecked before a BL.

    asn1  — ASN.1 long-form length: AND W_,W_,#0x7F (strip class bits) or
            CMP against 0x80/0x81/0x82 (length-form discriminator).

    lpf   — Length-prefixed frame: REV/REV16 in the first 16 instructions
            followed by that register used unchecked in a BL argument.

    seqof — Counted loop: LDRH/LDRB value used directly as a CBZ/CBNZ
            loop counter with no upper-bound check.

    Returns: {func_va: {'pattern': str, 'score': int, 'evidence': str}}
      score 3 = high confidence (multiple corroborating signals)
      score 2 = moderate (single clean pattern)
      score 1 = weak (isolated signal, no BL confirmation)
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return {}

    hdr = _read_header(data)
    if hdr is None:
        return {}
    e_machine, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx = hdr
    if e_machine != ARCH_AARCH64:
        return {}

    segments = _parse_load_segments(data, e_phoff, e_phnum)
    sections = _parse_sections(data, e_shoff, e_shnum, e_shstrndx)
    if '.text' not in sections:
        return {}

    _, text_va, text_foff, text_sz, _ = sections['.text']
    chunk = data[text_foff: text_foff + text_sz]

    # Collect function starts via prologue scan
    PROLOGUE_MASK = 0xFFC07FFF
    PROLOGUE_VAL  = 0xA9807BFD
    func_starts   = []
    for i in range(len(chunk) // 4):
        if (struct.unpack_from('<I', chunk, i * 4)[0] & PROLOGUE_MASK) == PROLOGUE_VAL:
            func_starts.append(text_va + i * 4)
        if len(func_starts) >= max_funcs:
            break

    # Restrict to functions reachable from source nodes when cg is available —
    # avoids scanning the entire binary for large binaries like gpsd.
    if cg:
        source_fns = cg.get('_source_fns', set())
        if source_fns:
            reachable = set()
            q = deque(source_fns)
            while q:
                va = q.popleft()
                if va in reachable:
                    continue
                reachable.add(va)
                node = cg.get(va)
                if node and 'callees' in node:
                    for t, _ in node['callees']:
                        if t not in reachable:
                            q.append(t)
            func_starts = [f for f in func_starts if f in reachable]

    results = {}

    for fs in func_starts:
        foff = _v2f(segments, fs)
        if foff is None:
            continue

        ldrb_count   = 0
        length_regs  = set()
        checked_regs = set()
        has_rev      = False
        rev_reg      = None
        rev_pos      = None
        has_and_7f   = False
        found        = None   # (pattern, score, evidence)

        for i in range(max_insns):
            off = foff + i * 4
            if off + 4 > len(data):
                break
            w  = struct.unpack_from('<I', data, off)[0]
            va = fs + i * 4

            if w == 0xD65F03C0:  # RET
                break

            # LDRB
            if (w >> 24) == 0x39 and ((w >> 22) & 3) == 1:
                length_regs.add(w & 0x1F)
                ldrb_count += 1

            # LDRH
            elif (w >> 24) == 0x79 and ((w >> 22) & 3) == 1:
                Rt = w & 0x1F
                length_regs.add(Rt)
                if ldrb_count > 0 and not found:
                    found = ('tlv', 2, f"LDRB(tag)+LDRH(len W{Rt})@{va:#x}")

            # REV / REV16 / REV32
            elif (w & 0xFFFFFC00) in (0x5AC00400, 0x5AC00800, 0x5AC00C00):
                Rd = w & 0x1F
                length_regs.add(Rd)
                if not has_rev:
                    has_rev, rev_reg, rev_pos = True, Rd, i

            # AND W_,W_,#0x7F  — ASN.1 class-byte masking
            # 32-bit AND immediate: top 9 bits = 000100100, imms=6 → mask 0x7F
            elif (w >> 23) == 0b000100100 and ((w >> 10) & 0xFFF) == 0x006:
                length_regs.add(w & 0x1F)
                has_and_7f = True

            # CMP on length register
            elif (w >> 24) in (0x71, 0x6B, 0xEB, 0xF1):
                Rn = (w >> 5) & 0x1F
                if Rn in length_regs:
                    checked_regs.add(Rn)
                    imm = (w >> 10) & 0xFFF
                    if imm in (0x80, 0x81, 0x82) and not found:
                        found = ('asn1', 2, f"CMP W{Rn},#{imm:#x}(long-form)@{va:#x}")

            # CBZ / CBNZ on a length register = counted SEQOF loop
            elif (w >> 25) in (0b0110100, 0b0110101):
                Rt = w & 0x1F
                if Rt in length_regs and Rt not in checked_regs:
                    if not found:
                        found = ('seqof', 2, f"CBZ/CBNZ W{Rt}(net-count)@{va:#x}")

            # BL — check if unchecked length is in argument position
            elif (w >> 26) == 0x25:
                unchecked_args = (length_regs & set(range(8))) - checked_regs
                if unchecked_args:
                    r = min(unchecked_args)
                    if has_rev and rev_pos is not None and rev_pos < 16:
                        score = 3 if found else 2
                        found = ('lpf', score,
                                 f"REV W{rev_reg}@+{rev_pos}+BL unc W{r}@{va:#x}")
                    elif found and found[0] == 'tlv':
                        found = ('tlv', 3, found[2] + f"+BL unc W{r}@{va:#x}")
                    elif has_and_7f and not found:
                        found = ('asn1', 3, f"AND#0x7F+BL unc W{r}@{va:#x}")

        if found:
            pattern, score, evidence = found
            if has_rev and ldrb_count >= 2 and score < 3:
                score = 3
            results[fs] = {'pattern': pattern, 'score': score, 'evidence': evidence}

    return results
