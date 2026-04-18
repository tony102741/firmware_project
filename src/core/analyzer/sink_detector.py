# Tiered sink classification:
#   critical — command execution, dynamic code loading
#   strong   — unchecked memory/string ops (no bounds check)
#   weak     — compiler-added checked variants (__chk), ubiquitous in Android;
#              only meaningful when dataflow confirms dangerous context

CRITICAL_SINKS = [
    # Command / shell execution
    "system(", "popen(", "execl(", "execv(", "execve(", "execvp(",
    "os.execute", "io.popen", "luci.sys.call", "luci.sys.exec", "nixio.exec",
    "/bin/sh", "sh -c",
    # Dynamic library loading — code execution if path is controllable
    "dlopen(", "dlsym(",
]

STRONG_SINKS = [
    # Unbounded string operations
    "strcpy(", "strcat(", "sprintf(", "vsprintf(",
    "gets(", "scanf(", "sscanf(",
    # Format string risk when argument is user-controlled
    "printf(",
]

WEAK_SINKS = [
    "__strcpy_chk", "__strcat_chk",
    "__memcpy_chk", "__memmove_chk",
    "memcpy(",
]


def classify_sink(line):
    l = line.lower()
    for k in CRITICAL_SINKS:
        if k in l:
            return "critical"
    for k in STRONG_SINKS:
        if k in l:
            return "strong"
    for k in WEAK_SINKS:
        if k in l:
            return "weak"
    return None


def detect_sinks(strings_list):
    """Return {"critical": [...], "strong": [...], "weak": [...]}"""
    results = {"critical": [], "strong": [], "weak": []}
    seen = set()

    for line in strings_list:
        s = line.strip()
        if not s or s in seen:
            continue
        tier = classify_sink(s)
        if tier:
            results[tier].append(s)
            seen.add(s)

    return results


def detect_sinks_from_imports(imports_dict):
    """
    Exact sink detection from ELF import table.

    Replaces string matching for the sink-detection stage: every name here
    is a real dynamic-linker symbol, not a substring of a log message.

    imports_dict: {sym_name: plt_va} from elf_analyzer.get_imports()
    Returns the same {"critical", "strong", "weak"} shape as detect_sinks().
    """
    from .elf_analyzer import SINK_IMPORTS
    results = {"critical": [], "strong": [], "weak": []}
    for sym_name in imports_dict:
        for tier, syms in SINK_IMPORTS.items():
            if sym_name in syms:
                results[tier].append(sym_name)
    return results


def is_valid_sink(s, tier):
    """
    Filter out common false-positive sink strings.

    Rules:
    - Reject C++ mangled symbols (_Z prefix, destructor patterns).
    - Reject long strings (> 100 chars) — typically log/debug messages.
    - Reject plain prose (spaces present but no parenthesis) unless it
      contains shell invocation patterns.
    - Weak sinks are handled separately via has_dangerous_memcpy_context
      in dataflow.py; always return False here to defer that decision.
    """
    l = s.lower()

    if len(l) > 100:
        return False

    # C++ mangled symbols
    if l.startswith("_zn") or l.startswith("_z") or "::~" in l:
        return False

    # Prose strings (spaces without call syntax) — not a sink reference
    if " " in l and "(" not in l:
        if not any(k in l for k in ["/bin/sh", "sh -c", "sh\""]):
            return False

    # Weak sinks evaluated in context separately — skip here
    if tier == "weak":
        return False

    return True
