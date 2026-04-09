import subprocess

# Evidence keywords — used only for human-readable output hints,
# NOT for scoring. Keep broad but avoid obvious noise.
KEYWORDS = [
    # Paths
    "config", "path", "file", "/data/", "/system/", "/vendor/",
    # IPC / input
    "socket", "recv", "binder",
    # Execution
    "exec", "system", "cmd", "/bin/sh", "sh -c",
    # Parsing
    "parse", "json", "xml", "packet", "decode",
    # Memory ops
    "memcpy", "strcpy", "sprintf",
]


def extract_strings(path, min_length=6):
    """Run strings(1) with a minimum length filter to reduce noise."""
    try:
        result = subprocess.check_output(
            ["strings", "-n", str(min_length), path],
            text=True,
            errors="ignore",
        )
        return result.splitlines()
    except Exception:
        return []


def filter_keywords(strings_list):
    seen = set()
    hits = []
    for line in strings_list:
        if line in seen:
            continue
        ll = line.lower()
        for kw in KEYWORDS:
            if kw in ll:
                hits.append(line)
                seen.add(line)
                break
    return hits
