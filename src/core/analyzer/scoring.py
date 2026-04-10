def score_sinks(sinks_by_tier):
    """
    Assign a numeric score based on sink tier and specific function.

    critical: command execution / dynamic loading — highest severity
    strong:   unchecked memory/string ops
    weak:     compiler-added checked variants; 1 pt each, only admitted
              after dataflow confirmation (see analyze_services in risk.py)
    """
    score = 0

    for s in sinks_by_tier.get("critical", []):
        l = s.lower()
        if "system(" in l or "popen(" in l:
            score += 8
        elif "exec" in l:
            score += 7
        elif "dlopen(" in l or "dlsym(" in l:
            score += 6   # dynamic loading = conditional code execution
        else:
            score += 5   # /bin/sh, sh -c

    for s in sinks_by_tier.get("strong", []):
        l = s.lower()
        if "gets(" in l:
            score += 5
        elif "strcpy(" in l or "strcat(" in l:
            score += 4
        elif "sprintf(" in l or "vsprintf(" in l:
            score += 3
        elif "printf(" in l:
            score += 2   # format string risk when arg is user-controlled
        else:
            score += 2

    for _ in sinks_by_tier.get("weak", []):
        score += 1

    return score


def calc_score(input_type, user, socket_perm, sink_score, flow_score,
               source="system", has_dlopen=False, is_parsing_heavy=False):
    """
    Aggregate all scoring factors into a single exploitability score.

    Base factors (preserved):
      input_type   : socket/netlink +3, binder +2, file +2
      user         : root +4, system/radio/media +2, bt/wifi/nfc +1
      socket_perm  : world-accessible (666/777) +2
      sink_score   : from score_sinks()
      flow_score   : from analyze_dataflow()

    New bonus factors:
      socket+root  : combo bonus +2  (externally reachable AND maximally privileged)
      vendor source: +2              (vendor services are less audited / hardened)
      has_dlopen   : +3              (dynamic loading widens the attack surface)
      parsing_heavy: +1              (more parsing code → more parser bugs)

    Cap raised to 35 to preserve ranking fidelity when multiple bonuses apply.
    """
    score = 0

    # ── Input type ────────────────────────────────────────────────────────────

    if input_type == "socket":
        score += 3
    elif input_type == "binder":
        score += 2
    elif input_type == "netlink":
        score += 3    # kernel netlink = privileged but reachable from unprivileged
    elif input_type == "file":
        score += 2

    # ── Privilege ─────────────────────────────────────────────────────────────

    if user == "root":
        score += 4
    elif user in ["system", "radio", "media"]:
        score += 2
    elif user in ["bluetooth", "wifi", "nfc", "secure_element"]:
        score += 1

    # ── Combo bonus: network-exposed AND maximally privileged ─────────────────

    if input_type in ("socket", "netlink") and user == "root":
        score += 2

    # ── World-accessible socket ───────────────────────────────────────────────

    if socket_perm and any(p in socket_perm for p in ["666", "777", "0666", "0777"]):
        score += 2

    # ── Vendor source: less audited, often missing compile-time hardening ─────

    if source == "vendor":
        score += 2

    # ── Dynamic loading: dlopen/dlsym widens the exploitable surface ──────────

    if has_dlopen:
        score += 3

    # ── Parsing-heavy binary: more code means more parser bugs ────────────────

    if is_parsing_heavy:
        score += 1

    # ── Sink and dataflow scores ──────────────────────────────────────────────

    score += sink_score
    score += flow_score

    return min(score, 35)   # Raised from 25 to preserve ranking at the top
