def score_sinks(sinks_by_tier):
    """
    Assign a numeric score based on sink tier and specific function.

    critical: command execution — highest severity
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
        else:
            score += 5  # /bin/sh, sh -c

    for s in sinks_by_tier.get("strong", []):
        l = s.lower()
        if "gets(" in l:
            score += 5
        elif "strcpy(" in l or "strcat(" in l:
            score += 4
        elif "sprintf(" in l or "vsprintf(" in l:
            score += 3
        else:
            score += 2

    for _ in sinks_by_tier.get("weak", []):
        score += 1

    return score


def calc_score(input_type, user, socket_perm, sink_score, flow_score):
    """
    Aggregate all scoring factors. Capped at 25 to prevent runaway scores
    from binaries with many sink hits.

    Factors:
      input_type   : socket +3, binder +2
      user         : root +4, system/radio/media +2, bt/wifi/nfc +1
      socket_perm  : world-accessible (666/777) +2
      sink_score   : from score_sinks()
      flow_score   : from analyze_dataflow()
    """
    score = 0

    if input_type == "socket":
        score += 3
    elif input_type == "binder":
        score += 2

    if user == "root":
        score += 4
    elif user in ["system", "radio", "media"]:
        score += 2
    elif user in ["bluetooth", "wifi", "nfc", "secure_element"]:
        score += 1

    if socket_perm and any(p in socket_perm for p in ["666", "777", "0666", "0777"]):
        score += 2

    score += sink_score
    score += flow_score

    return min(score, 25)
