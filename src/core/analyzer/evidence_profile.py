"""
Evidence profile builder for vulnerability candidates.

This module does not rescore or promote candidates. It converts existing
candidate fields into a stable review schema so later SCA, reachability, and
validation-plan work can share the same vocabulary.
"""

SCHEMA_VERSION = "2026-06-07"

EVIDENCE_FIELDS = (
    "entrypoint",
    "input",
    "handler",
    "sink",
    "argument_control",
    "execution_timing",
    "auth_boundary",
    "sanitization",
)

FALSE_POSITIVE_REASON_LABELS = {
    "constant_sink_argument": "sink argument appears constant or internally derived",
    "sink_import_only": "sink is import-level evidence without a call-site chain",
    "cross_function_token_contamination": "source and sink tokens may come from unrelated functions",
    "literal_logging_sink_only": "sink-like string appears to be logging or diagnostics only",
    "bridge_api_unproven": "bridge/API path is present but dispatch is not proven",
    "bounded_or_truncated_copy": "copy path appears bounded or truncating",
    "key_gated_protocol_surface": "surface appears gated by protocol key or session material",
    "rpc_default_validator": "RPC default validation path likely handles the input",
    "double_quoted_no_subshell_exec": "shell expansion risk is reduced by quoting context",
    "input_to_sink_unproven": "input-to-sink coupling is not proven",
    "no_exact_input": "exact attacker-controlled input field is unknown",
}

MISSING_LINK_LABELS = {
    "auth_boundary_unknown": "auth boundary is unknown",
    "dispatch_unknown": "handler dispatch is not proven",
    "input_unknown": "attacker-controlled input is unknown",
    "sink_unknown": "concrete sink is unknown",
    "attacker_argument_unknown": "attacker-controlled sink argument is unknown",
    "same_request_unknown": "same-request versus deferred execution is unknown",
    "sanitization_unknown": "sanitization behavior is unknown",
    "too_many_unknowns": "three or more chain elements remain unconfirmed",
}


def _known(value):
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "unknown", "unconfirmed", "none"}
    return bool(value)


def _state_for_bool(value):
    return "confirmed" if value else "missing"


def _field_state(candidate, field):
    if field == "entrypoint":
        if candidate.get("web_exposed") or candidate.get("web_reachable"):
            return "confirmed"
        if candidate.get("endpoints"):
            return "partial"
        return "missing"

    if field == "input":
        if _known(candidate.get("confirmed_input")):
            return "confirmed"
        if candidate.get("input_type") or candidate.get("config_keys"):
            return "partial"
        return "missing"

    if field == "handler":
        if candidate.get("handler_symbols"):
            return "confirmed"
        if candidate.get("handler_surface") or candidate.get("endpoints"):
            return "partial"
        return "missing"

    if field == "sink":
        if _known(candidate.get("confirmed_sink")):
            return "confirmed"
        if candidate.get("all_sinks"):
            return "partial"
        return "missing"

    if field == "argument_control":
        value = str(candidate.get("attacker_controlled_argument") or "unknown").lower()
        if value == "confirmed":
            return "confirmed"
        if value == "likely":
            return "partial"
        return "missing"

    if field == "execution_timing":
        value = str(candidate.get("same_request") or "unknown").lower()
        if value in {"confirmed", "same-request"}:
            return "confirmed"
        if value == "deferred":
            return "partial"
        return "missing"

    if field == "auth_boundary":
        value = str(candidate.get("auth_boundary") or candidate.get("auth_bypass") or "unknown").lower()
        if value in {"pre-auth", "post-auth", "required", "confirmed", "bypassable"}:
            return "confirmed"
        return "missing"

    if field == "sanitization":
        value = str(candidate.get("sanitization") or "unknown").lower()
        if value in {"absent", "present", "bounded-or-truncating"}:
            return "confirmed"
        return "missing"

    return "missing"


def _evidence_refs(candidate):
    refs = []
    binary = candidate.get("binary_path")
    if binary:
        refs.append({"kind": "binary", "value": binary})
    endpoints = candidate.get("endpoints") or []
    for endpoint in endpoints[:5]:
        refs.append({"kind": "endpoint", "value": endpoint})
    for symbol in (candidate.get("handler_symbols") or [])[:5]:
        refs.append({"kind": "handler_symbol", "value": symbol})
    for sink in (candidate.get("all_sinks") or [])[:5]:
        refs.append({"kind": "sink", "value": sink})
    for key in (candidate.get("config_keys") or [])[:5]:
        refs.append({"kind": "config_key", "value": key})
    return refs


def _review_state(field_states, fp_risks):
    confirmed = sum(1 for state in field_states.values() if state == "confirmed")
    missing = sum(1 for state in field_states.values() if state == "missing")
    hard_fp = {
        "constant_sink_argument",
        "sink_import_only",
        "cross_function_token_contamination",
        "literal_logging_sink_only",
        "input_to_sink_unproven",
    }
    if hard_fp & set(fp_risks):
        return "reject-risk"
    if missing >= 3:
        return "needs-evidence"
    if confirmed >= 5 and missing <= 1:
        return "well-supported"
    return "reviewable"


def build_evidence_profile(candidate):
    """Return a stable evidence profile for a candidate dict."""
    field_states = {field: _field_state(candidate, field) for field in EVIDENCE_FIELDS}
    missing_links = list(candidate.get("missing_links") or [])
    false_positive_risks = list(candidate.get("false_positive_risks") or [])
    blockers = [
        {
            "kind": "missing_link",
            "code": code,
            "label": MISSING_LINK_LABELS.get(code, code.replace("_", " ")),
        }
        for code in missing_links
    ]
    blockers.extend(
        {
            "kind": "false_positive_risk",
            "code": code,
            "label": FALSE_POSITIVE_REASON_LABELS.get(code, code.replace("_", " ")),
        }
        for code in false_positive_risks
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "field_states": field_states,
        "review_state": _review_state(field_states, false_positive_risks),
        "evidence_refs": _evidence_refs(candidate),
        "blockers": blockers,
        "validation_targets": _validation_targets(candidate, field_states),
    }


def evidence_adjusted_score(candidate, raw_score=None):
    """Return a conservative ranking score without dropping the candidate."""
    if raw_score is None:
        raw_score = candidate.get("triage_score") or candidate.get("score") or 0
    try:
        raw_score = int(raw_score)
    except (TypeError, ValueError):
        raw_score = 0

    profile = candidate.get("evidence_profile") or build_evidence_profile(candidate)
    state = profile.get("review_state") or "unknown"
    field_states = profile.get("field_states") or {}
    missing = sum(1 for value in field_states.values() if value == "missing")

    if state == "well-supported":
        return raw_score
    if state == "reviewable":
        return max(0, int(round(raw_score * 0.85)))
    if state == "needs-evidence":
        adjusted = int(round(raw_score * 0.45))
        if missing >= 3:
            adjusted = min(adjusted, 39)
        return max(0, adjusted)
    if state == "reject-risk":
        return max(0, min(29, int(round(raw_score * 0.25))))
    return max(0, int(round(raw_score * 0.7)))


def _validation_targets(candidate, field_states):
    targets = []
    if field_states.get("handler") != "confirmed":
        endpoints = candidate.get("endpoints") or []
        if endpoints:
            targets.append({
                "goal": "confirm handler dispatch",
                "hints": endpoints[:3],
            })
    if field_states.get("argument_control") != "confirmed" and candidate.get("all_sinks"):
        targets.append({
            "goal": "trace attacker-controlled argument into sink",
            "hints": (candidate.get("all_sinks") or [])[:3],
        })
    if field_states.get("execution_timing") == "partial":
        targets.append({
            "goal": "confirm deferred activation path",
            "hints": (candidate.get("config_keys") or [])[:5],
        })
    if field_states.get("auth_boundary") != "confirmed":
        targets.append({
            "goal": "resolve auth boundary",
            "hints": (candidate.get("endpoints") or [])[:3],
        })
    return targets
