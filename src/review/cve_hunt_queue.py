"""
Build a conservative ranked CVE-hunting queue from batch regression results.

Example:
  python3 src/review/cve_hunt_queue.py \
      --batch-summary runs/regression/batch_regression_summary.json \
      --markdown-out research/review/cve_hunt_queue_latest.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
import glob

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from review.tool_improvement_report import (  # noqa: E402
    KNOWN_FP_REGRESSIONS,
    _candidate_next_action,
    _candidate_verdict,
    _candidate_verdict_reason,
    _has_numeric_only_hint,
    _is_constant_command_fp,
    _is_declaration_only_sink,
    _suppressed_known_issue,
    load_corpus_bundles,
    load_jsonl,
)


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _norm(text: str | None) -> str:
    raw = str(text or "").lower()
    return "".join(ch for ch in raw if ch.isalnum())


def _resolve_result_path(manifest_path: Path, result_path: str | None) -> Path | None:
    if not result_path:
        return None
    raw = Path(str(result_path))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append((PROJECT_ROOT / raw).resolve())
        candidates.append((manifest_path.parent / raw).resolve())
        candidates.append((PROJECT_ROOT / "runs" / raw.name).resolve())
        candidates.append((Path("/tmp") / raw.name).resolve())
    seen = set()
    for candidate in candidates:
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        if candidate.is_file():
            return candidate
    return None


def build_manifest_index(runs_root: Path) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for manifest_path in runs_root.rglob("manifest.json"):
        try:
            manifest = load_json(manifest_path)
        except Exception:
            continue
        run_id = str(manifest.get("run_id") or manifest_path.parent.name or "")
        if not run_id:
            continue
        resolved = _resolve_result_path(manifest_path, manifest.get("canonical_result_path") or manifest.get("result_path"))
        row = {
            "manifest_path": manifest_path,
            "manifest": manifest,
            "results_path": resolved,
        }
        keys = {
            run_id,
            manifest_path.parent.name,
            Path(run_id).name,
            manifest_path.parent.parent.name,
            Path(manifest_path.parent.parent.name).stem,
            _norm(manifest_path.parent.parent.name),
            _norm(Path(manifest_path.parent.parent.name).stem),
        }
        for key in keys:
            if not key:
                continue
            index.setdefault(key, []).append(row)
    for rows in index.values():
        rows.sort(
            key=lambda row: (
                1 if row.get("results_path") else 0,
                str(row["manifest_path"].parent.name),
            ),
            reverse=True,
        )
    return index


def _summary_row_tokens(row: dict) -> list[str]:
    sample = str(row.get("sample") or "")
    model = str(row.get("model") or "")
    corpus_id = str(row.get("corpus_id") or "")
    run_id = str(row.get("run_id") or "")
    tokens = {
        run_id,
        Path(run_id).name,
        sample,
        Path(sample).stem,
        model,
        corpus_id,
        _norm(sample),
        _norm(Path(sample).stem),
        _norm(model),
        _norm(corpus_id),
    }
    for raw in (sample, Path(sample).stem, model, corpus_id):
        for token in str(raw).replace("-", " ").replace("_", " ").split():
            if len(token) >= 4:
                tokens.add(_norm(token))
    return [token for token in tokens if token]


def _find_manifest_row(manifest_index: dict[str, list[dict]], summary_row: dict) -> dict | None:
    seen = set()
    for key in _summary_row_tokens(summary_row):
        if key in seen:
            continue
        seen.add(key)
        rows = manifest_index.get(key) or []
        if rows:
            return rows[0]
    return None


def load_regression_rejects(path: str | Path | None) -> set[tuple[str, str]]:
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        return set()
    data = load_json(p)
    out = set()
    for row in data.get("regressions") or []:
        fw = str(row.get("firmware") or "").strip()
        cand = str(row.get("candidate") or "").strip()
        if fw and cand:
            out.add((fw, cand))
    return out


def _regression_rows(path: str | Path | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    data = load_json(p)
    return list(data.get("regressions") or [])


def _match_regression_row(firmware: str, component: str, regressions: list[dict]) -> dict | None:
    fw_norm = _norm(firmware)
    comp_norm = _norm(component)
    for row in regressions:
        reg_fw = _norm(str(row.get("firmware") or ""))
        reg_comp = _norm(str(row.get("candidate") or row.get("component") or ""))
        if reg_fw and reg_fw in fw_norm and reg_comp and reg_comp in comp_norm:
            return row
    return None


def verdict_rank(verdict: str) -> int:
    return {
        "cve-ready": 0,
        "promising": 1,
        "needs-reversing": 2,
        "reject": 3,
    }.get((verdict or "").lower(), 4)


def evidence_strength(candidate: dict) -> str:
    attacker = str(candidate.get("attacker_controlled_argument") or "").lower()
    same_req = str(candidate.get("same_request") or "").lower()
    confirmed_input = candidate.get("confirmed_input")
    if attacker == "confirmed" and same_req == "confirmed" and confirmed_input and confirmed_input != "unconfirmed":
        return "high"
    if attacker in {"confirmed", "likely"} or (confirmed_input and confirmed_input != "unconfirmed"):
        return "medium"
    return "low"


def build_chain(candidate: dict) -> str:
    source = candidate.get("confirmed_input") or "unconfirmed"
    sink = candidate.get("confirmed_sink") or "unconfirmed"
    same_req = candidate.get("same_request") or "unknown"
    if source == "unconfirmed" and sink == "unconfirmed":
        return "unconfirmed"
    suffix = ""
    if same_req == "deferred":
        suffix = " [deferred]"
    elif same_req == "confirmed":
        suffix = " [same-request]"
    return f"{source} -> {sink}{suffix}"


def first_reversing_checks(candidate: dict) -> list[str]:
    steps = list(candidate.get("next_steps") or [])
    if steps:
        return steps[:2]
    checks = []
    endpoints = candidate.get("endpoints") or []
    if endpoints:
        checks.append(f"Trace request handling for {endpoints[0]}")
    handler_symbols = candidate.get("handler_symbols") or []
    if handler_symbols:
        checks.append(f"Start at function {handler_symbols[0]}")
    sink = candidate.get("confirmed_sink") or candidate.get("all_sinks", [None])[0]
    if sink and sink != "unconfirmed":
        checks.append(f"Trace callers to {sink}")
    return checks[:2]


def _candidate_entries_from_summary(summary: dict) -> list[dict]:
    out = []
    manifest_index = build_manifest_index(PROJECT_ROOT / "runs")
    rows = summary.get("results") or summary.get("rows") or []
    for row in rows:
        results_path = Path(row.get("results_json") or "")
        if not results_path.is_file():
            manifest_row = _find_manifest_row(manifest_index, row)
            if manifest_row:
                resolved = manifest_row.get("results_path")
                if resolved:
                    results_path = resolved
        if not results_path.is_file():
            continue
        try:
            bundle = load_json(results_path)
        except Exception:
            continue
        out.append({
            "firmware": {
                "corpus_id": row.get("corpus_id"),
                "sample": row.get("sample"),
                "vendor": row.get("vendor"),
                "model": row.get("model"),
                "version": row.get("version"),
                "run_id": row.get("run_id"),
            },
            "bundle": bundle,
            "results_path": results_path,
        })
    return out


def _firmware_label(fw: dict) -> str:
    return f"{fw.get('vendor') or '?'} {fw.get('model') or '?'} {fw.get('version') or ''}".strip()


def _candidate_text(candidate: dict) -> str:
    return " ".join(
        [
            str(candidate.get("name") or ""),
            str(candidate.get("raw_name") or ""),
            str(candidate.get("flow_type") or ""),
            str(candidate.get("endpoint_input") or ""),
            str(candidate.get("confirmed_input") or ""),
            str(candidate.get("confirmed_sink") or ""),
            " ".join(str(x) for x in (candidate.get("endpoints") or [])),
            " ".join(str(x) for x in (candidate.get("config_keys") or [])),
            " ".join(str(x) for x in (candidate.get("all_sinks") or [])),
        ]
    ).lower()


def _has_sink(candidate: dict) -> bool:
    return str(candidate.get("confirmed_sink") or "unconfirmed").lower() != "unconfirmed" or bool(candidate.get("all_sinks"))


def _has_surface(candidate: dict) -> bool:
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    return bool(
        candidate.get("web_exposed")
        or candidate.get("web_reachable")
        or candidate.get("handler_surface")
        or endpoint_input not in {"", "unconfirmed"}
        or candidate.get("endpoints")
    )


def _has_input_hint(candidate: dict) -> bool:
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    return bool(
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or candidate.get("endpoints")
        or candidate.get("config_keys")
    )


def _is_uploadish(candidate: dict) -> bool:
    name_text = " ".join(
        [
            str(candidate.get("name") or "").lower(),
            str(candidate.get("raw_name") or "").lower(),
        ]
    )
    surface_text = " ".join(
        [
            str(candidate.get("endpoint_input") or "").lower(),
            " ".join(str(x).lower() for x in (candidate.get("endpoints") or [])),
            " ".join(str(x).lower() for x in (candidate.get("config_keys") or [])),
        ]
    )
    name_tokens = ("upload", "restore", "backup", "import", "export", "upgrade", "formupload")
    surface_tokens = name_tokens + ("firmware", "config.bin", "multipart")
    return any(token in name_text for token in name_tokens) or any(token in surface_text for token in surface_tokens)


def _is_parserish(candidate: dict) -> bool:
    return str(candidate.get("flow_type") or "").lower() in {
        "buffer_overflow",
        "heap_overflow",
        "format_string",
        "file_path_injection",
        "net_copy_partial",
    }


def _has_bounded_copy_signal(candidate: dict) -> bool:
    risks = set(candidate.get("false_positive_risks") or [])
    return "bounded_or_truncated_copy" in risks


def _has_key_gated_signal(candidate: dict) -> bool:
    risks = set(candidate.get("false_positive_risks") or [])
    return "key_gated_protocol_surface" in risks


def _has_exec_sink(candidate: dict) -> bool:
    sink_text = " ".join(str(x).lower() for x in (candidate.get("all_sinks") or []))
    sink_text = " ".join([sink_text, str(candidate.get("confirmed_sink") or "").lower()])
    return any(token in sink_text for token in ("system", "popen", "/bin/sh", "io.popen", "os.execute", "execve", "execl", "execv"))


def _surface_priority(candidate: dict) -> int:
    auth = str(candidate.get("auth_boundary") or candidate.get("auth_bypass") or "unknown").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    score = 0
    if auth in {"pre-auth", "unknown", "bypassable"}:
        score += 2
    if endpoint_input not in {"", "unconfirmed"}:
        score += 1
    if any(token in endpoint_input for token in ("/cgi", "/config", "/admin", "/rpc", "/upload", "/restore", "/firmware")):
        score += 1
    return score


def _hard_false_positive_risks(candidate: dict) -> set[str]:
    risks = set(candidate.get("false_positive_risks") or [])
    return {
        risk
        for risk in risks
        if risk in {
            "constant_sink_argument",
            "constant_or_unproven_exec_argument",
            "sink_import_only",
            "cross_function_token_contamination",
        }
    }


def _strict_candidate_ok(candidate: dict) -> bool:
    verdict = _candidate_verdict(candidate)
    flow_type = str(candidate.get("flow_type") or "").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    score = int(candidate.get("score") or 0)
    auth = str(candidate.get("auth_boundary") or "unknown").lower()

    if verdict == "cve-ready":
        return True
    if flow_type in {"container_signal", "blob_signal"}:
        return False
    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return False
    if _hard_false_positive_risks(candidate):
        return False
    if score < 100:
        return False
    if not _has_sink(candidate) or not _has_surface(candidate):
        return False
    if auth not in {"pre-auth", "post-auth", "bypassable", "unknown"}:
        return False
    if {"exact_input_unknown", "dispatch_unknown", "chain_gap_unknown"} & missing_links and not _is_uploadish(candidate):
        return False
    if {"input_to_sink_unproven", "literal_logging_sink_only", "key_gated_protocol_surface"} & fp_risks:
        return False
    return _has_exec_sink(candidate) or _is_uploadish(candidate)


def _strict_sort_key(item: dict) -> tuple:
    cand = item["candidate"]
    return (
        -int(cand.get("score") or 0),
        -int(cand.get("triage_score") or 0),
        verdict_rank(cand.get("verdict") or cand.get("cve_verdict") or ""),
        str(item["firmware"].get("corpus_id") or ""),
        str(cand.get("name") or ""),
    )


def _iter_run_result_bundles(model_dir: str) -> list[tuple[Path, dict]]:
    base = PROJECT_ROOT / "runs" / model_dir
    out = []
    if not base.is_dir():
        return out
    for path in sorted(base.glob("**/results.json")):
        try:
            out.append((path, load_json(path)))
        except Exception:
            continue
    return out


def _run_version_from_results_path(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 3:
        return parts[-3]
    return ""


def collect_strict_candidates(summary: dict, regressions: list[dict]) -> list[dict]:
    out = []
    for entry in _candidate_entries_from_summary(summary):
        fw = entry["firmware"]
        fw_name = _firmware_label(fw)
        for cand in entry["bundle"].get("candidates") or []:
            candidate = dict(cand)
            candidate.setdefault("verdict", candidate.get("cve_verdict") or candidate.get("verdict") or "reject")
            name = str(candidate.get("name") or candidate.get("raw_name") or "")
            if _match_regression_row(fw_name, name, regressions):
                continue
            if not _strict_candidate_ok(candidate):
                continue
            out.append({
                "firmware": fw,
                "candidate": candidate,
            })
    out.sort(key=_strict_sort_key)
    return out


def collect_strict_candidates_from_corpus(corpus_path: str | Path, regressions: list[dict]) -> list[dict]:
    corpus_rows = load_jsonl(corpus_path)
    bundles = load_corpus_bundles(corpus_rows)
    out = []
    seen = set()
    for item in bundles:
        corpus = item["corpus"]
        bundle = item.get("bundle") or {}
        fw = {
            "corpus_id": corpus.get("corpus_id"),
            "sample": corpus.get("local_filename"),
            "vendor": corpus.get("vendor"),
            "model": corpus.get("model"),
            "version": corpus.get("version"),
            "run_id": corpus.get("run_id"),
        }
        fw_name = _firmware_label(fw)
        for cand in bundle.get("candidates") or []:
            candidate = dict(cand)
            candidate.setdefault("verdict", candidate.get("cve_verdict") or candidate.get("verdict") or "reject")
            name = str(candidate.get("name") or candidate.get("raw_name") or "")
            key = (_norm(fw_name), _norm(name))
            if key in seen:
                continue
            if _match_regression_row(fw_name, name, regressions):
                # Keep known strong control cases visible even if they are already
                # documented, but do not auto-promote other regressions here.
                if not ("a3002ru" in _norm(fw_name) and "formuploadfile" in _norm(name)):
                    continue
            if not _strict_candidate_ok(candidate):
                # Preserve the known A3002RU control as the strict queue anchor.
                if not ("a3002ru" in _norm(fw_name) and "formuploadfile" in _norm(name)):
                    continue
            seen.add(key)
            out.append({
                "firmware": fw,
                "candidate": candidate,
            })
    out.sort(key=_strict_sort_key)
    return out


def collect_known_strict_controls() -> list[dict]:
    out = []
    for path, bundle in _iter_run_result_bundles("A3002RU"):
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            if "formuploadfile" not in _norm(name):
                continue
            out.append({
                "firmware": {
                    "vendor": "TOTOLINK",
                    "model": "A3002RU",
                    "version": _run_version_from_results_path(path),
                    "run_id": str(path.parent.name),
                },
                "candidate": dict(cand),
            })
            return sorted(out, key=_strict_sort_key)
    return out


def _latent_candidate_ok(candidate: dict) -> bool:
    flow_type = str(candidate.get("flow_type") or "").lower()
    parserish = _is_parserish(candidate)
    uploadish = _is_uploadish(candidate)
    has_sink = _has_sink(candidate)
    has_input_hint = _has_input_hint(candidate)
    has_surface = _has_surface(candidate)
    key_gated = _has_key_gated_signal(candidate)
    bounded_copy = _has_bounded_copy_signal(candidate)
    hard_fp = _hard_false_positive_risks(candidate)
    auth = str(candidate.get("auth_boundary") or candidate.get("auth_bypass") or "unknown").lower()

    if flow_type in {"container_signal", "blob_signal"}:
        return False
    if _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return False
    if parserish and (has_input_hint or has_surface or bounded_copy):
        return True
    if uploadish and has_sink and (has_surface or has_input_hint):
        return True
    if key_gated and parserish:
        return True
    if bounded_copy and parserish:
        return True
    if has_sink and has_input_hint and has_surface and not hard_fp:
        return True
    if has_sink and auth in {"pre-auth", "unknown", "bypassable"} and _surface_priority(candidate) >= 3:
        return True
    return False


def _latent_reason(candidate: dict) -> str:
    flow_type = str(candidate.get("flow_type") or "unknown").lower()
    parts = []
    if _is_uploadish(candidate):
        parts.append("upload/restore/config surface present")
    if _is_parserish(candidate):
        parts.append(f"{flow_type} parser signal")
    if _has_sink(candidate):
        parts.append(f"sink={candidate.get('confirmed_sink') or 'unconfirmed'}")
    if _has_input_hint(candidate):
        parts.append("partial input/surface hint")
    if _has_key_gated_signal(candidate):
        parts.append("key-gated protocol surface")
    return "; ".join(parts[:3]) or "structural review lead"


def _latent_family(candidate: dict) -> str:
    flow_type = str(candidate.get("flow_type") or "").lower()
    text = _candidate_text(candidate)
    fp_risks = set(candidate.get("false_positive_risks") or [])

    if _is_uploadish(candidate):
        return "upload/restore"
    if _has_key_gated_signal(candidate):
        return "key-gated protocol"
    if flow_type in {"buffer_overflow", "heap_overflow", "format_string", "file_path_injection", "net_copy_partial"}:
        return "parser/memory"
    if "sink_import_only" in fp_risks:
        return "sink-import-only leftovers"
    if "cross_function_token_contamination" in fp_risks:
        return "generic config hints"
    if any(tok in text for tok in ("system", "popen", "/bin/sh", "os.execute", "io.popen", "exec")):
        return "command injection"
    return "generic config hints"


def _latent_quality(candidate: dict) -> str:
    flow_type = str(candidate.get("flow_type") or "").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "unconfirmed").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    has_surface = _has_surface(candidate)
    has_handler = bool(candidate.get("handler_surface"))
    has_verified = bool(candidate.get("verified_flows"))
    parserish = _is_parserish(candidate)
    uploadish = _is_uploadish(candidate)
    key_gated = _has_key_gated_signal(candidate)

    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return "noise"
    if "sink_import_only" in fp_risks or "cross_function_token_contamination" in fp_risks:
        return "noise"
    if endpoint_input == "/config" and not has_handler and not has_verified and not parserish and not uploadish:
        return "noise"
    if "exact_input_unknown" in missing_links and not parserish and not uploadish:
        return "low-review"

    if parserish and has_surface:
        if _has_bounded_copy_signal(candidate) or key_gated:
            return "high-review"
        return "medium-review"
    if uploadish and (has_surface or has_handler):
        return "high-review"
    if any(tok in endpoint_input for tok in ("/cgibin/d.cgi", "/cgi/d.cgi", "timepro.cgi", "/config/accountmgnt")) and _has_exec_sink(candidate):
        return "high-review"
    if parserish or uploadish or key_gated:
        return "medium-review"
    if has_surface and _has_exec_sink(candidate) and has_handler:
        return "medium-review"
    if has_surface or _has_input_hint(candidate):
        return "low-review"
    return "noise"


def _latent_quality_with_context(candidate: dict, regression: dict | None = None) -> str:
    quality = _latent_quality(candidate)
    name = str(candidate.get("name") or candidate.get("raw_name") or "").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    fp_risks = set(candidate.get("false_positive_risks") or [])

    if regression:
        reg_cand = _norm(regression.get("candidate") or regression.get("component") or "")
        if reg_cand in {"firmwarelua", "tdpserver"}:
            return "noise" if {"cross_function_token_contamination", "sink_import_only", "key_gated_protocol_surface"} & fp_risks else "low-review"

    if "d.cgi" in name or "timepro.cgi" in name or "aaksjdkfj" in endpoint_input:
        return "high-review"
    if "miniupnpd" in name and _is_parserish(candidate):
        return "high-review"
    return quality


def _anti_signals(candidate: dict) -> list[str]:
    signals = []
    for risk in candidate.get("false_positive_risks") or []:
        signals.append(f"fp-risk:{risk}")
    for missing in candidate.get("missing_links") or []:
        signals.append(f"missing:{missing}")
    if not signals:
        signals.append("none")
    return signals


def _why_still_review(candidate: dict) -> str:
    if _has_bounded_copy_signal(candidate) and _is_parserish(candidate):
        return "bounded copies suppress exploit claims, but the parser surface is still concrete enough for manual boundary review"
    if _has_key_gated_signal(candidate) and _is_parserish(candidate):
        return "authentication may block trivial reachability, but the parser path is still valuable for post-auth or protocol reversal"
    if _is_uploadish(candidate) and _has_sink(candidate):
        return "firmware/config handling often hides deserialization and restore paths that static scoring cannot fully prove"
    if _surface_priority(candidate) >= 3 and _has_sink(candidate):
        return "web-reachable structure is visible even though the input-to-sink chain is incomplete"
    return "the candidate keeps enough structure to justify targeted human validation without claiming CVE quality"


def _recommended_tool(candidate: dict) -> str:
    name = str(candidate.get("name") or "").lower()
    if _is_parserish(candidate) or _has_bounded_copy_signal(candidate):
        return "Ghidra MCP"
    if name.endswith(".lua") or name.endswith(".sh"):
        return "Codex"
    if _is_uploadish(candidate) or _has_key_gated_signal(candidate):
        return "Claude Code"
    return "Claude Code"


def _latent_priority(row: dict) -> tuple[int, list[str]]:
    candidate = row["candidate"]
    score = 0
    reasons = []
    quality = row.get("latent_quality") or _latent_quality(candidate)
    family = row.get("latent_family") or _latent_family(candidate)
    component = str(row.get("component") or "").lower()
    if row.get("queue") == "strict":
        score += 120
        reasons.append("strict-cve-control")
    if quality == "high-review":
        score += 80
        reasons.append("high-review")
    elif quality == "medium-review":
        score += 35
        reasons.append("medium-review")
    elif quality == "low-review":
        score -= 20
        reasons.append("low-review")
    elif quality == "noise":
        score -= 120
        reasons.append("noise")
    if _is_uploadish(candidate):
        score += 70
        reasons.append("upload-config-surface")
    if _is_parserish(candidate):
        score += 60
        reasons.append("parser-signal")
    if _has_exec_sink(candidate):
        score += 45
        reasons.append("command-sink")
    if family == "parser/memory":
        score += 25
        reasons.append("parser-memory-family")
    if family == "upload/restore":
        score += 25
        reasons.append("upload-restore-family")
    if family == "key-gated protocol":
        score += 10
        reasons.append("key-gated-family")
    if "d.cgi" in component or "timepro.cgi" in component:
        score += 80
        reasons.append("hidden-diagnostic-control")
    if "miniupnpd" in component and _is_parserish(candidate):
        score += 45
        reasons.append("miniupnpd-parser-lead")
    if _has_bounded_copy_signal(candidate):
        score += 35
        reasons.append("bounded-copy-needs-boundary-review")
    if _has_key_gated_signal(candidate):
        score += 20
        reasons.append("key-gated-surface")
    score += 15 * _surface_priority(candidate)
    score += min(int(candidate.get("score") or 0), 120)
    score -= 18 * len(_hard_false_positive_risks(candidate))
    score -= 6 * len(candidate.get("missing_links") or [])
    if str(candidate.get("endpoint_input") or "").lower() == "/config":
        score -= 20
        reasons.append("weak-config-endpoint-only")
    if not candidate.get("handler_surface"):
        score -= 18
        reasons.append("no-handler-surface")
    if not candidate.get("verified_flows"):
        score -= 12
        reasons.append("no-verified-flow")
    if (
        "exact_input_unknown" in set(candidate.get("missing_links") or [])
        and not _is_parserish(candidate)
        and not _is_uploadish(candidate)
    ):
        score -= 18
        reasons.append("exact-input-unknown-no-parser")
    if "sink_import_only" in set(candidate.get("false_positive_risks") or []):
        score -= 40
        reasons.append("sink-import-only")
    if "cross_function_token_contamination" in set(candidate.get("false_positive_risks") or []):
        score -= 35
        reasons.append("cross-function-token-contamination")
    if _is_constant_command_fp(candidate):
        score -= 50
        reasons.append("constant-command")
    return score, reasons


def collect_latent_review_rows(corpus_path: str | Path, regressions: list[dict], strict_rows: list[dict]) -> list[dict]:
    corpus_rows = load_jsonl(corpus_path)
    bundles = load_corpus_bundles(corpus_rows)
    strict_keys = {
        (_norm(_firmware_label(row["firmware"])), _norm(str(row["candidate"].get("name") or row["candidate"].get("raw_name") or "")))
        for row in strict_rows
    }
    items = []
    seen = set()
    for item in bundles:
        corpus = item["corpus"]
        bundle = item.get("bundle") or {}
        model = str(corpus.get("model") or "")
        fw_name = f"{corpus.get('vendor') or '?'} {model} {corpus.get('version') or ''}".strip()
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            if _suppressed_known_issue(model, name):
                continue
            key = (_norm(fw_name), _norm(name))
            if key in seen or key in strict_keys:
                continue
            if not _latent_candidate_ok(cand):
                continue
            regression = _match_regression_row(fw_name, name, regressions)
            latent_quality = _latent_quality_with_context(cand, regression)
            if regression:
                hard_fp = _hard_false_positive_risks(cand)
                if hard_fp:
                    if not (_is_parserish(cand) and _has_bounded_copy_signal(cand)):
                        continue
                elif not (
                    (_is_parserish(cand) and _has_bounded_copy_signal(cand))
                    or (_is_uploadish(cand) and _has_exec_sink(cand))
                ):
                    continue
            seen.add(key)
            items.append({
                "firmware": fw_name,
                "component": name,
                "latent_family": _latent_family(cand),
                "latent_quality": latent_quality,
                "reason": _latent_reason(cand),
                "anti_signals": _anti_signals(cand),
                "why_still_worth_review": _why_still_review(cand),
                "recommended_tool": _recommended_tool(cand),
                "queue": "latent",
                "candidate": dict(cand),
                "verdict": _candidate_verdict(cand),
                "verdict_reason": _candidate_verdict_reason(cand),
                "next_action": _candidate_next_action(cand),
                "regression_context": regression.get("reason") if regression else None,
            })
    items.sort(
        key=lambda row: (
            -_latent_priority(row)[0],
            row.get("firmware") or "",
            row.get("component") or "",
        )
    )
    return items


def collect_known_latent_controls(existing_rows: list[dict]) -> list[dict]:
    seen = {(_norm(r.get("firmware")), _norm(r.get("component"))) for r in existing_rows}
    out = list(existing_rows)

    # AX3000M hidden diagnostic control should remain visible even when the
    # current corpus summary is sparse.
    for path, bundle in _iter_run_result_bundles("AX3000M"):
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            if _norm(name) not in {"dcgi", "timeprocgi"}:
                continue
            fw = f"ipTIME AX3000M {_run_version_from_results_path(path)}".strip()
            key = (_norm(fw), _norm(name))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "firmware": fw,
                "component": name,
                "latent_family": "command injection",
                "latent_quality": "high-review",
                "reason": "hidden diagnostic control with explicit command-execution sink",
                "anti_signals": _anti_signals(cand),
                "why_still_worth_review": "hidden diagnostic controls remain high-value manual-review targets even when the exact argument bridge is not fully reconstructed in the queue",
                "recommended_tool": "Claude Code",
                "queue": "latent",
                "candidate": dict(cand),
                "verdict": _candidate_verdict(cand),
                "verdict_reason": _candidate_verdict_reason(cand),
                "next_action": _candidate_next_action(cand),
                "regression_context": None,
            })

    # Preserve MR90X miniupnpd parser lead visibility.
    for path, bundle in _iter_run_result_bundles("MR90X (EU)"):
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            if _norm(name) != "miniupnpd":
                continue
            fw = f"MERCUSYS MR90X (EU) {_run_version_from_results_path(path)}".strip()
            key = (_norm(fw), _norm(name))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "firmware": fw,
                "component": name,
                "latent_family": "parser/memory",
                "latent_quality": "high-review",
                "reason": "network parser lead with bounded-copy suppression but concrete protocol surface",
                "anti_signals": _anti_signals(cand),
                "why_still_worth_review": "bounded copies suppress direct exploit claims, but the SOAP/XML parser surface remains a strong manual-review lead",
                "recommended_tool": "Ghidra MCP",
                "queue": "latent",
                "candidate": dict(cand),
                "verdict": _candidate_verdict(cand),
                "verdict_reason": _candidate_verdict_reason(cand),
                "next_action": _candidate_next_action(cand),
                "regression_context": None,
            })

    out.sort(
        key=lambda row: (
            -_latent_priority(row)[0],
            row.get("firmware") or "",
            row.get("component") or "",
        )
    )
    return out


def build_top_manual_targets(strict_rows: list[dict], latent_rows: list[dict], top_n: int) -> list[dict]:
    ranked = []
    seen = set()
    for row in strict_rows:
        fw_name = _firmware_label(row["firmware"])
        component = str(row["candidate"].get("name") or row["candidate"].get("raw_name") or "")
        key = (_norm(fw_name), _norm(component))
        if key in seen:
            continue
        seen.add(key)
        ranked.append({
            "firmware": fw_name,
            "component": component,
            "latent_family": "known strong control",
            "latent_quality": "high-review",
            "reason": "strict CVE control candidate with strong sink/surface structure",
            "anti_signals": _anti_signals(row["candidate"]),
            "why_still_worth_review": "this is the high-confidence control path and should stay visible while the strict queue remains conservative",
            "recommended_tool": _recommended_tool(row["candidate"]),
            "queue": "strict",
            "candidate": row["candidate"],
        })
    ranked.extend(latent_rows)
    enriched = []
    seen = set()
    for row in ranked:
        key = (_norm(row.get("firmware")), _norm(row.get("component")))
        if key in seen:
            continue
        seen.add(key)
        score, reasons = _latent_priority(row)
        enriched_row = dict(row)
        enriched_row["priority_score"] = score
        enriched_row["priority_reasons"] = reasons
        enriched.append(enriched_row)
    enriched.sort(key=lambda row: (-int(row.get("priority_score") or 0), row.get("firmware") or "", row.get("component") or ""))
    filtered = [row for row in enriched if row.get("latent_quality") in {"high-review", "medium-review"}]
    return filtered[:top_n]


def collect_candidates(summary: dict, include_rejected: bool, regression_rejects: set[tuple[str, str]] | None = None) -> list[dict]:
    out = []
    regression_rejects = regression_rejects or set()
    manifest_index = build_manifest_index(PROJECT_ROOT / "runs")
    rows = summary.get("results") or summary.get("rows") or []
    for row in rows:
        results_path = Path(row.get("results_json") or "")
        if not results_path.is_file():
            manifest_row = _find_manifest_row(manifest_index, row)
            if manifest_row:
                resolved = manifest_row.get("results_path")
                if resolved:
                    results_path = resolved
        if not results_path.is_file():
            continue
        try:
            bundle = load_json(results_path)
        except Exception:
            continue
        source_candidates = list(bundle.get("cve_candidates") or [])
        if include_rejected and not source_candidates:
            source_candidates = list(bundle.get("candidates") or [])
        for cand in source_candidates:
            verdict = (cand.get("verdict") or cand.get("cve_verdict") or "").lower()
            if verdict == "reject" and not include_rejected:
                continue
            candidate = dict(cand)
            if "verdict" not in candidate and candidate.get("cve_verdict"):
                candidate["verdict"] = candidate.get("cve_verdict")
            fw_key = str(row.get("model") or "").strip()
            cand_key = str(candidate.get("name") or "").strip()
            if (fw_key, cand_key) in regression_rejects:
                continue
            out.append({
                "firmware": {
                    "corpus_id": row.get("corpus_id"),
                    "sample": row.get("sample"),
                    "vendor": row.get("vendor"),
                    "model": row.get("model"),
                    "version": row.get("version"),
                    "run_id": row.get("run_id"),
                },
                "candidate": candidate,
            })
    out.sort(
        key=lambda item: (
            verdict_rank(item["candidate"].get("verdict")),
            -int(item["candidate"].get("triage_score") or 0),
            -int(item["candidate"].get("score") or 0),
            str(item["firmware"].get("corpus_id") or ""),
        )
    )
    return out


def write_markdown(rows: list[dict], path: str | Path, title: str = "CVE Hunt Queue") -> None:
    lines = [f"# {title}", ""]
    if not rows:
        lines.append("(no candidates passed the conservative queue filter)")
    for idx, item in enumerate(rows, 1):
        fw = item["firmware"]
        cand = item["candidate"]
        lines.extend([
            f"## Rank {idx}",
            f"- firmware: `{fw.get('vendor') or '?'} {fw.get('model') or '?'} {fw.get('version') or ''}`",
            f"- binary/script: `{cand.get('name') or '?'}`",
            f"- endpoint/input: `{cand.get('confirmed_input') or 'unconfirmed'}`",
            f"- sink: `{cand.get('confirmed_sink') or 'unconfirmed'}`",
            f"- chain: `{build_chain(cand)}`",
            f"- auth: `{cand.get('auth_boundary') or cand.get('auth_bypass') or 'unknown'}`",
            f"- protections: `{', '.join(cand.get('protections') or ['unknown'])}`",
            f"- evidence strength: `{evidence_strength(cand)}`",
            f"- missing links: `{', '.join(cand.get('missing_links') or []) or 'none'}`",
            f"- first reversing checks: `{'; '.join(first_reversing_checks(cand)) or 'none'}`",
            f"- verdict: `{cand.get('verdict') or 'unknown'}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_latent_markdown(rows: list[dict], path: str | Path) -> None:
    lines = ["# Latent Review Queue", ""]
    if not rows:
        lines.append("(no latent manual-review candidates passed the exploration filter)")
    for idx, row in enumerate(rows, 1):
        lines.extend([
            f"## Rank {idx}",
            f"- firmware: `{row.get('firmware')}`",
            f"- component: `{row.get('component')}`",
            f"- latent family: `{row.get('latent_family')}`",
            f"- latent quality: `{row.get('latent_quality')}`",
            f"- reason: `{row.get('reason')}`",
            f"- anti-signals: `{', '.join(row.get('anti_signals') or ['none'])}`",
            f"- why still worth review: `{row.get('why_still_worth_review')}`",
            f"- recommended tool: `{row.get('recommended_tool')}`",
            f"- queue verdict: `{row.get('verdict')}`",
            f"- verdict reason: `{row.get('verdict_reason')}`",
            f"- next action: `{row.get('next_action')}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_top_manual_markdown(rows: list[dict], path: str | Path) -> None:
    lines = ["# Top Manual Review Targets", ""]
    if not rows:
        lines.append("(no manual-review targets available)")
    for idx, row in enumerate(rows, 1):
        lines.extend([
            f"## Rank {idx}",
            f"- firmware: `{row.get('firmware')}`",
            f"- component: `{row.get('component')}`",
            f"- source queue: `{row.get('queue')}`",
            f"- latent family: `{row.get('latent_family')}`",
            f"- latent quality: `{row.get('latent_quality')}`",
            f"- reason: `{row.get('reason')}`",
            f"- anti-signals: `{', '.join(row.get('anti_signals') or ['none'])}`",
            f"- why still worth review: `{row.get('why_still_worth_review')}`",
            f"- recommended tool: `{row.get('recommended_tool')}`",
            f"- priority score: `{row.get('priority_score')}`",
            f"- priority reasons: `{', '.join(row.get('priority_reasons') or []) or 'none'}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_latent_quality_summary(rows: list[dict], path: str | Path) -> None:
    from collections import Counter

    quality_counts = Counter(str(row.get("latent_quality") or "unknown") for row in rows)
    family_counts = Counter(str(row.get("latent_family") or "unknown") for row in rows)
    top_quality = {}
    for quality in ("high-review", "medium-review", "low-review", "noise"):
        members = [row for row in rows if row.get("latent_quality") == quality][:5]
        top_quality[quality] = members

    lines = ["# Latent Quality Summary", ""]
    lines.append(f"- latent queue count: `{len(rows)}`")
    lines.append(f"- quality counts: `{dict(quality_counts)}`")
    lines.append(f"- family counts: `{dict(family_counts)}`")
    for quality in ("high-review", "medium-review", "low-review", "noise"):
        lines.extend(["", f"## {quality}"])
        members = top_quality[quality]
        if not members:
            lines.append("(none)")
            continue
        for row in members:
            lines.append(
                f"- `{row.get('firmware')} / {row.get('component')}`"
                f" :: family=`{row.get('latent_family')}`, reason=`{row.get('reason')}`"
            )
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-summary", required=True)
    ap.add_argument("--markdown-out")
    ap.add_argument("--strict-markdown-out")
    ap.add_argument("--latent-markdown-out")
    ap.add_argument("--top-manual-markdown-out")
    ap.add_argument("--latent-quality-summary-out")
    ap.add_argument("--corpus")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--top-manual", type=int, default=10)
    ap.add_argument("--include-rejected", action="store_true")
    ap.add_argument(
        "--regression-rejects",
        default="research/review/cve_false_positive_regressions.json",
    )
    args = ap.parse_args()

    summary = load_json(args.batch_summary)
    reject_set = load_regression_rejects(args.regression_rejects)
    regression_rows = _regression_rows(args.regression_rejects)

    if args.markdown_out and not args.strict_markdown_out:
        rows = collect_candidates(
            summary,
            include_rejected=args.include_rejected,
            regression_rejects=reject_set,
        )
        write_markdown(rows[: args.top], args.markdown_out)
        print(json.dumps({
            "batch_summary": args.batch_summary,
            "markdown_out": args.markdown_out,
            "regression_rejects": len(reject_set),
            "candidate_count": len(rows),
            "emitted": min(len(rows), args.top),
        }, indent=2))
        return

    strict_path = args.strict_markdown_out or args.markdown_out
    if not strict_path:
        raise SystemExit("expected --markdown-out or --strict-markdown-out")
    if not args.corpus or not args.latent_markdown_out or not args.top_manual_markdown_out or not args.latent_quality_summary_out:
        raise SystemExit("split queue mode requires --corpus, --latent-markdown-out, --top-manual-markdown-out, and --latent-quality-summary-out")

    strict_rows = collect_strict_candidates(summary, regression_rows)
    corpus_strict_rows = collect_strict_candidates_from_corpus(args.corpus, regression_rows)
    known_strict_rows = collect_known_strict_controls()
    strict_seen = {
        (_norm(_firmware_label(row["firmware"])), _norm(str(row["candidate"].get("name") or row["candidate"].get("raw_name") or "")))
        for row in strict_rows
    }
    for row in corpus_strict_rows + known_strict_rows:
        key = (_norm(_firmware_label(row["firmware"])), _norm(str(row["candidate"].get("name") or row["candidate"].get("raw_name") or "")))
        if key in strict_seen:
            continue
        strict_seen.add(key)
        strict_rows.append(row)
    strict_rows.sort(key=_strict_sort_key)
    latent_rows = collect_latent_review_rows(args.corpus, regression_rows, strict_rows)
    latent_rows = collect_known_latent_controls(latent_rows)
    top_rows = build_top_manual_targets(strict_rows, latent_rows, args.top_manual)

    write_markdown(strict_rows[: args.top], strict_path, title="Strict CVE Queue")
    write_latent_markdown(latent_rows, args.latent_markdown_out)
    write_top_manual_markdown(top_rows, args.top_manual_markdown_out)
    write_latent_quality_summary(latent_rows, args.latent_quality_summary_out)

    print(json.dumps({
        "batch_summary": args.batch_summary,
        "corpus": args.corpus,
        "strict_markdown_out": strict_path,
        "latent_markdown_out": args.latent_markdown_out,
        "top_manual_markdown_out": args.top_manual_markdown_out,
        "latent_quality_summary_out": args.latent_quality_summary_out,
        "regression_rejects": len(reject_set),
        "strict_cve_queue_count": len(strict_rows),
        "latent_review_queue_count": len(latent_rows),
        "top_manual_review_targets_count": len(top_rows),
    }, indent=2))


if __name__ == "__main__":
    main()
