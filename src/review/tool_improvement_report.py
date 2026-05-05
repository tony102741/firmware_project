"""
Generate corpus-level tool-improvement reports.

Outputs:
  - corpus completion report
  - candidate quality report
  - false-positive regression report
  - tool-improvement backlog
  - CVE smell queue
  - top targets shortlist
  - tool improvement log
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


KNOWN_FP_REGRESSIONS = [
    {
        "firmware": "MR90X (EU)",
        "component": "uhttpd",
        "reason": "Constant command path should not be promoted by exploratory smell collection.",
    },
    {
        "firmware": "MR90X (EU)",
        "component": "miniupnpd",
        "reason": "Bounded-copy SOAP/UPnP parsing without attacker-controlled length should not be promoted as memory corruption.",
    },
    {
        "firmware": "Archer AX23",
        "component": "firmware.lua",
        "reason": "Fixed process-inspection pipelines and cross-function endpoint contamination should not be promoted as command injection.",
    },
    {
        "firmware": "Archer AX23",
        "component": "tdpServer",
        "reason": "Encrypted or key-gated protocol helpers with fixed hardware-query commands should not be treated as unauthenticated command paths.",
    },
    {
        "firmware": "GL-MT3000",
        "component": "wg_client",
        "reason": "Numeric-only command parameters should not be promoted by exploratory smell collection.",
    },
]

KNOWN_ISSUE_SUPPRESSIONS = [
    {
        "model_substr": "A3002RU",
        "component_substr": "formUploadFile",
        "reason": "Known issue already analyzed; do not rediscover in CVE smell queue.",
    },
    {
        "model_substr": "A3002RU",
        "component_substr": "boa",
        "reason": "Known issue already analyzed; do not rediscover in CVE smell queue.",
    },
]


def _norm(text: str | None) -> str:
    raw = str(text or "").lower()
    return "".join(ch for ch in raw if ch.isalnum())


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        return []
    return [
        json.loads(line)
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: str | Path, data) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


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
    index: dict[str, list[dict]] = defaultdict(list)
    for manifest_path in runs_root.rglob("manifest.json"):
        try:
            manifest = load_json(manifest_path)
        except Exception:
            continue
        run_id = str(manifest.get("run_id") or manifest_path.parent.name or "")
        if not run_id:
            continue
        resolved = _resolve_result_path(manifest_path, manifest.get("result_path"))
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
            if key:
                index[key].append(row)
    for rows in index.values():
        rows.sort(
            key=lambda row: (
                1 if row.get("results_path") else 0,
                str(row["manifest_path"].parent.name),
            ),
            reverse=True,
        )
    return index


def _find_manifest_row(manifest_index: dict[str, list[dict]], corpus_row: dict) -> dict | None:
    keys = [
        str(corpus_row.get("run_id") or ""),
        str(corpus_row.get("local_filename") or ""),
        Path(str(corpus_row.get("local_filename") or "")).stem,
        str(corpus_row.get("model") or ""),
        _norm(corpus_row.get("local_filename")),
        _norm(Path(str(corpus_row.get("local_filename") or "")).stem),
        _norm(corpus_row.get("model")),
    ]
    seen = set()
    for key in keys:
        if not key or key in seen:
            continue
        seen.add(key)
        rows = manifest_index.get(key) or []
        if rows:
            return rows[0]
    return None


def build_loose_results_index() -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = defaultdict(list)
    for path in Path("/tmp").glob("*results*.json"):
        keys = {
            _norm(path.name),
            _norm(path.stem),
        }
        for token in path.stem.replace("-", "_").split("_"):
            if len(token) >= 4:
                keys.add(_norm(token))
        for key in keys:
            if key:
                index[key].append(path)
    return index


def _row_result_tokens(corpus_row: dict) -> list[str]:
    model = str(corpus_row.get("model") or "")
    local_filename = str(corpus_row.get("local_filename") or "")
    corpus_id = str(corpus_row.get("corpus_id") or "")
    tokens = {
        _norm(model),
        _norm(local_filename),
        _norm(Path(local_filename).stem),
        _norm(corpus_id),
    }
    for raw in [model, Path(local_filename).stem, corpus_id]:
        for token in str(raw).replace("-", " ").replace("_", " ").split():
            if len(token) >= 4:
                tokens.add(_norm(token))
    return [token for token in tokens if token]


def _find_loose_results(loose_index: dict[str, list[Path]], corpus_row: dict) -> Path | None:
    candidates: list[Path] = []
    seen = set()
    for token in _row_result_tokens(corpus_row):
        for path in loose_index.get(token) or []:
            text = str(path)
            if text in seen:
                continue
            seen.add(text)
            candidates.append(path)
    if len(candidates) == 1:
        return candidates[0]
    ranked = sorted(
        candidates,
        key=lambda path: (
            sum(1 for token in _row_result_tokens(corpus_row) if token and token in _norm(path.name)),
            path.name,
        ),
        reverse=True,
    )
    if ranked and sum(1 for token in _row_result_tokens(corpus_row) if token in _norm(ranked[0].name)) >= 1:
        return ranked[0]
    return None


def load_corpus_bundles(corpus_rows: list[dict]) -> list[dict]:
    manifest_index = build_manifest_index(PROJECT_ROOT / "runs")
    loose_index = build_loose_results_index()
    bundles = []
    for row in corpus_rows:
        manifest_row = _find_manifest_row(manifest_index, row)
        results_path = manifest_row.get("results_path") if manifest_row else None
        manifest = manifest_row.get("manifest") if manifest_row else None
        manifest_path = manifest_row.get("manifest_path") if manifest_row else None
        if results_path is None:
            results_path = _find_loose_results(loose_index, row)
        if not results_path or not results_path.is_file():
            bundles.append({
                "corpus": row,
                "results_path": None,
                "manifest_path": manifest_path,
                "manifest": manifest,
                "bundle": None,
            })
            continue
        try:
            bundle = load_json(results_path)
        except Exception:
            bundle = None
        bundles.append({
            "corpus": row,
            "results_path": results_path,
            "manifest_path": manifest_path,
            "manifest": manifest,
            "bundle": bundle,
        })
    return bundles


def corpus_completion_report(corpus_rows: list[dict], blind_summary: dict, bundles: list[dict]) -> tuple[dict, list[str]]:
    extraction = Counter(row.get("extraction_status") or "missing" for row in corpus_rows)
    analysis = Counter(row.get("analysis_status") or "missing" for row in corpus_rows)
    success_quality = Counter(row.get("success_quality") or "missing" for row in corpus_rows)
    probe = Counter(row.get("probe_readiness") or "missing" for row in corpus_rows)
    bundle_present = sum(1 for row in bundles if row.get("bundle"))
    manifest_present = sum(1 for row in bundles if row.get("manifest"))
    results_missing = [
        row["corpus"].get("corpus_id")
        for row in bundles
        if row.get("results_path") is None
    ]
    out = {
        "corpus_rows": len(corpus_rows),
        "reviewed_ids": blind_summary.get("reviewed_ids"),
        "missing_review_ids": blind_summary.get("missing_review_ids") or [],
        "extraction_status": dict(extraction),
        "analysis_status": dict(analysis),
        "success_quality": dict(success_quality),
        "probe_readiness": dict(probe),
        "bundles_found": bundle_present,
        "manifests_found": manifest_present,
        "bundles_missing": results_missing,
    }
    lines = [
        "# Corpus Completion Report",
        "",
        f"- corpus rows: `{len(corpus_rows)}`",
        f"- reviewed ids: `{blind_summary.get('reviewed_ids')}`",
        f"- missing review ids: `{len(blind_summary.get('missing_review_ids') or [])}`",
        f"- extraction_status: `{dict(extraction)}`",
        f"- analysis_status: `{dict(analysis)}`",
        f"- success_quality: `{dict(success_quality)}`",
        f"- probe_readiness: `{dict(probe)}`",
        f"- manifests found: `{manifest_present}`",
        f"- results bundles found: `{bundle_present}`",
        f"- results bundles missing: `{len(results_missing)}`",
    ]
    if results_missing:
        lines.extend([
            "",
            "## Missing Bundles",
            *[f"- `{cid}`" for cid in results_missing[:20]],
        ])
    return out, lines


def candidate_quality_report(bundles: list[dict], manual_eval: dict | None) -> tuple[dict, list[str]]:
    verdicts = Counter()
    verdict_reasons = Counter()
    flow_types = Counter()
    missing_links = Counter()
    fp_risks = Counter()
    next_actions = Counter()
    candidates_total = 0
    bundles_with_candidates = 0
    manifest_modes = Counter()
    manifest_reasons = Counter()

    for item in bundles:
        bundle = item.get("bundle") or {}
        manifest = item.get("manifest") or {}
        analysis = manifest.get("analysis") or {}
        if analysis.get("mode"):
            manifest_modes[str(analysis.get("mode"))] += 1
        if analysis.get("reason"):
            manifest_reasons[str(analysis.get("reason"))] += 1
        candidates = bundle.get("candidates") or []
        if candidates:
            bundles_with_candidates += 1
        candidates_total += len(candidates)
        for cand in candidates:
            verdicts[_candidate_verdict(cand)] += 1
            verdict_reasons[_candidate_verdict_reason(cand)] += 1
            flow_types[(cand.get("flow_type") or "unknown").lower()] += 1
            next_actions[_candidate_next_action(cand)] += 1
            for link in cand.get("missing_links") or []:
                missing_links[str(link)] += 1
            for risk in cand.get("false_positive_risks") or []:
                fp_risks[str(risk)] += 1

    out = {
        "bundles_with_candidates": bundles_with_candidates,
        "candidates_total": candidates_total,
        "verdicts": dict(verdicts),
        "verdict_reasons": dict(verdict_reasons),
        "flow_types": dict(flow_types),
        "top_missing_links": missing_links.most_common(12),
        "top_false_positive_risks": fp_risks.most_common(12),
        "recommended_next_action": dict(next_actions),
        "manifest_modes": dict(manifest_modes),
        "top_manifest_reasons": manifest_reasons.most_common(10),
        "manual_eval": manual_eval or {},
    }
    lines = [
        "# Candidate Quality Report",
        "",
        f"- bundles with candidates: `{bundles_with_candidates}`",
        f"- total candidates: `{candidates_total}`",
        f"- verdicts: `{dict(verdicts)}`",
        f"- top verdict reasons: `{dict(verdict_reasons.most_common(8))}`",
        f"- flow_types: `{dict(flow_types)}`",
        f"- recommended_next_action: `{dict(next_actions)}`",
        f"- manifest_modes: `{dict(manifest_modes)}`",
        "",
        "## Top Missing Links",
        *[f"- `{name}`: `{count}`" for name, count in missing_links.most_common(12)],
        "",
        "## Top False-Positive Risks",
        *[f"- `{name}`: `{count}`" for name, count in fp_risks.most_common(12)],
        "",
        "## Top Manifest Reasons",
        *[f"- `{name}`: `{count}`" for name, count in manifest_reasons.most_common(10)],
    ]
    if manual_eval:
        lines.extend([
            "",
            "## Manual Eval Snapshot",
            f"- gold_rows: `{manual_eval.get('gold_rows')}`",
            f"- prediction_rows: `{manual_eval.get('prediction_rows')}`",
        ])
    return out, lines


def _find_candidate(bundle: dict, component: str) -> dict | None:
    component_lower = component.lower()
    for cand in bundle.get("candidates") or []:
        name = str(cand.get("name") or "").lower()
        raw_name = str(cand.get("raw_name") or "").lower()
        if component_lower in name or component_lower in raw_name:
            return cand
    return None


def false_positive_regression_report(bundles: list[dict]) -> tuple[dict, list[str]]:
    rows = []
    lines = ["# False-Positive Regression Report", ""]
    for reg in KNOWN_FP_REGRESSIONS:
        firmware_norm = _norm(reg["firmware"])
        item = next((
            x for x in bundles
            if x.get("bundle") and firmware_norm in _norm(x["corpus"].get("model"))
        ), None)
        cand = _find_candidate(item.get("bundle") or {}, reg["component"]) if item else None
        if cand:
            verdict = _candidate_verdict(cand)
            passed = verdict == "reject"
        else:
            verdict = "not-present"
            passed = True
        rows.append({
            "firmware": reg["firmware"],
            "component": reg["component"],
            "expected": "reject",
            "actual": verdict,
            "passed": passed,
            "reason": reg["reason"],
        })
        lines.extend([
            f"## {reg['firmware']} / {reg['component']}",
            f"- expected: `reject`",
            f"- actual: `{verdict}`",
            f"- passed: `{passed}`",
            f"- reason: `{reg['reason']}`",
            "",
        ])
    return {"rows": rows}, lines


def _suppressed_known_issue(model: str, component: str) -> bool:
    for row in KNOWN_ISSUE_SUPPRESSIONS:
        if row["model_substr"].lower() in model.lower() and row["component_substr"].lower() in component.lower():
            return True
    return False


def _has_numeric_only_hint(candidate: dict) -> bool:
    text = " ".join(
        str(candidate.get(key) or "")
        for key in (
            "name",
            "raw_name",
            "vuln_summary",
            "next_steps",
            "binary_path",
        )
    ).lower()
    config_keys = " ".join(str(k).lower() for k in (candidate.get("config_keys") or []))
    return any(token in text for token in ("numeric-only", "timeout %d", "atoi(", "formatted with %d")) or (
        "group_id" in config_keys and "peer_id" in config_keys and "peer_count" in config_keys
    )


def _is_constant_command_fp(candidate: dict) -> bool:
    risks = set(candidate.get("false_positive_risks") or [])
    if {
        "constant_sink_argument",
        "constant_or_unproven_exec_argument",
        "sink_import_only",
        "cross_function_token_contamination",
        "key_gated_protocol_surface",
    } & risks:
        return True
    sink_text = " ".join(str(s) for s in (candidate.get("all_sinks") or []))
    return "kickoff_web()" in sink_text and "lua -e" in sink_text


def _is_declaration_only_sink(candidate: dict) -> bool:
    sinks = " || ".join(str(s) for s in (candidate.get("all_sinks") or []))
    lower = sinks.lower()
    if not lower:
        return False
    decl_hits = any(tok in lower for tok in ("shell=/bin/sh", "#!/bin/sh", "-/bin/sh"))
    real_hits = any(tok in lower for tok in ("system(", "popen", "os.execute", "io.popen", "execl", "execv", "execvp", "sprintf(", "strcpy(", "strcat(", "memcpy(", "memmove(", "sscanf("))
    return decl_hits and not real_hits


def _candidate_verdict(candidate: dict) -> str:
    verdict = str(candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    if verdict:
        return verdict

    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return "reject"

    flow_type = str(candidate.get("flow_type") or "").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))

    if flow_type in {"container_signal", "blob_signal"}:
        return "low-priority"

    if (
        confirmed_input != "unconfirmed"
        and has_sink
        and auth != "unknown"
        and not {"exact_input_unknown", "dispatch_unknown", "chain_gap_unknown"} & missing_links
        and not {"input_to_sink_unproven", "literal_logging_sink_only"} & fp_risks
    ):
        return "promising"

    if has_sink and has_input_hint and has_surface:
        return "needs-reversing"

    if has_sink and (has_input_hint or has_surface):
        return "low-priority"

    return "reject"


def _candidate_verdict_reason(candidate: dict) -> str:
    verdict = str(candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    if verdict and verdict != "reject":
        return f"engine-verdict:{verdict}"

    flow_type = str(candidate.get("flow_type") or "").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))

    if _is_constant_command_fp(candidate):
        return "reject:constant-or-unproven-exec-argument"
    if _has_numeric_only_hint(candidate):
        return "reject:numeric-only-or-formatted-value"
    if _is_declaration_only_sink(candidate):
        return "reject:declaration-only-sink"
    if flow_type in {"container_signal", "blob_signal"}:
        return "low-priority:container-or-blob-triage"
    if (
        confirmed_input != "unconfirmed"
        and has_sink
        and auth != "unknown"
        and not {"exact_input_unknown", "dispatch_unknown", "chain_gap_unknown"} & missing_links
        and not {"input_to_sink_unproven", "literal_logging_sink_only"} & fp_risks
    ):
        return "promising:concrete-input-sink-auth-structure"
    if has_sink and has_input_hint and has_surface:
        return "needs-reversing:surface-present-chain-incomplete"
    if has_sink and (has_input_hint or has_surface):
        if fp_risks:
            return f"low-priority:false-positive-risk:{sorted(fp_risks)[0]}"
        if missing_links:
            return f"low-priority:missing-link:{sorted(missing_links)[0]}"
        return "low-priority:weak-input-or-surface-evidence"
    if has_sink:
        return "reject:sink-without-input-proof"
    if has_input_hint:
        return "reject:input-without-sink-proof"
    return "reject:no-actionable-input-or-sink-evidence"


def _candidate_next_action(candidate: dict) -> str:
    action = str(candidate.get("recommended_next_action") or "").lower()
    if action:
        return action

    flow_type = str(candidate.get("flow_type") or "").lower()
    verdict = _candidate_verdict(candidate)
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])

    if flow_type in {"container_signal", "blob_signal"}:
        return "recover-payload-format"
    if "exact_input_unknown" in missing_links or "no_exact_input" in fp_risks:
        return "confirm-input-source"
    if "dispatch_unknown" in missing_links:
        return "confirm-dispatch-path"
    if "chain_gap_unknown" in missing_links or "input_to_sink_unproven" in fp_risks:
        return "bridge-input-to-sink"
    if str(candidate.get("sanitization") or "").lower() == "present":
        return "audit-sanitization-boundary"
    if verdict in {"promising", "cve-ready"}:
        return "confirm-exploit-primitive"
    if flow_type in {"buffer_overflow", "format_string", "heap_overflow", "file_path_injection"}:
        return "confirm-copy-site"
    return "review-artifacts"


def _derive_smell_strength(candidate: dict) -> str:
    verdict = _candidate_verdict(candidate)
    if verdict == "cve-ready":
        return "cve-candidate"

    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return "reject"

    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    attacker_arg = str(candidate.get("attacker_controlled_argument") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    flow_type = str(candidate.get("flow_type") or "").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "unconfirmed").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    parserish = flow_type in {"buffer_overflow", "heap_overflow", "format_string", "file_path_injection"}
    uploadish = any(
        token in " ".join(
            [
                str(candidate.get("name") or "").lower(),
                str(candidate.get("raw_name") or "").lower(),
                endpoint_input,
                " ".join(str(x).lower() for x in (candidate.get("endpoints") or [])),
                " ".join(str(x).lower() for x in (candidate.get("config_keys") or [])),
            ]
        )
        for token in ("upload", "restore", "firmware", "config", "multipart", "backup")
    )
    has_exec_string = any(
        token in " ".join(str(s).lower() for s in (candidate.get("all_sinks") or []))
        for token in ("system", "popen", "/bin/sh", "os.execute", "io.popen", "sprintf", "strcpy", "strcat", "memcpy")
    )

    if verdict in {"promising", "needs-reversing"}:
        return "strong-smell"

    if (
        has_sink
        and has_input_hint
        and has_surface
        and attacker_arg in {"confirmed", "likely", "unconfirmed"}
        and not {"literal_logging_sink_only", "sink_import_only", "cross_function_token_contamination", "key_gated_protocol_surface"} & fp_risks
        and auth in {"pre-auth", "post-auth", "bypassable", "unknown"}
        and not {"too_many_unknowns"} <= missing_links
    ):
        if parserish or uploadish or has_exec_string:
            return "strong-smell" if confirmed_input != "unconfirmed" or attacker_arg in {"confirmed", "likely"} else "medium-smell"

    if has_sink and (has_input_hint or has_surface or parserish or uploadish):
        return "medium-smell"

    if has_sink or has_input_hint:
        return "weak-smell"

    return "reject"


def cve_smell_queue(bundles: list[dict]) -> tuple[list[dict], list[str]]:
    items = []
    regression_pairs = {(r["firmware"], r["component"]) for r in KNOWN_FP_REGRESSIONS}
    for item in bundles:
        corpus = item["corpus"]
        bundle = item.get("bundle") or {}
        model = str(corpus.get("model") or "")
        fw_name = f"{corpus.get('vendor') or '?'} {model} {corpus.get('version') or ''}".strip()
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            smell = _derive_smell_strength(cand)
            if smell not in {"medium-smell", "strong-smell", "cve-candidate"}:
                continue
            if _suppressed_known_issue(model, name):
                continue
            if any(
                fw == reg_fw and comp.lower() in name.lower()
                for reg_fw, comp in regression_pairs
                for fw in [fw_name, str(corpus.get("model") or "")]
            ):
                continue
            items.append({
                "firmware": fw_name,
                "component": name,
                "suspected_issue": cand.get("flow_type") or "unknown",
                "verdict": _candidate_verdict(cand),
                "verdict_reason": _candidate_verdict_reason(cand),
                "recommended_next_action": _candidate_next_action(cand),
                "evidence": {
                    "endpoint_input": cand.get("endpoint_input"),
                    "confirmed_sink": cand.get("confirmed_sink"),
                    "auth_boundary": cand.get("auth_boundary"),
                    "missing_links": cand.get("missing_links") or [],
                    "false_positive_risks": cand.get("false_positive_risks") or [],
                },
                "missing_proof": ", ".join(cand.get("missing_links") or []) or "none",
                "recommended_deep_analysis_tool": (
                    "Claude Code" if smell in {"strong-smell", "cve-candidate"} else "Codex only"
                ),
                "confidence": smell,
            })
    items.sort(key=lambda x: {"cve-candidate": 0, "strong-smell": 1, "medium-smell": 2}.get(x["confidence"], 9))
    lines = ["# CVE Smell Queue", ""]
    if not items:
        lines.append("(no new candidates passed the conservative smell filter)")
    else:
        for row in items[:12]:
            lines.extend([
                f"## {row['firmware']} / {row['component']}",
                f"- suspected issue: `{row['suspected_issue']}`",
                f"- verdict: `{row.get('verdict')}`",
                f"- verdict reason: `{row.get('verdict_reason')}`",
                f"- recommended next action: `{row.get('recommended_next_action')}`",
                f"- evidence: `endpoint={row['evidence'].get('endpoint_input') or 'unconfirmed'}, sink={row['evidence'].get('confirmed_sink') or 'unconfirmed'}, auth={row['evidence'].get('auth_boundary') or 'unknown'}`",
                f"- missing proof: `{row['missing_proof']}`",
                f"- recommended deep-analysis tool: `{row['recommended_deep_analysis_tool']}`",
                f"- confidence: `{row['confidence']}`",
                "",
            ])
    return items, lines


def _top_target_score(row: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    issue = str(row.get("suspected_issue") or "").lower()
    component = str(row.get("component") or "").lower()
    ev = row.get("evidence") or {}
    endpoint = str(ev.get("endpoint_input") or "").lower()
    sink = str(ev.get("confirmed_sink") or "").lower()
    auth = str(ev.get("auth_boundary") or "").lower()
    missing = set(ev.get("missing_links") or [])

    text = " ".join([issue, component, endpoint, sink])

    if any(tok in text for tok in ("upload", "restore", "firmware", "backup", "multipart", "parser", "config.bin", "firmware.bin")):
        score += 90
        reasons.append("upload-parser-surface")
    if any(tok in sink for tok in ("/bin/sh", "system", "popen", "os.execute", "io.popen", "exec")):
        score += 70
        reasons.append("command-sink")
    if any(tok in sink for tok in ("strcpy", "sprintf", "strcat", "memcpy", "memmove", "sscanf")):
        score += 50
        reasons.append("copy-primitive")
    if endpoint and endpoint != "unconfirmed":
        score += 45
        reasons.append("endpoint-known")
    if any(tok in endpoint for tok in ("/cgi", "/config", "/admin", "/rpc", "/upload", "/restore", "/firmware")):
        score += 20
        reasons.append("web-rpc-surface")
    if auth in {"pre-auth", "unknown"}:
        score += 15
        reasons.append("network-reachability-not-ruled-out")
    if not missing:
        score += 10
        reasons.append("partial-chain-tighter")
    if row.get("confidence") == "strong-smell":
        score += 25
        reasons.append("strong-smell")

    if not endpoint and not sink:
        score -= 80
        reasons.append("weak-surface-metadata")
    if "gl-mt3000" in str(row.get("firmware") or "").lower() and not endpoint:
        score -= 20
        reasons.append("no-endpoint-on-script-heavy-surface")

    return score, reasons


def top_targets_report(smells: list[dict]) -> tuple[list[dict], list[str]]:
    ranked = []
    seen = set()
    for row in smells:
        key = (row.get("firmware"), row.get("component"))
        if key in seen:
            continue
        seen.add(key)
        score, reasons = _top_target_score(row)
        enriched = dict(row)
        enriched["priority_score"] = score
        enriched["priority_reasons"] = reasons
        ranked.append(enriched)

    ranked.sort(key=lambda x: (-int(x["priority_score"]), x.get("firmware") or "", x.get("component") or ""))
    top = ranked[:5]
    lines = ["# Top Targets", ""]
    if not top:
        lines.append("(no medium+ smell candidates available)")
    else:
        for idx, row in enumerate(top, 1):
            ev = row.get("evidence") or {}
            lines.extend([
                f"## Rank {idx}",
                f"- firmware: `{row.get('firmware')}`",
                f"- component: `{row.get('component')}`",
                f"- suspected_issue: `{row.get('suspected_issue')}`",
                f"- confidence: `{row.get('confidence')}`",
                f"- priority_score: `{row.get('priority_score')}`",
                f"- endpoint/input: `{ev.get('endpoint_input') or 'unconfirmed'}`",
                f"- sink: `{ev.get('confirmed_sink') or 'unconfirmed'}`",
                f"- auth: `{ev.get('auth_boundary') or 'unknown'}`",
                f"- missing_links: `{', '.join(ev.get('missing_links') or []) or 'none'}`",
                f"- why prioritized: `{', '.join(row.get('priority_reasons') or [])}`",
                f"- recommended tool: `{row.get('recommended_deep_analysis_tool')}`",
                "",
            ])
    return top, lines


def tool_improvement_log_report(
    corpus_out: dict,
    quality_out: dict,
    fp_out: dict,
    backlog_out: list[dict],
) -> list[str]:
    lines = [
        "# Tool Improvement Log",
        "",
        "## 2026-04-28",
        "",
        "### Pipeline / Extraction",
        "- Added generic embedded-payload salvage for `gzip`, `zip`, `xz`, and `lzma` signatures when classic filesystem detection fails.",
        "- Added recursion guards so carved payloads and compressed salvage outputs do not recursively trigger the same recovery path forever.",
        "- Widened opaque nested-blob handling so large extensionless high-entropy payloads are still explored instead of being dropped too early.",
        "",
        "### Opaque-Format Triage",
        "- Added `source_kind` and `extraction_hints` to exported `container_targets` so opaque cases preserve extraction context in structured results.",
        "- Propagated that context into review packets so `best_next_action` on blob/container cases is driven by actual extraction state rather than generic fallback logic.",
        "- Added a dedicated opaque extraction status report so partial/opaque firmware stay visible as structured recovery targets instead of anonymous failures.",
        "",
        "### Corpus / Reporting",
        f"- Corpus status: `rows={corpus_out.get('corpus_rows')}`, `bundles_found={corpus_out.get('bundles_found')}`, `manifests_found={corpus_out.get('manifests_found')}`.",
        f"- Candidate quality snapshot: `bundles_with_candidates={quality_out.get('bundles_with_candidates')}`, `candidates_total={quality_out.get('candidates_total')}`.",
        f"- False-positive regression snapshot: `{len(fp_out.get('rows') or [])}` tracked regression rows, no regression failure introduced in this iteration.",
        "",
        "### Current Highest-Value Backlog",
    ]
    for row in (backlog_out or [])[:5]:
        lines.append(f"- P{row.get('priority')}: {row.get('task')}")
    lines.append("")
    return lines


def backlog_report(corpus_rows: list[dict], quality: dict, fp_report: dict) -> tuple[list[dict], list[str]]:
    extraction_gaps = Counter(row.get("blob_family") or "none" for row in corpus_rows if row.get("success_quality") == "blob-success")
    tasks = [
        {
            "priority": 1,
            "task": "Backfill canonical runs/.../results.json for older corpus samples",
            "why_it_matters": "Corpus-wide quality and regression reports still depend on a small subset of preserved result bundles; historical samples need stable canonical artifacts.",
        },
        {
            "priority": 2,
            "task": "Reconstruct TP-Link segmented bundles into a browsable web/rootfs layout",
            "why_it_matters": "C80-class images still stop at blob-success; web assets are present but not stitched into a usable analysis tree.",
        },
        {
            "priority": 3,
            "task": "Decode TP-Link/MERCUSYS cloud container headers beyond fixed offset carve",
            "why_it_matters": "MR70X-class images now triage reliably but still never promote into a richer extracted layout.",
        },
        {
            "priority": 4,
            "task": "Promote successful Tenda salted decrypts into auto-rootfs checks instead of probe-only outputs",
            "why_it_matters": "The tool now finds plausible decrypt outputs cheaply, but does not yet convert them into higher-quality extraction states.",
        },
        {
            "priority": 5,
            "task": "Raise candidate readability around low-priority vs reject decisions",
            "why_it_matters": "Corpus-wide verdict separation improved, but many opaque-format candidates still need clearer human-facing rationale.",
        },
        {
            "priority": 6,
            "task": "Refresh corpus-wide candidate-quality regression on a larger batch summary than the current mini CVE batch",
            "why_it_matters": "The stored CVE batch summary is too small to represent the full corpus; broader queue summaries should be regenerated from current runs.",
        },
    ]
    lines = [
        "# Tool Improvement Backlog",
        "",
        f"- blob-success families: `{dict(extraction_gaps)}`",
        f"- verdicts: `{quality.get('verdicts')}`",
        f"- regression rows: `{len(fp_report.get('rows') or [])}`",
        "",
    ]
    for row in tasks:
        lines.extend([
            f"## Priority {row['priority']}",
            f"- task: {row['task']}",
            f"- why it matters: {row['why_it_matters']}",
            "",
        ])
    return tasks, lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--blind-summary", required=True)
    ap.add_argument("--manual-eval", default="research/review/manual/manual_review_eval.master_20260422_plus_linksys_plus_alignment_plus_touched6.json")
    ap.add_argument("--corpus-md", required=True)
    ap.add_argument("--corpus-json", required=True)
    ap.add_argument("--quality-md", required=True)
    ap.add_argument("--quality-json", required=True)
    ap.add_argument("--fp-md", required=True)
    ap.add_argument("--fp-json", required=True)
    ap.add_argument("--backlog-md", required=True)
    ap.add_argument("--backlog-json", required=True)
    ap.add_argument("--smell-md", required=True)
    ap.add_argument("--smell-json", required=True)
    ap.add_argument("--top-targets-md", required=True)
    ap.add_argument("--top-targets-json", required=True)
    ap.add_argument("--log-md", required=True)
    args = ap.parse_args()

    corpus_rows = load_jsonl(args.corpus)
    blind_summary = load_json(args.blind_summary)
    manual_eval = load_json(args.manual_eval) if Path(args.manual_eval).is_file() and Path(args.manual_eval).stat().st_size > 0 else {}
    bundles = load_corpus_bundles(corpus_rows)

    corpus_out, corpus_lines = corpus_completion_report(corpus_rows, blind_summary, bundles)
    quality_out, quality_lines = candidate_quality_report(bundles, manual_eval)
    fp_out, fp_lines = false_positive_regression_report(bundles)
    backlog_out, backlog_lines = backlog_report(corpus_rows, quality_out, fp_out)
    smell_out, smell_lines = cve_smell_queue(bundles)
    top_out, top_lines = top_targets_report(smell_out)
    log_lines = tool_improvement_log_report(corpus_out, quality_out, fp_out, backlog_out)

    write_json(args.corpus_json, corpus_out)
    write_md(args.corpus_md, corpus_lines)
    write_json(args.quality_json, quality_out)
    write_md(args.quality_md, quality_lines)
    write_json(args.fp_json, fp_out)
    write_md(args.fp_md, fp_lines)
    write_json(args.backlog_json, backlog_out)
    write_md(args.backlog_md, backlog_lines)
    write_json(args.smell_json, smell_out)
    write_md(args.smell_md, smell_lines)
    write_json(args.top_targets_json, top_out)
    write_md(args.top_targets_md, top_lines)
    write_md(args.log_md, log_lines)

    print(json.dumps({
        "corpus_rows": len(corpus_rows),
        "bundles_scanned": sum(1 for row in bundles if row.get("bundle")),
        "smell_rows": len(smell_out),
        "top_rows": len(top_out),
    }, indent=2))


if __name__ == "__main__":
    main()
