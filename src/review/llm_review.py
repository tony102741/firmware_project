"""
Build LLM-ready review packets from firmware analysis results.

This script does not require a live model. It prepares structured evidence so
an external LLM can perform stable classification, planning, triage, and report
writing against a consistent schema.

Examples:
  python3 src/review/llm_review.py --results runs/<run-id>/results.json
  python3 src/review/llm_review.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --batch-summary runs/regression/batch_regression_summary.json \
      --corpus-id tenda-ax12pro-v3-0-16-03-68-19-td01
  python3 src/review/llm_review.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --batch-summary runs/regression/batch_regression_summary.json \
      --emit-corpus-packets research/review/llm/llm_review_packets.jsonl
  python3 src/review/llm_review.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --batch-summary runs/regression/batch_regression_summary.json \
      --write-gold-stubs research/review/llm/llm_review_gold.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


SRC_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_ROOT.parent

TOP_CANDIDATES = 5
TOP_DOSSIERS = 5
COMPACT_TOP_CANDIDATES = 3
COMPACT_TOP_TARGETS = 2


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: str | Path) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for idx, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {idx}: invalid JSON: {exc}") from exc
    return rows


def _safe_rel(pathish: Optional[str]) -> str:
    if not pathish:
        return ""
    p = Path(pathish)
    try:
        return str(p.resolve().relative_to(PROJECT_ROOT.resolve()))
    except Exception:
        return str(pathish)


def _top_candidates(bundle: dict, limit: int = TOP_CANDIDATES) -> List[dict]:
    cve = bundle.get("cve_candidates") or []
    if cve:
        return cve[:limit]
    return (bundle.get("candidates") or [])[:limit]


def _infer_best_next_action(success_quality: str, probe_readiness: str, blob_family: Optional[str]) -> str:
    if probe_readiness == "decrypt-probe-ready":
        return "run-decrypt-probe"
    if probe_readiness == "scan-probe-ready":
        return "inspect-container-payload"
    if probe_readiness == "bundle-probe-ready":
        return "inspect-segmented-bundle"
    if success_quality == "rootfs-success":
        return "triage-top-candidates"
    if success_quality == "blob-success":
        if blob_family == "tenda-openssl-container":
            return "run-decrypt-probe"
        if blob_family == "mercusys-cloud-container":
            return "inspect-container-payload"
        if blob_family == "tp-link-segmented-bundle":
            return "inspect-segmented-bundle"
        return "expand-binary-signals"
    return "review-artifacts"


def _infer_top_risk_family(
    bundle: dict,
    success_quality: Optional[str] = None,
    probe_readiness: Optional[str] = None,
) -> str:
    summary_bundle = bundle.get("summary") or {}
    crypto_findings = int(summary_bundle.get("crypto_findings") or 0)

    if success_quality == "blob-success":
        return "container-analysis"
    if probe_readiness in {"decrypt-probe-ready", "scan-probe-ready", "bundle-probe-ready"}:
        return "container-analysis"

    cands = _top_candidates(bundle, limit=8)
    for cand in cands:
        flow_type = (cand.get("flow_type") or "").lower()
        sinks = [str(s).lower() for s in (cand.get("all_sinks") or [])]
        summary = (cand.get("vuln_summary") or "").lower()
        confidence = (cand.get("confidence") or "").upper()
        missing_links = set(cand.get("missing_links") or [])
        endpoints = [str(ep).lower() for ep in (cand.get("endpoints") or [])]
        handler_surface = bool(cand.get("handler_surface"))

        if flow_type == "shell_var_injection" and not cand.get("web_exposed") and not endpoints:
            return "no-clear-rce"
        if (
            not cand.get("web_exposed")
            and not endpoints
            and "/sbin/" in str(cand.get("binary_path") or "")
            and any(tok in summary for tok in ("command injection", "execvp", "popen", "system"))
            and any(link in missing_links for link in ("exact_input_unknown", "dispatch_unknown"))
        ):
            return "no-clear-rce"

        # Weak maintenance/upgrade heuristics should not outrank stronger
        # structural evidence as command-injection.
        if confidence == "LOW" and not handler_surface:
            if "exact_input_unknown" in missing_links:
                if any(tok in summary for tok in ("upgrade", "firmware", "backup", "reset", "administration")):
                    return "upgrade-risk"
                if any(ep in {"/firmware.img", "/upgrade", "/administration", "/applyreboot"} for ep in endpoints):
                    return "upgrade-risk"
            if "auth_boundary_unknown" in missing_links:
                if any(tok in summary for tok in ("upgrade", "firmware", "accountmgnt", "config.bin", "reboot")):
                    if any("grep -v" in sink or "awk" in sink or "echo %s" in summary for sink in sinks) or any(
                        ep in {"/config/accountmgnt", "/firmware_upgrade", "/config.bin", "/firmware.bin"} for ep in endpoints
                    ):
                        return "upgrade-risk"

        # When the current top binary looks like a local mesh/helper daemon with
        # no surfaced web handler, multiple unresolved chain gaps, and the same
        # firmware also carries explicit crypto findings, prefer the stronger
        # crypto exposure over speculative command-injection.
        if crypto_findings > 0 and not cand.get("web_exposed") and not handler_surface:
            if "too_many_unknowns" in missing_links and any(tok in summary for tok in ("command injection", "session::system", "config")):
                return "crypto-risk"

        if cand.get("web_exposed") and confidence in {"HIGH", "MEDIUM"}:
            if "command injection" in summary and any(
                tok in " ".join(sinks) for tok in ("os.execute", "/bin/sh", "session::system", "popen", "system", "exec")
            ):
                return "cmd-injection"

        if "overflow" in summary or "buffer_overflow" in flow_type:
            return "memory-corruption"

        if "cmd_injection" in flow_type or any(s in sinks for s in ("system", "popen", "exec", "/bin/sh", "command")):
            return "cmd-injection"
        if any(s in sinks for s in ("strcpy", "sprintf", "memcpy", "memmove")):
            return "memory-corruption"
    upgrade = int(summary_bundle.get("upgrade_findings") or 0)
    crypto = crypto_findings
    if upgrade > 0:
        return "upgrade-risk"
    if crypto > 0:
        return "crypto-risk"
    if bundle.get("container_targets"):
        return "container-analysis"
    return "no-clear-rce"


def _resolve_results_path(
    *,
    results_path: Optional[str],
    run_id: Optional[str],
    corpus_entry: Optional[dict],
    batch_summary_path: Optional[str],
) -> Path:
    if results_path:
        path = Path(results_path)
        if path.is_file():
            return path
        raise FileNotFoundError(f"results not found: {results_path}")

    if run_id:
        local = PROJECT_ROOT / "runs" / run_id / "results.json"
        if local.is_file():
            return local

    if batch_summary_path and corpus_entry:
        summary = load_json(batch_summary_path)
        for row in summary.get("results") or []:
            if corpus_entry.get("corpus_id") and row.get("corpus_id") == corpus_entry.get("corpus_id"):
                path = Path(row.get("results_json") or "")
                if path.is_file():
                    return path
            if corpus_entry.get("local_filename") and row.get("sample") == corpus_entry.get("local_filename"):
                path = Path(row.get("results_json") or "")
                if path.is_file():
                    return path

    raise FileNotFoundError("could not resolve results.json; pass --results or --batch-summary")


def _slim_candidate(candidate: dict) -> dict:
    return {
        "name": candidate.get("name"),
        "binary_path": _safe_rel(candidate.get("binary_path") or candidate.get("exec")),
        "flow_type": candidate.get("flow_type"),
        "score": candidate.get("score"),
        "triage_score": candidate.get("triage_score"),
        "level": candidate.get("level"),
        "confidence": candidate.get("confidence"),
        "web_exposed": candidate.get("web_exposed"),
        "auth_bypass": candidate.get("auth_bypass"),
        "handler_surface": candidate.get("handler_surface"),
        "endpoints": candidate.get("endpoints") or [],
        "handler_symbols": candidate.get("handler_symbols") or [],
        "all_sinks": candidate.get("all_sinks") or [],
        "vuln_summary": candidate.get("vuln_summary") or "",
        "missing_links": candidate.get("missing_links") or [],
        "next_steps": candidate.get("next_steps") or [],
    }


def _slim_container_target(target: dict) -> dict:
    probe = target.get("probe_bundle") or {}
    return {
        "name": target.get("name"),
        "vendor_guess": target.get("vendor_guess") or "",
        "crypto_profile": target.get("crypto_profile") or "",
        "payload_offset": target.get("payload_offset"),
        "payload_size": target.get("payload_size"),
        "ciphertext_offset": target.get("ciphertext_offset"),
        "ciphertext_size": target.get("ciphertext_size"),
        "openssl_salt": target.get("openssl_salt") or "",
        "dest": target.get("dest"),
        "ciphertext_dest": target.get("ciphertext_dest"),
        "probe_type": probe.get("probe_type"),
        "probe_script": probe.get("script"),
        "probe_meta": probe.get("meta"),
        "candidate_count": probe.get("candidate_count"),
    }


def build_review_packet(bundle: dict, corpus_entry: Optional[dict] = None) -> dict:
    analysis = bundle.get("analysis") or {}
    summary = bundle.get("summary") or {}
    top_candidates = [_slim_candidate(c) for c in _top_candidates(bundle)]
    container_targets = [_slim_container_target(t) for t in (bundle.get("container_targets") or [])]
    dossiers = [
        {
            "candidate_id": d.get("candidate_id"),
            "path": d.get("path"),
        }
        for d in (bundle.get("dossiers") or [])[:TOP_DOSSIERS]
    ]

    success_quality = corpus_entry.get("success_quality") if corpus_entry else None
    probe_readiness = corpus_entry.get("probe_readiness") if corpus_entry else None
    blob_family = corpus_entry.get("blob_family") if corpus_entry else None
    web_surface_detected = corpus_entry.get("web_surface_detected") if corpus_entry else None
    if web_surface_detected is None and summary.get("web_exposed") is not None:
        web_surface_detected = bool(summary.get("web_exposed"))

    packet = {
        "schema_version": "2026-04-21",
        "review_id": corpus_entry.get("corpus_id") if corpus_entry else bundle.get("run_id"),
        "firmware": {
            "vendor": (corpus_entry or {}).get("vendor"),
            "model": (corpus_entry or {}).get("model"),
            "version": (corpus_entry or {}).get("version"),
            "local_filename": (corpus_entry or {}).get("local_filename"),
            "input_type": (corpus_entry or {}).get("input_type"),
            "product_class": (corpus_entry or {}).get("product_class"),
            "run_id": bundle.get("run_id"),
            "run_dir": bundle.get("run_dir"),
        },
        "engine_state": {
            "analysis_mode": analysis.get("mode"),
            "analysis_reason": analysis.get("reason"),
            "analysis_system_path": analysis.get("system_path"),
            "success_quality": success_quality,
            "probe_readiness": probe_readiness,
            "blob_family": blob_family,
            "web_surface_detected": web_surface_detected,
            "summary": {
                "candidates_analyzed": summary.get("candidates_analyzed"),
                "web_exposed": summary.get("web_exposed"),
                "high": summary.get("high"),
                "medium": summary.get("medium"),
                "low": summary.get("low"),
                "crypto_findings": summary.get("crypto_findings"),
                "upgrade_findings": summary.get("upgrade_findings"),
            },
        },
        "evidence": {
            "top_candidates": top_candidates,
            "container_targets": container_targets,
            "dossiers": dossiers,
        },
        "llm_tasks": {
            "classifier": {
                "goal": "Classify the firmware analysis state and decide whether the engine has rootfs-level evidence or only container/blob-level evidence.",
                "required_fields": [
                    "has_rootfs",
                    "has_web_ui",
                    "artifact_kind",
                    "probe_readiness",
                    "blob_family",
                    "encrypted_container",
                ],
            },
            "planner": {
                "goal": "Recommend the best next technical action based on current evidence instead of generic reverse-engineering advice.",
                "required_fields": [
                    "best_next_action",
                    "next_actions",
                ],
            },
            "triager": {
                "goal": "Prioritize the strongest risk family from the evidence rather than from generic product assumptions.",
                "required_fields": [
                    "top_risk_family",
                    "triage_summary",
                ],
            },
            "writer": {
                "goal": "Write a short human-readable summary anchored to the evidence bundle.",
                "required_fields": [
                    "operator_summary",
                ],
            },
        },
        "output_contract": {
            "labels": {
                "has_rootfs": "boolean",
                "has_web_ui": "boolean",
                "artifact_kind": "rootfs-success | fallback-success | blob-success | unknown",
                "probe_readiness": "rootfs-ready | fallback-ready | bundle-probe-ready | decrypt-probe-ready | scan-probe-ready | blob-ready | unknown",
                "blob_family": "tp-link-segmented-bundle | mercusys-cloud-container | tenda-openssl-container | generic-container | generic-blob-signal | none",
                "encrypted_container": "boolean",
                "best_next_action": "triage-top-candidates | run-decrypt-probe | inspect-container-payload | inspect-segmented-bundle | expand-binary-signals | review-artifacts",
                "top_risk_family": "cmd-injection | memory-corruption | upgrade-risk | crypto-risk | container-analysis | no-clear-rce",
            },
            "explanations": {
                "triage_summary": "short paragraph",
                "operator_summary": "short paragraph",
                "next_actions": "list[str] with 1-3 concrete actions",
            },
        },
    }
    return packet


def build_prompt_markdown(packet: dict) -> str:
    return "\n".join([
        "# Firmware Review Packet",
        "",
        "You are reviewing a firmware-analysis evidence packet.",
        "Use only the supplied evidence. Do not invent missing files, endpoints, or exploit chains.",
        "Return JSON matching the `output_contract` exactly.",
        "",
        "## Evidence Packet",
        "```json",
        json.dumps(packet, ensure_ascii=False, indent=2),
        "```",
    ])


def build_compact_packet(packet: dict) -> dict:
    engine = packet.get("engine_state") or {}
    evidence = packet.get("evidence") or {}
    top_candidates = []
    for cand in (evidence.get("top_candidates") or [])[:COMPACT_TOP_CANDIDATES]:
        top_candidates.append({
            "name": cand.get("name"),
            "flow_type": cand.get("flow_type"),
            "level": cand.get("level"),
            "confidence": cand.get("confidence"),
            "score": cand.get("score"),
            "triage_score": cand.get("triage_score"),
            "web_exposed": cand.get("web_exposed"),
            "auth_bypass": cand.get("auth_bypass"),
            "endpoints": cand.get("endpoints") or [],
            "all_sinks": cand.get("all_sinks") or [],
            "vuln_summary": cand.get("vuln_summary") or "",
            "missing_links": cand.get("missing_links") or [],
        })

    container_targets = []
    for target in (evidence.get("container_targets") or [])[:COMPACT_TOP_TARGETS]:
        container_targets.append({
            "name": target.get("name"),
            "vendor_guess": target.get("vendor_guess"),
            "crypto_profile": target.get("crypto_profile"),
            "payload_offset": target.get("payload_offset"),
            "ciphertext_offset": target.get("ciphertext_offset"),
            "openssl_salt": target.get("openssl_salt"),
            "probe_type": target.get("probe_type"),
            "candidate_count": target.get("candidate_count"),
        })

    return {
        "schema_version": packet.get("schema_version"),
        "review_id": packet.get("review_id"),
        "firmware": packet.get("firmware"),
        "engine_state": {
            "analysis_mode": engine.get("analysis_mode"),
            "success_quality": engine.get("success_quality"),
            "probe_readiness": engine.get("probe_readiness"),
            "blob_family": engine.get("blob_family"),
            "web_surface_detected": engine.get("web_surface_detected"),
            "summary": engine.get("summary") or {},
        },
        "evidence": {
            "top_candidates": top_candidates,
            "container_targets": container_targets,
        },
        "llm_tasks": packet.get("llm_tasks"),
        "output_contract": packet.get("output_contract"),
    }


def build_gold_stub(packet: dict) -> dict:
    engine = packet["engine_state"]
    success_quality = engine.get("success_quality") or "unknown"
    probe_readiness = engine.get("probe_readiness") or "unknown"
    blob_family = engine.get("blob_family") or "none"
    top_candidates = packet["evidence"].get("top_candidates") or []
    top = top_candidates[0] if top_candidates else {}
    inferred_next_action = _infer_best_next_action(success_quality, probe_readiness, blob_family)
    if (
        success_quality == "rootfs-success"
        and (top.get("flow_type") or "").lower() == "shell_var_injection"
        and not top.get("web_exposed")
        and not (top.get("endpoints") or [])
    ):
        inferred_next_action = "review-artifacts"
    if (
        success_quality == "rootfs-success"
        and not top.get("web_exposed")
        and not (top.get("endpoints") or [])
        and "/sbin/" in str(top.get("binary_path") or "")
        and any(tok in (top.get("vuln_summary") or "").lower() for tok in ("command injection", "execvp", "popen", "system"))
        and any(link in set(top.get("missing_links") or []) for link in ("exact_input_unknown", "dispatch_unknown"))
    ):
        inferred_next_action = "review-artifacts"
    labels = {
        "has_rootfs": success_quality == "rootfs-success",
        "has_web_ui": bool(engine.get("web_surface_detected") or engine.get("analysis_mode") == "iot_web"),
        "artifact_kind": success_quality,
        "probe_readiness": probe_readiness,
        "blob_family": blob_family,
        "encrypted_container": blob_family == "tenda-openssl-container",
        "best_next_action": inferred_next_action,
        "top_risk_family": _infer_top_risk_family(
            {
                "summary": engine.get("summary") or {},
                "cve_candidates": top_candidates,
                "container_targets": packet["evidence"].get("container_targets") or [],
            },
            success_quality=success_quality,
            probe_readiness=probe_readiness,
        ),
    }
    return {
        "review_id": packet.get("review_id"),
        "firmware": packet.get("firmware"),
        "labels": labels,
        "notes": "Autogenerated stub from current engine state. Review and correct manually before using as gold truth.",
    }


def write_jsonl(path: str | Path, rows: Iterable[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", help="Path to a results.json file.")
    ap.add_argument("--run-id", help="Resolve results via runs/<run-id>/results.json.")
    ap.add_argument("--corpus", help="Path to firmware_corpus.jsonl.")
    ap.add_argument("--corpus-id", help="Target corpus_id for packet generation.")
    ap.add_argument("--batch-summary", help="Batch regression summary JSON for resolving isolated run artifacts.")
    ap.add_argument("--json-output", help="Write a single packet JSON to this path.")
    ap.add_argument("--compact-json-output", help="Write a compact single-packet JSON to this path.")
    ap.add_argument("--markdown-output", help="Write a markdown prompt bundle to this path.")
    ap.add_argument("--emit-corpus-packets", help="Write one packet per corpus row as JSONL.")
    ap.add_argument("--emit-corpus-packets-compact", help="Write compact packets as JSONL.")
    ap.add_argument("--write-gold-stubs", help="Write heuristic gold-label stubs as JSONL.")
    ap.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip corpus rows whose results.json cannot be resolved instead of stopping.",
    )
    args = ap.parse_args()

    corpus_rows = load_jsonl(args.corpus) if args.corpus else []
    corpus_map = {row.get("corpus_id"): row for row in corpus_rows}

    if args.emit_corpus_packets or args.write_gold_stubs:
        if not corpus_rows:
            raise SystemExit("--emit-corpus-packets/--write-gold-stubs requires --corpus")
        packets = []
        compact_packets = []
        stubs = []
        skipped = []
        for row in corpus_rows:
            try:
                results_path = _resolve_results_path(
                    results_path=None,
                    run_id=row.get("run_id"),
                    corpus_entry=row,
                    batch_summary_path=args.batch_summary,
                )
            except FileNotFoundError as exc:
                if not args.skip_missing:
                    raise
                skipped.append({
                    "corpus_id": row.get("corpus_id"),
                    "run_id": row.get("run_id"),
                    "error": str(exc),
                })
                continue
            bundle = load_json(results_path)
            packet = build_review_packet(bundle, row)
            packets.append(packet)
            compact_packets.append(build_compact_packet(packet))
            stubs.append(build_gold_stub(packet))
        if args.emit_corpus_packets:
            write_jsonl(args.emit_corpus_packets, packets)
        if args.emit_corpus_packets_compact:
            write_jsonl(args.emit_corpus_packets_compact, compact_packets)
        if args.write_gold_stubs:
            write_jsonl(args.write_gold_stubs, stubs)
        print(json.dumps({
            "packets_written": len(packets) if args.emit_corpus_packets else 0,
            "compact_packets_written": len(compact_packets) if args.emit_corpus_packets_compact else 0,
            "gold_stubs_written": len(stubs) if args.write_gold_stubs else 0,
            "packet_path": args.emit_corpus_packets,
            "compact_packet_path": args.emit_corpus_packets_compact,
            "gold_stub_path": args.write_gold_stubs,
            "skipped_rows": skipped,
        }, ensure_ascii=False, indent=2))
        return 0

    corpus_entry = corpus_map.get(args.corpus_id) if args.corpus_id else None
    results_path = _resolve_results_path(
        results_path=args.results,
        run_id=args.run_id or ((corpus_entry or {}).get("run_id") if corpus_entry else None),
        corpus_entry=corpus_entry,
        batch_summary_path=args.batch_summary,
    )
    packet = build_review_packet(load_json(results_path), corpus_entry)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.compact_json_output:
        Path(args.compact_json_output).write_text(
            json.dumps(build_compact_packet(packet), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.markdown_output:
        Path(args.markdown_output).write_text(build_prompt_markdown(packet) + "\n", encoding="utf-8")

    print(json.dumps(packet, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
