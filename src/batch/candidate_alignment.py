"""
Measure alignment between pipeline-surfaced candidates and reviewed ledger findings.

The goal is not perfect vulnerability identity resolution. Instead, this tool
answers a practical research question:

    "How close is the pipeline shortlist to the candidates that manual/LLM
     review ultimately considered real or worth chasing?"

It compares reviewed ledger entries against pipeline `results.json` candidates
grouped by firmware family (`vendor`, `model`) and produces:

- reviewed candidates matched by any pipeline candidate
- reviewed candidates matched by top CVE shortlist candidates
- pipeline top candidates that have no reviewed counterpart yet
- per-family mismatch lists to drive heuristic improvements

Usage:
  python3 src/batch/candidate_alignment.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --ledger research/review/manual/review_queue_20260420.jsonl \
      --markdown-out research/snapshots/candidate_alignment_snapshot_20260420.md \
      --json-out research/snapshots/candidate_alignment_snapshot_20260420.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


STOPWORDS = {
    "cgi", "form", "path", "direct", "hidden", "interface", "parameter",
    "handler", "command", "injection", "execution", "authenticated", "auth",
    "config", "endpoint", "legacy", "debug", "diagnostic", "admin",
}

SINK_WORDS = ("popen", "system", "exec", "os.execute", "iptables", "lua")


def load_jsonl(path: str) -> List[dict]:
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


def discover_ledgers(corpus_path: str) -> List[str]:
    research_dir = Path(corpus_path).resolve().parent
    discovered = []
    for path in sorted(research_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name in {
            "candidate_ledger.template.jsonl",
            "firmware_corpus.jsonl",
            "firmware_corpus.template.jsonl",
        }:
            continue
        if path.name.endswith(".jsonl") or path.name.endswith(".jsonl.json"):
            discovered.append(str(path))
    return discovered


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def _tokens(text: str) -> List[str]:
    toks = []
    for tok in _norm(text).split():
        if len(tok) <= 2:
            continue
        if tok in STOPWORDS:
            continue
        toks.append(tok)
    return toks


def _basename(pathish: str) -> str:
    if not pathish:
        return ""
    p = pathish.replace("\\", "/").rstrip("/")
    if "/" in p:
        return p.rsplit("/", 1)[-1]
    return p


def _firmware_key(vendor: str, model: str) -> str:
    return f"{(vendor or '?').strip().lower()}::{(model or '?').strip().lower()}"


def _extract_run_candidate_features(candidate: dict) -> dict:
    endpoints = candidate.get("endpoints") or []
    handler_symbols = candidate.get("handler_symbols") or []
    sinks = [str(s).lower() for s in (candidate.get("all_sinks") or [])]
    verified = candidate.get("verified_flows") or []
    flow_sinks = [str(f.get("sink_sym", "")).lower() for f in verified if f.get("sink_sym")]
    binary_path = candidate.get("binary_path") or candidate.get("exec") or ""
    name = candidate.get("name") or _basename(binary_path)
    summary = candidate.get("vuln_summary") or ""
    blob = " ".join([
        name,
        summary,
        " ".join(endpoints),
        " ".join(handler_symbols),
        " ".join(sinks),
        " ".join(flow_sinks),
        binary_path,
    ])
    return {
        "name": name,
        "binary_path": binary_path,
        "summary": summary,
        "endpoints": endpoints,
        "handler_symbols": handler_symbols,
        "sinks": sorted(set(sinks + flow_sinks)),
        "text": blob,
        "tokens": set(_tokens(blob)),
        "score": candidate.get("score", 0),
        "triage_score": candidate.get("triage_score", 0),
        "web_exposed": bool(candidate.get("web_exposed")),
        "source": candidate,
    }


def _extract_review_features(entry: dict) -> dict:
    firmware = entry.get("firmware", {})
    candidate = entry.get("candidate", {})
    pattern = entry.get("pattern", {})
    review = entry.get("review", {})
    entry_point = candidate.get("entry_point", "")
    sink = candidate.get("sink", "")
    name = candidate.get("name", "")
    processing = " ".join(candidate.get("processing_chain") or [])
    blob = " ".join([name, entry_point, sink, processing, pattern.get("primary", "")])
    endpoint_parts = [entry_point]
    if entry_point:
        endpoint_parts.append(_basename(entry_point))
    return {
        "entry_id": entry.get("entry_id", ""),
        "fw_key": _firmware_key(firmware.get("vendor", ""), firmware.get("model", "")),
        "vendor": firmware.get("vendor", ""),
        "model": firmware.get("model", ""),
        "version": firmware.get("version", ""),
        "name": name,
        "entry_point": entry_point,
        "endpoint_parts": [p for p in endpoint_parts if p],
        "sink": sink.lower(),
        "sink_tokens": set(_tokens(sink)),
        "tokens": set(_tokens(blob)),
        "pattern": pattern.get("primary", ""),
        "verdict": review.get("verdict", ""),
        "confidence": review.get("confidence", ""),
        "source": entry,
    }


def _sink_overlap(review_sink: str, pipeline_sinks: Iterable[str]) -> bool:
    review_norm = _norm(review_sink)
    if not review_norm:
        return False
    for sink in pipeline_sinks:
        s = _norm(sink)
        if not s:
            continue
        if s in review_norm or review_norm in s:
            return True
    return False


def _match_score(review_feat: dict, run_feat: dict) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    for part in review_feat["endpoint_parts"]:
        part_norm = part.lower()
        if not part_norm:
            continue
        if any(part_norm in str(ep).lower() for ep in run_feat["endpoints"]):
            score += 8
            reasons.append(f"endpoint:{part}")
            break
        if part_norm in run_feat["text"].lower():
            score += 5
            reasons.append(f"text-endpoint:{part}")
            break

    if _sink_overlap(review_feat["sink"], run_feat["sinks"]):
        score += 7
        reasons.append("sink")

    name_overlap = review_feat["tokens"] & run_feat["tokens"]
    if name_overlap:
        bonus = min(6, len(name_overlap) * 2)
        score += bonus
        reasons.append("tokens:" + ",".join(sorted(name_overlap)[:4]))

    review_name = _norm(review_feat["name"])
    run_name = _norm(run_feat["name"])
    if review_name and run_name and (review_name in run_name or run_name in review_name):
        score += 4
        reasons.append("name")

    if review_feat["pattern"]:
        pattern_tokens = set(_tokens(review_feat["pattern"]))
        if pattern_tokens & run_feat["tokens"]:
            score += 2
            reasons.append("pattern")

    return score, reasons


def _run_sort_key(run_feat: dict) -> Tuple[float, float, int]:
    return (
        float(run_feat.get("triage_score") or 0),
        float(run_feat.get("score") or 0),
        1 if run_feat.get("web_exposed") else 0,
    )


def _load_pipeline_groups(corpus_rows: List[dict]) -> Dict[str, dict]:
    groups: Dict[str, dict] = {}
    for row in corpus_rows:
        fw_key = _firmware_key(row.get("vendor", ""), row.get("model", ""))
        run_id = row.get("run_id")
        if not run_id:
            continue
        results_path = Path("runs") / run_id / "results.json"
        if not results_path.is_file():
            continue
        try:
            with results_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError:
            continue

        bucket = groups.setdefault(fw_key, {
            "vendor": row.get("vendor", ""),
            "model": row.get("model", ""),
            "versions": [],
            "runs": [],
            "all_candidates": [],
            "top_candidates": [],
        })
        bucket["versions"].append(row.get("version", ""))
        bucket["runs"].append({
            "run_id": run_id,
            "version": row.get("version", ""),
            "results_path": str(results_path),
        })
        bucket["all_candidates"].extend(
            _extract_run_candidate_features(c) for c in (data.get("candidates") or [])
        )
        cve = data.get("cve_candidates")
        if cve:
            bucket["top_candidates"].extend(_extract_run_candidate_features(c) for c in cve)
        else:
            ranked = sorted(
                (_extract_run_candidate_features(c) for c in (data.get("candidates") or [])),
                key=_run_sort_key,
                reverse=True,
            )
            bucket["top_candidates"].extend(ranked[:3])

    for bucket in groups.values():
        bucket["versions"] = sorted(set(bucket["versions"]))
        bucket["all_candidates"] = sorted(bucket["all_candidates"], key=_run_sort_key, reverse=True)
        bucket["top_candidates"] = sorted(bucket["top_candidates"], key=_run_sort_key, reverse=True)
    return groups


def _best_match(review_feat: dict, run_feats: List[dict], threshold: int = 8) -> Optional[dict]:
    best = None
    for run_feat in run_feats:
        score, reasons = _match_score(review_feat, run_feat)
        if best is None or score > best["score"]:
            best = {"score": score, "reasons": reasons, "candidate": run_feat}
    if not best or best["score"] < threshold:
        return None
    return best


def _miss_category(review_feat: dict, run_feats: List[dict]) -> str:
    if not run_feats:
        return "coverage_miss"
    for cand in run_feats:
        if _sink_overlap(review_feat["sink"], cand["sinks"]):
            return "granularity_miss"
    ep_base = _basename(review_feat["entry_point"]).lower()
    if ep_base:
        for cand in run_feats:
            if ep_base in cand["text"].lower():
                return "ranking_or_naming_miss"
    return "semantic_miss"


def build_alignment(corpus_rows: List[dict], ledger_rows: List[dict]) -> dict:
    pipeline_groups = _load_pipeline_groups(corpus_rows)
    reviewed = [_extract_review_features(r) for r in ledger_rows]

    family_rows = {}
    overall = Counter()
    focused = Counter()

    for fw_key in sorted({_firmware_key(r.get("vendor", ""), r.get("model", "")) for r in corpus_rows} |
                         {r["fw_key"] for r in reviewed}):
        group = pipeline_groups.get(fw_key, {
            "vendor": "",
            "model": "",
            "versions": [],
            "runs": [],
            "all_candidates": [],
            "top_candidates": [],
        })
        family_reviews = [r for r in reviewed if r["fw_key"] == fw_key]
        if not family_reviews and not group["runs"]:
            continue

        vendor = group["vendor"] or (family_reviews[0]["vendor"] if family_reviews else "")
        model = group["model"] or (family_reviews[0]["model"] if family_reviews else "")
        family = {
            "vendor": vendor,
            "model": model,
            "versions": group["versions"],
            "run_count": len(group["runs"]),
            "review_count": len(family_reviews),
            "pipeline_candidate_count": len(group["all_candidates"]),
            "pipeline_top_count": len(group["top_candidates"]),
            "review_matches_any": [],
            "review_matches_top": [],
            "review_matches_any_only": [],
            "review_missed": [],
            "pipeline_top_unmatched": [],
            "miss_categories": Counter(),
        }

        matched_top_idx = set()

        for review_feat in family_reviews:
            overall["review_total"] += 1
            focused["review_total"] += 1
            if review_feat["verdict"] in ("CONFIRMED", "LIKELY"):
                overall["review_positive"] += 1
                focused["review_positive"] += 1
            any_match = _best_match(review_feat, group["all_candidates"], threshold=8)
            top_match = _best_match(review_feat, group["top_candidates"], threshold=8)

            row = {
                "entry_id": review_feat["entry_id"],
                "name": review_feat["name"],
                "verdict": review_feat["verdict"],
                "entry_point": review_feat["entry_point"],
                "sink": review_feat["sink"],
            }
            if any_match:
                overall["review_matched_any"] += 1
                focused["review_matched_any"] += 1
                row_any = dict(row)
                row_any.update({
                    "match_score": any_match["score"],
                    "match_reasons": any_match["reasons"],
                    "pipeline_name": any_match["candidate"]["name"],
                    "pipeline_summary": any_match["candidate"]["summary"],
                })
                family["review_matches_any"].append(row_any)
            else:
                overall["review_missed_any"] += 1
                focused["review_missed_any"] += 1
                miss_cat = _miss_category(review_feat, group["all_candidates"])
                row["miss_category"] = miss_cat
                family["review_missed"].append(row)
                family["miss_categories"][miss_cat] += 1
                focused[f"miss_{miss_cat}"] += 1

            if top_match:
                overall["review_matched_top"] += 1
                focused["review_matched_top"] += 1
                row_top = dict(row)
                row_top.update({
                    "match_score": top_match["score"],
                    "match_reasons": top_match["reasons"],
                    "pipeline_name": top_match["candidate"]["name"],
                    "pipeline_summary": top_match["candidate"]["summary"],
                })
                family["review_matches_top"].append(row_top)
                try:
                    matched_top_idx.add(group["top_candidates"].index(top_match["candidate"]))
                except ValueError:
                    pass
            else:
                overall["review_missed_top"] += 1
                focused["review_missed_top"] += 1
                if any_match:
                    focused["ranking_miss"] += 1
                    family["review_matches_any_only"].append({
                        **row,
                        "match_score": any_match["score"],
                        "match_reasons": any_match["reasons"],
                        "pipeline_name": any_match["candidate"]["name"],
                        "pipeline_summary": any_match["candidate"]["summary"],
                    })

        for idx, cand in enumerate(group["top_candidates"]):
            if idx in matched_top_idx:
                continue
            family["pipeline_top_unmatched"].append({
                "name": cand["name"],
                "summary": cand["summary"],
                "sinks": cand["sinks"][:6],
            })
            overall["pipeline_top_unmatched"] += 1
            if family_reviews:
                focused["pipeline_top_unmatched"] += 1

        family_rows[fw_key] = family

    return {
        "overall": dict(overall),
        "focused": dict(focused),
        "families": family_rows,
    }


def _pct(num: int, den: int) -> str:
    if not den:
        return "0.0%"
    return f"{(100.0 * num / den):.1f}%"


def render_markdown(report: dict, corpus_path: str, ledger_paths: List[str]) -> str:
    overall = report["overall"]
    focused = report["focused"]
    lines = []
    lines.append("# Candidate Alignment Snapshot")
    lines.append("")
    lines.append(f"- corpus: `{corpus_path}`")
    lines.append(f"- ledgers: `{len(ledger_paths)}`")
    lines.append("")
    review_total = overall.get("review_total", 0)
    lines.append("## Overall")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| reviewed entries | `{review_total}` |")
    lines.append(f"| matched by any pipeline candidate | `{overall.get('review_matched_any', 0)}` ({_pct(overall.get('review_matched_any', 0), review_total)}) |")
    lines.append(f"| matched by top shortlist candidate | `{overall.get('review_matched_top', 0)}` ({_pct(overall.get('review_matched_top', 0), review_total)}) |")
    lines.append(f"| missed by any pipeline candidate | `{overall.get('review_missed_any', 0)}` ({_pct(overall.get('review_missed_any', 0), review_total)}) |")
    lines.append(f"| unmatched pipeline top candidates | `{overall.get('pipeline_top_unmatched', 0)}` |")
    lines.append("")
    lines.append("## Reviewed Families Only")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| reviewed entries | `{focused.get('review_total', 0)}` |")
    lines.append(f"| matched by any pipeline candidate | `{focused.get('review_matched_any', 0)}` ({_pct(focused.get('review_matched_any', 0), focused.get('review_total', 0))}) |")
    lines.append(f"| matched by top shortlist candidate | `{focused.get('review_matched_top', 0)}` ({_pct(focused.get('review_matched_top', 0), focused.get('review_total', 0))}) |")
    lines.append(f"| ranking misses (matched somewhere, not in top shortlist) | `{focused.get('ranking_miss', 0)}` |")
    lines.append(f"| granularity misses | `{focused.get('miss_granularity_miss', 0)}` |")
    lines.append(f"| semantic misses | `{focused.get('miss_semantic_miss', 0)}` |")
    lines.append(f"| coverage misses | `{focused.get('miss_coverage_miss', 0)}` |")
    lines.append(f"| unmatched pipeline top candidates in reviewed families | `{focused.get('pipeline_top_unmatched', 0)}` |")
    lines.append("")
    lines.append("## Family Detail")
    lines.append("")

    for fw_key, family in sorted(report["families"].items()):
        title = f"{family['vendor']} {family['model']}".strip()
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"- versions in corpus: `{', '.join(family['versions']) if family['versions'] else '-'}`")
        lines.append(f"- runs: `{family['run_count']}`")
        lines.append(f"- review entries: `{family['review_count']}`")
        lines.append(f"- pipeline candidates: `{family['pipeline_candidate_count']}`")
        lines.append(f"- pipeline top shortlist: `{family['pipeline_top_count']}`")
        lines.append("")
        if family["miss_categories"]:
            lines.append(f"- miss categories: `{dict(sorted(family['miss_categories'].items()))}`")
            lines.append("")

        if family["review_matches_top"]:
            lines.append("- matched in pipeline top shortlist:")
            for row in family["review_matches_top"]:
                lines.append(
                    f"  - `{row['name']}` -> `{row['pipeline_name']}` "
                    f"(score `{row['match_score']}`, reasons: {', '.join(row['match_reasons'])})"
                )
        if family["review_matches_any_only"]:
            lines.append("- matched somewhere in pipeline, but not in top shortlist:")
            for row in family["review_matches_any_only"]:
                lines.append(
                    f"  - `{row['name']}` -> `{row['pipeline_name']}` "
                    f"(score `{row['match_score']}`, reasons: {', '.join(row['match_reasons'])})"
                )
        if family["review_missed"]:
            lines.append("- reviewed but not matched by pipeline:")
            for row in family["review_missed"]:
                lines.append(
                    f"  - `{row['name']}` "
                    f"[{row['verdict']}] entry=`{row['entry_point'] or '-'}` sink=`{row['sink'] or '-'}`"
                )
        if family["pipeline_top_unmatched"]:
            lines.append("- pipeline shortlist items without reviewed counterpart yet:")
            for row in family["pipeline_top_unmatched"][:5]:
                lines.append(f"  - `{row['name']}`: {row['summary']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare pipeline candidates against reviewed ledger findings.")
    parser.add_argument("--corpus", required=True, help="Path to firmware corpus JSONL.")
    parser.add_argument("--ledger", action="append", default=[], help="Path to a review ledger JSONL.")
    parser.add_argument("--markdown-out", help="Write markdown summary to this path.")
    parser.add_argument("--json-out", help="Write machine-readable JSON report to this path.")
    args = parser.parse_args()

    if not os.path.isfile(args.corpus):
        print(f"not found: {args.corpus}", file=sys.stderr)
        return 1

    ledger_paths = args.ledger or discover_ledgers(args.corpus)
    corpus_rows = load_jsonl(args.corpus)

    ledger_rows = []
    for path in ledger_paths:
        if not os.path.isfile(path):
            print(f"[WARN] ledger not found: {path}", file=sys.stderr)
            continue
        ledger_rows.extend(load_jsonl(path))

    report = build_alignment(corpus_rows, ledger_rows)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    md = render_markdown(report, args.corpus, ledger_paths)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
