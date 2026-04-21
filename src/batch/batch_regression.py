"""
Batch regression runner for firmware samples.

Runs src/pipeline.py sequentially with isolated cache/run directories per sample
so extraction artifacts do not interfere with one another, then classifies each
run into SUCCESS / PARTIAL / BLOCKED / BUG.

Example:
  python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl --limit 8
  python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl --only-blocked
  python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl --write-corpus
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_ROOT.parent
PIPELINE = PROJECT_ROOT / "src" / "pipeline.py"
LLM_REVIEW = PROJECT_ROOT / "src" / "review" / "llm_review.py"
LLM_REVIEW_INFER = PROJECT_ROOT / "src" / "review" / "llm_review_infer.py"
MANUAL_REVIEW_QUEUE = PROJECT_ROOT / "src" / "review" / "manual_review_queue.py"
RUN_STATUSES = {"SUCCESS", "PARTIAL", "BLOCKED", "BUG", "SKIPPED"}
SUCCESS_QUALITIES = {"rootfs-success", "fallback-success", "blob-success"}
PROBE_READINESS = {
    "rootfs-ready",
    "fallback-ready",
    "blob-ready",
    "bundle-probe-ready",
    "decrypt-probe-ready",
    "scan-probe-ready",
}
BLOB_FAMILIES = {
    "tp-link-segmented-bundle",
    "mercusys-cloud-container",
    "tenda-openssl-container",
    "generic-container",
    "generic-blob-signal",
}
BLOCKED_MARKERS = (
    "unsupported method",
    "unsupported rar compression method",
    "encrypted firmware is not supported",
    "failed to inspect rar input",
    "failed to inspect zip input",
    "no payload.bin",
    "system partition not found",
    "no rootfs",
    "not a directory",
    "failed to unzip ota archive",
)


def llm_arming_status():
    env_key = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    anthropic_env_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    env_local = PROJECT_ROOT / ".env.local"
    secret_file = PROJECT_ROOT / ".secrets" / "openai_api_key"
    anthropic_secret_file = PROJECT_ROOT / ".secrets" / "anthropic_api_key"
    env_local_openai = False
    env_local_anthropic = False
    if env_local.is_file():
        try:
            raw = env_local.read_text(encoding="utf-8")
        except OSError:
            raw = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _ = line.split("=", 1)
            key = key.strip()
            if key == "OPENAI_API_KEY":
                env_local_openai = True
            elif key == "ANTHROPIC_API_KEY":
                env_local_anthropic = True
    return {
        "openai_env_key_present": env_key,
        "anthropic_env_key_present": anthropic_env_key,
        "env_local_present": env_local.is_file(),
        "env_local_openai_present": env_local_openai,
        "env_local_anthropic_present": env_local_anthropic,
        "openai_secret_file_present": secret_file.is_file(),
        "anthropic_secret_file_present": anthropic_secret_file.is_file(),
        "openai_api_armed": env_key or env_local_openai or secret_file.is_file(),
        "anthropic_api_armed": anthropic_env_key or env_local_anthropic or anthropic_secret_file.is_file(),
    }


def load_jsonl(path):
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            entries.append(json.loads(raw))
    return entries


def slugify(text):
    out = []
    for ch in text.lower():
        out.append(ch if ch.isalnum() else "-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "sample"


def path_label(text):
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "-", (text or "").strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" .-") or "UNKNOWN"


def load_json(path):
    if not path or not Path(path).is_file():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_jsonl(path, entries):
    with open(path, "w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False))
            fh.write("\n")


def classify_run(proc, manifest, results, output):
    lower_output = output.lower()
    summary = (results or {}).get("summary") or {}
    analysis = (results or {}).get("analysis") or {}
    candidates = (results or {}).get("candidates") or []
    blob_candidate_count = int(summary.get("blob_candidates") or 0)
    system_path = analysis.get("system_path") or ""

    if proc == "timeout":
        return "BUG", "pipeline timeout"
    if proc is None:
        return "BUG", "pipeline did not start"

    if manifest and manifest.get("status") == "completed" and results:
        if analysis and (summary.get("candidates_analyzed", 0) > 0 or candidates):
            return "SUCCESS", "completed with analysis output"
        if analysis and blob_candidate_count > 0:
            return "SUCCESS", "completed with blob-level evidence"
        if analysis and system_path:
            return "SUCCESS", "completed with extracted filesystem but no prioritized findings"
        if analysis or summary or candidates:
            return "PARTIAL", "completed with weak or incomplete analysis output"
        return "PARTIAL", "completed without summarized findings"

    if proc.returncode == 0 and manifest and manifest.get("status") == "dry_run_complete":
        return "PARTIAL", "dry run completed"

    if any(marker in lower_output for marker in BLOCKED_MARKERS):
        return "BLOCKED", "known extraction or format limitation"

    if proc.returncode == 0:
        return "PARTIAL", "process exited cleanly but run artifacts are incomplete"

    return "BUG", f"pipeline exited with rc={proc.returncode}"


def map_corpus_statuses(run_status):
    if run_status == "SUCCESS":
        return "SUCCESS", "COMPLETED"
    if run_status == "PARTIAL":
        return "PARTIAL", "COMPLETED"
    if run_status == "BLOCKED":
        return "FAILED", "BLOCKED"
    if run_status == "BUG":
        return "FAILED", "PENDING"
    return None, None


def classify_success_quality(result):
    if result.get("status") != "SUCCESS":
        return None

    analysis_mode = result.get("analysis_mode")
    candidate_count = result.get("candidate_count") or 0
    blob_candidate_count = result.get("blob_candidate_count") or 0
    system_path = (result.get("analysis_system_path") or "").lower()

    rootfs_markers = (
        "/squashfs-root",
        "/rootfs",
        "/system",
        "/_ubi_extract/",
        "/.cache/rootfs/",
    )
    if analysis_mode in {"iot_web", "android"} and any(marker in system_path for marker in rootfs_markers):
        return "rootfs-success"
    if analysis_mode == "general" and (candidate_count > 0 or blob_candidate_count > 0):
        return "blob-success"
    return "fallback-success"


def classify_blob_family(result):
    if result.get("success_quality") != "blob-success":
        return None

    candidates = result.get("_candidates") or []
    if not candidates:
        return "generic-blob-signal"

    top = candidates[0]
    flow_type = (top.get("flow_type") or "").lower()
    vendor_guess = (top.get("vendor_guess") or "").lower()
    binary_path = (top.get("binary_path") or "").lower()
    name = (top.get("name") or "").lower()
    vendor = (result.get("vendor") or "").lower()

    if flow_type == "container_signal":
        if "tenda-style" in vendor_guess or "openssl salted" in (top.get("vuln_summary") or "").lower():
            return "tenda-openssl-container"
        if "tp-link/mercusys cloud" in vendor_guess:
            if vendor == "mercusys":
                return "mercusys-cloud-container"
            return "generic-container"
        return "generic-container"

    if flow_type == "blob_signal":
        if "_decoded.bin" in binary_path or "blob-signal" in name:
            return "tp-link-segmented-bundle"
        return "generic-blob-signal"

    return "generic-blob-signal"


def classify_probe_readiness(result):
    if result.get("status") != "SUCCESS":
        return None

    success_quality = result.get("success_quality")
    if success_quality == "rootfs-success":
        return "rootfs-ready"
    if success_quality == "fallback-success":
        return "fallback-ready"

    container_targets = result.get("_container_targets") or []
    for target in container_targets:
        probe_bundle = target.get("probe_bundle") or {}
        probe_type = probe_bundle.get("probe_type")
        if probe_type == "openssl-enc-probe":
            return "decrypt-probe-ready"
        if probe_type == "container-scan-probe":
            return "scan-probe-ready"
        if probe_type == "segmented-bundle-scan-probe":
            return "bundle-probe-ready"

    if success_quality == "blob-success":
        return "blob-ready"
    return None


def update_corpus_entry(corpus_entries, entry, result):
    target = None
    for row in corpus_entries:
        if row.get("corpus_id") == entry.get("corpus_id"):
            target = row
            break
        if row.get("local_filename") == entry.get("local_filename"):
            target = row
            break
    if target is None:
        return False

    extraction_status, analysis_status = map_corpus_statuses(result["status"])
    if extraction_status:
        target["extraction_status"] = extraction_status
    if analysis_status:
        target["analysis_status"] = analysis_status
    target["run_id"] = result.get("run_id") or target.get("run_id", "")
    target["web_surface_detected"] = result.get("web_surface_detected")
    target["regression_status"] = result["status"]
    target["regression_reason"] = result.get("reason", "")
    target["success_quality"] = result.get("success_quality")
    target["probe_readiness"] = result.get("probe_readiness")
    target["blob_family"] = result.get("blob_family")
    target["last_regression_at"] = datetime.now().isoformat(timespec="seconds")
    return True


def run_one(entry, workspace_root):
    local_path = entry.get("local_path")
    if not local_path:
        return {
            "sample": entry.get("local_filename"),
            "status": "SKIPPED",
            "reason": "missing local_path",
        }

    input_path = Path(local_path)
    if not input_path.is_absolute():
        input_path = PROJECT_ROOT / local_path
    if not input_path.exists():
        return {
            "sample": entry.get("local_filename"),
            "status": "SKIPPED",
            "reason": f"missing file: {input_path}",
        }

    product_label = path_label(entry.get("model") or input_path.stem)
    version_label = path_label(input_path.stem)
    workspace_root = Path(workspace_root)
    sample_root = workspace_root / product_label / version_label
    cache_dir = sample_root / ".cache"
    runs_dir = workspace_root / "runs"
    shutil.rmtree(cache_dir, ignore_errors=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["FIRMWARE_CACHE_DIR"] = str(cache_dir)
    env["FIRMWARE_RUNS_DIR"] = str(runs_dir)
    env["FIRMWARE_INPUTS_DIR"] = str(PROJECT_ROOT / "inputs")
    env["FIRMWARE_PRODUCT_LABEL"] = product_label
    env["FIRMWARE_VERSION_LABEL"] = version_label

    cmd = ["python3", str(PIPELINE), "--input", str(input_path)]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=entry.get("_timeout_seconds"),
        )
    except subprocess.TimeoutExpired as exc:
        proc = "timeout"
        output = ((exc.stdout or "") + (exc.stderr or "")).strip()
    else:
        output = (proc.stdout or "") + (proc.stderr or "")
    elapsed = round(time.time() - started, 2)

    run_bucket = runs_dir / product_label / version_label
    manifest_files = sorted(run_bucket.rglob("manifest.json"))
    result_files = sorted(run_bucket.rglob("results.json"))
    manifest = load_json(manifest_files[-1]) if manifest_files else None
    results = load_json(result_files[-1]) if result_files else None
    status, reason = classify_run(proc, manifest, results, output)
    if status not in RUN_STATUSES:
        raise ValueError(f"unexpected status: {status}")

    summary = (results or {}).get("summary") or {}
    analysis = (results or {}).get("analysis") or {}
    candidates = (results or {}).get("candidates") or []
    return {
        "corpus_id": entry.get("corpus_id"),
        "sample": entry.get("local_filename"),
        "vendor": entry.get("vendor"),
        "model": entry.get("model"),
        "version": entry.get("version"),
        "returncode": None if proc == "timeout" else proc.returncode,
        "status": status,
        "reason": reason,
        "elapsed_seconds": elapsed,
        "run_id": (manifest or {}).get("run_id"),
        "manifest_json": str(manifest_files[-1]) if manifest_files else None,
        "results_json": str(result_files[-1]) if result_files else None,
        "analysis_mode": analysis.get("mode"),
        "analysis_system_path": analysis.get("system_path"),
        "candidates_analyzed": summary.get("candidates_analyzed"),
        "candidate_count": len(candidates),
        "blob_candidate_count": int(summary.get("blob_candidates") or 0),
        "web_surface_detected": None if summary.get("web_exposed") is None else summary.get("web_exposed", 0) > 0,
        "tail": "\n".join(output.strip().splitlines()[-20:]),
        "_candidates": candidates,
        "_container_targets": (results or {}).get("container_targets") or [],
    }


def run_llm_followup(args, entries, results):
    llm_corpus_path = args.corpus
    temp_corpus_path = None
    if entries:
        source_rows = load_jsonl(args.corpus)
        corpus_entries = []
        wanted_ids = {e.get("corpus_id") for e in entries if e.get("corpus_id")}
        wanted_files = {e.get("local_filename") for e in entries if e.get("local_filename")}
        for row in source_rows:
            if row.get("corpus_id") in wanted_ids or row.get("local_filename") in wanted_files:
                corpus_entries.append(row)
        updated = 0
        for entry, result in zip(entries, results):
            if update_corpus_entry(corpus_entries, entry, result):
                updated += 1
        if updated:
            temp_corpus_path = Path(args.workspace_root) / "llm_followup_corpus.jsonl"
            write_jsonl(temp_corpus_path, corpus_entries)
            llm_corpus_path = str(temp_corpus_path)

    packet_path = Path(args.llm_packets_output or (PROJECT_ROOT / "research" / "review" / "llm" / "llm_review_packets.jsonl"))
    compact_packet_path = Path(
        args.llm_packets_compact_output or (PROJECT_ROOT / "research" / "review" / "llm" / "llm_review_packets_compact.jsonl")
    )
    prediction_path = Path(
        args.llm_predictions_output or (PROJECT_ROOT / "research" / "review" / "llm" / "llm_review_predictions_hybrid.jsonl")
    )

    review_cmd = [
        "python3",
        str(LLM_REVIEW),
        "--corpus",
        llm_corpus_path,
        "--batch-summary",
        args.json_output,
        "--emit-corpus-packets",
        str(packet_path),
        "--emit-corpus-packets-compact",
        str(compact_packet_path),
    ]
    if args.write_corpus:
        review_cmd.extend(["--write-gold-stubs", str(PROJECT_ROOT / "research" / "review" / "llm" / "llm_review_gold.jsonl")])
    subprocess.run(review_cmd, cwd=str(PROJECT_ROOT), check=True)

    infer_cmd = [
        "python3",
        str(LLM_REVIEW_INFER),
        "--packets",
        str(packet_path),
        "--provider",
        args.llm_provider,
        "--output",
        str(prediction_path),
        "--fallback-provider",
        args.llm_fallback_provider,
    ]
    if args.llm_provider in {"openai", "hybrid"}:
        infer_cmd.extend(["--model", args.llm_model])
    if args.llm_preflight:
        infer_cmd.append("--preflight")
    if args.llm_limit:
        infer_cmd.extend(["--limit", str(args.llm_limit)])
    subprocess.run(infer_cmd, cwd=str(PROJECT_ROOT), check=True)

    return {
        "corpus_path": llm_corpus_path,
        "temp_corpus_path": str(temp_corpus_path) if temp_corpus_path else None,
        "packet_path": str(packet_path),
        "compact_packet_path": str(compact_packet_path),
        "prediction_path": str(prediction_path),
        "provider": args.llm_provider,
        "model": args.llm_model if args.llm_provider in {"openai", "hybrid"} else "heuristic-baseline",
        "preflight": args.llm_preflight,
        "fallback_provider": args.llm_fallback_provider,
    }


def run_manual_review_queue(args):
    packet_path = Path(args.llm_packets_output or (PROJECT_ROOT / "research" / "review" / "llm" / "llm_review_packets.jsonl"))
    queue_json = Path(args.review_queue_json_output or (PROJECT_ROOT / "research" / "review" / "manual" / "manual_review_queue.json"))
    queue_jsonl = Path(args.review_queue_jsonl_output or (PROJECT_ROOT / "research" / "review" / "manual" / "manual_review_queue.jsonl"))
    queue_md = Path(args.review_queue_markdown_output or (PROJECT_ROOT / "research" / "review" / "manual" / "manual_review_queue.md"))
    manual_labels = Path(args.manual_review_labels or (PROJECT_ROOT / "research" / "review" / "manual" / "manual_review_labels.jsonl"))

    cmd = [
        "python3",
        str(MANUAL_REVIEW_QUEUE),
        "--packets",
        str(packet_path),
        "--json-out",
        str(queue_json),
        "--jsonl-out",
        str(queue_jsonl),
        "--markdown-out",
        str(queue_md),
    ]
    if manual_labels.is_file():
        cmd.extend(["--manual", str(manual_labels)])
    if args.review_queue_limit:
        cmd.extend(["--limit", str(args.review_queue_limit)])
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)
    return {
        "packet_path": str(packet_path),
        "manual_labels": str(manual_labels) if manual_labels.is_file() else None,
        "queue_json": str(queue_json),
        "queue_jsonl": str(queue_jsonl),
        "queue_markdown": str(queue_md),
        "limit": args.review_queue_limit or None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only-blocked", action="store_true")
    ap.add_argument("--workspace-root", default="/tmp/fw_batch_regression")
    ap.add_argument("--timeout", type=int, default=1800, help="Per-sample timeout in seconds.")
    ap.add_argument("--json-output", help="Write the batch summary JSON to this path.")
    ap.add_argument("--write-corpus", action="store_true", help="Update the corpus JSONL in place with regression statuses.")
    ap.add_argument("--with-llm", action="store_true", help="After regression, generate review packets and run LLM inference automatically.")
    ap.add_argument("--llm-provider", choices=("heuristic", "openai", "hybrid"), default="heuristic")
    ap.add_argument("--llm-model", default=os.environ.get("OPENAI_MODEL", "gpt-5.2"))
    ap.add_argument("--llm-preflight", action="store_true", help="Run OpenAI preflight before hybrid/openai inference.")
    ap.add_argument("--llm-fallback-provider", choices=("heuristic", "fail"), default="heuristic")
    ap.add_argument("--llm-limit", type=int, default=0, help="Optional limit for the follow-up LLM pass.")
    ap.add_argument("--llm-packets-output", help="Override JSONL output path for full review packets.")
    ap.add_argument("--llm-packets-compact-output", help="Override JSONL output path for compact review packets.")
    ap.add_argument("--llm-predictions-output", help="Override JSONL output path for LLM predictions.")
    ap.add_argument("--with-review-queue", action="store_true", help="After packet generation, write a prioritized manual review queue.")
    ap.add_argument("--manual-review-labels", help="Manual review labels JSONL used to suppress already-reviewed rows.")
    ap.add_argument("--review-queue-limit", type=int, default=0, help="Optional top-N limit for the emitted review queue.")
    ap.add_argument("--review-queue-json-output", help="Override JSON path for the manual review queue.")
    ap.add_argument("--review-queue-jsonl-output", help="Override JSONL path for the manual review queue.")
    ap.add_argument("--review-queue-markdown-output", help="Override Markdown path for the manual review queue.")
    args = ap.parse_args()
    if (args.with_llm or args.with_review_queue) and not args.json_output:
        args.json_output = str(PROJECT_ROOT / "runs" / "regression" / "batch_regression_summary.json")
    if args.with_llm:
        print(json.dumps({"llm_arming": llm_arming_status()}, ensure_ascii=False, indent=2), flush=True)

    entries = load_jsonl(args.corpus)
    if args.only_blocked:
        entries = [
            e for e in entries
            if e.get("analysis_status") == "BLOCKED" or e.get("extraction_status") == "FAILED"
        ]
    if args.limit:
        entries = entries[: args.limit]
    for entry in entries:
        entry["_timeout_seconds"] = args.timeout

    Path(args.workspace_root).mkdir(parents=True, exist_ok=True)
    results = []
    for idx, entry in enumerate(entries, 1):
        print(
            f"[{idx}/{len(entries)}] {entry.get('vendor')} {entry.get('model')} "
            f"{entry.get('version')} -> {entry.get('local_filename')}",
            flush=True,
        )
        result = run_one(entry, args.workspace_root)
        result["success_quality"] = classify_success_quality(result)
        result["blob_family"] = classify_blob_family(result)
        result["probe_readiness"] = classify_probe_readiness(result)
        results.append(result)
        print(
            f"    {result['status']} rc={result.get('returncode')} "
            f"elapsed={result.get('elapsed_seconds')}s "
            f"reason={result.get('reason')}"
            + (f" quality={result['success_quality']}" if result.get("success_quality") else "")
            + (f" probe={result['probe_readiness']}" if result.get("probe_readiness") else "")
            + (f" blob_family={result['blob_family']}" if result.get("blob_family") else ""),
            flush=True,
        )
        if result["status"] in {"BLOCKED", "BUG"} and result.get("tail"):
            print(result["tail"], flush=True)

    counts = {status.lower(): sum(1 for r in results if r["status"] == status) for status in RUN_STATUSES}
    quality_counts = {
        quality: sum(1 for r in results if r.get("success_quality") == quality)
        for quality in SUCCESS_QUALITIES
    }
    readiness_counts = {
        readiness: sum(1 for r in results if r.get("probe_readiness") == readiness)
        for readiness in PROBE_READINESS
    }
    payload = {
        "total": len(results),
        "workspace_root": args.workspace_root,
        "counts": counts,
        "success_quality_counts": quality_counts,
        "probe_readiness_counts": readiness_counts,
        "blob_family_counts": {
            family: sum(1 for r in results if r.get("blob_family") == family)
            for family in BLOB_FAMILIES
        },
        "results": [
            {k: v for k, v in r.items() if k not in {"_candidates", "_container_targets"}}
            for r in results
        ],
    }

    if args.write_corpus:
        corpus_entries = load_jsonl(args.corpus)
        updated = 0
        for entry, result in zip(entries, results):
            if update_corpus_entry(corpus_entries, entry, result):
                updated += 1
        write_jsonl(args.corpus, corpus_entries)
        payload["corpus_updates"] = updated

    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_output:
        Path(args.json_output).write_text(rendered + "\n", encoding="utf-8")

    if args.with_llm:
        llm_payload = run_llm_followup(args, entries, results)
        payload["llm_followup"] = llm_payload
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
        print(json.dumps({"llm_followup": llm_payload}, indent=2, ensure_ascii=False))
        if args.json_output:
            Path(args.json_output).write_text(rendered + "\n", encoding="utf-8")

    if args.with_review_queue:
        queue_payload = run_manual_review_queue(args)
        payload["manual_review_queue"] = queue_payload
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
        print(json.dumps({"manual_review_queue": queue_payload}, indent=2, ensure_ascii=False))
        if args.json_output:
            Path(args.json_output).write_text(rendered + "\n", encoding="utf-8")

    return 0 if counts["bug"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
