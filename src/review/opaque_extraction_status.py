"""
Summarize opaque / partially extracted firmware status from the corpus.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: str | Path) -> list[dict]:
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def result_path_for_row(row: dict) -> Path | None:
    run_id = str(row.get("run_id") or "")
    if not run_id:
        return None
    parts = run_id.split("/", 1)
    if len(parts) != 2:
        return None
    return PROJECT_ROOT / "runs" / parts[0] / parts[1] / "results.json"


def classify_container_type(row: dict, bundle: dict) -> str:
    targets = bundle.get("container_targets") or []
    if not targets:
        return row.get("blob_family") or "opaque-blob"
    target = targets[0]
    source_kind = str(target.get("source_kind") or "").lower()
    vendor_guess = str(target.get("vendor_guess") or "").lower()
    crypto_profile = str(target.get("crypto_profile") or "").lower()
    hints = [str(h).lower() for h in (target.get("extraction_hints") or [])]

    if "openssl" in crypto_profile or source_kind == "encrypted-container":
        return "encrypted-container"
    if "cloud" in vendor_guess:
        return "cloud-container"
    if "segmented" in source_kind or row.get("blob_family") == "tp-link-segmented-bundle":
        return "segmented-bundle"
    if any(h.startswith("embedded-") for h in hints):
        return "embedded-payload-container"
    if source_kind:
        return source_kind
    return row.get("blob_family") or "opaque-blob"


def summarize_row(row: dict) -> dict | None:
    sq = row.get("success_quality")
    if sq not in {"blob-success", "fallback-success"}:
        return None

    rp = result_path_for_row(row)
    bundle = load_json(rp) if rp and rp.is_file() else {}
    targets = bundle.get("container_targets") or []
    target = targets[0] if targets else {}
    hints = target.get("extraction_hints") or []
    source_kind = target.get("source_kind") or ""
    probe_type = ((target.get("probe_bundle") or {}).get("probe_type")) or target.get("probe_type") or ""

    recovered = []
    salvageable = []
    if sq == "blob-success":
        recovered.append("blob-candidate")
    if row.get("probe_readiness") == "scan-probe-ready":
        recovered.append("container-scan-probe")
    if row.get("probe_readiness") == "decrypt-probe-ready":
        recovered.append("decrypt-probe")
    if row.get("probe_readiness") == "bundle-probe-ready":
        recovered.append("bundle-probe")
    if targets:
        recovered.append("container-target")
    if source_kind:
        recovered.append(source_kind)
    recovered.extend(h for h in hints if h not in recovered)

    blob_family = row.get("blob_family")
    if blob_family == "tp-link-segmented-bundle":
        salvageable.extend(["web assets", "nested payloads", "chunk-level decoded blobs"])
        next_action = "deeper_extract"
    elif blob_family == "mercusys-cloud-container":
        salvageable.extend(["opaque payload", "embedded compressed payloads", "header fields"])
        next_action = "deeper_extract"
    elif blob_family == "tenda-openssl-container":
        salvageable.extend(["ciphertext payload", "decrypted candidate blobs"])
        next_action = "decrypt_attempt"
    else:
        salvageable.extend(["opaque payload", "static strings", "partial binary artifacts"])
        next_action = "static_only_analysis"

    encryption_suspected = bool(
        "encrypted" in classify_container_type(row, bundle)
        or "cloud" in classify_container_type(row, bundle)
        or row.get("probe_readiness") == "decrypt-probe-ready"
    )

    extraction_status = "partial" if targets or row.get("probe_readiness") else "opaque"
    if sq == "rootfs-success":
        extraction_status = "full_rootfs"

    return {
        "firmware": f"{row.get('vendor')} {row.get('model')} {row.get('version')}".strip(),
        "corpus_id": row.get("corpus_id"),
        "extraction_status": extraction_status,
        "container_type": classify_container_type(row, bundle),
        "nested_layers": len(targets),
        "recovered_artifacts": recovered,
        "salvageable_paths": salvageable,
        "encryption_suspected": encryption_suspected,
        "next_action": next_action,
        "probe_type": probe_type,
        "blob_family": row.get("blob_family"),
        "probe_readiness": row.get("probe_readiness"),
        "run_id": row.get("run_id"),
    }


def write_markdown(rows: list[dict], path: str | Path) -> None:
    lines = [
        "# Opaque Extraction Status",
        "",
    ]
    for row in rows:
        lines.extend([
            f"## {row['firmware']}",
            f"- extraction_status: `{row['extraction_status']}`",
            f"- container_type: `{row['container_type']}`",
            f"- nested_layers: `{row['nested_layers']}`",
            f"- recovered_artifacts: `{', '.join(row['recovered_artifacts'])}`",
            f"- salvageable_paths: `{', '.join(row['salvageable_paths'])}`",
            f"- encryption_suspected: `{row['encryption_suspected']}`",
            f"- next_action: `{row['next_action']}`",
            f"- blob_family: `{row['blob_family']}`",
            f"- probe_readiness: `{row['probe_readiness']}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--markdown-out", required=True)
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    rows = load_jsonl(args.corpus)
    out = [row for row in (summarize_row(r) for r in rows) if row]
    out.sort(key=lambda x: (x["extraction_status"] != "opaque", x["firmware"]))
    Path(args.json_out).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out, args.markdown_out)
    print(json.dumps({"rows": len(out)}, indent=2))


if __name__ == "__main__":
    main()
