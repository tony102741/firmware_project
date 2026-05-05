"""
Show whether the current corpus still has blind-first expansion headroom.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load_jsonl(path: str | Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_reviewed_ids(paths: list[str | Path]) -> set[str]:
    out: set[str] = set()
    for path in paths:
        p = Path(path)
        if not p.is_file():
            continue
        for row in load_jsonl(p):
            rid = str(row.get("review_id") or "").strip()
            if rid:
                out.add(rid)
    return out


def write_markdown(corpus_rows: list[dict], reviewed_ids: set[str], path: str | Path) -> None:
    corpus_ids = {str(r.get("corpus_id") or "").strip() for r in corpus_rows if r.get("corpus_id")}
    missing = [r for r in corpus_rows if str(r.get("corpus_id") or "").strip() not in reviewed_ids]
    vendor_counts = Counter(r.get("vendor") or "UNKNOWN" for r in corpus_rows)
    lines = [
        "# Blind-First Expansion Report",
        "",
        f"- corpus_rows: `{len(corpus_rows)}`",
        f"- reviewed_ids: `{len(reviewed_ids)}`",
        f"- corpus_review_gap: `{len(missing)}`",
        f"- vendors: `{dict(vendor_counts)}`",
        "",
    ]
    if not missing:
        lines.extend([
            "## Status",
            "- Current corpus is saturated: every corpus_id already has a reviewed label.",
            "- Next blind-first growth requires new firmware families or new versions outside the current 54-row corpus.",
            "",
            "## Recommended Next Input Families",
            "- `MR60X / MR70X`: expand Mercusys web/router family beyond the single MR90X line.",
            "- `TX2Pro / X6000R`: expand Tenda family beyond the current AX12Pro/RX9 Pro coverage.",
            "- `RT2600ac`: add more Synology versions to improve memory-corruption vs no-clear-rce boundaries.",
            "- `RAX50`: add more Netgear versions because current corpus only has one reviewed family line.",
        ])
    else:
        lines.extend(["## Missing Reviewed Labels", ""])
        for row in missing:
            lines.append(f"- `{row['corpus_id']}` — `{row['vendor']} {row['model']} {row['version']}`")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--labels", nargs="+", required=True)
    ap.add_argument("--markdown-out", required=True)
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    corpus_rows = load_jsonl(args.corpus)
    reviewed_ids = load_reviewed_ids(args.labels)
    missing = [
        {
            "corpus_id": r.get("corpus_id"),
            "vendor": r.get("vendor"),
            "model": r.get("model"),
            "version": r.get("version"),
        }
        for r in corpus_rows
        if str(r.get("corpus_id") or "").strip() not in reviewed_ids
    ]
    write_markdown(corpus_rows, reviewed_ids, args.markdown_out)
    Path(args.json_out).write_text(json.dumps({
        "corpus_rows": len(corpus_rows),
        "reviewed_ids": len(reviewed_ids),
        "missing_review_ids": missing,
    }, indent=2), encoding="utf-8")
    print(json.dumps({
        "corpus_rows": len(corpus_rows),
        "reviewed_ids": len(reviewed_ids),
        "missing": len(missing),
    }, indent=2))


if __name__ == "__main__":
    main()
