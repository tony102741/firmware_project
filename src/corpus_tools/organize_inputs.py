"""
Organize firmware files under inputs/ by product folder and remove stray
Zone.Identifier sidecar files. Optionally sync the corpus local_path fields.

Usage:
  python3 src/corpus_tools/organize_inputs.py
  python3 src/corpus_tools/organize_inputs.py --write-corpus
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from corpus_tools.corpus import load_jsonl
from corpus_tools.corpus_sync import ZONE_SUFFIX, infer_entry, path_label


def load_corpus_rows(corpus_path):
    rows, errors = load_jsonl(corpus_path)
    if errors:
        raise ValueError("\n".join(errors))
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")


def desired_product_dir(path, inputs_dir, corpus_by_path, corpus_by_name):
    rel = str(path.relative_to(inputs_dir)).replace("\\", "/")
    row = corpus_by_path.get(rel) or corpus_by_name.get(path.name)
    if row and row.get("model"):
        return path_label(row["model"])
    inferred = infer_entry(path, inputs_root=inputs_dir)
    return path_label(inferred.get("model") or path.stem)


def organize_inputs(inputs_dir, corpus_rows):
    corpus_by_path = {}
    for row in corpus_rows:
        local_path = row.get("local_path")
        if not local_path:
            continue
        try:
            rel = str(Path(local_path).relative_to(inputs_dir)).replace("\\", "/")
        except Exception:
            rel = str(Path(local_path).as_posix()).removeprefix("inputs/").replace("\\", "/")
        corpus_by_path[rel] = row
    corpus_by_name = {}
    for row in corpus_rows:
        name = row.get("local_filename")
        if name and name not in corpus_by_name:
            corpus_by_name[name] = row

    moved = []
    removed_zone = []
    skipped = []
    root = Path(inputs_dir)

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        if path.name.endswith(ZONE_SUFFIX):
            path.unlink(missing_ok=True)
            removed_zone.append(str(path.relative_to(root)).replace("\\", "/"))
            continue

        product_dir = desired_product_dir(path, root, corpus_by_path, corpus_by_name)
        dest = root / product_dir / path.name
        if path == dest:
            continue
        if dest.exists():
            skipped.append({
                "source": str(path.relative_to(root)).replace("\\", "/"),
                "reason": f"destination exists: {dest.relative_to(root)}",
            })
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest))
        moved.append({
            "from": str(path.relative_to(root)).replace("\\", "/"),
            "to": str(dest.relative_to(root)).replace("\\", "/"),
            "product_dir": product_dir,
        })

        for row in corpus_rows:
            row_local = row.get("local_path")
            if not row_local:
                continue
            current = str(Path(row_local).as_posix()).removeprefix("inputs/")
            if current == moved[-1]["from"] or row.get("local_filename") == dest.name:
                row["local_path"] = f"inputs/{moved[-1]['to']}"
                row["local_filename"] = dest.name

    file_index = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.name.endswith(ZONE_SUFFIX):
            file_index.setdefault(path.name, []).append(path)

    for row in corpus_rows:
        matches = file_index.get(row.get("local_filename") or "", [])
        if len(matches) == 1:
            rel = str(matches[0].relative_to(root)).replace("\\", "/")
            row["local_path"] = f"inputs/{rel}"

    # prune now-empty directories below inputs/
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass

    return {
        "moved": moved,
        "removed_zone": removed_zone,
        "skipped": skipped,
        "corpus_rows": corpus_rows,
    }


def main():
    ap = argparse.ArgumentParser(description="Group inputs/ firmware files by product folder.")
    ap.add_argument("--inputs", default="inputs")
    ap.add_argument("--corpus", default="research/corpus/firmware_corpus.jsonl")
    ap.add_argument("--write-corpus", action="store_true")
    args = ap.parse_args()

    corpus_rows = load_corpus_rows(args.corpus)
    result = organize_inputs(args.inputs, corpus_rows)
    print(json.dumps({
        "moved_count": len(result["moved"]),
        "removed_zone_count": len(result["removed_zone"]),
        "skipped_count": len(result["skipped"]),
        "moved": result["moved"],
        "removed_zone": result["removed_zone"],
        "skipped": result["skipped"],
    }, ensure_ascii=False, indent=2))

    if args.write_corpus:
        write_jsonl(args.corpus, result["corpus_rows"])


if __name__ == "__main__":
    main()
