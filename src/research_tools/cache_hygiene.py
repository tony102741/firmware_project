"""
Conservative cache hygiene for the firmware project.

Default behavior only reports sizes.
Use --prune-safe to remove clearly regenerable local caches only.
It never deletes preserved corpus evidence under research/regeneration unless
that logic is added deliberately later.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAFE_CACHE_DIRS = [
    PROJECT_ROOT / ".cache",
    PROJECT_ROOT / "src" / "__pycache__",
    PROJECT_ROOT / "src" / "core" / "parser" / "__pycache__",
    PROJECT_ROOT / "src" / "core" / "analyzer" / "__pycache__",
    PROJECT_ROOT / "src" / "core" / "scanner" / "__pycache__",
    PROJECT_ROOT / "src" / "research_tools" / "__pycache__",
    PROJECT_ROOT / "src" / "batch" / "__pycache__",
    PROJECT_ROOT / "src" / "corpus_tools" / "__pycache__",
    PROJECT_ROOT / "src" / "review" / "__pycache__",
]


def format_bytes(num: int) -> str:
    units = ["B", "K", "M", "G", "T"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024
    return f"{num}B"


def dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for child in path.rglob("*"):
        if child.is_file():
            try:
                total += child.stat().st_size
            except OSError:
                continue
    return total


def top_regeneration_caches(limit: int) -> list[tuple[Path, int]]:
    root = PROJECT_ROOT / "research" / "regeneration" / "full_corpus_20260508"
    entries = []
    if not root.exists():
        return entries
    for cache_dir in root.glob("*/*/.cache"):
        entries.append((cache_dir, dir_size(cache_dir)))
    entries.sort(key=lambda item: item[1], reverse=True)
    return entries[:limit]


def prune_safe() -> list[Path]:
    removed = []
    for path in SAFE_CACHE_DIRS:
        if path.exists():
            shutil.rmtree(path)
            removed.append(path)
    return removed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prune-safe", action="store_true")
    parser.add_argument("--top", type=int, default=10, help="number of largest preserved corpus caches to report")
    args = parser.parse_args()

    print("# Safe Local Caches")
    safe_total = 0
    for path in SAFE_CACHE_DIRS:
        size = dir_size(path)
        safe_total += size
        print(f"{path.relative_to(PROJECT_ROOT)}\t{format_bytes(size)}")
    print(f"safe_total\t{format_bytes(safe_total)}")

    print("\n# Largest Preserved Corpus Caches")
    for path, size in top_regeneration_caches(args.top):
        print(f"{path.relative_to(PROJECT_ROOT)}\t{format_bytes(size)}")

    if args.prune_safe:
        removed = prune_safe()
        print("\n# Removed")
        for path in removed:
            print(path.relative_to(PROJECT_ROOT))


if __name__ == "__main__":
    main()
