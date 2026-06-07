from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    return Path(os.environ.get("FIRMWARE_PROJECT_ROOT", Path(__file__).resolve().parents[2])).resolve()


def regeneration_dir() -> Path:
    return project_root() / "research/regeneration/full_corpus_20260508"


def ghidra_targets_dir() -> Path:
    return project_root() / "ghidra_targets"


def relative_to_project(path: str | Path) -> str:
    path_obj = Path(path)
    try:
        return str(path_obj.resolve().relative_to(project_root()))
    except (OSError, ValueError):
        return str(path_obj)
