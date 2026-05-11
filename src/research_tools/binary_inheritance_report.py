"""
Corpus-wide inheritance analysis for orchestration binaries and helpers.

Usage:
  python3 src/research_tools/binary_inheritance_report.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"
TARGET_NAMES = {
    "connmode",
    "cwmp",
    "meshd",
    "v6plus",
    "getfirm",
    "dut_auto_upgrade",
    "firmware.lua",
    "offline_download_monitor.lua",
}
REPORT_FILES = [
    "binary_inheritance_report.md",
    "cross_vendor_binary_reuse.md",
    "orchestration_binary_clusters.md",
    "sdk_artifact_recurrence.md",
    "shared_build_environment_evidence.md",
]
FAMILY_PREFERENCE = {
    "openwrt-vendor-management-stack": 0,
    "openwrt-shell-helper-sdk": 1,
    "openwrt-mtk-lua-wireless": 2,
    "legacy-boa-apmib": 3,
    "mixed-embedded-control-plane": 4,
    "dual-httpd-lighttpd-nvram": 5,
    "lighttpd-cgi-mtk": 6,
    "opaque-or-partial": 7,
}


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def stable_id(*parts: str, size: int = 12) -> str:
    payload = "||".join(str(x or "") for x in parts)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:size]


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_cmd(args: list[str], path: Path) -> str:
    try:
        proc = subprocess.run(
            args + [str(path)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return proc.stdout
    except Exception:
        return ""


def file_description(path: Path) -> str:
    return run_cmd(["file", "-b"], path).strip()


def _is_text_blob(blob: bytes) -> bool:
    if not blob:
        return True
    if b"\x00" in blob:
        return False
    good = sum(1 for b in blob if b in b"\t\n\r\f\b" or 32 <= b < 127)
    return (good / max(1, len(blob))) > 0.9


def detect_kind(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except Exception:
        return "unknown"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if path.suffix.lower() == ".lua":
        return "lua"
    if head.startswith(b"#!"):
        return "script"
    if _is_text_blob(head):
        return "text"
    return "binary-other"


def normalize_text(content: str, kind: str) -> str:
    lines = []
    for raw in content.splitlines():
        line = raw.rstrip()
        if kind in {"script", "text"}:
            stripped = line.strip()
            if stripped.startswith("#!"):
                lines.append("#!")
                continue
            if stripped.startswith("#") or not stripped:
                continue
            line = re.sub(r"\s+", " ", stripped)
        elif kind == "lua":
            stripped = line.strip()
            if stripped.startswith("--") or not stripped:
                continue
            line = re.sub(r"\s+", " ", stripped)
        else:
            line = re.sub(r"\s+", " ", line.strip())
        if line:
            lines.append(line)
    return "\n".join(lines)


def normalize_string_token(token: str) -> str:
    token = token.strip()
    if not token:
        return ""
    token = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", token)
    token = re.sub(r"\b\d+\b", "<NUM>", token)
    token = re.sub(r"/tmp/[\w./-]+", "/tmp/<PATH>", token)
    token = re.sub(r"/var/[\w./-]+", "/var/<PATH>", token)
    token = re.sub(r"/proc/\d+", "/proc/<PID>", token)
    return token


def is_build_noise_string(token: str) -> bool:
    raw = token.strip()
    return any(
        raw.startswith(prefix)
        for prefix in (
            "GCC: (OpenWrt GCC ",
            "GCC: (GNU) ",
            "clang version ",
            "OpenWrt GCC ",
        )
    )


def parse_readelf_header(path: Path) -> dict:
    text = run_cmd(["readelf", "-h"], path)
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = [part.strip() for part in line.split(":", 1)]
        if k in {"Class", "Data", "Machine", "Type"}:
            out[k.lower()] = v
    return out


def parse_readelf_notes(path: Path) -> dict:
    text = run_cmd(["readelf", "-n"], path)
    build_id = ""
    for line in text.splitlines():
        if "Build ID:" in line:
            build_id = line.split("Build ID:", 1)[1].strip()
            break
    return {"build_id": build_id}


def parse_readelf_dynamic(path: Path) -> dict:
    text = run_cmd(["readelf", "-d"], path)
    libs = []
    interp = ""
    for line in text.splitlines():
        m = re.search(r"Shared library: \[(.+?)\]", line)
        if m:
            libs.append(m.group(1))
        if "program interpreter" in line.lower():
            m = re.search(r"\[(.+?)\]", line)
            if m:
                interp = m.group(1)
    return {
        "needed_libs": sorted(set(libs)),
        "interpreter": interp,
    }


def parse_dyn_imports(path: Path) -> list[str]:
    text = run_cmd(["readelf", "--dyn-syms", "--wide"], path)
    imports = []
    for line in text.splitlines():
        if " UND " not in f" {line} ":
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        name = name.split("@", 1)[0].strip()
        if name:
            imports.append(name)
    return sorted(set(imports))


def parse_strings(path: Path) -> list[str]:
    text = run_cmd(["strings", "-a", "-n", "4"], path)
    tokens = []
    for raw in text.splitlines():
        token = normalize_string_token(raw)
        if 4 <= len(token) <= 200 and not is_build_noise_string(token):
            tokens.append(token)
    return tokens


def rel_after_root(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root).as_posix()
    except Exception:
        rel = os.path.relpath(str(path), str(root)).replace("\\", "/")
    parts = rel.split("/")
    for idx, part in enumerate(parts):
        if re.fullmatch(r"(squashfs-root(?:-\d+)?)|(rootfs(?:-\d+)?)|ubifs-root", part):
            suffix = "/".join(parts[idx + 1 :]).strip("/")
            if suffix:
                return suffix
    return rel


def rel_rank(relpath: str) -> tuple[int, int, str]:
    parts = relpath.split("/")
    penalty = 1 if any(re.fullmatch(r"squashfs-root-\d+", part) for part in parts) else 0
    return (penalty, len(parts), relpath)


def architecture_sort_key(family: str) -> tuple[int, str]:
    return (FAMILY_PREFERENCE.get(family, 99), family)


@dataclass
class ArtifactRecord:
    corpus_id: str
    vendor: str
    model: str
    version: str
    architecture_family: str
    run_id: str
    target_name: str
    relpath: str
    kind: str
    path: Path
    sha256: str
    size: int
    normalized_sha256: str = ""
    file_desc: str = ""
    elf_header: dict | None = None
    elf_notes: dict | None = None
    elf_dynamic: dict | None = None
    dyn_imports: list[str] | None = None
    strings_sha256: str = ""
    string_sample: list[str] | None = None

    @property
    def label(self) -> str:
        return f"{self.vendor} {self.model} {self.version}"


def iter_results(workspace_root: Path) -> Iterable[tuple[Path, dict]]:
    for path in sorted((workspace_root / "runs").glob("**/results.json")):
        try:
            yield path, load_json(path)
        except Exception:
            continue


def resolve_system_root(bundle: dict) -> Path | None:
    fs = bundle.get("filesystem_inventory") or {}
    art = bundle.get("artifact_paths") or {}
    analysis = bundle.get("analysis") or {}
    candidates = [
        fs.get("system_root"),
        art.get("system_path"),
        analysis.get("system_path"),
    ]
    for raw in candidates:
        if not raw:
            continue
        p = Path(str(raw))
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()
        if p.exists():
            return p
    return None


def record_from_path(meta: dict, family: str, target_name: str, system_root: Path, path: Path) -> ArtifactRecord | None:
    if not path.is_file():
        return None
    kind = detect_kind(path)
    sha = sha256_path(path)
    relpath = rel_after_root(system_root, path)
    size = path.stat().st_size
    file_desc = file_description(path)
    record = ArtifactRecord(
        corpus_id=str(meta.get("corpus_id") or ""),
        vendor=str(meta.get("vendor") or "UNKNOWN"),
        model=str(meta.get("model") or "UNKNOWN"),
        version=str(meta.get("version") or "UNKNOWN"),
        architecture_family=family or "unknown",
        run_id=str(meta.get("run_id") or ""),
        target_name=target_name,
        relpath=relpath,
        kind=kind,
        path=path,
        sha256=sha,
        size=size,
        file_desc=file_desc,
    )
    if kind in {"script", "text", "lua"}:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        normalized = normalize_text(text, "lua" if kind == "lua" else "script")
        record.normalized_sha256 = sha256_text(normalized) if normalized else ""
        tokens = [normalize_string_token(line) for line in normalized.splitlines() if line.strip()]
        record.string_sample = tokens[:20]
        record.strings_sha256 = sha256_text("\n".join(tokens)) if tokens else ""
    elif kind == "elf":
        record.elf_header = parse_readelf_header(path)
        record.elf_notes = parse_readelf_notes(path)
        record.elf_dynamic = parse_readelf_dynamic(path)
        if record.elf_dynamic is not None and not record.elf_dynamic.get("interpreter"):
            m = re.search(r"interpreter\s+([^,]+)", file_desc)
            if m:
                record.elf_dynamic["interpreter"] = m.group(1).strip()
        record.dyn_imports = parse_dyn_imports(path)
        tokens = parse_strings(path)
        record.string_sample = tokens[:30]
        record.strings_sha256 = sha256_text("\n".join(tokens)) if tokens else ""
    return record


def collect_records(workspace_root: Path) -> tuple[list[ArtifactRecord], dict[str, dict]]:
    records: list[ArtifactRecord] = []
    bundle_index = {}
    for _, bundle in iter_results(workspace_root):
        meta = bundle.get("target_metadata") or {}
        corpus_id = str(meta.get("corpus_id") or "").strip()
        if not corpus_id:
            continue
        bundle_index[corpus_id] = bundle
        system_root = resolve_system_root(bundle)
        if not system_root or not system_root.exists():
            continue
        family = str((bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        per_target_dedupe: dict[tuple[str, str], ArtifactRecord] = {}
        for path in system_root.rglob("*"):
            if path.name not in TARGET_NAMES or not path.is_file():
                continue
            rec = record_from_path(meta, family, path.name, system_root, path)
            if not rec:
                continue
            key = (rec.target_name, rec.sha256)
            existing = per_target_dedupe.get(key)
            if existing is None or rel_rank(rec.relpath) < rel_rank(existing.relpath):
                per_target_dedupe[key] = rec
        records.extend(sorted(per_target_dedupe.values(), key=lambda r: (r.corpus_id, r.target_name, r.relpath)))
    return records, bundle_index


def exact_cluster_id(record: ArtifactRecord) -> str:
    if record.kind == "elf":
        return stable_id("exact", record.target_name, record.kind, record.sha256)
    return stable_id("exact-helper", record.target_name, record.kind, record.sha256)


def near_cluster_id(record: ArtifactRecord) -> str:
    if record.kind != "elf":
        return ""
    header = record.elf_header or {}
    dyn = record.elf_dynamic or {}
    imports = record.dyn_imports or []
    return stable_id(
        "near",
        record.target_name,
        header.get("class", ""),
        header.get("data", ""),
        header.get("machine", ""),
        header.get("type", ""),
        dyn.get("interpreter", ""),
        "|".join(dyn.get("needed_libs", [])),
        "|".join(imports),
        record.strings_sha256,
    )


def build_analysis(records: list[ArtifactRecord]) -> dict:
    exact_clusters = defaultdict(list)
    exact_helper_clusters = defaultdict(list)
    near_clusters = defaultdict(list)
    helper_norm_clusters = defaultdict(list)
    basename_counts = Counter()
    family_counts = Counter()

    for rec in records:
        basename_counts[rec.target_name] += 1
        family_counts[rec.architecture_family] += 1
        if rec.kind == "elf":
            exact_clusters[exact_cluster_id(rec)].append(rec)
            near_clusters[near_cluster_id(rec)].append(rec)
        elif rec.kind in {"lua", "script", "text"}:
            exact_helper_clusters[exact_cluster_id(rec)].append(rec)
            if rec.normalized_sha256:
                helper_norm_clusters[
                    stable_id("helper-norm", rec.target_name, rec.kind, rec.normalized_sha256)
                ].append(rec)

    return {
        "records": records,
        "basename_counts": basename_counts,
        "family_counts": family_counts,
        "exact_clusters": exact_clusters,
        "exact_helper_clusters": exact_helper_clusters,
        "near_clusters": near_clusters,
        "helper_norm_clusters": helper_norm_clusters,
    }


def vendors(records: list[ArtifactRecord]) -> list[str]:
    return sorted({rec.vendor for rec in records})


def models(records: list[ArtifactRecord]) -> list[str]:
    return sorted({f"{rec.vendor} {rec.model}" for rec in records})


def corpus_ids(records: list[ArtifactRecord]) -> list[str]:
    return sorted({rec.corpus_id for rec in records})


def architectures(records: list[ArtifactRecord]) -> list[str]:
    return sorted({rec.architecture_family for rec in records}, key=architecture_sort_key)


def exact_reuse_rows(clusters: dict[str, list[ArtifactRecord]]) -> list[dict]:
    rows = []
    for cid, recs in clusters.items():
        corpus = corpus_ids(recs)
        if len(corpus) < 2:
            continue
        sha_values = sorted({rec.sha256 for rec in recs})
        rows.append(
            {
                "cluster_id": cid,
                "target_name": recs[0].target_name,
                "kind": recs[0].kind,
                "sha256": sha_values[0],
                "count": len(corpus),
                "corpus_ids": corpus,
                "vendors": vendors(recs),
                "models": models(recs),
                "architectures": architectures(recs),
                "records": sorted(recs, key=lambda r: (r.vendor, r.model, r.version, r.relpath)),
            }
        )
    return sorted(rows, key=lambda row: (-len(row["vendors"]), -row["count"], row["target_name"], row["cluster_id"]))


def near_reuse_rows(clusters: dict[str, list[ArtifactRecord]]) -> list[dict]:
    rows = []
    for cid, recs in clusters.items():
        sha_values = sorted({rec.sha256 for rec in recs})
        corpus = corpus_ids(recs)
        if len(corpus) < 2 or len(sha_values) < 2:
            continue
        header = recs[0].elf_header or {}
        dyn = recs[0].elf_dynamic or {}
        rows.append(
            {
                "cluster_id": cid,
                "target_name": recs[0].target_name,
                "count": len(corpus),
                "sha_count": len(sha_values),
                "corpus_ids": corpus,
                "vendors": vendors(recs),
                "models": models(recs),
                "architectures": architectures(recs),
                "elf_header": header,
                "interpreter": dyn.get("interpreter", ""),
                "needed_libs": dyn.get("needed_libs", []),
                "import_count": len(recs[0].dyn_imports or []),
                "strings_sha256": recs[0].strings_sha256,
                "records": sorted(recs, key=lambda r: (r.vendor, r.model, r.version, r.relpath)),
            }
        )
    return sorted(rows, key=lambda row: (-len(row["vendors"]), -row["count"], row["target_name"], row["cluster_id"]))


def helper_reuse_rows(clusters: dict[str, list[ArtifactRecord]]) -> list[dict]:
    rows = []
    for cid, recs in clusters.items():
        corpus = corpus_ids(recs)
        if len(corpus) < 2:
            continue
        rows.append(
            {
                "cluster_id": cid,
                "target_name": recs[0].target_name,
                "kind": recs[0].kind,
                "count": len(corpus),
                "corpus_ids": corpus,
                "vendors": vendors(recs),
                "models": models(recs),
                "architectures": architectures(recs),
                "records": sorted(recs, key=lambda r: (r.vendor, r.model, r.version, r.relpath)),
            }
        )
    return sorted(rows, key=lambda row: (-len(row["vendors"]), -row["count"], row["target_name"], row["cluster_id"]))


def render_record_bullets(records: list[ArtifactRecord], limit: int = 12) -> list[str]:
    lines = []
    for rec in records[:limit]:
        lines.append(
            f"- `{rec.label}` / family=`{rec.architecture_family}` / relpath=`{rec.relpath}`"
        )
    if len(records) > limit:
        lines.append(f"- `... {len(records) - limit} more`")
    return lines or ["- `(none)`"]


def render_cluster_header(row: dict, include_sha: bool = False) -> list[str]:
    line = (
        f"## `{row['target_name']}` `{row['cluster_id']}`\n"
        f"\n"
        f"- kind: `{row.get('kind') or 'elf'}`\n"
        f"- corpus targets: `{row['count']}`\n"
        f"- vendors: `{', '.join(row['vendors'])}`\n"
        f"- architectures: `{', '.join(row['architectures'])}`"
    )
    out = line.splitlines()
    if include_sha and row.get("sha256"):
        out.append(f"- sha256: `{row['sha256']}`")
    return out


def build_reports(workspace_root: Path, analysis: dict, bundle_index: dict[str, dict]) -> dict[str, list[str]]:
    records: list[ArtifactRecord] = analysis["records"]
    fresh_targets = len(bundle_index)
    targets_with_hits = len({rec.corpus_id for rec in records})
    exact_rows = exact_reuse_rows(analysis["exact_clusters"])
    helper_exact_rows = helper_reuse_rows(analysis["exact_helper_clusters"])
    helper_norm_rows = helper_reuse_rows(analysis["helper_norm_clusters"])
    near_rows = near_reuse_rows(analysis["near_clusters"])

    cross_vendor_exact = [row for row in exact_rows if len(row["vendors"]) > 1]
    cross_vendor_helper = [row for row in helper_exact_rows if len(row["vendors"]) > 1]
    cross_vendor_near = [row for row in near_rows if len(row["vendors"]) > 1]

    by_target = Counter(rec.target_name for rec in records)
    by_kind = Counter(rec.kind for rec in records)
    by_family = Counter(rec.architecture_family for rec in records)

    build_env_rows = []
    for row in exact_rows + near_rows:
        rec = row["records"][0]
        header = rec.elf_header or {}
        dynamic = rec.elf_dynamic or {}
        build_env_rows.append(
            {
                "target_name": row["target_name"],
                "cluster_id": row["cluster_id"],
                "count": row["count"],
                "vendors": row["vendors"],
                "architectures": row["architectures"],
                "machine": header.get("machine", ""),
                "class": header.get("class", ""),
                "data": header.get("data", ""),
                "type": header.get("type", ""),
                "interpreter": dynamic.get("interpreter", ""),
                "needed_libs": dynamic.get("needed_libs", []),
                "build_id": (rec.elf_notes or {}).get("build_id", ""),
            }
        )
    build_env_rows.sort(key=lambda row: (-len(row["vendors"]), -row["count"], row["target_name"], row["cluster_id"]))

    family_target_matrix = defaultdict(set)
    for rec in records:
        family_target_matrix[rec.architecture_family].add(rec.target_name)

    reports = {}
    reports["binary_inheritance_report.md"] = [
        "# Binary Inheritance Report",
        "",
        f"- workspace: `{workspace_root.relative_to(PROJECT_ROOT)}`",
        f"- reproducible corpus targets scanned: `{fresh_targets}`",
        f"- targets with at least one requested artifact: `{targets_with_hits}`",
        f"- artifact records after per-target deduplication: `{len(records)}`",
        f"- exact ELF reuse clusters: `{len(exact_rows)}`",
        f"- near-identical ELF clusters: `{len(near_rows)}`",
        f"- exact helper-content clusters: `{len(helper_exact_rows)}`",
        f"- normalized helper-content clusters: `{len(helper_norm_rows)}`",
        "",
        "## Coverage",
        "",
        *[f"- `{name}`: `{count}`" for name, count in sorted(by_target.items())],
        "",
        "## File Kinds",
        "",
        *[f"- `{kind}`: `{count}`" for kind, count in sorted(by_kind.items())],
        "",
        "## Architecture Families With Hits",
        "",
        *[f"- `{family}`: `{count}` records / `{len(family_target_matrix[family])}` target names" for family, count in sorted(by_family.items(), key=lambda kv: architecture_sort_key(kv[0]))],
        "",
        "## Interpretation Rules",
        "",
        "- `exact binary reuse`: identical ELF `sha256` across at least two corpus targets.",
        "- `near-identical binaries`: same basename plus identical ELF header tuple, identical interpreter and imported-symbol set, and identical normalized strings hash, but different `sha256`.",
        "- `exact helper reuse`: identical shell/Lua file content across at least two corpus targets.",
        "- `normalized helper reuse`: identical helper semantics after whitespace/comment normalization; used only for helper-level reuse, not binary inheritance claims.",
        "",
        "## Cross-Vendor Exact Reuse",
        "",
    ]
    if cross_vendor_exact:
        for row in cross_vendor_exact[:10]:
            reports["binary_inheritance_report.md"].extend(render_cluster_header(row, include_sha=True))
            reports["binary_inheritance_report.md"].extend(render_record_bullets(row["records"], limit=8))
            reports["binary_inheritance_report.md"].append("")
    else:
        reports["binary_inheritance_report.md"].append("- `(none)`")

    reports["cross_vendor_binary_reuse.md"] = [
        "# Cross-Vendor Binary Reuse",
        "",
        "## Exact ELF Reuse",
        "",
    ]
    if cross_vendor_exact:
        for row in cross_vendor_exact:
            reports["cross_vendor_binary_reuse.md"].extend(render_cluster_header(row, include_sha=True))
            reports["cross_vendor_binary_reuse.md"].extend(render_record_bullets(row["records"], limit=12))
            reports["cross_vendor_binary_reuse.md"].append("")
    else:
        reports["cross_vendor_binary_reuse.md"].append("- `(none)`")
    reports["cross_vendor_binary_reuse.md"].extend(["", "## Near-Identical ELF Reuse", ""])
    if cross_vendor_near:
        for row in cross_vendor_near:
            reports["cross_vendor_binary_reuse.md"].extend(render_cluster_header(row))
            reports["cross_vendor_binary_reuse.md"].append(
                f"- build tuple: `{row['elf_header'].get('machine','')}` / `{row['elf_header'].get('class','')}` / `{row['interpreter']}`"
            )
            reports["cross_vendor_binary_reuse.md"].append(
                f"- imports: `{row['import_count']}` / libs: `{', '.join(row['needed_libs'])}`"
            )
            reports["cross_vendor_binary_reuse.md"].extend(render_record_bullets(row["records"], limit=12))
            reports["cross_vendor_binary_reuse.md"].append("")
    else:
        reports["cross_vendor_binary_reuse.md"].append("- `(none)`")
    reports["cross_vendor_binary_reuse.md"].extend(["", "## Cross-Vendor Helper Reuse", ""])
    if cross_vendor_helper:
        for row in cross_vendor_helper:
            reports["cross_vendor_binary_reuse.md"].extend(render_cluster_header(row))
            reports["cross_vendor_binary_reuse.md"].extend(render_record_bullets(row["records"], limit=12))
            reports["cross_vendor_binary_reuse.md"].append("")
    else:
        reports["cross_vendor_binary_reuse.md"].append("- `(none)`")

    reports["orchestration_binary_clusters.md"] = [
        "# Orchestration Binary Clusters",
        "",
        "## Exact ELF Identity Clusters",
        "",
    ]
    if exact_rows:
        for row in exact_rows:
            reports["orchestration_binary_clusters.md"].extend(render_cluster_header(row, include_sha=True))
            rec = row["records"][0]
            reports["orchestration_binary_clusters.md"].append(f"- file: `{rec.file_desc}`")
            reports["orchestration_binary_clusters.md"].extend(render_record_bullets(row["records"], limit=10))
            reports["orchestration_binary_clusters.md"].append("")
    else:
        reports["orchestration_binary_clusters.md"].append("- `(none)`")
    reports["orchestration_binary_clusters.md"].extend(["", "## Near-Identical ELF Clusters", ""])
    if near_rows:
        for row in near_rows:
            reports["orchestration_binary_clusters.md"].extend(render_cluster_header(row))
            reports["orchestration_binary_clusters.md"].append(
                f"- sha variants: `{row['sha_count']}` / imports: `{row['import_count']}` / libs: `{', '.join(row['needed_libs'])}`"
            )
            reports["orchestration_binary_clusters.md"].extend(render_record_bullets(row["records"], limit=10))
            reports["orchestration_binary_clusters.md"].append("")
    else:
        reports["orchestration_binary_clusters.md"].append("- `(none)`")
    reports["orchestration_binary_clusters.md"].extend(["", "## Helper Exact-Content Clusters", ""])
    if helper_exact_rows:
        for row in helper_exact_rows:
            reports["orchestration_binary_clusters.md"].extend(render_cluster_header(row))
            reports["orchestration_binary_clusters.md"].extend(render_record_bullets(row["records"], limit=10))
            reports["orchestration_binary_clusters.md"].append("")
    else:
        reports["orchestration_binary_clusters.md"].append("- `(none)`")

    reports["sdk_artifact_recurrence.md"] = [
        "# SDK Artifact Recurrence",
        "",
        "## Probable Shared Orchestration Stacks",
        "",
    ]
    grouped = defaultdict(list)
    for row in exact_rows + near_rows + helper_exact_rows + helper_norm_rows:
        key = (row["target_name"], tuple(row["architectures"]))
        grouped[key].append(row)
    for (target_name, archs), rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0][0], item[0][1])):
        total_targets = len({cid for row in rows for cid in row["corpus_ids"]})
        vendor_set = sorted({vendor for row in rows for vendor in row["vendors"]})
        if total_targets < 2:
            continue
        cluster_id = stable_id("sdk-artifact", target_name, ",".join(archs))
        reports["sdk_artifact_recurrence.md"].append(
            f"## `{target_name}` `{cluster_id}`"
        )
        reports["sdk_artifact_recurrence.md"].append(
            f"- architectures: `{', '.join(archs)}`"
        )
        reports["sdk_artifact_recurrence.md"].append(
            f"- vendors: `{', '.join(vendor_set)}` / targets: `{total_targets}` / evidence clusters: `{len(rows)}`"
        )
        exact_elf = sum(1 for row in rows if row["cluster_id"] in analysis["exact_clusters"])
        near_elf = sum(1 for row in rows if row["cluster_id"] in analysis["near_clusters"])
        exact_helper = sum(1 for row in rows if row["cluster_id"] in analysis["exact_helper_clusters"])
        norm_helper = sum(1 for row in rows if row["cluster_id"] in analysis["helper_norm_clusters"])
        reports["sdk_artifact_recurrence.md"].append(
            f"- cluster mix: exact-elf=`{exact_elf}` / near-elf=`{near_elf}` / exact-helper=`{exact_helper}` / normalized-helper=`{norm_helper}`"
        )
        sample_row = rows[0]
        reports["sdk_artifact_recurrence.md"].extend(render_record_bullets(sample_row["records"], limit=8))
        reports["sdk_artifact_recurrence.md"].append("")
    if reports["sdk_artifact_recurrence.md"][-1] != "":
        pass

    reports["shared_build_environment_evidence.md"] = [
        "# Shared Build Environment Evidence",
        "",
        "## ELF Build Tuples",
        "",
    ]
    if build_env_rows:
        for row in build_env_rows[:40]:
            reports["shared_build_environment_evidence.md"].append(
                f"## `{row['target_name']}` `{row['cluster_id']}`"
            )
            reports["shared_build_environment_evidence.md"].append(
                f"- corpus targets: `{row['count']}` / vendors: `{', '.join(row['vendors'])}` / architectures: `{', '.join(row['architectures'])}`"
            )
            reports["shared_build_environment_evidence.md"].append(
                f"- ELF tuple: `{row['machine']}` / `{row['class']}` / `{row['data']}` / `{row['type']}`"
            )
            reports["shared_build_environment_evidence.md"].append(
                f"- interpreter: `{row['interpreter'] or 'missing'}`"
            )
            reports["shared_build_environment_evidence.md"].append(
                f"- needed libs: `{', '.join(row['needed_libs']) or 'none'}`"
            )
            reports["shared_build_environment_evidence.md"].append(
                f"- build id sample: `{row['build_id'] or 'missing'}`"
            )
            reports["shared_build_environment_evidence.md"].append("")
    else:
        reports["shared_build_environment_evidence.md"].append("- `(none)`")
    reports["shared_build_environment_evidence.md"].extend(
        [
            "",
            "## Interpretation Limits",
            "",
            "- Matching interpreters and NEEDED libraries are build-environment evidence, not proof of shared provenance.",
            "- Identical imports plus identical normalized strings are treated as `probable same-source recompilation`, not exact binary reuse, when `sha256` differs.",
            "- Helper-script reuse is reported separately from ELF inheritance to avoid overclaiming SDK binary reuse.",
        ]
    )

    return reports


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE))
    args = parser.parse_args()

    workspace_root = Path(args.workspace_root).resolve()
    records, bundle_index = collect_records(workspace_root)
    analysis = build_analysis(records)
    reports = build_reports(workspace_root, analysis, bundle_index)
    for name, lines in reports.items():
        write_md(workspace_root / name, lines)
    summary = {
        "workspace_root": str(workspace_root),
        "records": len(records),
        "targets": len(bundle_index),
        "exact_elf_clusters": len(exact_reuse_rows(analysis["exact_clusters"])),
        "near_elf_clusters": len(near_reuse_rows(analysis["near_clusters"])),
        "exact_helper_clusters": len(helper_reuse_rows(analysis["exact_helper_clusters"])),
        "normalized_helper_clusters": len(helper_reuse_rows(analysis["helper_norm_clusters"])),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
