"""
Generate meshd target inventory and Ghidra preparation notes from the reproducible corpus.

Usage:
  python3 src/research_tools/meshd_target_report.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"
REPORT_FILES = [
    "meshd_target_inventory.md",
    "meshd_candidate_ranking.md",
    "meshd_helper_context.md",
    "meshd_ghidra_preparation.md",
]
HELPER_REL_PATHS = [
    "usr/lib/lua/luci/controller/admin/easymesh_network.lua",
    "usr/lib/lua/luci/controller/admin/firmware.lua",
    "usr/lib/lua/luci/controller/admin/system.lua",
    "usr/lib/lua/luci/model/easy_mesh.lua",
    "usr/lib/lua/luci/model/one_mesh.lua",
    "etc/init.d/meshd",
    "etc/easymesh_cfg.json",
    "etc/meshd_cfg.json",
    "etc/config/easy_mesh",
    "etc/config/mesh",
    "usr/bin/easymesh-agent",
    "usr/bin/easymesh-controller",
    "usr/bin/mesh_cli",
    "usr/lib/libmesh_db_api.so",
    "usr/sbin/onemesh_search",
    "usr/bin/ubus",
    "sbin/ubus",
    "usr/sbin/rpcd",
    "sbin/rpcd",
]
MESH_RELATED_NAMES = {
    "easymesh_network.lua",
    "firmware.lua",
    "system.lua",
    "easy_mesh.lua",
    "one_mesh.lua",
    "meshd",
    "mesh_cli",
    "easymesh-agent",
    "easymesh-controller",
    "onemesh_search",
}
ARCH_PREFERENCE = {
    "AArch64": 0,
    "ARM": 1,
    "MIPS R3000": 2,
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_md(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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


def parse_readelf_header(path: Path) -> dict:
    text = run_cmd(["readelf", "-h"], path)
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = [part.strip() for part in line.split(":", 1)]
        if k in {"Class", "Machine", "Type"}:
            out[k.lower()] = v
    return out


def parse_readelf_dynamic(path: Path) -> dict:
    text = run_cmd(["readelf", "-d"], path)
    libs = []
    interp = ""
    for line in text.splitlines():
        if "Shared library:" in line:
            start = line.find("[")
            end = line.find("]", start + 1)
            if start != -1 and end != -1:
                libs.append(line[start + 1:end])
        if "program interpreter" in line.lower():
            start = line.find("[")
            end = line.find("]", start + 1)
            if start != -1 and end != -1:
                interp = line[start + 1:end]
    return {"needed_libs": sorted(set(libs)), "interpreter": interp}


def parse_dyn_imports(path: Path) -> list[str]:
    text = run_cmd(["readelf", "--dyn-syms", "--wide"], path)
    imports = []
    for line in text.splitlines():
        if " UND " not in f" {line} ":
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1].split("@", 1)[0].strip()
        if name:
            imports.append(name)
    return sorted(set(imports))


def relpath(path: Path, start: Path) -> str:
    try:
        return str(path.relative_to(start))
    except ValueError:
        return str(path)


def find_results(workspace_root: Path) -> list[Path]:
    return sorted(workspace_root.glob("runs/**/results.json"))


def locate_meshd(rootfs: Path) -> list[Path]:
    found = []
    for rel in ("usr/bin/meshd", "usr/sbin/meshd", "bin/meshd", "sbin/meshd"):
        path = rootfs / rel
        if path.exists():
            found.append(path)
    if found:
        return found
    for path in rootfs.rglob("meshd"):
        if path.is_file():
            found.append(path)
    return sorted(found)


def mesh_related_files(rootfs: Path) -> list[str]:
    out = []
    for rel in HELPER_REL_PATHS:
        if (rootfs / rel).exists():
            out.append(rel)
    if not out:
        for path in sorted(rootfs.rglob("*mesh*")):
            if path.is_file():
                rp = relpath(path, rootfs)
                if rp not in out:
                    out.append(rp)
            if len(out) >= 30:
                break
    return out


def best_run_bundle(results_paths: list[Path]) -> dict[str, dict]:
    best = {}
    for results_path in results_paths:
        bundle = load_json(results_path)
        meta = bundle.get("target_metadata") or {}
        corpus_id = meta.get("corpus_id")
        if not corpus_id:
            continue
        current = best.get(corpus_id)
        quality = bundle.get("extraction_quality_flags") or {}
        score = (
            1 if quality.get("rootfs_recovered") else 0,
            quality.get("marker_count", 0),
            quality.get("helper_count", 0),
            str(results_path),
        )
        if current is None or score > current["score"]:
            best[corpus_id] = {"bundle": bundle, "path": results_path, "score": score}
    return best


def collect_candidates(workspace_root: Path) -> list[dict]:
    candidates = []
    bundles = best_run_bundle(find_results(workspace_root))
    for corpus_id, item in sorted(bundles.items()):
        bundle = item["bundle"]
        meta = bundle.get("target_metadata") or {}
        arch = bundle.get("architecture_profile") or {}
        quality = bundle.get("extraction_quality_flags") or {}
        analysis = bundle.get("analysis") or {}
        system_path = analysis.get("system_path")
        if not system_path:
            continue
        rootfs = PROJECT_ROOT / system_path
        if not rootfs.exists():
            continue
        for meshd_path in locate_meshd(rootfs):
            header = parse_readelf_header(meshd_path)
            dynamic = parse_readelf_dynamic(meshd_path)
            imports = parse_dyn_imports(meshd_path)
            related = mesh_related_files(rootfs)
            helper_inventory = bundle.get("helper_script_inventory") or {}
            service_topology = bundle.get("service_topology") or {}
            command_features = bundle.get("command_materialization_features") or {}
            candidates.append(
                {
                    "vendor": meta.get("vendor", "UNKNOWN"),
                    "model": meta.get("model", "UNKNOWN"),
                    "version": meta.get("version", ""),
                    "corpus_id": corpus_id,
                    "architecture_family": arch.get("architecture_family", "unknown"),
                    "architecture_fingerprint": arch.get("architecture_fingerprint", ""),
                    "rootfs_path": str(rootfs.resolve()),
                    "binary_path": str(meshd_path.resolve()),
                    "binary_relpath": relpath(meshd_path, rootfs),
                    "elf_arch": header.get("machine", ""),
                    "elf_class": header.get("class", ""),
                    "elf_type": header.get("type", ""),
                    "file_size": meshd_path.stat().st_size,
                    "sha256": sha256_path(meshd_path),
                    "file_desc": file_description(meshd_path),
                    "rootfs_preserved": bool(quality.get("rootfs_recovered")),
                    "quality_class": quality.get("quality_class", "unknown"),
                    "openwrt_vendor_management_stack": arch.get("architecture_family") == "openwrt-vendor-management-stack",
                    "needed_libs": dynamic.get("needed_libs", []),
                    "interpreter": dynamic.get("interpreter", ""),
                    "dyn_import_count": len(imports),
                    "helper_count": len(related),
                    "related_files": related,
                    "orchestration_helpers": helper_inventory.get("orchestration_helpers", []),
                    "execution_helpers": helper_inventory.get("execution_helpers", []),
                    "topology_signature": service_topology.get("topology_signature", ""),
                    "control_plane": service_topology.get("control_plane", ""),
                    "orchestration_hooks": service_topology.get("orchestration_hooks", []),
                    "command_templates": command_features.get("command_templates", {}),
                    "release_date": meta.get("release_date", ""),
                }
            )
    return candidates


def helper_richness(candidate: dict) -> int:
    score = 0
    related = set(candidate["related_files"])
    for rel in HELPER_REL_PATHS:
        if rel in related:
            score += 2
    for rel in related:
        if os.path.basename(rel) in MESH_RELATED_NAMES:
            score += 1
    score += len(candidate["orchestration_hooks"])
    return score


def recurrence_counts(candidates: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    sha_counts = defaultdict(int)
    fingerprint_counts = defaultdict(int)
    for cand in candidates:
        sha_counts[cand["sha256"]] += 1
        key = (
            cand["architecture_family"],
            cand["binary_relpath"],
            cand["elf_arch"],
            ",".join(cand["needed_libs"]),
        )
        fingerprint_counts["||".join(key)] += 1
    return dict(sha_counts), dict(fingerprint_counts)


def score_candidate(candidate: dict, sha_counts: dict[str, int], fp_counts: dict[str, int]) -> tuple:
    recurrence_key = "||".join(
        [
            candidate["architecture_family"],
            candidate["binary_relpath"],
            candidate["elf_arch"],
            ",".join(candidate["needed_libs"]),
        ]
    )
    return (
        1 if candidate["rootfs_preserved"] else 0,
        1 if candidate["openwrt_vendor_management_stack"] else 0,
        1 if candidate["elf_arch"] == "AArch64" else 0,
        helper_richness(candidate),
        sha_counts.get(candidate["sha256"], 0),
        fp_counts.get(recurrence_key, 0),
        candidate["dyn_import_count"],
        candidate["file_size"],
        -ARCH_PREFERENCE.get(candidate["elf_arch"], 9),
        candidate["corpus_id"],
    )


def recommend(candidates: list[dict]) -> tuple[dict, dict]:
    sha_counts, fp_counts = recurrence_counts(candidates)
    ranked = sorted(
        candidates,
        key=lambda cand: score_candidate(cand, sha_counts, fp_counts),
        reverse=True,
    )
    best = ranked[0]
    comparison = None
    for cand in ranked[1:]:
        if cand["vendor"] != best["vendor"] and cand["elf_arch"] == best["elf_arch"]:
            comparison = cand
            break
    if comparison is None and len(ranked) > 1:
        comparison = ranked[1]
    return best, comparison


def md_table(rows: list[list[str]]) -> list[str]:
    if not rows:
        return []
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for idx, row in enumerate(rows):
        lines.append("| " + " | ".join(str(val).ljust(widths[i]) for i, val in enumerate(row)) + " |")
        if idx == 0:
            lines.append("| " + " | ".join("-" * widths[i] for i in range(len(widths))) + " |")
    return lines


def generate_inventory_report(output_dir: Path, candidates: list[dict]) -> None:
    rows = [[
        "Vendor", "Model", "Version", "Corpus ID", "Family", "ELF", "Size", "SHA256", "Preserved", "Path"
    ]]
    for cand in candidates:
        rows.append([
            cand["vendor"],
            cand["model"],
            cand["version"],
            cand["corpus_id"],
            cand["architecture_family"],
            f'{cand["elf_arch"]} {cand["elf_class"]}',
            str(cand["file_size"]),
            cand["sha256"][:16],
            "yes" if cand["rootfs_preserved"] else "no",
            cand["binary_relpath"],
        ])
    lines = [
        "# Meshd Target Inventory",
        "",
        f"Found `{len(candidates)}` preserved `meshd` candidates in the reproducible corpus.",
        "",
        *md_table(rows),
        "",
    ]
    for cand in candidates:
        lines.extend([
            f"## {cand['vendor']} {cand['model']} {cand['version']}",
            f"- `corpus_id`: `{cand['corpus_id']}`",
            f"- `architecture_family`: `{cand['architecture_family']}`",
            f"- `architecture_fingerprint`: `{cand['architecture_fingerprint']}`",
            f"- `rootfs_path`: `{cand['rootfs_path']}`",
            f"- `binary_path`: `{cand['binary_path']}`",
            f"- `ELF`: `{cand['elf_arch']} {cand['elf_class']} {cand['elf_type']}`",
            f"- `file_size`: `{cand['file_size']}` bytes",
            f"- `sha256`: `{cand['sha256']}`",
            f"- `rootfs_preserved`: `{cand['rootfs_preserved']}`",
            f"- `openwrt_vendor_management_stack`: `{cand['openwrt_vendor_management_stack']}`",
            f"- `interpreter`: `{cand['interpreter'] or 'n/a'}`",
            f"- `needed_libs`: `{', '.join(cand['needed_libs']) or 'none'}`",
            "",
        ])
    write_md(output_dir / "meshd_target_inventory.md", lines)


def generate_ranking_report(output_dir: Path, candidates: list[dict]) -> None:
    sha_counts, fp_counts = recurrence_counts(candidates)
    ranked = sorted(
        candidates,
        key=lambda cand: score_candidate(cand, sha_counts, fp_counts),
        reverse=True,
    )
    rows = [[
        "Rank", "Target", "Family", "Arch", "Helper Richness", "SHA Reuse", "FP Reuse", "Imports", "Why"
    ]]
    for idx, cand in enumerate(ranked, start=1):
        why = []
        if cand["openwrt_vendor_management_stack"]:
            why.append("stack-match")
        if cand["elf_arch"] == "AArch64":
            why.append("aarch64")
        if sha_counts[cand["sha256"]] > 1:
            why.append("exact-reuse")
        if helper_richness(cand) >= 20:
            why.append("rich-helpers")
        rows.append([
            str(idx),
            f'{cand["vendor"]} {cand["model"]} {cand["version"]}',
            cand["architecture_family"],
            cand["elf_arch"],
            str(helper_richness(cand)),
            str(sha_counts[cand["sha256"]]),
            str(fp_counts["||".join([cand["architecture_family"], cand["binary_relpath"], cand["elf_arch"], ",".join(cand["needed_libs"])])]),
            str(cand["dyn_import_count"]),
            ",".join(why) or "baseline",
        ])
    lines = [
        "# Candidate Ranking",
        "",
        "Ranking favors preserved rootfs quality, `openwrt-vendor-management-stack` relevance, helper/context richness, recurrence value, and Ghidra semantic density.",
        "",
        *md_table(rows),
        "",
    ]
    best, comparison = recommend(candidates)
    lines.extend([
        f"Best first target: `{best['vendor']} {best['model']} {best['version']}` because it combines preserved EasyMesh context, rich helper adjacency, and high semantic density.",
        f"Best comparison target: `{comparison['vendor']} {comparison['model']} {comparison['version']}` because it preserves the same orchestration family while changing vendor or binary lineage.",
        "",
        "AX72 vs MR90X:",
        "- Start with `Archer AX72 V2_241119_US` for the initial deep dive.",
        "- Use `MR90X (EU) V1.20_23080820240123090924` as the second AArch64 comparison target to test family-level reuse without assuming identical provenance.",
    ])
    write_md(output_dir / "meshd_candidate_ranking.md", lines)


def generate_helper_context_report(output_dir: Path, candidates: list[dict]) -> None:
    lines = [
        "# Related Helper Ecosystem",
        "",
        "This report lists the helper/controller context that should be read alongside `meshd` in Ghidra.",
        "",
    ]
    for cand in candidates:
        lines.extend([
            f"## {cand['vendor']} {cand['model']} {cand['version']}",
            f"- `control_plane`: `{cand['control_plane']}`",
            f"- `topology_signature`: `{cand['topology_signature']}`",
            f"- `orchestration_helpers`: `{', '.join(cand['orchestration_helpers']) or 'none'}`",
            f"- `execution_helpers`: `{', '.join(cand['execution_helpers']) or 'none'}`",
            "- `mesh_related_files`:",
        ])
        for rel in cand["related_files"]:
            lines.append(f"  - `{rel}`")
        lines.append("")
    write_md(output_dir / "meshd_helper_context.md", lines)


def generate_ghidra_prep_report(output_dir: Path, candidates: list[dict]) -> None:
    best, comparison = recommend(candidates)
    lines = [
        "# Best Ghidra Target",
        "",
        f"`{best['vendor']} {best['model']} {best['version']}` is the best first load target.",
        "",
        "- Reasons:",
        "  - preserved rootfs with explicit EasyMesh configs and init hooks",
        "  - `openwrt-vendor-management-stack` family with dense helper adjacency",
        "  - AArch64 executable with larger code surface and richer import table",
        "  - good comparison path to MR90X and AX55 family members",
        "",
        "# Comparison Target",
        "",
        f"`{comparison['vendor']} {comparison['model']} {comparison['version']}` is the recommended second load target.",
        "",
        "# Exact Path To Load In Ghidra",
        "",
        f"- first: `{best['binary_path']}`",
        f"- comparison: `{comparison['binary_path']}`",
        "",
        "# Expected Analysis Value",
        "",
        f"- first target helper count: `{best['helper_count']}`",
        f"- first target imports: `{best['dyn_import_count']}`",
        f"- first target libs: `{', '.join(best['needed_libs'])}`",
        f"- comparison target helper count: `{comparison['helper_count']}`",
        "",
        "# Recommended Next Step",
        "",
        "Load the first target into Ghidra, then read these files in parallel from the same rootfs:",
    ]
    for rel in best["related_files"]:
        if rel in HELPER_REL_PATHS:
            lines.append(f"- `{Path(best['rootfs_path']) / rel}`")
    write_md(output_dir / "meshd_ghidra_preparation.md", lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args()

    candidates = collect_candidates(args.workspace_root)
    if not candidates:
        raise SystemExit("no meshd targets found")
    candidates = sorted(candidates, key=lambda cand: (cand["vendor"], cand["model"], cand["version"], cand["binary_relpath"]))
    for report in REPORT_FILES:
        path = args.workspace_root / report
        path.parent.mkdir(parents=True, exist_ok=True)
    generate_inventory_report(args.workspace_root, candidates)
    generate_ranking_report(args.workspace_root, candidates)
    generate_helper_context_report(args.workspace_root, candidates)
    generate_ghidra_prep_report(args.workspace_root, candidates)


if __name__ == "__main__":
    main()
