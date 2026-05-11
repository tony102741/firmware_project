"""
Generate tdpServer target inventory and Ghidra preparation notes from the reproducible corpus.

Usage:
  python3 src/research_tools/tdpserver_target_report.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"
REPORT_FILES = [
    "tdpserver_target_inventory.md",
    "tdpserver_candidate_ranking.md",
    "tdpserver_ghidra_preparation.md",
]
HELPER_REL_PATHS = [
    "etc/init.d/tdpServer",
    "etc_ro/init.d/tdpServer",
    "etc/rc.d/S50tdpServer",
    "usr/lib/lua/luci/controller/admin/system.lua",
    "usr/lib/lua/luci/controller/admin/firmware.lua",
    "usr/sbin/connmode",
    "usr/bin/connmode",
    "usr/sbin/ndppd",
    "etc/init.d/ndppd",
    "etc/ndppd.conf",
    "bin/ubus",
    "etc/init.d/ubus",
    "etc/rc.d/S11ubus",
    "sbin/ubusd",
    "lib/lua/ubus.so",
    "usr/lib/lua/ubus.so",
    "usr/lib/uhttpd_ubus.so",
]


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
    rpath = ""
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
        if "RPATH" in line or "RUNPATH" in line:
            start = line.find("[")
            end = line.find("]", start + 1)
            if start != -1 and end != -1:
                rpath = line[start + 1:end]
    return {"needed_libs": sorted(set(libs)), "interpreter": interp, "rpath": rpath}


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


def helper_files(rootfs: Path) -> list[str]:
    found = []
    for rel in HELPER_REL_PATHS:
        if (rootfs / rel).exists():
            found.append(rel)
    return found


def locate_tdpserver(rootfs: Path) -> list[Path]:
    found = []
    for rel in ("usr/bin/tdpServer", "usr/sbin/tdpServer", "bin/tdpServer", "sbin/tdpServer"):
        path = rootfs / rel
        if path.exists():
            found.append(path)
    return found


def collect_candidates(workspace_root: Path) -> list[dict]:
    candidates = []
    bundles = best_run_bundle(sorted(workspace_root.glob("runs/**/results.json")))
    for corpus_id, item in sorted(bundles.items()):
        bundle = item["bundle"]
        meta = bundle.get("target_metadata") or {}
        arch = bundle.get("architecture_profile") or {}
        quality = bundle.get("extraction_quality_flags") or {}
        analysis = bundle.get("analysis") or {}
        helper_inventory = bundle.get("helper_script_inventory") or {}
        service_topology = bundle.get("service_topology") or {}
        management_inventory = bundle.get("management_inventory") or {}
        system_path = analysis.get("system_path")
        if not system_path:
            continue
        rootfs = PROJECT_ROOT / system_path
        if not rootfs.exists():
            continue
        for binary in locate_tdpserver(rootfs):
            header = parse_readelf_header(binary)
            dynamic = parse_readelf_dynamic(binary)
            imports = parse_dyn_imports(binary)
            helpers = helper_files(rootfs)
            candidates.append(
                {
                    "vendor": meta.get("vendor", "UNKNOWN"),
                    "model": meta.get("model", "UNKNOWN"),
                    "version": meta.get("version", ""),
                    "corpus_id": corpus_id,
                    "architecture_family": arch.get("architecture_family", "unknown"),
                    "architecture_fingerprint": arch.get("architecture_fingerprint", ""),
                    "rootfs_path": str(rootfs.resolve()),
                    "binary_path": str(binary.resolve()),
                    "binary_relpath": relpath(binary, rootfs),
                    "elf_arch": header.get("machine", ""),
                    "elf_class": header.get("class", ""),
                    "elf_type": header.get("type", ""),
                    "file_size": binary.stat().st_size,
                    "sha256": sha256_path(binary),
                    "file_desc": file_description(binary),
                    "rootfs_preserved": bool(quality.get("rootfs_recovered")),
                    "quality_class": quality.get("quality_class", "unknown"),
                    "rootfs_marker_count": quality.get("marker_count", 0),
                    "helper_count": len(helpers),
                    "related_init_scripts": [p for p in helpers if "init.d/tdpServer" in p or "rc.d/S50tdpServer" in p],
                    "related_helper_files": helpers,
                    "orchestration_helpers": helper_inventory.get("orchestration_helpers", []),
                    "execution_helpers": helper_inventory.get("execution_helpers", []),
                    "topology_signature": service_topology.get("topology_signature", ""),
                    "control_plane": service_topology.get("control_plane", ""),
                    "management_endpoints": management_inventory.get("management_endpoints", []),
                    "management_handlers": management_inventory.get("management_handlers", []),
                    "needed_libs": dynamic.get("needed_libs", []),
                    "interpreter": dynamic.get("interpreter", ""),
                    "rpath": dynamic.get("rpath", ""),
                    "dyn_import_count": len(imports),
                    "tp_link_stack": arch.get("architecture_family") == "openwrt-vendor-management-stack",
                }
            )
    return candidates


def recurrence_counts(candidates: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    sha_counts = defaultdict(int)
    family_counts = defaultdict(int)
    for cand in candidates:
        sha_counts[cand["sha256"]] += 1
        key = (
            cand["architecture_family"],
            cand["elf_arch"],
            cand["binary_relpath"],
            ",".join(cand["needed_libs"]),
        )
        family_counts["||".join(key)] += 1
    return dict(sha_counts), dict(family_counts)


def network_relevance(candidate: dict) -> int:
    score = 0
    endpoints = " ".join(candidate["management_endpoints"]).lower()
    handlers = " ".join(candidate["management_handlers"]).lower()
    if "/config" in endpoints:
        score += 2
    if "tdpserver" in handlers:
        score += 2
    if "ubus" in candidate["control_plane"]:
        score += 1
    return score


def score_candidate(candidate: dict, sha_counts: dict[str, int], family_counts: dict[str, int]) -> tuple:
    cluster_key = "||".join(
        [
            candidate["architecture_family"],
            candidate["elf_arch"],
            candidate["binary_relpath"],
            ",".join(candidate["needed_libs"]),
        ]
    )
    return (
        1 if candidate["rootfs_preserved"] else 0,
        1 if candidate["tp_link_stack"] else 0,
        1 if candidate["elf_arch"] == "AArch64" else 0,
        candidate["file_size"],
        candidate["dyn_import_count"],
        candidate["helper_count"],
        network_relevance(candidate),
        sha_counts.get(candidate["sha256"], 0),
        family_counts.get(cluster_key, 0),
        candidate["corpus_id"],
    )


def recommend(candidates: list[dict]) -> tuple[dict, dict]:
    sha_counts, family_counts = recurrence_counts(candidates)
    ranked = sorted(candidates, key=lambda c: score_candidate(c, sha_counts, family_counts), reverse=True)
    best = ranked[0]
    comparison = None
    for cand in ranked[1:]:
        if cand["elf_arch"] != best["elf_arch"] and cand["tp_link_stack"] == best["tp_link_stack"]:
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
        "# TdpServer Target Inventory",
        "",
        f"Found `{len(candidates)}` preserved `tdpServer` candidates in the reproducible corpus.",
        "",
        *md_table(rows),
        "",
    ]
    for cand in candidates:
        lines.extend([
            f"## {cand['vendor']} {cand['model']} {cand['version']}",
            f"- `corpus_id`: `{cand['corpus_id']}`",
            f"- `architecture_family`: `{cand['architecture_family']}`",
            f"- `rootfs_path`: `{cand['rootfs_path']}`",
            f"- `binary_path`: `{cand['binary_path']}`",
            f"- `ELF`: `{cand['elf_arch']} {cand['elf_class']} {cand['elf_type']}`",
            f"- `file_size`: `{cand['file_size']}` bytes",
            f"- `sha256`: `{cand['sha256']}`",
            f"- `preserved_rootfs`: `{cand['rootfs_preserved']}`",
            f"- `related_init_scripts`: `{', '.join(cand['related_init_scripts']) or 'none'}`",
            f"- `related_ubus_config_helper_files`: `{', '.join(cand['related_helper_files']) or 'none'}`",
            "",
        ])
    write_md(output_dir / "tdpserver_target_inventory.md", lines)


def generate_ranking_report(output_dir: Path, candidates: list[dict]) -> None:
    sha_counts, family_counts = recurrence_counts(candidates)
    ranked = sorted(candidates, key=lambda c: score_candidate(c, sha_counts, family_counts), reverse=True)
    rows = [[
        "Rank", "Target", "Arch", "Helpers", "Imports", "SHA Reuse", "Cluster Reuse", "Why"
    ]]
    for idx, cand in enumerate(ranked, start=1):
        why = []
        if cand["tp_link_stack"]:
            why.append("mgmt-stack")
        if cand["elf_arch"] == "AArch64":
            why.append("aarch64")
        if cand["helper_count"] >= 8:
            why.append("rich-context")
        if sha_counts[cand["sha256"]] > 1:
            why.append("exact-reuse")
        rows.append([
            str(idx),
            f'{cand["vendor"]} {cand["model"]} {cand["version"]}',
            cand["elf_arch"],
            str(cand["helper_count"]),
            str(cand["dyn_import_count"]),
            str(sha_counts[cand["sha256"]]),
            str(family_counts["||".join([cand["architecture_family"], cand["elf_arch"], cand["binary_relpath"], ",".join(cand["needed_libs"])])]),
            ",".join(why) or "baseline",
        ])
    best, comparison = recommend(candidates)
    lines = [
        "# Candidate Ranking",
        "",
        "Ranking favors network-facing relevance, preserved rootfs quality, TP-Link/MERCUSYS management-stack relevance, Ghidra suitability, and semantic richness.",
        "",
        *md_table(rows),
        "",
        f"Best first target: `{best['vendor']} {best['model']} {best['version']}`.",
        f"Best comparison target: `{comparison['vendor']} {comparison['model']} {comparison['version']}`.",
    ]
    write_md(output_dir / "tdpserver_candidate_ranking.md", lines)


def generate_ghidra_prep_report(output_dir: Path, candidates: list[dict]) -> tuple[dict, dict]:
    best, comparison = recommend(candidates)
    lines = [
        "# Best Ghidra Target",
        "",
        f"`{best['vendor']} {best['model']} {best['version']}` is the best first load target.",
        "",
        "- Reasons:",
        "  - network-facing management-stack component with preserved rootfs",
        "  - rich ubus/system/firmware/connmode adjacency in the same image",
        "  - highest semantic density among preserved `tdpServer` samples",
        "",
        "# Comparison Target",
        "",
        f"`{comparison['vendor']} {comparison['model']} {comparison['version']}` is the recommended comparison target.",
        "",
        "# Related Helper/Config Context",
        "",
    ]
    for rel in best["related_helper_files"]:
        lines.append(f"- `{Path(best['rootfs_path']) / rel}`")
    lines.extend([
        "",
        "# Exact Path To Load In Ghidra",
        "",
        f"- first: `{best['binary_path']}`",
        f"- comparison: `{comparison['binary_path']}`",
        "",
        "# Recommended Next Step",
        "",
        "Load the first target in Ghidra, then inspect its init script and ubus/system/firmware helper files from the same rootfs before cross-checking the comparison target.",
    ])
    write_md(output_dir / "tdpserver_ghidra_preparation.md", lines)
    return best, comparison


def copy_ghidra_targets(best: dict, comparison: dict) -> None:
    out_dir = PROJECT_ROOT / "ghidra_targets" / "tdpserver_comparison"
    out_dir.mkdir(parents=True, exist_ok=True)
    best_name = "tdpserver_tplink_ax72_v2_241119_aarch64" if "AX72" in best["model"] else f"tdpserver_{best['corpus_id'].replace('-', '_')}"
    if "ax55" in comparison["corpus_id"]:
        cmp_name = f"tdpserver_{comparison['corpus_id'].replace('-', '_')}"
    else:
        cmp_name = f"tdpserver_{comparison['corpus_id'].replace('-', '_')}"
    shutil.copy2(best["binary_path"], out_dir / best_name)
    shutil.copy2(comparison["binary_path"], out_dir / cmp_name)
    md = [
        "# tdpServer Ghidra Targets",
        "",
        "## Primary Target",
        f"- file: `ghidra_targets/tdpserver_comparison/{best_name}`",
        f"- source firmware: `{best['vendor']} {best['model']} {best['version']}`",
        f"- corpus_id: `{best['corpus_id']}`",
        f"- architecture family: `{best['architecture_family']}`",
        f"- original source path: `{best['binary_path']}`",
        "",
        "## Comparison Target",
        f"- file: `ghidra_targets/tdpserver_comparison/{cmp_name}`",
        f"- source firmware: `{comparison['vendor']} {comparison['model']} {comparison['version']}`",
        f"- corpus_id: `{comparison['corpus_id']}`",
        f"- architecture family: `{comparison['architecture_family']}`",
        f"- original source path: `{comparison['binary_path']}`",
    ]
    write_md(out_dir / "tdpserver_targets.md", md)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args()
    candidates = collect_candidates(args.workspace_root)
    if not candidates:
        raise SystemExit("no tdpServer targets found")
    candidates = sorted(candidates, key=lambda c: (c["vendor"], c["model"], c["version"]))
    generate_inventory_report(args.workspace_root, candidates)
    generate_ranking_report(args.workspace_root, candidates)
    best, comparison = generate_ghidra_prep_report(args.workspace_root, candidates)
    copy_ghidra_targets(best, comparison)


if __name__ == "__main__":
    main()
