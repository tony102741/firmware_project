#!/usr/bin/env python3
"""
Static cross-firmware orchestration motif scanner for OpenWrt-derived management planes.

This scanner is intentionally conservative. It uses preserved rootfs artifacts,
analysis-stage metadata, helper inventories, and binary strings to identify
management-plane trust-collapse motifs without making runtime assertions.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"
RUNS_DIRNAME = "runs"

OPENWRT_FAMILIES = {
    "openwrt-vendor-management-stack",
    "openwrt-shell-helper-sdk",
    "openwrt-mtk-lua-wireless",
}

OUTPUT_FILES = {
    "scorecards": "orchestration_motif_scorecards.md",
    "matrix": "cross_firmware_orchestration_motif_matrix.md",
    "prevalence": "trust_collapse_prevalence_report.md",
    "graphs": "orchestration_motif_recurrence_graphs.md",
    "results": "orchestration_motif_results.json",
    "schema": "orchestration_motif_schema.json",
}

MOTIF_DEFS = {
    "M1": "cloud relay bypass",
    "M2": "all-root cluster",
    "M3": "Lua dispatch without auth",
    "M4": "ubus ACL vacuum",
    "M5": "hardcoded transport credentials",
    "M6": "mesh privilege propagation",
}

MOTIF_ORDER = ["M1", "M2", "M3", "M4", "M5", "M6"]

RISKY_INIT_TOKENS = (
    "procd_set_param user",
    "procd_set_param group",
    "su -",
    "setuid",
    "setgid",
    "dropbear -u",
    "nobody",
)

DIRECT_CREDENTIAL_MARKERS = (
    "TPONEMESH_",
    "-----BEGIN RSA",
    "-----BEGIN PRIVATE KEY",
    "-----BEGIN CERTIFICATE",
    "onemesh_rsa_private_key.pem",
)

LOOPBACK_STRINGS = (
    "127.0.0.1",
    "localhost",
    "20002",
    "tmp_app",
    "tmpd",
    "mobile_app",
    "request_token",
    "tmp_client_connect_direct",
    "tdp_client_prepare_packet",
)

MESH_MARKERS = (
    "meshd",
    "sync-server",
    "easymesh-agent",
    "easymesh-controller",
    "ieee1905",
    "onemesh_client_list",
    "request_clients",
    "sync_wifi",
    "one_mesh.lua",
    "easy_mesh.lua",
)


@dataclass
class Evidence:
    source: str
    detail: str
    direct: bool
    evidence_type: str

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "detail": self.detail,
            "direct": self.direct,
            "evidence_type": self.evidence_type,
        }


def write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_cmd(args: list[str], path: Path) -> str:
    try:
        proc = subprocess.run(
            args + [str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return proc.stdout
    except Exception:
        return ""


def strings_text(path: Path, cache: dict[Path, str]) -> str:
    if path not in cache:
        cache[path] = run_cmd(["strings", "-a", "-n", "4"], path)
    return cache[path]


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def iter_results(workspace_root: Path) -> Iterable[Path]:
    runs = workspace_root / RUNS_DIRNAME
    yield from sorted(runs.rglob("results.json"))


def resolve_rootfs(bundle: dict) -> Path | None:
    system_path = Path((bundle.get("analysis") or {}).get("system_path") or "")
    return system_path if system_path.exists() else None


def find_named(rootfs: Path | None, name: str) -> list[Path]:
    if rootfs is None:
        return []
    return sorted(rootfs.rglob(name))


def normalize_target(bundle: dict) -> dict[str, str]:
    meta = bundle.get("target_metadata") or {}
    return {
        "vendor": meta.get("vendor") or "UNKNOWN",
        "model": meta.get("model") or "UNKNOWN",
        "version": meta.get("version") or "UNKNOWN",
        "corpus_id": meta.get("corpus_id") or "UNKNOWN",
    }


def bundle_family(bundle: dict) -> str:
    return (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"


def is_openwrt_target(bundle: dict) -> bool:
    family = bundle_family(bundle)
    if family in OPENWRT_FAMILIES:
        return True
    cfg = bundle.get("config_backend") or {}
    return cfg.get("family") == "uci" and "ubus" in (cfg.get("markers") or [])


def helper_names(bundle: dict) -> set[str]:
    names: set[str] = set()
    for field, key in [
        ("helper_script_inventory", "helpers"),
        ("management_inventory", "management_handlers"),
        ("service_topology", "orchestration_hooks"),
        ("execution_wrapper_features", "execution_wrappers"),
    ]:
        for name in (bundle.get(field) or {}).get(key) or []:
            if not name:
                continue
            names.add(Path(str(name)).name)
    return names


def init_script_texts(rootfs: Path | None, names: set[str]) -> list[tuple[Path, str]]:
    if rootfs is None:
        return []
    init_dir = rootfs / "etc/init.d"
    if not init_dir.exists():
        return []
    rows = []
    for path in sorted(init_dir.iterdir()):
        if not path.is_file():
            continue
        text = load_text(path)
        lowered = text.lower()
        if any(name.lower() in lowered for name in names):
            rows.append((path, text))
    return rows


def acl_markers(rootfs: Path | None) -> list[Path]:
    if rootfs is None:
        return []
    hits = []
    for rel in ["usr/share/rpcd/acl.d", "usr/share/acl.d", "etc/rpcd", "etc/ubus"]:
        path = rootfs / rel
        if path.exists():
            hits.append(path)
    return hits


def candidate_files(rootfs: Path | None) -> dict[str, list[Path]]:
    names = [
        "tmpsvr",
        "tdpServer",
        "tmp-luci",
        "libtmpv2.so",
        "cloud-pfclient",
        "cloud-brd",
        "cloud-client",
        "cloud-https",
        "tmp_server.lua",
        "onemesh.lua",
        "one_mesh.lua",
        "meshd",
        "sync-server",
        "easymesh-agent",
        "easymesh-controller",
        "ieee1905",
        "sauth.lua",
        "cloud_account.lua",
        "app_account.lua",
        "cloud_manager.lua",
        "accountmgnt",
    ]
    return {name: find_named(rootfs, name) for name in names}


def has_any(text: str, needles: Iterable[str]) -> list[str]:
    lowered = text.lower()
    hits = []
    for needle in needles:
        if needle.lower() in lowered:
            hits.append(needle)
    return hits


def add_evidence(rows: list[Evidence], source: str, detail: str, direct: bool, evidence_type: str) -> None:
    rows.append(Evidence(source=source, detail=detail, direct=direct, evidence_type=evidence_type))


def classify(evidence: list[Evidence], max_class: str | None = None) -> tuple[str, int]:
    direct = sum(1 for row in evidence if row.direct)
    indirect = len(evidence) - direct
    score = min(100, direct * 25 + indirect * 10)
    label = "absent"
    if direct >= 3 or (direct >= 2 and score >= 60):
        label = "confirmed"
    elif direct >= 1 and score >= 35:
        label = "high-confidence"
    elif score >= 20:
        label = "inferred"
    order = ["absent", "inferred", "high-confidence", "confirmed"]
    if max_class is not None and order.index(label) > order.index(max_class):
        label = max_class
    return label, score


def motif_m1(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]], cache: dict[Path, str]) -> dict[str, object]:
    evidence: list[Evidence] = []
    helpers = helper_names(bundle)
    family = bundle_family(bundle)
    relay_paths = files["cloud-pfclient"] + files["tmpsvr"] + files["tdpServer"] + files["libtmpv2.so"]
    for path in relay_paths:
        text = strings_text(path, cache)
        hits = has_any(text, LOOPBACK_STRINGS)
        if hits:
            add_evidence(evidence, str(path.relative_to(rootfs)), ", ".join(sorted(set(hits))), True, "strings")
    if files["tmp-luci"] and files["tmp_server.lua"]:
        add_evidence(evidence, "tmp relay bridge", "tmp-luci + tmp_server.lua present", True, "filesystem")
    if {"cloud-pfclient", "tmpsvr", "cloud-brd"} & helpers:
        add_evidence(evidence, "analysis metadata", "cloud relay helpers present in helper inventory", False, "results.json")
    if family == "openwrt-vendor-management-stack":
        add_evidence(evidence, "architecture family", family, False, "results.json")
    label, score = classify(evidence)
    return {"id": "M1", "name": MOTIF_DEFS["M1"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_m2(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]]) -> dict[str, object]:
    evidence: list[Evidence] = []
    cluster_names = {"tmpsvr", "tdpServer", "sync-server", "meshd", "cloud-pfclient", "cloud-brd", "cloud-client", "easymesh-agent", "easymesh-controller"}
    present = sorted(name for name in cluster_names if files.get(name))
    if len(present) >= 3:
        add_evidence(evidence, "filesystem", f"cluster components present: {', '.join(present)}", True, "filesystem")
    init_hits = init_script_texts(rootfs, cluster_names)
    if init_hits:
        touched = [path.name for path, _ in init_hits]
        add_evidence(evidence, "init scripts", f"init-managed services: {', '.join(sorted(touched))}", True, "init script")
        risky = []
        for path, text in init_hits:
            lowered = text.lower()
            risky.extend(token for token in RISKY_INIT_TOKENS if token in lowered)
        if not risky:
            add_evidence(evidence, "init scripts", "no privilege-drop markers found in touched init scripts", False, "absence heuristic")
    label, score = classify(evidence, max_class="high-confidence")
    return {"id": "M2", "name": MOTIF_DEFS["M2"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_m3(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]]) -> dict[str, object]:
    evidence: list[Evidence] = []
    lua_targets = files["tmp_server.lua"] + files["onemesh.lua"] + files["one_mesh.lua"]
    lua_targets += files["cloud_account.lua"] + files["app_account.lua"] + files["cloud_manager.lua"]
    for path in lua_targets:
        text = load_text(path)
        dispatch_hits = has_any(text, ["dispatch", "sgi", "tmp", "mobile_app", "controller"])
        if dispatch_hits:
            add_evidence(evidence, str(path.relative_to(rootfs)), ", ".join(sorted(set(dispatch_hits))), True, "Lua source")
        auth_hits = has_any(text, ["sauth", "auth", "login", "token_verify", "checklogin", "is_login"])
        if not auth_hits and dispatch_hits:
            add_evidence(evidence, str(path.relative_to(rootfs)), "dispatch markers without local auth helper markers", True, "Lua source absence")
    if files["sauth.lua"]:
        add_evidence(evidence, "filesystem", "sauth.lua exists as separate helper context", False, "filesystem")
    label, score = classify(evidence)
    return {"id": "M3", "name": MOTIF_DEFS["M3"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_m4(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]]) -> dict[str, object]:
    evidence: list[Evidence] = []
    control = (bundle.get("service_topology") or {}).get("control_plane") or ""
    if "ubus" in control:
        add_evidence(evidence, "results.json", control, False, "results.json")
    if files["tmpsvr"] or files["tdpServer"] or files["meshd"] or files["sync-server"]:
        add_evidence(evidence, "filesystem", "ubus-facing orchestration daemons present", True, "filesystem")
    acl = acl_markers(rootfs)
    if not acl and rootfs is not None:
        add_evidence(evidence, "rootfs", "no rpcd/ubus ACL artifact directories visible", True, "filesystem absence")
    label, score = classify(evidence, max_class="high-confidence")
    return {"id": "M4", "name": MOTIF_DEFS["M4"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_m5(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]], cache: dict[Path, str]) -> dict[str, object]:
    evidence: list[Evidence] = []
    to_scan = (
        files["tdpServer"]
        + files["tmpsvr"]
        + files["cloud-pfclient"]
        + files["cloud-brd"]
        + files["libtmpv2.so"]
        + files["onemesh.lua"]
        + files["one_mesh.lua"]
        + files["accountmgnt"]
    )
    for path in to_scan:
        if path.suffix == ".lua" or path.name == "accountmgnt":
            text = load_text(path)
        else:
            text = strings_text(path, cache)
        hits = has_any(text, DIRECT_CREDENTIAL_MARKERS)
        for hit in sorted(set(hits)):
            rel = str(path.relative_to(rootfs))
            add_evidence(evidence, rel, hit, True, "literal credential marker")
    # Weaker but still useful recurrence indicator.
    if rootfs is not None:
        for rel in ["etc/config/accountmgnt", "etc/group-info"]:
            path = rootfs / rel
            if path.exists():
                text = load_text(path)
                weak_hits = has_any(text, ["meshkeys", "rsa2048_enable"])
                if weak_hits:
                    add_evidence(evidence, rel, ", ".join(sorted(set(weak_hits))), False, "config marker")
    label, score = classify(evidence)
    return {"id": "M5", "name": MOTIF_DEFS["M5"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_m6(bundle: dict, rootfs: Path | None, files: dict[str, list[Path]], cache: dict[Path, str]) -> dict[str, object]:
    evidence: list[Evidence] = []
    helpers = helper_names(bundle)
    present = sorted(name for name in MESH_MARKERS if files.get(name))
    if present:
        add_evidence(evidence, "filesystem", f"mesh orchestration components present: {', '.join(present)}", True, "filesystem")
    if {"sync-server", "meshd", "easymesh-agent", "easymesh-controller"} & helpers:
        add_evidence(evidence, "results.json", "mesh propagation helpers present in helper inventory", False, "results.json")
    for name in ["sync-server", "meshd"]:
        for path in files.get(name, []):
            text = strings_text(path, cache)
            hits = has_any(text, ["onemesh_client_list", "request_clients", "sync_wifi", "ieee1905", "mesh"])
            if hits:
                add_evidence(evidence, str(path.relative_to(rootfs)), ", ".join(sorted(set(hits))), True, "strings")
    label, score = classify(evidence)
    return {"id": "M6", "name": MOTIF_DEFS["M6"], "classification": label, "score": score, "evidence": [row.as_dict() for row in evidence]}


def motif_record(bundle: dict, rootfs: Path | None) -> dict[str, object]:
    meta = normalize_target(bundle)
    family = bundle_family(bundle)
    files = candidate_files(rootfs)
    cache: dict[Path, str] = {}
    motifs = {
        "M1": motif_m1(bundle, rootfs, files, cache),
        "M2": motif_m2(bundle, rootfs, files),
        "M3": motif_m3(bundle, rootfs, files),
        "M4": motif_m4(bundle, rootfs, files),
        "M5": motif_m5(bundle, rootfs, files, cache),
        "M6": motif_m6(bundle, rootfs, files, cache),
    }
    return {
        "target": meta,
        "architecture_family": family,
        "rootfs_preserved": bool(rootfs),
        "motifs": motifs,
    }


def scan_workspace(workspace_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for result_path in iter_results(workspace_root):
        bundle = load_json(result_path)
        if not is_openwrt_target(bundle):
            continue
        rootfs = resolve_rootfs(bundle)
        rows.append(motif_record(bundle, rootfs))
    return rows


def confidence_counts(rows: list[dict[str, object]]) -> dict[str, Counter]:
    out: dict[str, Counter] = {motif: Counter() for motif in MOTIF_ORDER}
    for row in rows:
        for motif in MOTIF_ORDER:
            out[motif][row["motifs"][motif]["classification"]] += 1
    return out


def vendor_matrix(rows: list[dict[str, object]]) -> dict[str, Counter]:
    out: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        vendor = row["target"]["vendor"]
        for motif in MOTIF_ORDER:
            if row["motifs"][motif]["classification"] != "absent":
                out[vendor][motif] += 1
    return out


def family_matrix(rows: list[dict[str, object]]) -> dict[str, Counter]:
    out: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        family = row["architecture_family"]
        for motif in MOTIF_ORDER:
            if row["motifs"][motif]["classification"] != "absent":
                out[family][motif] += 1
    return out


def top_patterns(rows: list[dict[str, object]]) -> list[tuple[str, int]]:
    counts = Counter()
    for row in rows:
        active = [motif for motif in MOTIF_ORDER if row["motifs"][motif]["classification"] != "absent"]
        counts["+".join(active) if active else "none"] += 1
    return counts.most_common()


def render_scorecards(rows: list[dict[str, object]]) -> str:
    lines = [
        "# Orchestration Motif Scorecards",
        "",
        "Each scorecard below is static-only. `confirmed` and `high-confidence` refer to artifact visibility, not exploitability or runtime reachability proof.",
        "",
    ]
    for row in sorted(rows, key=lambda item: (item["target"]["vendor"], item["target"]["model"], item["target"]["version"])):
        tgt = row["target"]
        lines += [
            f"## {tgt['vendor']} {tgt['model']} {tgt['version']}",
            "",
            f"- `corpus_id`: `{tgt['corpus_id']}`",
            f"- `architecture_family`: `{row['architecture_family']}`",
            f"- `rootfs_preserved`: `{row['rootfs_preserved']}`",
            "",
            "| Motif | Classification | Score | Representative Evidence |",
            "| --- | --- | ---: | --- |",
        ]
        for motif in MOTIF_ORDER:
            record = row["motifs"][motif]
            preview = "; ".join(
                f"{ev['source']}: {ev['detail']}" for ev in record["evidence"][:2]
            ) or "-"
            lines.append(
                f"| `{motif}` {record['name']} | `{record['classification']}` | {record['score']} | {preview} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_matrix(rows: list[dict[str, object]]) -> str:
    lines = [
        "# Cross-Firmware Orchestration Motif Matrix",
        "",
        "| Vendor | Model | Version | Family | M1 | M2 | M3 | M4 | M5 | M6 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(rows, key=lambda item: (item["target"]["vendor"], item["target"]["model"], item["target"]["version"])):
        tgt = row["target"]
        vals = [
            f"{row['motifs'][motif]['classification']} ({row['motifs'][motif]['score']})"
            for motif in MOTIF_ORDER
        ]
        lines.append(
            f"| {tgt['vendor']} | {tgt['model']} | {tgt['version']} | `{row['architecture_family']}` | "
            + " | ".join(f"`{v}`" for v in vals)
            + " |"
        )
    lines += ["", "## Cross-Vendor Motif Counts", "", "| Vendor | M1 | M2 | M3 | M4 | M5 | M6 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for vendor, counts in sorted(vendor_matrix(rows).items()):
        lines.append(f"| {vendor} | " + " | ".join(str(counts[m]) for m in MOTIF_ORDER) + " |")
    return "\n".join(lines)


def render_prevalence(rows: list[dict[str, object]]) -> str:
    counts = confidence_counts(rows)
    family_counts = family_matrix(rows)
    lines = [
        "# Trust-Collapse Prevalence Report",
        "",
        f"- OpenWrt-derived targets scanned: `{len(rows)}`",
        f"- Architecture families covered: `{len({row['architecture_family'] for row in rows})}`",
        "",
        "## Motif Classification Counts",
        "",
        "| Motif | Confirmed | High-Confidence | Inferred | Absent |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for motif in MOTIF_ORDER:
        c = counts[motif]
        lines.append(f"| `{motif}` {MOTIF_DEFS[motif]} | {c['confirmed']} | {c['high-confidence']} | {c['inferred']} | {c['absent']} |")
    lines += ["", "## Architecture-Family Recurrence", "", "| Family | M1 | M2 | M3 | M4 | M5 | M6 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for family, c in sorted(family_counts.items()):
        lines.append(f"| `{family}` | " + " | ".join(str(c[m]) for m in MOTIF_ORDER) + " |")
    lines += ["", "## Most Frequent Co-Occurrence Patterns", ""]
    for pattern, count in top_patterns(rows)[:10]:
        lines.append(f"- `{pattern}`: `{count}` targets")
    return "\n".join(lines)


def render_graphs(rows: list[dict[str, object]]) -> str:
    family_counts = family_matrix(rows)
    motif_nodes = " ".join(f"{m}[{m}]" for m in MOTIF_ORDER)
    lines = [
        "# Orchestration Motif Recurrence Graphs",
        "",
        "## Family-to-Motif Recurrence",
        "",
        "```mermaid",
        "graph LR",
        f"    {motif_nodes}",
    ]
    for family, c in sorted(family_counts.items()):
        fam_id = family.replace("-", "_")
        lines.append(f'    {fam_id}["{family}"]')
        for motif in MOTIF_ORDER:
            if c[motif]:
                lines.append(f"    {fam_id} -->|{c[motif]}| {motif}")
    lines += ["```", "", "## Motif Definitions", ""]
    for motif in MOTIF_ORDER:
        lines.append(f"- `{motif}`: {MOTIF_DEFS[motif]}")
    lines += [
        "",
        "## Confidence Interpretation",
        "",
        "- `confirmed`: direct strings, Lua source, config files, or file-presence chains exist in preserved rootfs artifacts.",
        "- `high-confidence`: direct artifact evidence exists, but the motif depends partly on absence reasoning or distributed control-plane inference.",
        "- `inferred`: helper inventories or architecture metadata suggest the motif, but direct static corroboration is incomplete.",
    ]
    return "\n".join(lines)


def schema_json() -> dict[str, object]:
    return {
        "schema_version": "2026-05-10.motif.v1",
        "target": {
            "vendor": "string",
            "model": "string",
            "version": "string",
            "corpus_id": "string",
        },
        "architecture_family": "string",
        "rootfs_preserved": "boolean",
        "motifs": {
            motif: {
                "id": motif,
                "name": MOTIF_DEFS[motif],
                "classification": "absent|inferred|high-confidence|confirmed",
                "score": "0-100 integer",
                "evidence": [
                    {
                        "source": "string",
                        "detail": "string",
                        "direct": "boolean",
                        "evidence_type": "filesystem|strings|Lua source|init script|results.json|absence heuristic|literal credential marker|config marker",
                    }
                ],
            }
            for motif in MOTIF_ORDER
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan OpenWrt-derived firmware bundles for orchestration trust-collapse motifs.")
    ap.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE))
    args = ap.parse_args()

    workspace = Path(args.workspace_root)
    rows = scan_workspace(workspace)

    write_text(workspace / OUTPUT_FILES["scorecards"], render_scorecards(rows))
    write_text(workspace / OUTPUT_FILES["matrix"], render_matrix(rows))
    write_text(workspace / OUTPUT_FILES["prevalence"], render_prevalence(rows))
    write_text(workspace / OUTPUT_FILES["graphs"], render_graphs(rows))
    write_text(workspace / OUTPUT_FILES["results"], json.dumps({"schema_version": "2026-05-10.motif.v1", "targets": rows}, indent=2))
    write_text(workspace / OUTPUT_FILES["schema"], json.dumps(schema_json(), indent=2))

    print(f"Scanned {len(rows)} OpenWrt-derived firmware bundles.")
    for name in OUTPUT_FILES.values():
        print(workspace / name)


if __name__ == "__main__":
    main()
