#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from research_tools.build_management_plane_graphs_annotated import (  # noqa: E402
    Graph as BaseGraph,
    Node as BaseNode,
    Edge as BaseEdge,
    mr90x_graph,
    tp_link_graph,
)

from research_tools.paths import regeneration_dir  # noqa: E402

OUTDIR = regeneration_dir()
MOTIF_RESULTS = OUTDIR / "orchestration_motif_results.json"

OUTPUTS = {
    "schema": "semantic_graph_schema_v2.md",
    "graphs": "motif_annotated_graphs.md",
    "heatmap": "trust_heatmap_generation.md",
    "chains": "propagation_chain_analysis.md",
    "comparison": "cross_firmware_semantic_comparison.md",
    "json": "semantic_graph_results.json",
}

MOTIF_TO_SEMANTIC = {
    "M1": ["CLOUD_RELAY", "LOCALHOST_TRUST"],
    "M2": ["ROOT_MANAGED_CLUSTER"],
    "M3": ["LUA_DISPATCH", "SESSION_WITHOUT_AUTH"],
    "M4": ["UBUS_CONTROL", "ACL_GAP"],
    "M5": ["TRANSPORT_CREDENTIAL", "STATIC_TRUST_MATERIAL"],
    "M6": ["PROPAGATES_TRUST", "MESH_PROPAGATION"],
}


@dataclass
class SemanticNode:
    node_id: str
    label: str
    component_type: str
    firmware_target: str
    architecture_family: str
    role: str
    privilege_level: str
    ipc_exposure: str
    externally_reachable: bool
    localhost_only: bool
    shell_capable: bool
    persistence_role: str
    relay_role: str
    orchestration_role: str
    motifs: list[str] = field(default_factory=list)
    trust_indicators: list[str] = field(default_factory=list)


@dataclass
class SemanticEdge:
    src: str
    dst: str
    firmware_target: str
    architecture_family: str
    relationship_type: str
    confidence: str
    evidence_source: str
    evidence_type: str
    source_locator: str
    validation_tier: str
    runtime_validation_required: bool
    motifs: list[str] = field(default_factory=list)
    semantic_tags: list[str] = field(default_factory=list)
    trust_collapse_indicators: list[str] = field(default_factory=list)


@dataclass
class SemanticGraph:
    graph_id: str
    firmware_target: str
    corpus_id: str
    vendor: str
    model: str
    version: str
    architecture_family: str
    motifs: dict[str, str]
    nodes: list[SemanticNode]
    edges: list[SemanticEdge]
    notes: list[str]


def write(path: str, text: str) -> None:
    (OUTDIR / path).write_text(text.rstrip() + "\n", encoding="utf-8")


def load_motif_targets() -> list[dict]:
    return json.loads(MOTIF_RESULTS.read_text(encoding="utf-8"))["targets"]


def motif_map(row: dict) -> dict[str, str]:
    return {k: v["classification"] for k, v in row["motifs"].items()}


def motif_active(row: dict, motif: str) -> bool:
    return row["motifs"][motif]["classification"] != "absent"


def semantic_node(base: BaseNode, family: str, motifs: dict[str, str]) -> SemanticNode:
    localhost_only = base.node_id in {"tmp_luci", "tmp_server_lua", "ubusd", "sync_server", "sync_request", "sync_request_clients", "sync_wifi", "onemesh_lua"}
    privilege = "root-managed" if motifs.get("M2") in {"confirmed", "high-confidence"} and base.component_type in {"daemon", "helper", "lua", "relay-helper", "ingress-daemon"} else "unknown"
    ipc = "ubus" if base.node_id == "ubusd" else (
        "loopback-relay" if base.node_id in {"tmp_luci", "tmp_server_lua"} else
        "network-ingress" if base.externally_reachable and base.component_type in {"external", "ingress-daemon"} else
        "state-files" if base.node_id == "sync_state" else
        "local-process"
    )
    persistence_role = "persistent" if base.node_id in {"uci_onemesh", "uci_accountmgnt"} else ("runtime-state" if base.node_id == "sync_state" else "none")
    relay_role = (
        "ingress" if base.node_id in {"tdp", "tmpsvr"} else
        "localhost-relay" if base.node_id in {"tmp_luci", "tmp_server_lua"} else
        "distributed-relay" if base.node_id in {"sync_server", "sync_request", "sync_request_clients", "sync_wifi"} else
        "none"
    )
    orchestration_role = (
        "Lua dispatch" if base.node_id in {"tmp_server_lua", "onemesh_lua"} else
        "IPC coordination" if base.node_id == "ubusd" else
        "mesh coordinator" if base.node_id == "meshd" else
        "downstream mesh transport" if base.node_id in {"easymesh_agent", "easymesh_controller", "ieee1905"} else
        base.role
    )
    motif_labels = []
    trust_indicators = []
    if relay_role != "none" and motifs.get("M1") != "absent":
        motif_labels.append("M1")
        trust_indicators.append("relay-trust")
    if base.node_id in {"tmp_server_lua", "onemesh_lua"} and motifs.get("M3") != "absent":
        motif_labels.append("M3")
        trust_indicators.append("lua-dispatch")
    if base.node_id in {"ubusd", "sync_server", "meshd"} and motifs.get("M4") != "absent":
        motif_labels.append("M4")
        trust_indicators.append("ubus-orchestration")
    if base.node_id in {"uci_onemesh", "uci_accountmgnt", "sync_state", "sync_server", "meshd"} and motifs.get("M6") != "absent":
        motif_labels.append("M6")
        trust_indicators.append("trust-propagation")
    if base.node_id in {"tdp", "tmpsvr", "uci_accountmgnt"} and motifs.get("M5") != "absent":
        motif_labels.append("M5")
        trust_indicators.append("static-transport-material")
    return SemanticNode(
        node_id=base.node_id,
        label=base.label,
        component_type=base.component_type,
        firmware_target=base.target,
        architecture_family=family,
        role=base.role,
        privilege_level=privilege,
        ipc_exposure=ipc,
        externally_reachable=base.externally_reachable,
        localhost_only=localhost_only,
        shell_capable=base.shell_capable,
        persistence_role=persistence_role,
        relay_role=relay_role,
        orchestration_role=orchestration_role,
        motifs=sorted(set(motif_labels)),
        trust_indicators=sorted(set(trust_indicators)),
    )


def edge_motifs(edge: BaseEdge, graph_motifs: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    motifs: list[str] = []
    tags: list[str] = []
    indicators: list[str] = []
    if edge.relationship_type in {"exec-relay", "lua-dispatch", "lua-bridge"} and graph_motifs.get("M1") != "absent":
        motifs.append("M1")
        tags.extend(["CLOUD_RELAY", "LOCALHOST_TRUST"])
        indicators.append("relay-crossing")
    if edge.relationship_type in {"lua-dispatch", "lua-bridge", "lua-callback"} and graph_motifs.get("M3") != "absent":
        motifs.append("M3")
        tags.extend(["LUA_DISPATCH", "SESSION_WITHOUT_AUTH"])
        indicators.append("lua-session-gap")
    if edge.relationship_type in {"ubus-provider", "ubus-consumer", "ubus-coordination"} and graph_motifs.get("M4") != "absent":
        motifs.append("M4")
        tags.append("UBUS_CONTROL")
        indicators.append("ubus-authorization-unknown")
    if edge.relationship_type in {"uci-write", "uci-read", "uci-consumer", "state-persistence", "runtime-state-write", "state-input"}:
        tags.append("UCI_PERSISTENCE")
        if graph_motifs.get("M6") != "absent":
            motifs.append("M6")
            tags.append("PROPAGATES_TRUST")
            indicators.append("persistent-trust-transfer")
    if edge.relationship_type == "helper-exec":
        tags.append("HELPER_EXECUTION")
        if graph_motifs.get("M6") != "absent":
            motifs.append("M6")
            indicators.append("helper-fanout")
    if graph_motifs.get("M5") != "absent" and edge.dst == "uci_accountmgnt":
        motifs.append("M5")
        tags.append("TRANSPORT_CREDENTIAL")
        indicators.append("trust-material-read")
    if edge.src in {"tmpsvr", "tmp_luci"} and edge.dst in {"tmp_luci", "tmp_server_lua"} and graph_motifs.get("M1") == "confirmed":
        tags.append("BYPASSES_AUTH")
        indicators.append("localhost-assumed-trust")
    return sorted(set(motifs)), sorted(set(tags)), sorted(set(indicators))


def validation_tier(edge: BaseEdge) -> str:
    if edge.confidence == "confirmed":
        return "confirmed"
    if edge.confidence == "high-confidence":
        return "high-confidence"
    if edge.confidence == "inferred":
        return "inferred"
    return "runtime-required"


def semantic_edge(base: BaseEdge, family: str, motifs: dict[str, str], target: str) -> SemanticEdge:
    motif_labels, tags, indicators = edge_motifs(base, motifs)
    tier = validation_tier(base)
    runtime_required = False
    if tier in {"high-confidence", "inferred"} and (
        {"BYPASSES_AUTH", "SESSION_WITHOUT_AUTH", "LOCALHOST_TRUST", "PROPAGATES_TRUST"} & set(tags)
        or base.relationship_type in {"state-input", "uci-write", "ubus-consumer", "uci-consumer", "runtime-state-write"}
    ):
        runtime_required = True
    if tier == "inferred" and (
        {"BYPASSES_AUTH", "SESSION_WITHOUT_AUTH", "LOCALHOST_TRUST", "PROPAGATES_TRUST"} & set(tags)
        or base.relationship_type in {"state-input"}
    ):
        tier = "runtime-required"
    return SemanticEdge(
        src=base.src,
        dst=base.dst,
        firmware_target=target,
        architecture_family=family,
        relationship_type=base.relationship_type,
        confidence=base.confidence,
        evidence_source=base.evidence_source,
        evidence_type=base.evidence_type,
        source_locator=base.source_locator,
        validation_tier=tier,
        runtime_validation_required=runtime_required or tier == "runtime-required",
        motifs=motif_labels,
        semantic_tags=tags,
        trust_collapse_indicators=indicators,
    )


def choose_target(rows: list[dict], needle: str) -> dict:
    for row in rows:
        if needle in row["target"]["corpus_id"]:
            return row
    raise KeyError(needle)


def build_graph_for_row(row: dict, base_graph: BaseGraph) -> SemanticGraph:
    family = row["architecture_family"]
    motifs = motif_map(row)
    nodes = [semantic_node(node, family, motifs) for node in base_graph.nodes]
    edges = [semantic_edge(edge, family, motifs, base_graph.name) for edge in base_graph.edges]
    target = row["target"]
    notes = [
        "Semantic tags are static motif labels, not exploit claims.",
        "Runtime-required edges mark places where static evidence is meaningful but incomplete.",
    ]
    return SemanticGraph(
        graph_id=target["corpus_id"],
        firmware_target=base_graph.name,
        corpus_id=target["corpus_id"],
        vendor=target["vendor"],
        model=target["model"],
        version=target["version"],
        architecture_family=family,
        motifs=motifs,
        nodes=nodes,
        edges=edges,
        notes=notes,
    )


def base_graphs(rows: list[dict]) -> list[SemanticGraph]:
    ax23_row = choose_target(rows, "tp-link-archer-ax23")
    ax72_row = choose_target(rows, "tp-link-archer-ax72")
    mr90x_row = choose_target(rows, "mercusys-mr90x")
    ax55_row = choose_target(rows, "tp-link-archer-ax55-v4-251030-eu")
    return [
        build_graph_for_row(ax23_row, tp_link_graph("TP-Link Archer AX23 1.2_250904")),
        build_graph_for_row(ax55_row, tp_link_graph("TP-Link Archer AX55 V4_251030_EU")),
        build_graph_for_row(ax72_row, tp_link_graph("TP-Link Archer AX72 V2_241119_US")),
        build_graph_for_row(mr90x_row, mr90x_graph()),
    ]


def other_target_summaries(rows: list[dict], covered: set[str]) -> list[dict]:
    summaries = []
    for row in rows:
        cid = row["target"]["corpus_id"]
        if cid in covered:
            continue
        active = [motif for motif, status in motif_map(row).items() if status != "absent"]
        summaries.append(
            {
                "corpus_id": cid,
                "vendor": row["target"]["vendor"],
                "model": row["target"]["model"],
                "version": row["target"]["version"],
                "family": row["architecture_family"],
                "active_motifs": active,
                "strongest_classification": max(
                    (row["motifs"][m]["classification"] for m in row["motifs"]),
                    key=lambda x: ["absent", "inferred", "high-confidence", "confirmed"].index(x),
                ),
            }
        )
    return summaries


def mermaid_semantic(graph: SemanticGraph) -> str:
    lines = ["```mermaid", "flowchart TD"]
    for node in graph.nodes:
        attrs = []
        if node.externally_reachable:
            attrs.append("ext")
        if node.localhost_only:
            attrs.append("localhost")
        if node.shell_capable:
            attrs.append("shell")
        if node.persistence_role != "none":
            attrs.append(node.persistence_role)
        if node.motifs:
            attrs.append(",".join(node.motifs))
        suffix = "\\n[" + "; ".join(attrs) + "]" if attrs else ""
        lines.append(f'    {node.node_id}["{node.label}{suffix}"]')
    for edge in graph.edges:
        tags = ",".join(edge.semantic_tags[:2]) if edge.semantic_tags else edge.relationship_type
        lines.append(f"    {edge.src} -->|{tags} [{edge.validation_tier}]| {edge.dst}")
    lines.append("```")
    return "\n".join(lines)


def schema_md() -> str:
    return "\n".join(
        [
            "# Semantic Graph Schema v2",
            "",
            "This schema unifies management-plane graph topology with motif scanner output.",
            "",
            "## Node Fields",
            "",
            "- `component_type`",
            "- `privilege_level`",
            "- `ipc_exposure`",
            "- `externally_reachable`",
            "- `localhost_only`",
            "- `shell_capable`",
            "- `persistence_role`",
            "- `relay_role`",
            "- `orchestration_role`",
            "- `motifs`",
            "- `trust_indicators`",
            "",
            "## Edge Fields",
            "",
            "- `relationship_type`",
            "- `semantic_tags`",
            "- `trust_collapse_indicators`",
            "- `confidence`",
            "- `validation_tier`",
            "- `runtime_validation_required`",
            "- `evidence_source`",
            "- `evidence_type`",
            "- `source_locator`",
            "",
            "## Tag Semantics",
            "",
            "- `BYPASSES_AUTH`: static relay pattern where local trust appears to replace edge-local authorization checks.",
            "- `PROPAGATES_TRUST`: state or orchestration edge that carries trusted management intent onward.",
            "- `SESSION_WITHOUT_AUTH`: Lua/session edge whose local dispatch semantics lack adjacent auth evidence in static artifacts.",
            "- `CLOUD_RELAY`: relay path between ingress, local control-plane helper, and management fabric.",
            "- `LUA_DISPATCH`: handoff into Lua controller/policy logic.",
            "- `LOCALHOST_TRUST`: edge grounded in local IPC or loopback trust assumptions.",
            "- `UCI_PERSISTENCE`: persistent configuration or runtime-state materialization edge.",
            "- `HELPER_EXECUTION`: helper/script fan-out edge.",
            "",
            "## Validation Tiers",
            "",
            "- `confirmed`: direct static evidence supports the edge on that target.",
            "- `high-confidence`: strong static evidence exists but some semantics are reconstructed.",
            "- `inferred`: family-level or indirect target evidence only.",
            "- `runtime-required`: static motif is meaningful but the edge needs dynamic confirmation to settle authorization semantics.",
        ]
    )


def motif_graphs_md(graphs: list[SemanticGraph], summaries: list[dict]) -> str:
    lines = ["# Motif-Annotated Graphs", ""]
    for graph in graphs:
        lines += [
            f"## {graph.firmware_target}",
            "",
            f"- `corpus_id`: `{graph.corpus_id}`",
            f"- `architecture_family`: `{graph.architecture_family}`",
            f"- `active motifs`: `{', '.join(k for k, v in graph.motifs.items() if v != 'absent') or 'none'}`",
            "",
            mermaid_semantic(graph),
            "",
            "| Edge | Validation | Motifs | Semantic Tags | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for edge in graph.edges:
            lines.append(
                f"| `{edge.src} -> {edge.dst}` | `{edge.validation_tier}` | `{', '.join(edge.motifs) or '-'}` | "
                f"`{', '.join(edge.semantic_tags) or '-'}` | `{edge.source_locator}` |"
            )
        lines.append("")
    lines += [
        "## Other OpenWrt-Derived Targets",
        "",
        "| Vendor | Model | Version | Family | Active Motifs | Strongest Classification |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in summaries:
        lines.append(
            f"| {row['vendor']} | {row['model']} | {row['version']} | `{row['family']}` | "
            f"`{', '.join(row['active_motifs']) or 'none'}` | `{row['strongest_classification']}` |"
        )
    return "\n".join(lines)


def heatmap_md(graphs: list[SemanticGraph], rows: list[dict]) -> str:
    all_rows = {row["target"]["corpus_id"]: row for row in rows}
    lines = [
        "# Trust Heatmap Generation",
        "",
        "The heatmap below is a static semantic summary. Higher values reflect more active motif-tagged trust edges, not exploitability.",
        "",
        "| Target | Family | Active Motifs | Trust Edge Count | Runtime-Required Edge Count | Heat |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for graph in graphs:
        trust_edges = sum(1 for edge in graph.edges if edge.trust_collapse_indicators)
        runtime_edges = sum(1 for edge in graph.edges if edge.runtime_validation_required)
        motif_count = sum(1 for status in graph.motifs.values() if status != "absent")
        heat = "high" if trust_edges >= 10 else "medium" if trust_edges >= 6 else "low"
        lines.append(
            f"| {graph.firmware_target} | `{graph.architecture_family}` | {motif_count} | {trust_edges} | {runtime_edges} | `{heat}` |"
        )
    lines += [
        "",
        "## Fleet Motif Heat by Family",
        "",
        "| Family | Targets | Active Motif Total |",
        "| --- | ---: | ---: |",
    ]
    family_totals: dict[str, tuple[int, int]] = {}
    for row in rows:
        fam = row["architecture_family"]
        active = sum(1 for status in motif_map(row).values() if status != "absent")
        count, total = family_totals.get(fam, (0, 0))
        family_totals[fam] = (count + 1, total + active)
    for fam, (count, total) in sorted(family_totals.items()):
        lines.append(f"| `{fam}` | {count} | {total} |")
    return "\n".join(lines)


def chains_md(graphs: list[SemanticGraph]) -> str:
    lines = [
        "# Propagation Chain Analysis",
        "",
        "| Target | Representative Chain | Static Status | Authorization Semantics |",
        "| --- | --- | --- | --- |",
    ]
    for graph in graphs:
        if any(node.node_id == "tmpsvr" for node in graph.nodes):
            chain = "external -> tmpsvr -> tmp-luci -> tmp_server.lua -> sync-server -> meshd"
            auth = "localhost relay + Lua dispatch + downstream trust propagation"
        else:
            chain = "external -> tdpServer -> onemesh.lua -> UCI/sync-server -> meshd"
            auth = "ingress gateway + Lua dispatch + persistent/state propagation"
        tier = "runtime-required" if any(edge.runtime_validation_required for edge in graph.edges) else "static-covered"
        lines.append(f"| {graph.firmware_target} | `{chain}` | `{tier}` | {auth} |")
    lines += [
        "",
        "## Authorization-Collapse Chain Table",
        "",
        "| Edge Class | Meaning | Typical Targets |",
        "| --- | --- | --- |",
        "| `CLOUD_RELAY + LOCALHOST_TRUST` | loopback/local relay edge accepted as trusted orchestration input | MR90X, XE75 family |",
        "| `LUA_DISPATCH + SESSION_WITHOUT_AUTH` | state enters Lua/controller logic without adjacent auth evidence in the same static layer | AX23, AX55, AX72, MR90X |",
        "| `UCI_PERSISTENCE + PROPAGATES_TRUST` | accepted state persists into config/runtime files and is later consumed by daemons | AX23, AX55, AX72, MR90X |",
        "| `HELPER_EXECUTION + PROPAGATES_TRUST` | downstream helper fan-out turns prior state into distributed control actions | AX23, AX55, AX72, MR90X |",
    ]
    return "\n".join(lines)


def comparison_md(graphs: list[SemanticGraph], summaries: list[dict]) -> str:
    lines = [
        "# Cross-Firmware Semantic Comparison",
        "",
        "## Motif-to-Edge Mapping",
        "",
        "| Motif | Edge Classes | Representative Targets |",
        "| --- | --- | --- |",
        "| `M1` | `exec-relay`, `lua-dispatch`, ingress-to-local control relay | MR90X, XE75 family |",
        "| `M2` | root-managed daemon/helper cluster with no explicit drop markers | TP-Link/MERCUSYS management stack, select Xiaomi |",
        "| `M3` | `lua-bridge`, `lua-dispatch`, `lua-callback` | AX23, AX55, AX72, MR90X |",
        "| `M4` | `ubus-provider`, `ubus-consumer`, `ubus-coordination` without visible ACL artifacts | TP-Link/MERCUSYS stack, Xiaomi |",
        "| `M5` | trust-material reads, hardcoded transport material markers | TP-Link AX23/AX55/AX72, MR90X weakly |",
        "| `M6` | `uci-consumer`, `state-persistence`, `helper-exec`, mesh coordinator fan-out | TP-Link/MERCUSYS, Xiaomi |",
        "",
        "## Architecture-Family Comparison",
        "",
        "| Family | Targets | Main Motifs | Interpretation |",
        "| --- | ---: | --- | --- |",
    ]
    family_map: dict[str, list[dict]] = {}
    for row in summaries:
        family_map.setdefault(row["family"], []).append(row)
    for graph in graphs:
        family_map.setdefault(graph.architecture_family, []).append({"active_motifs": [m for m, s in graph.motifs.items() if s != "absent"]})
    for family, items in sorted(family_map.items()):
        counts = {}
        for item in items:
            for motif in item["active_motifs"]:
                counts[motif] = counts.get(motif, 0) + 1
        motifs = ", ".join(sorted(counts, key=counts.get, reverse=True)) or "none"
        interpretation = (
            "relay/auth/state mesh stack" if family == "openwrt-vendor-management-stack" else
            "helper-heavy but weaker trust-collapse motifs" if family == "openwrt-shell-helper-sdk" else
            "mesh propagation without strong relay evidence" if family == "openwrt-mtk-lua-wireless" else
            "mixed semantics"
        )
        lines.append(f"| `{family}` | {len(items)} | `{motifs}` | {interpretation} |")
    lines += [
        "",
        "## Primary Target Comparison",
        "",
        "| Target | Confirmed Edges | High-Confidence Edges | Inferred Edges | Runtime-Tier Edges | Runtime-Required Edges |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for graph in graphs:
        counts = {"confirmed": 0, "high-confidence": 0, "inferred": 0, "runtime-required": 0}
        for edge in graph.edges:
            counts[edge.validation_tier] += 1
        runtime_required = sum(1 for edge in graph.edges if edge.runtime_validation_required)
        lines.append(
            f"| {graph.firmware_target} | {counts['confirmed']} | {counts['high-confidence']} | {counts['inferred']} | {counts['runtime-required']} | {runtime_required} |"
        )
    return "\n".join(lines)


def results_json(graphs: list[SemanticGraph], summaries: list[dict]) -> str:
    payload = {
        "schema_version": "2026-05-10.semantic-graph.v2",
        "graphs": [asdict(graph) for graph in graphs],
        "fleet_summaries": summaries,
    }
    return json.dumps(payload, indent=2)


def main() -> None:
    rows = load_motif_targets()
    graphs = base_graphs(rows)
    covered = {graph.corpus_id for graph in graphs}
    summaries = other_target_summaries(rows, covered)
    write(OUTPUTS["schema"], schema_md())
    write(OUTPUTS["graphs"], motif_graphs_md(graphs, summaries))
    write(OUTPUTS["heatmap"], heatmap_md(graphs, rows))
    write(OUTPUTS["chains"], chains_md(graphs))
    write(OUTPUTS["comparison"], comparison_md(graphs, summaries))
    write(OUTPUTS["json"], results_json(graphs, summaries))


if __name__ == "__main__":
    main()
