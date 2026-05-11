#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


OUTDIR = Path("/home/user/firmware_project/research/regeneration/full_corpus_20260508")


@dataclass
class Node:
    node_id: str
    label: str
    kind: str
    attrs: list[str] = field(default_factory=list)


@dataclass
class Edge:
    src: str
    dst: str
    label: str
    kind: str


@dataclass
class GraphModel:
    name: str
    nodes: list[Node]
    edges: list[Edge]
    notes: list[str]


def write(path: str, text: str) -> None:
    (OUTDIR / path).write_text(text.rstrip() + "\n")


def common_nodes() -> list[Node]:
    return [
        Node("wan_lan", "External mesh / mgmt peer", "external", ["externally reachable origin"]),
        Node("ubusd", "ubusd / ubus fabric", "ipc", ["IPC hub"]),
        Node("uci_onemesh", "UCI onemesh state", "persistence", ["persistent state", "packet-derived state possible"]),
        Node("uci_accountmgnt", "UCI accountmgnt", "persistence", ["persistent credentials / trust material"]),
        Node("sync_state", "/tmp/sync-server/onemesh_client_list", "persistence", ["persistent-ish runtime state", "distributed propagation"]),
        Node("sync_request", "sync-server helper: request", "helper", ["helper execution hub", "outbound relay"]),
        Node("sync_request_clients", "sync-server helper: request_clients", "helper", ["helper execution hub", "outbound relay"]),
        Node("sync_wifi", "sync-server helper: sync_wifi", "helper", ["helper execution hub", "deferred workflow"]),
        Node("meshd", "meshd", "daemon", ["orchestration coordinator", "shell-capable"]),
        Node("sync_server", "sync-server", "daemon", ["persistence node", "distributed propagator", "shell-capable"]),
        Node("easymesh_agent", "easymesh-agent", "daemon", ["EasyMesh lane", "shell-capable"]),
        Node("easymesh_controller", "easymesh-controller", "daemon", ["EasyMesh lane"]),
        Node("ieee1905", "ieee1905", "daemon", ["1905 transport lane"]),
        Node("onemesh_lua", "onemesh.lua / one_mesh.lua", "lua", ["Lua trust / policy layer", "shell-capable"]),
    ]


def tp_link_graph(name: str, tdp_label: str = "tdpServer") -> GraphModel:
    nodes = common_nodes() + [
        Node("tdp", tdp_label, "ingress", ["externally reachable", "packet parser", "shell-capable"]),
    ]
    edges = [
        Edge("wan_lan", "tdp", "UDP/TDP ingress", "packet"),
        Edge("tdp", "ubusd", "registers ubus object / IPC provider", "ubus"),
        Edge("tdp", "uci_onemesh", "writes mesh / client / role state", "uci_write"),
        Edge("tdp", "uci_accountmgnt", "reads account / RSA trust material", "uci_read"),
        Edge("tdp", "onemesh_lua", "direct Lua bridge", "lua_call"),
        Edge("tdp", "sync_state", "writes flags / client-state artifacts", "file_state"),
        Edge("ubusd", "sync_server", "onemesh list / state query", "ubus"),
        Edge("uci_onemesh", "sync_server", "consumes OneMesh state", "uci_read"),
        Edge("sync_server", "sync_state", "persists client list", "file_write"),
        Edge("sync_server", "sync_request", "exec helper", "exec"),
        Edge("sync_server", "sync_request_clients", "exec helper", "exec"),
        Edge("sync_server", "sync_wifi", "exec helper", "exec"),
        Edge("sync_server", "onemesh_lua", "Lua timeout / orchestration callback", "lua_call"),
        Edge("uci_onemesh", "meshd", "consumes mesh config / state", "uci_read"),
        Edge("ubusd", "meshd", "ubus coordination", "ubus"),
        Edge("meshd", "easymesh_agent", "spawns / coordinates", "exec"),
        Edge("meshd", "easymesh_controller", "spawns / coordinates", "exec"),
        Edge("easymesh_agent", "ieee1905", "uses 1905 transport lane", "transport"),
        Edge("easymesh_controller", "ieee1905", "uses 1905 transport lane", "transport"),
    ]
    notes = [
        "TP-Link models in this family keep the external ingress concentrated in `tdpServer`.",
        "The externally-derived management state crosses into Lua, UCI, ubus, and sync-server without a second trust boundary.",
        "AX23, AX55, and AX72 differ in helper density, but the orchestration spine is materially shared.",
    ]
    return GraphModel(name, nodes, edges, notes)


def mr90x_graph() -> GraphModel:
    nodes = common_nodes() + [
        Node("tmpsvr", "tmpsvr", "ingress", ["externally reachable", "packet parser", "shell-capable"]),
        Node("tmp_luci", "tmp-luci", "helper", ["CGI/Lua relay"]),
        Node("tmp_server_lua", "tmp_server.lua", "lua", ["Lua dispatch layer", "shell-capable"]),
    ]
    edges = [
        Edge("wan_lan", "tmpsvr", "UDP/TDP ingress", "packet"),
        Edge("tmpsvr", "tmp_luci", "exec relay", "exec"),
        Edge("tmp_luci", "tmp_server_lua", "Lua SGI dispatch", "lua_call"),
        Edge("tmpsvr", "ubusd", "registers tdpServer-style ubus object", "ubus"),
        Edge("tmpsvr", "onemesh_lua", "direct legacy OneMesh Lua bridge", "lua_call"),
        Edge("tmp_server_lua", "uci_onemesh", "writes / reads management state", "uci_rw"),
        Edge("tmp_server_lua", "uci_accountmgnt", "reads trust material context", "uci_read"),
        Edge("tmp_server_lua", "sync_server", "packet-derived state becomes sync input", "state_flow"),
        Edge("ubusd", "sync_server", "reads device list / orchestration state", "ubus"),
        Edge("uci_onemesh", "sync_server", "default-on master/router sync policy", "uci_read"),
        Edge("sync_server", "sync_state", "persists onemesh client list", "file_write"),
        Edge("sync_server", "sync_request", "exec helper", "exec"),
        Edge("sync_server", "sync_request_clients", "exec helper", "exec"),
        Edge("sync_server", "sync_wifi", "exec helper", "exec"),
        Edge("sync_server", "onemesh_lua", "Lua timeout / orchestration callback", "lua_call"),
        Edge("uci_onemesh", "meshd", "consumes mesh policy / state", "uci_read"),
        Edge("ubusd", "meshd", "map / meshd control", "ubus"),
        Edge("meshd", "easymesh_agent", "spawns / coordinates", "exec"),
        Edge("meshd", "easymesh_controller", "spawns / coordinates", "exec"),
        Edge("easymesh_agent", "ieee1905", "uses 1905 transport lane", "transport"),
        Edge("easymesh_controller", "ieee1905", "uses 1905 transport lane", "transport"),
    ]
    notes = [
        "MR90X splits TP-Link `tdpServer` semantics across `tmpsvr`, `tmp-luci`, `tmp_server.lua`, `sync-server`, and `meshd`.",
        "The TMP v2 relay path is explicit: packet -> tmpsvr -> tmp-luci -> tmp_server.lua.",
        "The same downstream trust pattern remains: ubus, UCI, helper scripts, and EasyMesh daemons consume the resulting state.",
    ]
    return GraphModel("MERCUSYS MR90X (EU) V1.20_23080820240123090924", nodes, edges, notes)


def mermaid_for_graph(graph: GraphModel) -> str:
    lines = ["```mermaid", "flowchart TD"]
    for node in graph.nodes:
        label = node.label.replace('"', '\\"')
        lines.append(f'    {node.node_id}["{label}"]')
    for edge in graph.edges:
        label = edge.label.replace('"', '\\"')
        lines.append(f"    {edge.src} -->|{label}| {edge.dst}")
    lines.append("```")
    return "\n".join(lines)


def dot_for_graph(graph: GraphModel) -> str:
    lines = [f'digraph "{graph.name}" {{', "  rankdir=LR;"]
    for node in graph.nodes:
        label = node.label.replace('"', '\\"')
        lines.append(f'  {node.node_id} [label="{label}"];')
    for edge in graph.edges:
        label = edge.label.replace('"', '\\"')
        lines.append(f'  {edge.src} -> {edge.dst} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def summary_table(graphs: list[GraphModel]) -> str:
    rows = [
        "| Target | Ingress Node | Lua Bridge | Persistence Node | Helper Hub | Downstream Coordinator |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    mapping = {
        "TP-Link Archer AX23 1.2_250904": ("tdpServer", "onemesh.lua", "UCI onemesh + sync-state", "sync-server helpers", "meshd"),
        "TP-Link Archer AX55 V4 family": ("tdpServer", "onemesh.lua", "UCI onemesh + sync-state", "sync-server helpers", "meshd"),
        "TP-Link Archer AX72 V2_241119_US": ("tdpServer", "onemesh.lua", "UCI onemesh + sync-state", "sync-server helpers", "meshd"),
        "MERCUSYS MR90X (EU) V1.20_23080820240123090924": ("tmpsvr", "tmp-luci + tmp_server.lua + onemesh.lua", "UCI onemesh + sync-state", "sync-server helpers", "meshd"),
    }
    for name, vals in mapping.items():
        rows.append(f"| {name} | {vals[0]} | {vals[1]} | {vals[2]} | {vals[3]} | {vals[4]} |")
    return "\n".join(rows)


def orchestration_graph(graphs: list[GraphModel]) -> str:
    global_graph = mr90x_graph()
    lines = [
        "# Global Orchestration Graph",
        "",
        "This document reconstructs the management-plane orchestration graph for the TP-Link/MERCUSYS mesh ecosystem using the preserved corpus evidence and previously generated daemon/Lua relationship reports.",
        "",
        "## Shared Topology Summary",
        "",
        summary_table(graphs),
        "",
        "## Canonical Ecosystem Graph",
        "",
        mermaid_for_graph(global_graph),
        "",
        "## Graphviz DOT",
        "",
        "```dot",
        dot_for_graph(global_graph),
        "```",
        "",
        "## Node Annotation Legend",
        "",
        "- `externally reachable`: network-facing ingress or transport process",
        "- `packet-derived state`: state that may incorporate externally supplied mesh-management values",
        "- `persistent state`: UCI or persistent runtime files used after ingress processing",
        "- `deferred workflow`: helper-triggered or later-executed management action",
        "- `distributed propagation`: state reused by later daemons or helper scripts",
        "- `shell-capable`: node with confirmed or strongly indicated process execution capability",
    ]
    return "\n".join(lines)


def distributed_management_graph(graphs: list[GraphModel]) -> str:
    lines = [
        "# Distributed Management Graph",
        "",
        "## Target Graphs",
        "",
    ]
    for graph in graphs:
        lines.append(f"### {graph.name}")
        lines.append("")
        lines.append(mermaid_for_graph(graph))
        lines.append("")
        lines.append("Notes:")
        for note in graph.notes:
            lines.append(f"- {note}")
        lines.append("")
    lines += [
        "## Graphviz DOT Subgraphs",
        "",
    ]
    for graph in graphs:
        lines.append(f"### {graph.name}")
        lines.append("")
        lines.append("```dot")
        lines.append(dot_for_graph(graph))
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def packet_to_state_topology() -> str:
    return "\n".join(
        [
            "# Packet to State Topology",
            "",
            "## Packet-to-State Pipeline",
            "",
            "```mermaid",
            "flowchart LR",
            '    ext["External mesh / management packet"] --> ingress["Ingress daemon\\n(tdpServer or tmpsvr)"]',
            '    ingress --> lua["Lua bridge / dispatch\\n(onemesh.lua or tmp-luci -> tmp_server.lua)"]',
            '    ingress --> ubus["ubusd / tdpServer-style ubus object"]',
            '    lua --> uci["UCI onemesh / accountmgnt state"]',
            '    ingress --> files["runtime flags / client-state files"]',
            '    ubus --> sync["sync-server"]',
            '    uci --> sync',
            '    files --> sync',
            '    sync --> helpers["request / request_clients / sync_wifi"]',
            '    uci --> meshd["meshd"]',
            '    sync --> meshd',
            '    meshd --> agent["easymesh-agent"]',
            '    meshd --> ctrl["easymesh-controller"]',
            '    agent --> ieee["ieee1905"]',
            '    ctrl --> ieee',
            "```",
            "",
            "## Trust-Boundary Note",
            "",
            "- The first explicit validation boundary is the ingress daemon.",
            "- After that point, packet-derived management state is repackaged as trusted local orchestration state.",
        ]
    )


def trust_boundary_graph() -> str:
    return "\n".join(
        [
            "# Trust Boundary Graph",
            "",
            "```mermaid",
            "flowchart TD",
            '    ext["External peer\\n(untrusted)"] -->|UDP 20002 / TDP / 1905| ingress["Ingress daemon\\n(td pServer / tmpsvr / 1905 lane)"]',
            '    ingress -->|packet accepted once| local["Local trusted orchestration domain"]',
            '    local --> ubus["ubusd / IPC"]',
            '    local --> uci["UCI persistent config"]',
            '    local --> files["runtime state files"]',
            '    ubus --> sync["sync-server"]',
            '    uci --> sync',
            '    files --> sync',
            '    sync --> helpers["helper scripts / tmpv2 clients"]',
            '    ubus --> meshd["meshd"]',
            '    uci --> meshd',
            '    meshd --> easy["easymesh-agent/controller"]',
            "```",
            "",
            "## Boundary Annotations",
            "",
            "- `External -> ingress`: true network trust boundary",
            "- `ingress -> local orchestration domain`: trust collapse point",
            "- `local -> sync-server/helpers/meshd`: deferred and distributed execution region",
        ]
    )


def cross_vendor_comparison(graphs: list[GraphModel]) -> str:
    lines = [
        "# Cross-Vendor Graph Comparison",
        "",
        "| Target | Ingress Role | Lua Relay Style | UCI Persistence | sync-server Role | meshd / EasyMesh Role | Distinctive Graph Difference |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        "| AX23 | `tdpServer` concentrated gateway | direct OneMesh/LuCI bridge | yes | persistent relay + helper trigger | downstream coordinator | older TP-Link style, no explicit tmp-luci relay confirmed |",
        "| AX55 family | `tdpServer` concentrated gateway | direct OneMesh/LuCI bridge | yes | same distributed relay pattern across 3 versions | downstream coordinator | strongest cross-version persistence |",
        "| AX72 | `tdpServer` concentrated gateway | direct OneMesh/LuCI bridge | yes | same distributed relay pattern | meshd + EasyMesh lane richer | clearest published gateway semantics |",
        "| MR90X | `tmpsvr` split ingress gateway | `tmp-luci` + `tmp_server.lua` plus direct legacy Lua bridge | yes | same relay and persistence role | same coordinator family | ingress split across more daemons |",
        "",
        "## Strong Similarities",
        "",
        "- All four targets expose an ingress daemon that feeds a Lua/UCI-backed management domain.",
        "- All four reuse `sync-server` as the distributed state propagation and helper execution hub.",
        "- All four rely on `meshd` and EasyMesh-side daemons as downstream orchestration consumers rather than primary ingress nodes.",
        "",
        "## Main Structural Delta",
        "",
        "- TP-Link keeps more semantics inside `tdpServer`.",
        "- MR90X splits them across `tmpsvr`, `tmp-luci`, `tmp_server.lua`, `sync-server`, and `meshd` while preserving the same trust flow.",
    ]
    return "\n".join(lines)


def main() -> None:
    graphs = [
        tp_link_graph("TP-Link Archer AX23 1.2_250904"),
        tp_link_graph("TP-Link Archer AX55 V4 family"),
        tp_link_graph("TP-Link Archer AX72 V2_241119_US"),
        mr90x_graph(),
    ]
    write("orchestration_graph.md", orchestration_graph(graphs))
    write("distributed_management_graph.md", distributed_management_graph(graphs))
    write("packet_to_state_topology.md", packet_to_state_topology())
    write("trust_boundary_graph.md", trust_boundary_graph())
    write("cross_vendor_graph_comparison.md", cross_vendor_comparison(graphs))


if __name__ == "__main__":
    main()
