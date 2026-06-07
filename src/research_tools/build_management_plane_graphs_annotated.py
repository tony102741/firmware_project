#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field

try:
    from .paths import regeneration_dir
except ImportError:
    from paths import regeneration_dir

OUTDIR = regeneration_dir()


@dataclass
class Node:
    node_id: str
    label: str
    component_type: str
    target: str
    role: str
    externally_reachable: bool = False
    shell_capable: bool = False
    persists_state: bool = False
    propagates_state: bool = False


@dataclass
class Edge:
    src: str
    dst: str
    relationship_type: str
    evidence_source: str
    confidence: str
    evidence_type: str
    source_locator: str
    why_it_matters: str
    packet_state: bool = False
    persistence: bool = False
    deferred: bool = False


@dataclass
class Graph:
    name: str
    nodes: list[Node]
    edges: list[Edge]
    caption: str


def write(path: str, text: str) -> None:
    (OUTDIR / path).write_text(text.rstrip() + "\n")


def base_nodes(target: str) -> list[Node]:
    return [
        Node("external", "External mesh / management peer", "external", target, "origin", True, False, False, False),
        Node("ubusd", "ubusd / ubus fabric", "ipc", target, "IPC coordination hub", False, False, False, True),
        Node("uci_onemesh", "UCI onemesh state", "persistence", target, "mesh policy / persistent state", False, False, True, True),
        Node("uci_accountmgnt", "UCI accountmgnt", "persistence", target, "credentials / trust material", False, False, True, False),
        Node("sync_state", "/tmp/sync-server/onemesh_client_list", "runtime-state", target, "distributed runtime client state", False, False, True, True),
        Node("sync_server", "sync-server", "daemon", target, "distributed propagator", False, True, True, True),
        Node("sync_request", "helper: request", "helper", target, "outbound relay helper", False, True, False, True),
        Node("sync_request_clients", "helper: request_clients", "helper", target, "outbound client relay helper", False, True, False, True),
        Node("sync_wifi", "helper: sync_wifi", "helper", target, "deferred wifi sync helper", False, True, False, True),
        Node("meshd", "meshd", "daemon", target, "orchestration coordinator", False, True, False, True),
        Node("easymesh_agent", "easymesh-agent", "daemon", target, "EasyMesh agent lane", False, True, False, True),
        Node("easymesh_controller", "easymesh-controller", "daemon", target, "EasyMesh controller lane", False, False, False, True),
        Node("ieee1905", "ieee1905", "daemon", target, "1905 transport lane", True, False, False, True),
        Node("onemesh_lua", "onemesh.lua / one_mesh.lua", "lua", target, "Lua trust / policy layer", False, True, False, True),
    ]


def tp_link_graph(target: str) -> Graph:
    nodes = base_nodes(target) + [
        Node("tdp", "tdpServer", "ingress-daemon", target, "external OneMesh/TDP ingress gateway", True, True, False, True),
    ]
    edges = [
        Edge("external", "tdp", "packet-ingress", "research/tdp_packet_processing.md", "confirmed", "Ghidra+strings", "socket/bind/recvfrom on UDP 20002", "Establishes the primary external management entry point.", packet_state=True),
        Edge("tdp", "ubusd", "ubus-provider", "research/tdp_management_plane_gateway.md", "confirmed", "Ghidra+report-derived", "ubus child registers onemesh methods", "Shows that ingress state is exposed to the local control plane."),
        Edge("tdp", "uci_onemesh", "uci-write", "research/packet_to_uci_propagation.md; research/tdp_management_plane_gateway.md", "high-confidence", "Ghidra+report-derived", "probe/OneMesh fields written into onemesh UCI", "Shows persistence of packet-derived management state.", packet_state=True, persistence=True),
        Edge("tdp", "uci_accountmgnt", "uci-read", "research/tdp_management_plane_gateway.md", "high-confidence", "Ghidra+report-derived", "RSA/account material read from accountmgnt", "Shows trust material is consumed directly by ingress code."),
        Edge("tdp", "onemesh_lua", "lua-bridge", "research/lua_execution_bridges.md; research/tdp_management_plane_gateway.md", "confirmed", "Lua source+Ghidra", "tpApp_lua_do_luci / onemesh.dispatch", "Shows parser output crossing into Lua orchestration."),
        Edge("tdp", "sync_state", "runtime-state-write", "research/orchestration_boundary_crossing.md", "high-confidence", "report-derived", "/tmp/sync-server client/flag artifacts", "Shows deferred downstream propagation beyond immediate packet handling.", packet_state=True, persistence=True, deferred=True),
        Edge("ubusd", "sync_server", "ubus-consumer", "research/tdp_management_plane_gateway.md; research/tmpsvr_lua_bridge.md", "high-confidence", "report-derived", "onemesh_list_devices and related state queries", "Shows sync-server depends on ingress-populated IPC state.", deferred=True),
        Edge("uci_onemesh", "sync_server", "uci-consumer", "research/regeneration/full_corpus_20260508/management_plane_trust_recurrence.md", "confirmed", "init script+UCI config", "sync-server default-on onemesh master/router logic", "Shows default activation and policy reuse.", persistence=True, deferred=True),
        Edge("sync_server", "sync_state", "state-persistence", "research/tmpsvr_lua_bridge.md", "confirmed", "strings+report-derived", "/tmp/sync-server/onemesh_client_list", "Shows distributed mesh state is materialized into a reusable file.", persistence=True),
        Edge("sync_server", "sync_request", "helper-exec", "research/tmpsvr_lua_bridge.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/request", "Shows helper-driven outbound relay."),
        Edge("sync_server", "sync_request_clients", "helper-exec", "research/tmpsvr_lua_bridge.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/request_clients", "Shows helper-driven outbound client-state propagation."),
        Edge("sync_server", "sync_wifi", "helper-exec", "research/tmpsvr_lua_bridge.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/sync_wifi", "Shows deferred WiFi/config propagation.", deferred=True),
        Edge("sync_server", "onemesh_lua", "lua-callback", "research/tmpsvr_lua_bridge.md", "confirmed", "strings", "lua -e 'require(\"luci.model.one_mesh\").api_timeout_called()'", "Shows sync-server can re-enter Lua orchestration."),
        Edge("uci_onemesh", "meshd", "uci-consumer", "research/regeneration/full_corpus_20260508/management_plane_trust_recurrence.md", "high-confidence", "init script+report-derived", "meshd enabled / reads onemesh policy", "Shows downstream daemons consume trusted persisted state.", persistence=True, deferred=True),
        Edge("ubusd", "meshd", "ubus-coordination", "research/regeneration/full_corpus_20260508/state_machine_orchestration_clusters.md", "high-confidence", "report-derived", "ubus-control-plane classification", "Shows meshd is coordinated through the same local IPC fabric.", deferred=True),
        Edge("meshd", "easymesh_agent", "spawn", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "inferred", "cross-target architectural inference", "spawn relationship confirmed directly on MR90X, family-level reuse on TP-Link", "Shows likely same downstream EasyMesh orchestration pattern.", deferred=True),
        Edge("meshd", "easymesh_controller", "spawn", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "inferred", "cross-target architectural inference", "spawn relationship confirmed directly on MR90X, family-level reuse on TP-Link", "Shows likely same downstream EasyMesh orchestration pattern.", deferred=True),
        Edge("easymesh_agent", "ieee1905", "transport-use", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "inferred", "cross-target architectural inference", "EasyMesh/1905 lane reuse across stack family", "Shows eventual transport/runtime lane for distributed mesh control.", deferred=True),
        Edge("easymesh_controller", "ieee1905", "transport-use", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "inferred", "cross-target architectural inference", "EasyMesh/1905 lane reuse across stack family", "Shows eventual transport/runtime lane for distributed mesh control.", deferred=True),
    ]
    caption = (
        f"Figure: Reconstructed distributed management-plane orchestration graph for {target}. "
        "Confirmed edges capture direct ingress, Lua bridging, UCI persistence, and sync-server helper execution; "
        "inferred edges capture family-level downstream EasyMesh coordination where target-local reverse engineering is incomplete."
    )
    return Graph(target, nodes, edges, caption)


def mr90x_graph() -> Graph:
    target = "MERCUSYS MR90X (EU) V1.20_23080820240123090924"
    nodes = base_nodes(target) + [
        Node("tmpsvr", "tmpsvr", "ingress-daemon", target, "external TDP/TMPv2 ingress gateway", True, True, False, True),
        Node("tmp_luci", "tmp-luci", "relay-helper", target, "CGI/Lua relay", False, False, False, True),
        Node("tmp_server_lua", "tmp_server.lua", "lua", target, "temporary-management dispatch layer", False, True, False, True),
    ]
    edges = [
        Edge("external", "tmpsvr", "packet-ingress", "research/regeneration/full_corpus_20260508/mr90x_tdpserver_replacement_analysis.md", "confirmed", "Ghidra+strings", "recvfrom/sendto + TDP Server strings", "Establishes MR90X external management ingress.", packet_state=True),
        Edge("tmpsvr", "tmp_luci", "exec-relay", "research/tmpsvr_lua_bridge.md", "confirmed", "strings+plaintext script", "/usr/bin/tmp-luci relay_run path", "Shows external packets are relayed into Lua rather than handled only in C.", packet_state=True, deferred=True),
        Edge("tmp_luci", "tmp_server_lua", "lua-dispatch", "research/tmpsvr_lua_bridge.md", "confirmed", "Lua source+bytecode strings", "luci.sgi.tmp.run() -> tmp_server.lua", "Shows the concrete packet-to-Lua dispatch layer.", packet_state=True),
        Edge("tmpsvr", "ubusd", "ubus-provider", "research/tmpsvr_architecture.md", "confirmed", "strings+report-derived", "registers tdpServer ubus object", "Shows ingress state is exported into IPC."),
        Edge("tmpsvr", "onemesh_lua", "legacy-lua-bridge", "research/tmpsvr_lua_bridge.md", "confirmed", "Ghidra+strings", "tpAppLua.c / luci.controller.admin.onemesh", "Shows legacy OneMesh path still crosses into Lua."),
        Edge("tmp_server_lua", "uci_onemesh", "uci-read-write", "research/tmp_server_handler_semantics.md", "high-confidence", "Lua bytecode strings+semantics report", "decoded JSON handlers write/read UCI-backed models", "Shows packet-derived temporary-management state reaches persistent config.", packet_state=True, persistence=True),
        Edge("tmp_server_lua", "uci_accountmgnt", "uci-read", "research/tmpsvr_lua_bridge.md", "high-confidence", "report-derived", "trust/key path context through accountmgnt", "Shows packet handling has access to trust material context."),
        Edge("tmp_server_lua", "sync_server", "state-input", "research/regeneration/full_corpus_20260508/mr90x_tdpserver_replacement_analysis.md", "inferred", "report-derived", "tmp_server state becomes sync input", "Shows likely bridge from packet-derived management state into distributed sync.", packet_state=True, deferred=True),
        Edge("ubusd", "sync_server", "ubus-consumer", "research/tmpsvr_lua_bridge.md", "confirmed", "helper script+report-derived", "ubus:call(\"tdpServer\", \"onemesh_list_devices\", {})", "Shows sync-server queries ingress-populated local state.", deferred=True),
        Edge("uci_onemesh", "sync_server", "uci-consumer", "research/regeneration/full_corpus_20260508/management_plane_trust_recurrence.md; ghidra_targets/mr90x_tmpsvr_stack/init_boot_order.md", "confirmed", "init script+UCI config", "sync-server default-on master/router logic", "Shows default activation and persistence reuse.", persistence=True, deferred=True),
        Edge("sync_server", "sync_state", "state-persistence", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "confirmed", "strings", "/tmp/sync-server/onemesh_client_list", "Shows distributed mesh state materialization.", persistence=True),
        Edge("sync_server", "sync_request", "helper-exec", "research/tmpsvr_lua_bridge.md; ghidra_targets/mr90x_tmpsvr_stack/target_inventory.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/request", "Shows outbound helper-driven relay."),
        Edge("sync_server", "sync_request_clients", "helper-exec", "research/tmpsvr_lua_bridge.md; ghidra_targets/mr90x_tmpsvr_stack/target_inventory.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/request_clients", "Shows outbound client-state relay."),
        Edge("sync_server", "sync_wifi", "helper-exec", "research/tmpsvr_lua_bridge.md; ghidra_targets/mr90x_tmpsvr_stack/target_inventory.md", "confirmed", "helper script+strings", "lib/sync-server/scripts/sync_wifi", "Shows deferred WiFi/config propagation.", deferred=True),
        Edge("sync_server", "onemesh_lua", "lua-callback", "research/tmpsvr_lua_bridge.md", "confirmed", "strings", "lua -e 'require(\"luci.model.one_mesh\").api_timeout_called()'", "Shows re-entry from sync-server into Lua orchestration."),
        Edge("uci_onemesh", "meshd", "uci-consumer", "ghidra_targets/mr90x_tmpsvr_stack/init_boot_order.md; research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "confirmed", "init script+strings", "meshd init loads onemesh/sysmode", "Shows meshd consumes persisted management state.", persistence=True, deferred=True),
        Edge("ubusd", "meshd", "ubus-coordination", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "confirmed", "strings", "ubus call map meshd ...", "Shows local IPC control into orchestration coordinator.", deferred=True),
        Edge("meshd", "easymesh_agent", "spawn", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md; ghidra_targets/mr90x_tmpsvr_stack/ghidra_loading_order.md", "confirmed", "strings+Ghidra prep report", "/usr/bin/easymesh-agent", "Shows downstream EasyMesh agent execution.", deferred=True),
        Edge("meshd", "easymesh_controller", "spawn", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md; ghidra_targets/mr90x_tmpsvr_stack/ghidra_loading_order.md", "confirmed", "strings+Ghidra prep report", "/usr/bin/easymesh-controller", "Shows downstream EasyMesh controller execution.", deferred=True),
        Edge("easymesh_agent", "ieee1905", "transport-use", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "high-confidence", "strings", "libieee1905.so / ieee1905_start", "Shows 1905 transport lane usage.", deferred=True),
        Edge("easymesh_controller", "ieee1905", "transport-use", "research/regeneration/full_corpus_20260508/mr90x_network_daemon_inventory.md", "high-confidence", "strings", "libieee1905.so / map_ieee1905_*", "Shows controller-side 1905 transport lane usage.", deferred=True),
    ]
    caption = (
        "Figure: Annotated MR90X management-plane orchestration graph. Confirmed edges identify the external `tmpsvr` ingress, "
        "`tmp-luci` relay, Lua dispatch, sync-server helper fan-out, and meshd-to-EasyMesh process chain. Inferred edges mark likely "
        "state handoff from `tmp_server.lua` into `sync-server` where static evidence is architectural but not yet function-level complete."
    )
    return Graph(target, nodes, edges, caption)


def mermaid(graph: Graph) -> str:
    lines = ["```mermaid", "flowchart TD"]
    for node in graph.nodes:
        attrs = []
        if node.externally_reachable:
            attrs.append("ext")
        if node.shell_capable:
            attrs.append("shell")
        if node.persists_state:
            attrs.append("persist")
        if node.propagates_state:
            attrs.append("prop")
        suffix = "\\n[" + ", ".join(attrs) + "]" if attrs else ""
        lines.append(f'    {node.node_id}["{node.label}{suffix}"]')
    for idx, edge in enumerate(graph.edges, start=1):
        lines.append(f"    {edge.src} -->|{edge.relationship_type} [{edge.confidence}]| {edge.dst}")
        style = "edge_confirmed"
        if edge.confidence == "inferred":
            style = "edge_inferred"
        elif edge.confidence == "hypothetical":
            style = "edge_hypothetical"
        elif edge.confidence == "high-confidence":
            style = "edge_high"
        if edge.packet_state:
            style += "_packet"
        elif edge.persistence:
            style += "_persist"
        elif edge.deferred:
            style += "_deferred"
        lines.append(f"    linkStyle {idx-1} stroke-width:2px;")
    lines.append("```")
    return "\n".join(lines)


def edge_table(graph: Graph) -> str:
    lines = [
        "| Edge | Target | Relationship | Evidence | Confidence | Evidence Type | Source Locator | Why It Matters |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for edge in graph.edges:
        lines.append(
            f"| `{edge.src} -> {edge.dst}` | {graph.name} | {edge.relationship_type} | `{edge.evidence_source}` | "
            f"`{edge.confidence}` | `{edge.evidence_type}` | `{edge.source_locator}` | {edge.why_it_matters} |"
        )
    return "\n".join(lines)


def node_table(graph: Graph) -> str:
    lines = [
        "| Node | Type | Role | External | Shell | Persists State | Propagates State |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for node in graph.nodes:
        lines.append(
            f"| `{node.label}` | `{node.component_type}` | {node.role} | `{node.externally_reachable}` | "
            f"`{node.shell_capable}` | `{node.persists_state}` | `{node.propagates_state}` |"
        )
    return "\n".join(lines)


def orchestration_graph_annotated(graphs: list[Graph]) -> str:
    lines = [
        "# Annotated Orchestration Graphs",
        "",
        "## Canonical Annotated Graph",
        "",
        mermaid(mr90x_graph()),
        "",
        "## Node Annotation Table",
        "",
        node_table(mr90x_graph()),
        "",
        "## Edge Confidence Legend",
        "",
        "- `confirmed`: direct evidence from target-local init script, helper script, Lua source/bytecode strings, Ghidra/string extraction, or explicit prior report.",
        "- `high-confidence`: target-local evidence is strong but the exact function-level transition is reconstructed rather than directly observed end-to-end.",
        "- `inferred`: edge is family-level architectural reuse or likely state handoff not yet tied to one direct code site on that exact target.",
        "- `hypothetical`: plausible but not used for the main figures unless clearly labeled.",
        "",
        "## Evidence Table",
        "",
        edge_table(mr90x_graph()),
    ]
    return "\n".join(lines)


def packet_state_annotated(graphs: list[Graph]) -> str:
    return "\n".join(
        [
            "# Packet to State Topology Annotated",
            "",
            "```mermaid",
            "flowchart LR",
            '    ext["External peer\\n[externally reachable]"] -->|packet-ingress [confirmed]| ingress["tdpServer / tmpsvr\\n[shell-capable, propagates state]"]',
            '    ingress -->|lua-bridge [confirmed]| lua["onemesh.lua or tmp-luci -> tmp_server.lua\\n[shell-capable]"]',
            '    ingress -->|ubus-provider [confirmed/high-confidence]| ubus["ubusd / ubus fabric\\n[propagates state]"]',
            '    lua -->|uci-read-write [high-confidence]| uci["UCI onemesh / accountmgnt\\n[persistent state]"]',
            '    ingress -->|runtime-state-write [high-confidence]| files["/tmp/sync-server/*\\n[persistent-ish runtime state]"]',
            '    ubus -->|ubus-consumer [confirmed/high-confidence]| sync["sync-server\\n[shell-capable, propagates state]"]',
            '    uci -->|uci-consumer [confirmed]| sync',
            '    files -->|state-consumer [high-confidence]| sync',
            '    sync -->|helper-exec [confirmed]| helpers["request / request_clients / sync_wifi\\n[deferred workflow]"]',
            '    uci -->|uci-consumer [confirmed/high-confidence]| meshd["meshd\\n[shell-capable, coordinator]"]',
            '    sync -->|state-input [inferred/high-confidence]| meshd',
            '    meshd -->|spawn [confirmed/inferred]| easy["easymesh-agent / controller"]',
            "```",
            "",
            "## Figure Intent",
            "",
            "- Highlights the state transitions that matter for trust propagation rather than only parser-local control flow.",
            "- Distinguishes confirmed ingress and helper edges from inferred downstream state-consumption edges.",
        ]
    )


def trust_boundary_annotated(graphs: list[Graph]) -> str:
    return "\n".join(
        [
            "# Trust Boundary Graph Annotated",
            "",
            "```mermaid",
            "flowchart TD",
            '    ext["External network / mesh peer"] -->|UDP/TDP/1905\\nconfirmed ingress| ingress["Ingress daemon\\n(td pServer / tmpsvr)"]',
            '    ingress -->|packet accepted once| trust["Trusted local orchestration domain"]',
            '    trust -->|confirmed/high-confidence| ubus["ubusd"]',
            '    trust -->|persistent write| uci["UCI state"]',
            '    trust -->|runtime-state write| files["sync-server files / flags"]',
            '    ubus -->|confirmed/high-confidence| sync["sync-server"]',
            '    uci -->|confirmed| sync',
            '    files -->|high-confidence| sync',
            '    sync -->|confirmed helper exec| helpers["helper scripts"]',
            '    ubus -->|confirmed/high-confidence| meshd["meshd"]',
            '    uci -->|confirmed/high-confidence| meshd',
            "```",
            "",
            "## Boundary Interpretation",
            "",
            "- The only strong external trust boundary is at ingress acceptance.",
            "- After ingress, later nodes mostly consume prior state as trusted management intent.",
        ]
    )


def cross_vendor_annotated(graphs: list[Graph]) -> str:
    lines = [
        "# Cross Vendor Graph Comparison Annotated",
        "",
        "| Target | Ingress Edge Confidence | Lua Bridge Confidence | UCI Persistence Confidence | sync-server Helper Confidence | Downstream EasyMesh Confidence | Main Caveat |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        "| AX23 | confirmed | high-confidence | high-confidence | high-confidence | inferred | target-local TP-Link daemon split less directly reconstructed than MR90X |",
        "| AX55 family | confirmed | high-confidence | high-confidence | high-confidence | inferred | strongest recurrence, but helper/child process edges rely partly on family reuse |",
        "| AX72 | confirmed | confirmed | high-confidence | high-confidence | inferred/high-confidence | ingress side best understood; downstream file/consumer edges partly report-derived |",
        "| MR90X | confirmed | confirmed | high-confidence | confirmed | confirmed/high-confidence | `tmp_server.lua -> sync-server` exact function-level handoff remains inferred |",
        "",
        "## Comparison Note",
        "",
        "- MR90X provides the strongest direct evidence for the split ingress-to-Lua-to-sync graph.",
        "- AX72 provides the strongest direct evidence for the concentrated `tdpServer` gateway model.",
    ]
    return "\n".join(lines)


def captions(graphs: list[Graph]) -> str:
    lines = ["# Figure Captions", ""]
    lines.append("## Figure 1 — Canonical Management-Plane Orchestration Graph")
    lines.append(mr90x_graph().caption)
    lines.append("")
    lines.append("## Figure 2 — Packet-to-State Propagation Topology")
    lines.append(
        "Figure: Packet-to-state propagation across the TP-Link/MERCUSYS mesh stack. "
        "Confirmed edges show ingress, Lua relay, UCI persistence, and sync-server helper execution. "
        "The figure emphasizes how packet-derived state becomes distributed orchestration input."
    )
    lines.append("")
    lines.append("## Figure 3 — Trust-Boundary Collapse")
    lines.append(
        "Figure: Trust-boundary interpretation of the management plane. The dominant security transition is not a single parser sink, "
        "but the point at which accepted packet-derived state is reclassified as trusted local orchestration state."
    )
    lines.append("")
    lines.append("## Figure 4 — Cross-Vendor Graph Comparison")
    lines.append(
        "Figure: Cross-vendor comparison of AX23, AX55, AX72, and MR90X. TP-Link concentrates ingress semantics in `tdpServer`, "
        "while MR90X splits them across `tmpsvr`, `tmp-luci`, and `tmp_server.lua`; both converge on the same sync-server / meshd trust fabric."
    )
    return "\n".join(lines)


def main() -> None:
    graphs = [
        tp_link_graph("TP-Link Archer AX23 1.2_250904"),
        tp_link_graph("TP-Link Archer AX55 V4 family"),
        tp_link_graph("TP-Link Archer AX72 V2_241119_US"),
        mr90x_graph(),
    ]
    write("orchestration_graph_annotated.md", orchestration_graph_annotated(graphs))
    write("packet_to_state_topology_annotated.md", packet_state_annotated(graphs))
    write("trust_boundary_graph_annotated.md", trust_boundary_annotated(graphs))
    write("cross_vendor_graph_comparison_annotated.md", cross_vendor_annotated(graphs))
    write("figure_captions.md", captions(graphs))


if __name__ == "__main__":
    main()
