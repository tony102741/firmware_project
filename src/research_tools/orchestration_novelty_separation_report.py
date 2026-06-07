#!/usr/bin/env python3
from __future__ import annotations

try:
    from .paths import regeneration_dir
except ImportError:
    from paths import regeneration_dir

OUTDIR = regeneration_dir()


KNOWN_CVE_ROWS = [
    {
        "family": "UDP 20002 tdpServer RCE / probe-response overflow",
        "component": "TP-Link tdpServer",
        "root_cause": "memory corruption in packet parser / response handler",
        "parser_stage": "external UDP ingress, probe-response JSON handling",
        "sink_type": "stack overwrite / control-flow corruption",
        "memory_only": "mostly yes",
        "orchestration": "incidental only",
        "persistent_state": "sometimes incidental (`ssh_port` UCI write), but not the core finding",
        "lua_uci_helper": "not required for exploit claim",
    },
    {
        "family": "tmpserver/tdpserver packet overflows",
        "component": "tmpserver / tdpServer parser layer",
        "root_cause": "length validation failure / unchecked copy in packet parsing",
        "parser_stage": "pre-dispatch packet decode and field extraction",
        "sink_type": "stack/heap corruption",
        "memory_only": "yes",
        "orchestration": "no demonstrated need",
        "persistent_state": "no",
        "lua_uci_helper": "no",
    },
    {
        "family": "ssh_port strcpy overflow",
        "component": "TP-Link tdpServer probe-response handler",
        "root_cause": "unbounded `strcpy` from packet JSON field",
        "parser_stage": "opcode-2 probe-response client path",
        "sink_type": "stack overflow, plus adjacent UCI write",
        "memory_only": "the public vulnerability framing is yes",
        "orchestration": "not needed for the bug class",
        "persistent_state": "yes, same path also writes `onemesh.<mac>.ssh_port`",
        "lua_uci_helper": "UCI yes, Lua/helper no direct proof required",
    },
    {
        "family": "probe-handling memory corruption",
        "component": "TP-Link tdpServer / probe handlers",
        "root_cause": "parser-side copy/length bug",
        "parser_stage": "probe / discovery packet processing",
        "sink_type": "memory corruption or crash",
        "memory_only": "yes",
        "orchestration": "no",
        "persistent_state": "no",
        "lua_uci_helper": "no",
    },
    {
        "family": "OneMesh DoS",
        "component": "OneMesh management packet handling",
        "root_cause": "protocol / parser robustness failure",
        "parser_stage": "external management protocol handling",
        "sink_type": "availability loss",
        "memory_only": "not necessarily, but still parser/protocol scoped",
        "orchestration": "no demonstrated distributed propagation requirement",
        "persistent_state": "no",
        "lua_uci_helper": "no",
    },
]


RECURRENCE = [
    {
        "target": "TP-Link Archer AX23 1.2_250904",
        "family": "TP-Link management stack",
        "external_ingress": "tdpServer",
        "tmp_luci": "not confirmed in this slice",
        "lua_dispatch": "OneMesh Lua + LuCI reuse confirmed",
        "sync_fallback_on": "yes",
        "persistent_state": "yes",
        "distributed_sync": "yes",
    },
    {
        "target": "TP-Link Archer AX53",
        "family": "not in reproducible corpus",
        "external_ingress": "n/a",
        "tmp_luci": "n/a",
        "lua_dispatch": "n/a",
        "sync_fallback_on": "n/a",
        "persistent_state": "n/a",
        "distributed_sync": "n/a",
    },
    {
        "target": "TP-Link Archer AX55 V4 (240531 / 241014 / 251030_EU)",
        "family": "TP-Link management stack",
        "external_ingress": "tdpServer",
        "tmp_luci": "not confirmed in this slice",
        "lua_dispatch": "OneMesh Lua + LuCI reuse confirmed",
        "sync_fallback_on": "yes across 3 builds",
        "persistent_state": "yes",
        "distributed_sync": "yes",
    },
    {
        "target": "TP-Link Archer AX72 V2_241119_US",
        "family": "TP-Link management stack",
        "external_ingress": "tdpServer",
        "tmp_luci": "not primary path",
        "lua_dispatch": "direct OneMesh Lua bridge confirmed",
        "sync_fallback_on": "yes",
        "persistent_state": "yes",
        "distributed_sync": "yes",
    },
    {
        "target": "MERCUSYS MR90X (EU) V1.20_23080820240123090924",
        "family": "MERCUSYS management stack",
        "external_ingress": "tmpsvr",
        "tmp_luci": "yes",
        "lua_dispatch": "tmp-luci + tmp_server.lua + direct OneMesh Lua bridge",
        "sync_fallback_on": "yes",
        "persistent_state": "yes",
        "distributed_sync": "yes",
    },
]


def write(path: str, text: str) -> None:
    (OUTDIR / path).write_text(text.rstrip() + "\n")


def known_vs_orchestration() -> str:
    lines = [
        "# Known CVE vs Orchestration Findings",
        "",
        "This comparison separates previously-known TP-Link/MERCUSYS parser-centric issues from the management-plane trust and orchestration semantics reconstructed in this corpus study.",
        "",
        "## Known CVE-Oriented Families",
        "",
        "| Family | Affected Component | Root Cause Type | Parser Stage | Sink Type | Memory Corruption Only? | Reaches Orchestration Semantics? | Persistent State? | Lua/UCI/Helper Propagation? |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in KNOWN_CVE_ROWS:
        lines.append(
            f"| {row['family']} | {row['component']} | {row['root_cause']} | {row['parser_stage']} | "
            f"{row['sink_type']} | {row['memory_only']} | {row['orchestration']} | "
            f"{row['persistent_state']} | {row['lua_uci_helper']} |"
        )
    lines += [
        "",
        "## Our Reconstructed Finding Family",
        "",
        "| Dimension | Reconstructed Finding |",
        "| --- | --- |",
        "| Packet ingress semantics | External management traffic lands in a gateway daemon (`tdpServer` on TP-Link; `tmpsvr` on MR90X) before any web UI or ordinary HTTP handler is involved. |",
        "| tmp-luci relay model | MR90X `tmpsvr` relays packet payloads to `/usr/bin/tmp-luci`, which enters `luci.sgi.tmp` and then `tmp_server.lua`. |",
        "| Lua dispatch architecture | Packet-derived content reaches compiled LuCI/Lua dispatch logic rather than stopping at a fixed parser. |",
        "| Packet-derived UCI persistence | Network-originated mesh fields and management decisions are written into UCI/config state and consumed later. |",
        "| sync-server propagation | `sync-server` reuses that trusted state and relays it outward through helper scripts and tmpv2 client logic. |",
        "| Distributed orchestration semantics | Multiple daemons (`tdpServer`/`tmpsvr`, `sync-server`, `meshd`, `easymesh-*`) cooperate over ubus/UCI/files without re-authenticating origin. |",
        "| Cross-vendor recurrence | The same trust pattern recurs across AX23, AX55, AX72, and MR90X; AX53 is not present in the reproducible corpus. |",
        "| Trust-boundary collapse | The meaningful boundary is not parser memory safety but that packet-originated management state becomes internally trusted and persistent across daemons. |",
    ]
    return "\n".join(lines)


def orchestration_trust_model() -> str:
    return "\n".join(
        [
            "# Orchestration Trust Model",
            "",
            "## Core Model",
            "",
            "The reconstructed trust model is:",
            "",
            "`external management packet -> ingress daemon -> Lua bridge / dispatch -> UCI / state persistence -> sync-server / helper scripts -> downstream mesh daemons`",
            "",
            "This is distinct from a parser bug. The core issue is that after the first daemon accepts the message, later layers treat the resulting state as trusted management intent.",
            "",
            "## Distinguishing Properties",
            "",
            "- It is not tied to one overflow or one malformed field.",
            "- It survives across daemons and time because state is written to UCI, shared files, client lists, and helper inputs.",
            "- It is distributed: `sync-server`, `meshd`, `easymesh-agent`, and Lua controllers all participate.",
            "- It is cross-vendor within the TP-Link/MERCUSYS management-stack family.",
            "",
            "## Boundaries That Collapse",
            "",
            "- `protocol validation` is treated as if it were `authorization`.",
            "- `packet accepted once` becomes `state trusted everywhere`.",
            "- `local helper invocation` is treated as trusted orchestration, even when its inputs derive from prior network-originated state.",
            "",
            "## Scope Compared with Parser Bugs",
            "",
            "- Parser bugs explain memory corruption and immediate crash/RCE conditions.",
            "- The trust-model finding explains why accepted packet-derived state has unusual downstream reach even without a memory safety failure.",
        ]
    )


def distributed_semantics() -> str:
    return "\n".join(
        [
            "# Distributed Management Plane Semantics",
            "",
            "## AX72 / TP-Link Pattern",
            "",
            "- `tdpServer` is the external UDP gateway.",
            "- OneMesh packet handling crosses into Lua (`luci.controller.admin.onemesh`) and persistent UCI state.",
            "- `sync-server` and related consumers rely on flag files, client lists, and shared management state without independent origin checks.",
            "",
            "## MR90X / MERCUSYS Pattern",
            "",
            "- `tmpsvr` is the external TDP ingress candidate.",
            "- `/usr/bin/tmp-luci` relays into `luci.sgi.tmp` and `tmp_server.lua`.",
            "- `sync-server` defaults missing `onemesh.onemesh.enable` to `on` in master/router mode and reuses persistent OneMesh state.",
            "- `meshd`, `ieee1905`, `easymesh-agent`, and `easymesh-controller` form the orchestration backend.",
            "",
            "## Why This Is Distributed-State Semantics",
            "",
            "- The externally-relevant effect is not limited to the first packet parser.",
            "- Network-derived decisions are reflected in persistent config, temporary state files, client lists, and helper-driven relay actions.",
            "- Later daemons consume these artifacts as management truth rather than tainted input.",
        ]
    )


def cross_vendor() -> str:
    lines = [
        "# Cross-Vendor Recurrence",
        "",
        "| Target | Architecture Family | External Ingress | tmp-luci Relay | Lua Dispatch | sync-server Default-On Fallback | Persistent State | Distributed Sync / Helper Propagation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in RECURRENCE:
        lines.append(
            f"| {row['target']} | {row['family']} | {row['external_ingress']} | {row['tmp_luci']} | "
            f"{row['lua_dispatch']} | {row['sync_fallback_on']} | {row['persistent_state']} | {row['distributed_sync']} |"
        )
    lines += [
        "",
        "## Recurrence Notes",
        "",
        "- AX23, AX55, AX72, and MR90X all retain the management-plane trust pattern in this corpus slice.",
        "- AX55 contributes three firmware generations with the same default-on sync behavior.",
        "- MR90X shows the same semantics even though `tdpServer` is replaced by `tmpsvr` plus a more explicit `tmp-luci` relay.",
        "- AX53 is absent from the reproducible corpus, so no recurrence claim is made for it here.",
    ]
    return "\n".join(lines)


def novelty() -> str:
    return "\n".join(
        [
            "# Novelty Assessment",
            "",
            "## What is already known",
            "",
            "- Publicly-known work already covers UDP 20002 packet-parser exposure, memory corruption, overflow conditions, and probe-handling crashes/RCE.",
            "- Those findings are component-local: they explain what goes wrong inside the ingress parser.",
            "",
            "## What this work adds",
            "",
            "- A packet-to-Lua semantic reconstruction for MR90X `tmpsvr -> tmp-luci -> tmp_server.lua`.",
            "- A distributed-state model showing how accepted management state persists into UCI, state files, and helper scripts.",
            "- A cross-vendor comparison showing that TP-Link and MERCUSYS reuse the same orchestration trust assumptions even when the ingress binary name changes.",
            "- A clear split between `parser bug` and `management-plane trust collapse` as two different classes of weakness.",
            "",
            "## Why the contribution is not just another sink count",
            "",
            "- The key claim is architectural: once accepted, management-plane state is propagated and trusted by later daemons without a second boundary.",
            "- That claim remains meaningful even when a given firmware build has no confirmed overflow.",
            "",
            "## Limits",
            "",
            "- This is not a standalone CVE claim.",
            "- It does not prove every downstream consumer is exploitable.",
            "- It does show a reproducible, cross-firmware trust model that is broader than any single parser bug.",
        ]
    )


def main() -> None:
    write("known_cve_vs_orchestration_findings.md", known_vs_orchestration())
    write("orchestration_trust_model.md", orchestration_trust_model())
    write("distributed_management_plane_semantics.md", distributed_semantics())
    write("cross_vendor_recurrence.md", cross_vendor())
    write("novelty_assessment.md", novelty())


if __name__ == "__main__":
    main()
