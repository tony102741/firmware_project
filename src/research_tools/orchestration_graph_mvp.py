#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

try:
    from src.research_tools.orch_graph_normalization import normalize_note_target, normalize_signal
except ModuleNotFoundError:
    from orch_graph_normalization import normalize_note_target, normalize_signal


HELPER_PATH_RE = re.compile(r"/(?:(?:usr/)?(?:s?bin|libexec)|lib/sync-server/scripts)/[^\s'\";|&]+")
ABS_PATH_RE = re.compile(r"/[A-Za-z0-9_./%+\-]+")
GENERIC_HELPER_PATHS = {
    "/bin/sh",
    "/bin/ash",
    "/bin/bash",
}

SHELL_EXEC_TOKENS = {
    "system",
    "popen",
    "fork_exec",
    "exec",
    "execl",
    "execv",
    "execve",
}

UBUS_RPC_TOKENS = {
    "ubus",
    "rpc",
    "gl_ubus_",
    "oui-httpd",
    "uhttpd",
}

PERSISTENCE_TOKENS = {
    "uci",
    "guci_",
    "commit",
    "saveconfig",
    "sync()",
    "sync",
    "glmodem.",
    "network.",
    "firewall.",
    "history_list",
}

IDENTITY_POLICY_TOKENS = {
    "iccid",
    "imsi",
    "mac",
    "current_sim",
    "slot",
    "target_id",
    "target",
    "device",
    "policy",
    "client_list",
}

DOWNSTREAM_MUTATION_TOKENS = {
    "network.",
    "firewall",
    "kmwan",
    "mwan",
    "uci set",
    "uci commit",
    "glmodem.",
}

RESTART_RECONNECT_HINTS = {
    "restart",
    "reload",
    "reconnect",
    "connect",
    "dial",
    "switch_sim_slot",
    "ifup",
    "ifdown",
}

PROJECTION_PHRASES = (
    "sync configuration to network",
    "update dial configuration information to network",
    "update configuration to network",
    "apply configuration to network",
)

ACTIVATION_PHRASES = (
    "start_dial",
    "common_auto_connect",
    "reload network",
    "firewall reload",
    "kmwan restart",
    "saveconfig",
)

SYNC_SERVER_HELPER_PREFIX = "/lib/sync-server/scripts/"
SYNC_SERVER_TMP_PREFIX = "/tmp/sync-server/"
SYNC_SERVER_REQUEST_STAGING_RE = re.compile(r"^/tmp/sync-server/request-(?:input|output)-\d+-\d+$")

ALLOWED_NOTE_CATEGORIES = {
    "function_role",
    "xref_confirmed_edge",
    "helper_relationship",
    "persistence_boundary",
    "restart_relationship",
    "reconnect_relationship",
    "replay_boundary",
    "ordering_hint",
    "semantic_recurrence_hint",
}

CONFIDENCE_RANK = {
    "C3_low": 0,
    "C2_medium": 1,
    "C1_high": 2,
}

ORDERING_RANK = {
    "unordered": 0,
    "partially_ordered": 1,
    "ordered": 2,
}

COMPATIBLE_NODE_TYPE_PAIRS = {
    frozenset({"persistence_object", "staging_boundary"}),
    frozenset({"native_coordinator", "staging_boundary"}),
    frozenset({"activation_endpoint", "downstream_mutation_endpoint"}),
    frozenset({"staging_boundary", "downstream_mutation_endpoint"}),
}


@dataclass(frozen=True)
class Signal:
    category: str
    value: str
    source_kind: str
    original_value: str
    normalization_reason: str | None = None


def run_tool(cmd: list[str]) -> tuple[list[str], str | None]:
    tool_name = cmd[0]
    if shutil.which(tool_name) is None:
        return [], f"tool unavailable: {tool_name}"
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            errors="ignore",
        )
    except Exception as exc:
        return [], f"{tool_name} failed: {exc}"
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or f"exit {proc.returncode}"
        return [], f"{tool_name} failed: {stderr}"
    return proc.stdout.splitlines(), None


def unique_ordered(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def collect_strings(binary: Path, warnings: list[str]) -> list[str]:
    lines, error = run_tool(["strings", "-a", str(binary)])
    if error:
        warnings.append(error)
        return []
    cleaned = [line.strip() for line in lines if line.strip()]
    return unique_ordered(cleaned)


def collect_imports(binary: Path, warnings: list[str]) -> list[str]:
    imports: list[str] = []

    readelf_lines, readelf_error = run_tool(["readelf", "--dyn-syms", str(binary)])
    if readelf_error:
        warnings.append(readelf_error)
    else:
        for line in readelf_lines:
            if "UND" not in line:
                continue
            parts = line.split()
            if parts:
                imports.append(parts[-1].split("@", 1)[0])

    nm_lines, nm_error = run_tool(["nm", "-D", str(binary)])
    if nm_error:
        warnings.append(nm_error)
    else:
        for line in nm_lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[-1].split("@", 1)[0]
            if len(parts) >= 2 and parts[-2] == "U":
                imports.append(name)

    objdump_lines, objdump_error = run_tool(["objdump", "-T", str(binary)])
    if objdump_error:
        warnings.append(objdump_error)
    else:
        for line in objdump_lines:
            if "*UND*" not in line:
                continue
            parts = line.split()
            if parts:
                imports.append(parts[-1].split("@", 1)[0])

    return unique_ordered([name for name in imports if name])


def collect_exports(binary: Path, warnings: list[str]) -> list[str]:
    exports: list[str] = []
    nm_lines, nm_error = run_tool(["nm", "-D", "--defined-only", str(binary)])
    if nm_error:
        warnings.append(nm_error)
        return []
    for line in nm_lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        exports.append(parts[-1].split("@", 1)[0])
    return unique_ordered(exports)


def load_notes(path: Path | None, warnings: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        warnings.append(f"failed to read notes: {exc}")
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        warnings.append("notes JSON was not an object; ignored")
        return {}
    except json.JSONDecodeError:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return {"lines": lines}


def normalize_notes(notes: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    normalized = {
        "schema_version": notes.get("schema_version", "0.1"),
        "target_id": notes.get("target_id"),
        "notes": [],
        "lines": notes.get("lines", []),
        "suppress_nodes": notes.get("suppress_nodes", []),
        "suppress_edges": notes.get("suppress_edges", []),
        "prune_context_only_noise": bool(notes.get("prune_context_only_noise", False)),
    }
    raw_notes = notes.get("notes", [])
    if not isinstance(raw_notes, list):
        if raw_notes:
            warnings.append("notes field was not a list; ignoring structured notes")
        return normalized
    for idx, item in enumerate(raw_notes):
        if not isinstance(item, dict):
            warnings.append(f"ignored non-object analyst note at index {idx}")
            continue
        category = str(item.get("category", "")).strip()
        if category not in ALLOWED_NOTE_CATEGORIES:
            warnings.append(f"ignored unsupported analyst note category: {category or '<empty>'}")
            continue
        claim = str(item.get("claim", "")).lower()
        if any(token in claim for token in ("exploit", "rce", "cve", "vulnerability", "universal")):
            warnings.append(f"rejected unsupported claim-like analyst note category={category}")
            continue
        item_copy = dict(item)
        target = item_copy.get("target")
        if isinstance(target, str) and target.strip():
            normalized_target = normalize_note_target(category, target.strip())
            item_copy["target"] = normalized_target.normalized
            if normalized_target.normalization_reason:
                item_copy["original_target"] = normalized_target.original
                item_copy["normalization_reason"] = normalized_target.normalization_reason
        normalized["notes"].append(item_copy)
    return normalized


def classify_string_signal(value: str) -> list[Signal]:
    lower = value.lower()
    signals: list[Signal] = []
    special_path = classify_special_path_node_type(value) if value.startswith("/") else None
    helper_paths = HELPER_PATH_RE.findall(value)
    for helper in helper_paths:
        if helper in GENERIC_HELPER_PATHS:
            continue
        normalized = normalize_signal("helper_invocation", helper)
        signals.append(
            Signal(
                "helper_invocation",
                normalized.normalized,
                "string",
                helper,
                normalized.normalization_reason,
            )
        )

    if any(token in lower for token in RESTART_RECONNECT_HINTS):
        normalized = normalize_signal("restart_reconnect", value)
        signals.append(
            Signal(
                "restart_reconnect",
                normalized.normalized,
                "string",
                value,
                normalized.normalization_reason,
            )
        )

    if any(token in lower for token in PERSISTENCE_TOKENS) and not (
        special_path is not None and special_path[0] in {"semantic_helper", "temporary_state_object"}
    ):
        normalized = normalize_signal("persistence_uci", value)
        signals.append(
            Signal(
                "persistence_uci",
                normalized.normalized,
                "string",
                value,
                normalized.normalization_reason,
            )
        )

    if (
        value.startswith("/tmp/")
        or value.startswith("/var/run/")
        or value.startswith("/var/state/")
        or value.startswith("/etc/")
    ):
        normalized = normalize_signal("state_file", value)
        signals.append(
            Signal(
                "state_file",
                normalized.normalized,
                "string",
                value,
                normalized.normalization_reason,
            )
        )

    if "uci -p /var/state revert fing." in lower:
        signals.append(
            Signal(
                "state_file",
                "/var/state/fing",
                "string",
                value,
                "derived local-state target from /var/state revert command",
            )
        )

    if any(token in lower for token in UBUS_RPC_TOKENS):
        signals.append(Signal("ubus_rpc", value, "string", value))

    if any(token in lower for token in SHELL_EXEC_TOKENS):
        normalized = normalize_signal("shell_execution", value)
        signals.append(
            Signal(
                "shell_execution",
                normalized.normalized,
                "string",
                value,
                normalized.normalization_reason,
            )
        )

    if any(token in lower for token in IDENTITY_POLICY_TOKENS):
        signals.append(Signal("identity_or_policy_carrier", value, "string", value))

    if any(token in lower for token in DOWNSTREAM_MUTATION_TOKENS):
        signals.append(Signal("downstream_mutation", value, "string", value))

    return signals


def classify_import_signal(name: str) -> list[Signal]:
    lower = name.lower()
    signals: list[Signal] = []
    if any(token in lower for token in SHELL_EXEC_TOKENS):
        normalized = normalize_signal("shell_execution", name)
        signals.append(
            Signal(
                "shell_execution",
                normalized.normalized,
                "import",
                name,
                normalized.normalization_reason,
            )
        )
    if any(token in lower for token in UBUS_RPC_TOKENS):
        signals.append(Signal("ubus_rpc", name, "import", name))
    if any(token in lower for token in PERSISTENCE_TOKENS):
        normalized = normalize_signal("persistence_uci", name)
        signals.append(
            Signal(
                "persistence_uci",
                normalized.normalized,
                "import",
                name,
                normalized.normalization_reason,
            )
        )
    if any(token in lower for token in RESTART_RECONNECT_HINTS):
        normalized = normalize_signal("restart_reconnect", name)
        signals.append(
            Signal(
                "restart_reconnect",
                normalized.normalized,
                "import",
                name,
                normalized.normalization_reason,
            )
        )
    if any(token in lower for token in IDENTITY_POLICY_TOKENS):
        signals.append(Signal("identity_or_policy_carrier", name, "import", name))
    return signals


def add_signal_index(index: dict[str, list[Signal]], signal: Signal) -> None:
    index.setdefault(signal.category, []).append(signal)


def classify_signals(strings: list[str], imports: list[str], notes: dict[str, Any]) -> dict[str, list[Signal]]:
    index: dict[str, list[Signal]] = {}
    for value in strings:
        for signal in classify_string_signal(value):
            add_signal_index(index, signal)
    for name in imports:
        for signal in classify_import_signal(name):
            add_signal_index(index, signal)

    note_lines = notes.get("lines", [])
    if isinstance(note_lines, list):
        for line in note_lines:
            if not isinstance(line, str):
                continue
            for signal in classify_string_signal(line):
                add_signal_index(
                    index,
                    Signal(
                        signal.category,
                        signal.value,
                        "analyst_annotation",
                        signal.original_value,
                        signal.normalization_reason,
                    ),
                )

    for category, sigs in list(index.items()):
        deduped: list[Signal] = []
        seen: set[tuple[str, str, str]] = set()
        for sig in sigs:
            key = (sig.category, sig.value, sig.source_kind)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(sig)
        index[category] = deduped
    return index


def make_evidence(sig: Signal, evidence_class: str, summary: str | None = None) -> dict[str, Any]:
    evidence = {
        "class": evidence_class,
        "summary": summary or sig.value,
        "source_kind": sig.source_kind,
        "source_ref": sig.value,
    }
    if sig.normalization_reason:
        evidence["normalization_reason"] = sig.normalization_reason
        evidence["original_signal"] = sig.original_value
        evidence["normalized_signal"] = sig.value
    return evidence


def binary_label(binary: Path) -> str:
    return binary.name


def classify_raw_orchestration_phrase(value: str) -> str | None:
    lower = value.lower()
    if any(phrase in lower for phrase in PROJECTION_PHRASES):
        return "projection"
    if any(phrase in lower for phrase in ACTIVATION_PHRASES):
        return "activation"
    return None


def classify_special_path_node_type(value: str) -> tuple[str, str | None] | None:
    if value.startswith(SYNC_SERVER_HELPER_PREFIX):
        return ("semantic_helper", "sync-server helper path prioritized over generic persistence")
    if SYNC_SERVER_REQUEST_STAGING_RE.match(value):
        return ("temporary_state_object", "sync-server request staging path prioritized over generic persistence")
    if value in {
        "/tmp/sync-server/onemesh_client_list",
        "/tmp/sync-server/mesh_dev_link_list",
        "/tmp/sync-server/mesh_dev_offline_list",
    }:
        return ("temporary_state_object", "sync-server staging/snapshot path prioritized over generic persistence")
    return None


def classify_special_sink_artifact(value: str) -> tuple[str, str | None, str | None] | None:
    lower = value.lower()
    if value == "history_list":
        return (
            "persistence_object",
            "client_mgmt history_list treated as downstream sink persistence object",
            "sink_persistence_object",
        )
    if value == "/var/state/fing":
        return (
            "temporary_state_object",
            "client_mgmt local state revert target prioritized as temporary sink state",
            "local_state_revert_object",
        )
    if value == "saveconfig":
        return (
            "activation_endpoint",
            "client_mgmt saveconfig treated as persistent mutation activation endpoint",
            "persistent_mutation_activation",
        )
    if lower in {"uci_commit", "uci_set", "uci_save", "uci_lookup_ptr", "uci_delete"}:
        return (
            "persistence_object",
            "client_mgmt uci primitive treated as sink mutation primitive",
            "sink_mutation_primitive",
        )
    return None


def build_nodes_and_edges(
    binary: Path,
    target_id: str,
    signals: dict[str, list[Signal]],
    imports: list[str],
    exports: list[str],
    notes: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    binary_node_id = f"{target_id}:binary"

    binary_evidence: list[dict[str, Any]] = []
    if imports:
        binary_evidence.append(
            {
                "class": "E3_converging_static_evidence",
                "summary": f"{len(imports)} imported symbols harvested",
                "source_kind": "import",
                "source_ref": binary.name,
            }
        )
    if exports:
        binary_evidence.append(
            {
                "class": "E3_converging_static_evidence",
                "summary": f"{len(exports)} exported symbols harvested",
                "source_kind": "other",
                "source_ref": binary.name,
            }
        )
    nodes.append(
        {
            "id": binary_node_id,
            "label": binary_label(binary),
            "node_type": "native_coordinator",
            "tags": ["mvp_root_binary", "manual_scope_review"],
            "confidence": "C2_medium",
            "evidence": binary_evidence or [
                {
                    "class": "E4_candidate_only",
                    "summary": "binary root node added by MVP scaffold",
                    "source_kind": "other",
                    "source_ref": str(binary),
                }
            ],
            "manual_review_required": True,
        }
    )
    node_ids.add(binary_node_id)

    def ensure_node(
        label: str,
        node_type: str,
        evidence: list[dict[str, Any]],
        confidence: str,
        tags: list[str] | None = None,
    ) -> str:
        node_id = f"{target_id}:node:{len(node_ids)}"
        existing = next((n for n in nodes if n["label"] == label and n["node_type"] == node_type), None)
        if existing is not None:
            existing["evidence"].extend(evidence)
            return existing["id"]
        node = {
            "id": node_id,
            "label": label,
            "node_type": node_type,
            "tags": tags or [],
            "confidence": confidence,
            "evidence": evidence,
            "manual_review_required": True,
        }
        nodes.append(node)
        node_ids.add(node_id)
        return node_id

    def ensure_edge(
        source: str,
        target: str,
        edge_type: str,
        evidence: list[dict[str, Any]],
        confidence: str,
        ordering: str = "unordered",
    ) -> None:
        edge_id = f"{source}->{target}:{edge_type}"
        if edge_id in edge_ids:
            existing = next(e for e in edges if e["id"] == edge_id)
            existing["evidence"].extend(evidence)
            return
        edge_ids.add(edge_id)
        edges.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "edge_type": edge_type,
                "confidence": confidence,
                "ordering": ordering,
                "recurrence_label": "not_applicable",
                "evidence": evidence,
                "manual_review_required": True,
            }
        )

    for sig in signals.get("helper_invocation", []):
        helper_id = ensure_node(
            sig.value,
            "semantic_helper",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C2_medium",
            ["helper_path"],
        )
        ensure_edge(
            binary_node_id,
            helper_id,
            "invokes_helper",
            [make_evidence(sig, "E3_converging_static_evidence", "helper path observed in target binary")],
            "C2_medium",
        )

    for sig in signals.get("restart_reconnect", []):
        lower = sig.value.lower()
        if "dial" in lower or "connect" in lower:
            edge_type = "triggers_reconnect"
        else:
            edge_type = "triggers_restart"
        endpoint_id = ensure_node(
            sig.value,
            "activation_endpoint",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C2_medium",
            ["restart_or_reconnect_signal"],
        )
        ensure_edge(
            binary_node_id,
            endpoint_id,
            edge_type,
            [make_evidence(sig, "E3_converging_static_evidence", "restart/reconnect indicator observed")],
            "C2_medium",
        )

    for sig in signals.get("persistence_uci", []):
        lower = sig.value.lower()
        phrase_role = classify_raw_orchestration_phrase(sig.value)
        special_path = classify_special_path_node_type(sig.value) if sig.value.startswith("/") else None
        special_sink = classify_special_sink_artifact(sig.value)
        if phrase_role == "projection":
            persist_id = ensure_node(
                sig.value,
                "downstream_mutation_endpoint",
                [make_evidence(sig, "E3_converging_static_evidence", "projection-like configuration phrase observed")],
                "C2_medium",
                ["projection_like_signal"],
            )
            ensure_edge(
                binary_node_id,
                persist_id,
                "projects_downstream",
                [make_evidence(sig, "E3_converging_static_evidence", "projection-like configuration phrase observed")],
                "C2_medium",
            )
            continue
        if phrase_role == "activation":
            persist_id = ensure_node(
                sig.value,
                "activation_endpoint",
                [make_evidence(sig, "E3_converging_static_evidence", "activation-like configuration phrase observed")],
                "C2_medium",
                ["activation_like_signal"],
            )
            ensure_edge(
                binary_node_id,
                persist_id,
                "triggers_reconnect" if ("dial" in lower or "connect" in lower) else "triggers_restart",
                [make_evidence(sig, "E3_converging_static_evidence", "activation-like configuration phrase observed")],
                "C2_medium",
            )
            continue
        if special_sink is not None:
            node_type, reason, sink_tag = special_sink
            tags = ["persistence_signal"]
            edge_type = "writes_stage_state"
            edge_summary = "sink-aware persistence artifact observed"
            confidence = "C2_medium"
            if node_type == "activation_endpoint":
                tags = ["sink_activation_signal"]
                edge_type = "projects_downstream"
                edge_summary = "sink-aware save/flush activation observed"
            elif node_type == "temporary_state_object":
                tags = ["state_path", "sink_local_state_signal"]
                edge_type = "projects_downstream"
                edge_summary = "sink-local state mutation/revert path observed"
            elif sink_tag == "sink_mutation_primitive":
                tags = ["sink_mutation_primitive"]
                edge_type = "projects_downstream"
                edge_summary = "sink mutation primitive observed"
            else:
                tags = ["sink_persistence_signal"]
                edge_type = "projects_downstream"
                edge_summary = "sink persistence artifact observed"
            if sink_tag:
                tags.append(sink_tag)
            special_evidence = make_evidence(sig, "E3_converging_static_evidence", edge_summary)
            if reason:
                special_evidence["normalization_reason"] = reason
                special_evidence.setdefault("original_signal", sig.original_value)
                special_evidence.setdefault("normalized_signal", sig.value)
            persist_id = ensure_node(
                sig.value,
                node_type,
                [special_evidence],
                confidence,
                tags,
            )
            ensure_edge(
                binary_node_id,
                persist_id,
                edge_type,
                [special_evidence],
                confidence,
            )
            continue
        if special_path is not None:
            node_type, reason = special_path
            tags = ["persistence_signal"]
            edge_type = "writes_stage_state"
            edge_summary = "sync-server staging/helper path observed"
            confidence = "C2_medium"
            if node_type == "semantic_helper":
                tags = ["helper_path", "sync_server_helper_path"]
                edge_type = "invokes_helper"
                edge_summary = "sync-server helper path observed"
            else:
                tags = ["state_path", "sync_server_staging_path"]
            special_evidence = make_evidence(sig, "E3_converging_static_evidence", edge_summary)
            if reason:
                special_evidence["normalization_reason"] = reason
                special_evidence.setdefault("original_signal", sig.original_value)
                special_evidence.setdefault("normalized_signal", sig.value)
            persist_id = ensure_node(
                sig.value,
                node_type,
                [special_evidence],
                confidence,
                tags,
            )
            ensure_edge(
                binary_node_id,
                persist_id,
                edge_type,
                [special_evidence],
                confidence,
            )
            continue
        if sig.value.startswith("/") or "glmodem." in lower or "network." in lower or "firewall." in lower:
            label = sig.value
        else:
            label = f"persistence:{sig.value}"
        persist_id = ensure_node(
            label,
            "persistence_object",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C2_medium",
            ["persistence_signal"],
        )
        ensure_edge(
            binary_node_id,
            persist_id,
            "writes_stage_state",
            [make_evidence(sig, "E3_converging_static_evidence", "persistence-oriented token observed")],
            "C2_medium",
        )

    for sig in signals.get("state_file", []):
        node_type = "temporary_state_object"
        special_path = classify_special_path_node_type(sig.value)
        if special_path is not None:
            node_type = special_path[0]
        if sig.value.startswith("/etc/"):
            node_type = "persistence_object"
        state_id = ensure_node(
            sig.value,
            node_type,
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C2_medium" if sig.value.startswith("/var/run/") or sig.value.startswith("/tmp/") else "C1_high",
            ["state_path"],
        )
        edge_type = "reads_replay_state"
        if sig.value.startswith("/etc/"):
            edge_type = "writes_stage_state"
        ensure_edge(
            binary_node_id,
            state_id,
            edge_type,
            [make_evidence(sig, "E3_converging_static_evidence", "state path observed in target binary")],
            "C2_medium",
        )

    for sig in signals.get("ubus_rpc", []):
        rpc_id = ensure_node(
            sig.value,
            "context_only",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C3_low",
            ["ubus_or_rpc_signal"],
        )
        ensure_edge(
            binary_node_id,
            rpc_id,
            "unordered_association",
            [make_evidence(sig, "E3_converging_static_evidence", "ubus/RPC-related token observed")],
            "C3_low",
        )

    for sig in signals.get("shell_execution", []):
        shell_id = ensure_node(
            sig.value,
            "context_only",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C3_low",
            ["shell_execution_signal"],
        )
        ensure_edge(
            binary_node_id,
            shell_id,
            "unordered_association",
            [make_evidence(sig, "E3_converging_static_evidence", "shell execution primitive observed")],
            "C3_low",
        )

    for sig in signals.get("identity_or_policy_carrier", []):
        carrier_id = ensure_node(
            sig.value,
            "temporary_state_object" if sig.value.startswith("/") else "context_only",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C3_low" if not sig.value.startswith("/") else "C2_medium",
            ["identity_or_policy_signal"],
        )
        ensure_edge(
            binary_node_id,
            carrier_id,
            "updates_identity_state",
            [make_evidence(sig, "E3_converging_static_evidence", "identity/policy carrier token observed")],
            "C3_low" if not sig.value.startswith("/") else "C2_medium",
        )

    for sig in signals.get("downstream_mutation", []):
        if classify_raw_orchestration_phrase(sig.value) == "activation":
            continue
        mut_id = ensure_node(
            sig.value,
            "downstream_mutation_endpoint",
            [make_evidence(sig, "E3_converging_static_evidence")],
            "C2_medium",
            ["downstream_mutation_signal"],
        )
        ensure_edge(
            binary_node_id,
            mut_id,
            "projects_downstream",
            [make_evidence(sig, "E3_converging_static_evidence", "downstream mutation token observed")],
            "C2_medium",
        )

    analyst_nodes = notes.get("nodes", [])
    if isinstance(analyst_nodes, list):
        for item in analyst_nodes:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "")).strip()
            node_type = str(item.get("node_type", "context_only")).strip()
            if not label:
                continue
            ensure_node(
                label,
                node_type,
                [
                    {
                        "class": "E1_function_level_confirmed",
                        "summary": str(item.get("summary", "analyst-supplied node")),
                        "source_kind": "analyst_annotation",
                        "source_ref": str(item.get("source_ref", "notes")),
                    }
                ],
                "C1_high",
                ["analyst_seed"],
            )

    return nodes, edges


def find_node(nodes: list[dict[str, Any]], label: str) -> dict[str, Any] | None:
    for node in nodes:
        if node.get("label") == label:
            return node
    return None


def make_node_id(target_id: str, nodes: list[dict[str, Any]]) -> str:
    return f"{target_id}:node:{len(nodes)}"


def promote_confidence(current: str, desired: str) -> str:
    if CONFIDENCE_RANK.get(desired, -1) > CONFIDENCE_RANK.get(current, -1):
        return desired
    return current


def merge_ordering(current: str, new_value: str, warnings: list[str], context: str) -> str:
    if current == new_value:
        return current
    if current == "unordered":
        return new_value
    if new_value == "unordered":
        return current
    if current != new_value:
        warnings.append(f"ordering conflict for {context}: {current} vs {new_value}; downgraded to partially_ordered")
        return "partially_ordered"
    return current


def note_evidence(note: dict[str, Any], default_class: str, default_summary: str) -> dict[str, Any]:
    note_class = str(note.get("evidence_class", default_class))
    if note_class not in {
        "E1_function_level_confirmed",
        "E2_xref_confirmed",
        "E3_converging_static_evidence",
        "E4_candidate_only",
    }:
        note_class = default_class
    evidence = {
        "class": note_class,
        "summary": str(note.get("summary", default_summary)),
        "source_kind": "analyst_annotation",
        "source_ref": str(note.get("source_ref", "analyst_notes")),
    }
    if note.get("normalization_reason"):
        evidence["normalization_reason"] = str(note.get("normalization_reason"))
        evidence["original_signal"] = str(note.get("original_target", note.get("target", "")))
        evidence["normalized_signal"] = str(note.get("target", ""))
    return evidence


def classify_node_type_conflict(existing_type: str, new_type: str) -> str:
    if existing_type == new_type:
        return "exact"
    if existing_type == "context_only" or new_type == "context_only":
        return "promotable"
    if existing_type in {"persistence_object", "temporary_state_object"} and new_type == "staging_boundary":
        return "promotable"
    if frozenset({existing_type, new_type}) in COMPATIBLE_NODE_TYPE_PAIRS:
        return "compatible"
    if existing_type in {"activation_endpoint", "downstream_mutation_endpoint"} and new_type in {
        "activation_endpoint",
        "downstream_mutation_endpoint",
        "staging_boundary",
    }:
        return "partial"
    if existing_type in {"native_coordinator", "staging_boundary"} and new_type in {
        "native_coordinator",
        "staging_boundary",
        "downstream_mutation_endpoint",
    }:
        return "partial"
    return "hard"


def ensure_node_refined(
    target_id: str,
    nodes: list[dict[str, Any]],
    label: str,
    node_type: str,
    confidence: str,
    evidence: dict[str, Any],
    warnings: list[str],
) -> str:
    existing = find_node(nodes, label)
    if existing is not None:
        existing_type = str(existing.get("node_type"))
        severity = classify_node_type_conflict(existing_type, node_type)
        if severity == "promotable":
            existing["node_type"] = node_type
        elif severity == "compatible":
            existing.setdefault("tags", []).append(f"semantic_overlay:{node_type}")
            existing.setdefault("tags", []).append("conflict_severity:compatible")
        elif severity == "partial":
            existing.setdefault("tags", []).append(f"semantic_overlay:{node_type}")
            existing.setdefault("tags", []).append("conflict_severity:partial")
            warnings.append(
                f"partial node type conflict for {label}: existing={existing_type} new={node_type}; keeping existing with overlay"
            )
        elif severity == "hard":
            existing.setdefault("tags", []).append(f"semantic_overlay:{node_type}")
            existing.setdefault("tags", []).append("conflict_severity:hard")
            warnings.append(
                f"hard node type conflict for {label}: existing={existing_type} new={node_type}; keeping existing"
            )
        existing["confidence"] = promote_confidence(str(existing.get("confidence", "C3_low")), confidence)
        existing.setdefault("tags", []).append("analyst_override")
        existing.setdefault("evidence", []).append(evidence)
        existing["manual_review_required"] = True
        return str(existing["id"])
    node_id = make_node_id(target_id, nodes)
    nodes.append(
        {
            "id": node_id,
            "label": label,
            "node_type": node_type,
            "tags": ["analyst_override"],
            "confidence": confidence,
            "evidence": [evidence],
            "manual_review_required": True,
        }
    )
    return node_id


def find_edge(edges: list[dict[str, Any]], source: str, target: str, edge_type: str) -> dict[str, Any] | None:
    edge_id = f"{source}->{target}:{edge_type}"
    for edge in edges:
        if edge.get("id") == edge_id:
            return edge
    return None


def ensure_edge_refined(
    edges: list[dict[str, Any]],
    source: str,
    target: str,
    edge_type: str,
    confidence: str,
    evidence: dict[str, Any],
    warnings: list[str],
    ordering: str = "unordered",
) -> None:
    existing = find_edge(edges, source, target, edge_type)
    edge_id = f"{source}->{target}:{edge_type}"
    if existing is not None:
        existing["confidence"] = promote_confidence(str(existing.get("confidence", "C3_low")), confidence)
        existing["ordering"] = merge_ordering(str(existing.get("ordering", "unordered")), ordering, warnings, edge_id)
        existing.setdefault("evidence", []).append(evidence)
        existing["manual_review_required"] = True
        return
    edges.append(
        {
            "id": edge_id,
            "source": source,
            "target": target,
            "edge_type": edge_type,
            "confidence": confidence,
            "ordering": ordering,
            "recurrence_label": "not_applicable",
            "evidence": [evidence],
            "manual_review_required": True,
        }
    )


def apply_analyst_refinement(
    target_id: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    notes: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    summary = {
        "structured_notes_applied": 0,
        "nodes_promoted_or_added": 0,
        "edges_promoted_or_added": 0,
        "nodes_suppressed": 0,
        "edges_suppressed": 0,
    }

    structured_notes = notes.get("notes", [])
    if not isinstance(structured_notes, list):
        structured_notes = []

    category_to_edge = {
        "xref_confirmed_edge": "calls_native",
        "helper_relationship": "invokes_helper",
        "persistence_boundary": "writes_stage_state",
        "restart_relationship": "triggers_restart",
        "reconnect_relationship": "triggers_reconnect",
        "replay_boundary": "reads_replay_state",
    }
    category_to_confidence = {
        "function_role": "C1_high",
        "xref_confirmed_edge": "C1_high",
        "helper_relationship": "C1_high",
        "persistence_boundary": "C1_high",
        "restart_relationship": "C2_medium",
        "reconnect_relationship": "C2_medium",
        "replay_boundary": "C2_medium",
    }

    for note in structured_notes:
        category = str(note.get("category", "")).strip()
        summary["structured_notes_applied"] += 1
        if category == "function_role":
            label = str(note.get("function") or note.get("label") or "").strip()
            node_type = str(note.get("node_type", "context_only")).strip()
            if not label:
                warnings.append("ignored function_role note without label/function")
                continue
            ev = note_evidence(note, "E1_function_level_confirmed", "analyst-supplied function role")
            before = find_node(nodes, label)
            ensure_node_refined(target_id, nodes, label, node_type, "C1_high", ev, warnings)
            if before is None:
                summary["nodes_promoted_or_added"] += 1
            continue

        if category == "ordering_hint":
            source_label = str(note.get("source", "")).strip()
            target_label = str(note.get("target", "")).strip()
            edge_type = str(note.get("edge_type", "unordered_association")).strip()
            ordering = str(note.get("ordering", "partially_ordered")).strip()
            src = find_node(nodes, source_label)
            dst = find_node(nodes, target_label)
            if not src or not dst:
                warnings.append(f"ordering_hint skipped; unresolved node(s): {source_label} -> {target_label}")
                continue
            ev = note_evidence(note, "E2_xref_confirmed", "analyst ordering hint")
            ensure_edge_refined(edges, str(src["id"]), str(dst["id"]), edge_type, "C2_medium", ev, warnings, ordering)
            summary["edges_promoted_or_added"] += 1
            continue

        if category == "semantic_recurrence_hint":
            warnings.append("semantic_recurrence_hint recorded but not auto-applied to single-binary graph")
            continue

        if category in category_to_edge:
            source_label = str(note.get("source", "")).strip()
            target_label = str(note.get("target", "")).strip()
            if not source_label or not target_label:
                warnings.append(f"{category} skipped; missing source or target")
                continue
            source_type = str(note.get("source_type", "context_only")).strip()
            target_type = str(note.get("target_type", "context_only")).strip()
            source_evidence = note_evidence(note, "E1_function_level_confirmed", f"analyst source for {category}")
            target_evidence = note_evidence(note, "E1_function_level_confirmed", f"analyst target for {category}")
            src_before = find_node(nodes, source_label)
            dst_before = find_node(nodes, target_label)
            src_id = ensure_node_refined(
                target_id,
                nodes,
                source_label,
                source_type,
                category_to_confidence.get(category, "C2_medium"),
                source_evidence,
                warnings,
            )
            dst_id = ensure_node_refined(
                target_id,
                nodes,
                target_label,
                target_type,
                category_to_confidence.get(category, "C2_medium"),
                target_evidence,
                warnings,
            )
            if src_before is None:
                summary["nodes_promoted_or_added"] += 1
            if dst_before is None:
                summary["nodes_promoted_or_added"] += 1
            edge_type = str(note.get("edge_type", category_to_edge[category])).strip()
            ordering = str(note.get("ordering", "unordered")).strip()
            ev = note_evidence(note, "E2_xref_confirmed", f"analyst refined {category}")
            ensure_edge_refined(
                edges,
                src_id,
                dst_id,
                edge_type,
                category_to_confidence.get(category, "C2_medium"),
                ev,
                warnings,
                ordering,
            )
            summary["edges_promoted_or_added"] += 1
            continue

    suppressed_labels = set()
    raw_suppressed_nodes = notes.get("suppress_nodes", [])
    if isinstance(raw_suppressed_nodes, list):
        suppressed_labels.update(str(item) for item in raw_suppressed_nodes if isinstance(item, str))

    if notes.get("prune_context_only_noise"):
        for node in nodes:
            if node.get("node_type") == "context_only" and node.get("confidence") == "C3_low":
                tags = set(node.get("tags", []))
                if "analyst_override" not in tags:
                    suppressed_labels.add(str(node.get("label")))

    if suppressed_labels:
        removed_ids = {str(node["id"]) for node in nodes if str(node.get("label")) in suppressed_labels}
        if removed_ids:
            before_nodes = len(nodes)
            before_edges = len(edges)
            nodes[:] = [node for node in nodes if str(node.get("id")) not in removed_ids]
            edges[:] = [
                edge
                for edge in edges
                if str(edge.get("source")) not in removed_ids and str(edge.get("target")) not in removed_ids
            ]
            summary["nodes_suppressed"] += before_nodes - len(nodes)
            summary["edges_suppressed"] += before_edges - len(edges)

    suppressed_edges = notes.get("suppress_edges", [])
    if isinstance(suppressed_edges, list):
        for item in suppressed_edges:
            if not isinstance(item, dict):
                continue
            src_label = str(item.get("source", "")).strip()
            dst_label = str(item.get("target", "")).strip()
            edge_type = str(item.get("edge_type", "")).strip()
            src = find_node(nodes, src_label)
            dst = find_node(nodes, dst_label)
            if not src or not dst or not edge_type:
                continue
            before_edges = len(edges)
            edges[:] = [
                edge for edge in edges
                if not (
                    str(edge.get("source")) == str(src["id"])
                    and str(edge.get("target")) == str(dst["id"])
                    and str(edge.get("edge_type")) == edge_type
                )
            ]
            summary["edges_suppressed"] += before_edges - len(edges)

    return summary


def summarize_signals(signals: dict[str, list[Signal]]) -> dict[str, Any]:
    counts = {category: len(items) for category, items in signals.items()}
    top_signals = {
        category: [
            {
                "normalized": sig.value,
                "original": sig.original_value,
                "normalization_reason": sig.normalization_reason,
            }
            for sig in items[:10]
        ]
        for category, items in sorted(signals.items())
    }
    return {
        "counts_by_category": counts,
        "top_examples": top_signals,
        "total_signals": sum(counts.values()),
    }


def maybe_validate_schema(output: dict[str, Any], warnings: list[str]) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        warnings.append("jsonschema unavailable; schema validation skipped")
        return
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "research/regeneration/full_corpus_20260508/corpus_wide/graphs/orchestration_graph_json_schema.json"
    )
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"failed to load schema: {exc}")
        return
    try:
        subset = {
            "graph_id": output.get("graph_id"),
            "target": output.get("target"),
            "metadata": output.get("metadata"),
            "nodes": output.get("nodes"),
            "edges": output.get("edges"),
        }
        jsonschema.validate(subset, schema)
    except Exception as exc:
        warnings.append(f"schema validation warning: {exc}")


def build_output(
    binary: Path,
    target_id: str,
    signals: dict[str, list[Signal]],
    imports: list[str],
    exports: list[str],
    notes: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    nodes, edges = build_nodes_and_edges(binary, target_id, signals, imports, exports, notes)
    refinement_summary = apply_analyst_refinement(target_id, nodes, edges, notes, warnings)
    output = {
        "graph_id": target_id,
        "target": {
            "binary_path": str(binary),
        },
        "metadata": {
            "extractor_version": "0.1.0-mvp",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "supported_evidence_classes": [
                "E2_xref_confirmed via analyst notes",
                "E3_converging_static_evidence",
            ],
            "notes": [
                "single-binary MVP",
                "strings/imports-based extraction",
                "manual review required for all nodes and edges",
            ],
        },
        "raw_signal_summary": summarize_signals(signals),
        "refinement_summary": refinement_summary,
        "nodes": nodes,
        "edges": edges,
        "warnings": list(warnings),
        "unsupported_assumptions": [
            "no exploitability inference",
            "no runtime ordering inference",
            "no automatic xref reconstruction",
            "no exact recurrence inference",
        ],
    }
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal provisional orchestration graph extractor.")
    parser.add_argument("--binary", required=True, help="Path to one firmware binary or module.")
    parser.add_argument("--target-id", required=True, help="Identifier for the provisional graph.")
    parser.add_argument("--output", required=True, help="Output JSON path.")
    parser.add_argument("--notes", help="Optional analyst notes JSON or text file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    binary = Path(args.binary)
    notes_path = Path(args.notes) if args.notes else None
    warnings: list[str] = []

    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")

    strings = collect_strings(binary, warnings)
    imports = collect_imports(binary, warnings)
    exports = collect_exports(binary, warnings)
    notes = normalize_notes(load_notes(notes_path, warnings), warnings)
    signals = classify_signals(strings, imports, notes)
    output = build_output(binary, args.target_id, signals, imports, exports, notes, warnings)
    maybe_validate_schema(output, warnings)
    output["warnings"] = list(warnings)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    output_path.write_text(json.dumps(output, indent=indent, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
