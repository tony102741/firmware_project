#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    from src.research_tools.orch_graph_normalization import normalize_note_target
except ModuleNotFoundError:
    from orch_graph_normalization import normalize_note_target


BACKTICK_RE = re.compile(r"`([^`]+)`")
ARROW_RE = re.compile(r"`([^`]+)`\s*->\s*`([^`]+)`")
XREF_FROM_RE = re.compile(r"`([^`]+)`[^`\n]*xref[^`\n]*from\s+`([^`]+)`", re.IGNORECASE)
FROM_SOURCE_RE = re.compile(r"from\s+`([^`]+)`", re.IGNORECASE)
LIKELY_WORDS = ("likely", "inferred", "plausible", "most plausible")
UNRESOLVED_WORDS = ("unresolved", "remaining gap", "timed out", "not fully recovered", "not fully closed")
PROJECTION_HINTS = (
    "sync configuration to network",
    "update dial configuration information to network",
    "project",
    "projection",
    "projected into",
    "synchronized state is projected",
    "translated into firewall",
    "propagated into kmwan",
)
ACTIVATION_HINTS = (
    "start_dial",
    "common_auto_connect",
    "start connect",
    "start dial",
    "connect-auto",
    "dial_from_apn_database",
    "load modem dialing configuration",
)
STAGING_HINTS = (
    "save configuration to glmodem",
    "staged",
    "staging",
    "canonicalization",
    "canonical choice",
    "glmodem.%s.synced",
)
PERSISTENCE_HINTS = (
    "save configuration",
    "persist",
    "commit",
    "write",
)
RESTART_HINTS = (
    "restart",
    "reload",
    "stop",
    "kill",
)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Draft analyst-note JSON from markdown reverse summaries.")
    ap.add_argument("--input", required=True, help="Markdown reverse summary path")
    ap.add_argument("--target-id", required=True, help="Target identifier for the drafted notes")
    ap.add_argument("--output", required=True, help="Output JSON path")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return ap.parse_args()


def slugify_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_./%+-]+", "_", label).strip("_")


def infer_edge_type(target: str, line: str) -> str:
    lower = (target + " " + line).lower()
    if any(token in lower for token in PROJECTION_HINTS):
        return "projects_downstream"
    if "dial" in lower or "connect" in lower or "reconnect" in lower:
        return "triggers_reconnect"
    if "restart" in lower or "reload" in lower or "kill" in lower or "stop" in lower:
        return "triggers_restart"
    if target.startswith("/usr/bin/") or "helper" in lower or "switch_sim_slot" in lower or "dual_sim_failover" in lower:
        return "invokes_helper"
    if target.startswith("/tmp/") or target.startswith("/var/run/"):
        return "reads_replay_state"
    if target.startswith("/etc/") or "glmodem." in lower or "network." in lower or "uci" in lower:
        return "writes_stage_state"
    return "calls_native"


def infer_target_type(target: str, edge_type: str) -> str:
    lower = target.lower()
    if target.startswith("/tmp/") or target.startswith("/var/run/"):
        return "temporary_state_object"
    if edge_type == "projects_downstream":
        return "downstream_mutation_endpoint"
    if target.startswith("/etc/") or "glmodem." in lower or "network." in lower or "firewall." in lower:
        return "staging_boundary"
    if edge_type in {"triggers_restart", "triggers_reconnect"}:
        return "activation_endpoint"
    if edge_type == "invokes_helper":
        return "semantic_helper"
    return "native_coordinator"


def infer_source_type(source: str) -> str:
    lower = source.lower()
    if source.startswith("/"):
        return "temporary_state_object"
    if lower.startswith("set_") or lower.startswith("get_"):
        return "entry_handler"
    return "native_coordinator"


def line_semantic_role(line: str, ref: str) -> str:
    lower = f"{line} {ref}".lower()
    if ref.startswith("/tmp/") or ref.startswith("/var/run/"):
        return "replay"
    if any(token in lower for token in RESTART_HINTS):
        return "restart"
    if any(token in lower for token in ACTIVATION_HINTS):
        return "activation"
    if any(token in lower for token in PROJECTION_HINTS):
        return "projection"
    if any(token in lower for token in STAGING_HINTS):
        return "staging"
    if ref.startswith("/etc/") or any(token in lower for token in PERSISTENCE_HINTS):
        return "persistence"
    if ref.startswith("/usr/bin/") or ref.startswith("/sbin/") or ref.startswith("/bin/"):
        return "helper"
    return "generic"


def is_state_like_target(ref: str) -> bool:
    if ref.startswith(("/tmp/", "/var/run/", "/etc/", "/usr/", "/sbin/", "/bin/")):
        return True
    if ref.endswith(".so") and "/" not in ref:
        return False
    if ref.startswith(("network", "glmodem", "firewall", "kmwan")):
        return True
    if any(token in ref for token in (".", "%", " ")):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\(\.\.\.\))?", ref):
        return False
    return False


def note_shape_for_ref(line: str, ref: str) -> tuple[str, str, str, str]:
    role = line_semantic_role(line, ref)
    if role == "replay":
        return ("replay_boundary", "reads_replay_state", "temporary_state_object", "replay-state candidate from markdown")
    if role == "restart":
        return ("restart_relationship", "triggers_restart", "activation_endpoint", "restart/reload candidate from markdown")
    if role == "activation":
        return ("reconnect_relationship", "triggers_reconnect", "activation_endpoint", "activation/reconnect candidate from markdown")
    if role == "projection":
        return ("xref_confirmed_edge", "projects_downstream", "downstream_mutation_endpoint", "downstream projection candidate from markdown")
    if role == "staging":
        return ("persistence_boundary", "writes_stage_state", "staging_boundary", "staging-boundary candidate from markdown")
    if role == "persistence":
        return ("persistence_boundary", "writes_stage_state", "persistence_object" if ref.startswith("/etc/") else "staging_boundary", "persistence-boundary candidate from markdown")
    if role == "helper":
        return ("helper_relationship", "invokes_helper", "semantic_helper", "helper relationship from helper path mention")
    return ("persistence_boundary", "writes_stage_state", "staging_boundary", "ambiguous config-like candidate from markdown")


def evidence_from_line(line: str) -> str:
    lower = line.lower()
    if "function-level" in lower or "decompile" in lower or "decompiled" in lower or "confirmed" in lower:
        return "E1_function_level_confirmed"
    if "xref" in lower:
        return "E2_xref_confirmed"
    if any(word in lower for word in LIKELY_WORDS):
        return "E3_converging_static_evidence"
    return "E3_converging_static_evidence"


def ordering_from_line(line: str) -> str:
    lower = line.lower()
    if "before" in lower or "after" in lower or "followed by" in lower:
        return "ordered"
    return "partially_ordered" if "xref" in lower else "unordered"


def add_note(notes: list[dict[str, Any]], seen: set[str], note: dict[str, Any]) -> None:
    category = str(note.get("category", "")).strip()
    target = note.get("target")
    if isinstance(target, str) and target.strip():
        normalized = normalize_note_target(category, target.strip())
        note = dict(note)
        note["target"] = normalized.normalized
        if normalized.normalization_reason:
            note["original_target"] = normalized.original
            note["normalization_reason"] = normalized.normalization_reason
    key = json.dumps(note, sort_keys=True)
    if key in seen:
        return
    seen.add(key)
    notes.append(note)


def draft_from_markdown(text: str, target_id: str) -> dict[str, Any]:
    notes: list[dict[str, Any]] = []
    seen: set[str] = set()
    warnings: list[str] = []

    lines = text.splitlines()
    current_section = ""
    current_list_target = ""

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            current_list_target = ""
            continue

        lower = line.lower()
        if line.startswith("#"):
            current_section = line.lstrip("#").strip().lower()
            continue

        if any(word in lower for word in UNRESOLVED_WORDS):
            warnings.append(f"unresolved wording at line {idx + 1}: {line}")
            continue

        if line.startswith("- ") and "xrefs from" in lower:
            refs = BACKTICK_RE.findall(line)
            if refs:
                current_list_target = refs[0]
            continue

        if current_list_target and line.startswith("- "):
            refs = BACKTICK_RE.findall(line)
            for source in refs:
                edge_type = infer_edge_type(current_list_target, current_list_target)
                note_category = "xref_confirmed_edge"
                if edge_type == "invokes_helper":
                    note_category = "helper_relationship"
                elif edge_type == "triggers_restart":
                    note_category = "restart_relationship"
                elif edge_type == "triggers_reconnect":
                    note_category = "reconnect_relationship"
                add_note(
                    notes,
                    seen,
                    {
                        "category": note_category,
                        "source": source,
                        "source_type": infer_source_type(source),
                        "target": current_list_target,
                        "target_type": infer_target_type(current_list_target, edge_type),
                        "edge_type": edge_type,
                        "ordering": "partially_ordered",
                        "evidence_class": "E2_xref_confirmed",
                        "summary": f"Drafted from xref list in markdown: {source} -> {current_list_target}",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            continue

        if "management-driven through" in lower:
            refs = BACKTICK_RE.findall(line)
            if not refs and idx + 1 < len(lines):
                refs = BACKTICK_RE.findall(lines[idx + 1])
            for fn in refs:
                add_note(
                    notes,
                    seen,
                    {
                        "category": "function_role",
                        "function": fn,
                        "node_type": "entry_handler",
                        "evidence_class": "E1_function_level_confirmed",
                        "summary": "Drafted entry-handler role from management-driven wording",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            continue

        if "strongest recovered persistence function" in lower:
            refs = BACKTICK_RE.findall(line)
            if not refs and idx + 1 < len(lines):
                refs = BACKTICK_RE.findall(lines[idx + 1])
            for fn in refs:
                add_note(
                    notes,
                    seen,
                    {
                        "category": "function_role",
                        "function": fn,
                        "node_type": "native_coordinator",
                        "evidence_class": "E1_function_level_confirmed",
                        "summary": "Drafted persistence-oriented coordinator role",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            continue

        if "management-facing setters" in lower or "management-facing getters" in lower or "embedded orchestration or staging helpers" in lower:
            continue

        if current_section in {"management-facing setters", "management-facing getters"} and line.startswith("- "):
            refs = BACKTICK_RE.findall(line)
            for fn in refs:
                add_note(
                    notes,
                    seen,
                    {
                        "category": "function_role",
                        "function": fn,
                        "node_type": "entry_handler",
                        "evidence_class": "E1_function_level_confirmed" if "confirmed" in text.lower() else "E3_converging_static_evidence",
                        "summary": f"Drafted entry-handler role from {current_section}",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            continue

        if current_section == "embedded orchestration or staging helpers inside the same module" and line.startswith("- "):
            refs = BACKTICK_RE.findall(line)
            for fn in refs:
                node_type = "activation_endpoint" if ("dial" in fn.lower() or "conn" in fn.lower()) else "native_coordinator"
                add_note(
                    notes,
                    seen,
                    {
                        "category": "function_role",
                        "function": fn,
                        "node_type": node_type,
                        "evidence_class": "E1_function_level_confirmed",
                        "summary": "Drafted internal orchestration helper role from markdown section",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            continue

        for src, dst in ARROW_RE.findall(line):
            edge_type = infer_edge_type(dst, line)
            category = "xref_confirmed_edge" if "xref" in lower else "ordering_hint" if ("before" in lower or "after" in lower) else "xref_confirmed_edge"
            add_note(
                notes,
                seen,
                {
                    "category": category,
                    "source": src,
                    "source_type": infer_source_type(src),
                    "target": dst,
                    "target_type": infer_target_type(dst, edge_type),
                    "edge_type": edge_type,
                    "ordering": ordering_from_line(line),
                    "evidence_class": evidence_from_line(line),
                    "summary": f"Drafted from markdown arrow: {src} -> {dst}",
                    "source_ref": f"{target_id}:{idx + 1}",
                },
            )

        m = XREF_FROM_RE.search(line)
        if m:
            target, source = m.group(1), m.group(2)
            edge_type = infer_edge_type(target, line)
            category = "xref_confirmed_edge"
            if edge_type == "invokes_helper":
                category = "helper_relationship"
            elif edge_type == "triggers_restart":
                category = "restart_relationship"
            elif edge_type == "triggers_reconnect":
                category = "reconnect_relationship"
            add_note(
                notes,
                seen,
                {
                    "category": category,
                    "source": source,
                    "source_type": infer_source_type(source),
                    "target": target,
                    "target_type": infer_target_type(target, edge_type),
                    "edge_type": edge_type,
                    "ordering": "partially_ordered",
                    "evidence_class": "E2_xref_confirmed" if "xref" in lower else evidence_from_line(line),
                    "summary": f"Drafted from xref wording: {source} -> {target}",
                    "source_ref": f"{target_id}:{idx + 1}",
                },
            )

        if line.startswith("- "):
            refs = BACKTICK_RE.findall(line)
            if current_section == "decompiled methods":
                for fn in refs:
                    add_note(
                        notes,
                        seen,
                        {
                            "category": "function_role",
                            "function": fn,
                            "node_type": "native_coordinator",
                            "evidence_class": evidence_from_line(line),
                            "summary": "Drafted from decompiled methods section",
                            "source_ref": f"{target_id}:{idx + 1}",
                        },
                    )

        refs = BACKTICK_RE.findall(line)
        for ref in refs:
            ref_lower = ref.lower()
            role = line_semantic_role(line, ref)
            if role == "generic" and ("sync" in lower or "update" in lower or "start dial" in lower):
                warnings.append(f"ambiguous staging/projection wording at line {idx + 1}: {line}")
            if role in {"projection", "staging", "persistence"} and not is_state_like_target(ref):
                continue
            if role == "replay":
                add_note(
                    notes,
                    seen,
                    {
                        "category": "replay_boundary",
                        "source": slugify_label(current_section) or "markdown_context",
                        "source_type": "native_coordinator",
                        "target": ref,
                        "target_type": "temporary_state_object",
                        "edge_type": "reads_replay_state",
                        "ordering": "unordered",
                        "evidence_class": evidence_from_line(line),
                        "summary": "Drafted replay-boundary candidate from markdown path mention",
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            elif role in {"projection", "staging", "persistence"}:
                category, edge_type, target_type, summary = note_shape_for_ref(line, ref)
                add_note(
                    notes,
                    seen,
                    {
                        "category": category,
                        "source": slugify_label(current_section) or "markdown_context",
                        "source_type": "native_coordinator",
                        "target": ref,
                        "target_type": target_type,
                        "edge_type": edge_type,
                        "ordering": "unordered",
                        "evidence_class": evidence_from_line(line),
                        "summary": summary,
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )
            elif role in {"helper", "activation"}:
                source = ""
                if "from" in lower:
                    m2 = FROM_SOURCE_RE.search(line)
                    if m2:
                        source = m2.group(1)
                if not source and "set_slot_config" in text:
                    source = "set_slot_config"
                category, edge_type, target_type, summary = note_shape_for_ref(line, ref)
                add_note(
                    notes,
                    seen,
                    {
                        "category": category,
                        "source": source or "markdown_context",
                        "source_type": infer_source_type(source or "markdown_context"),
                        "target": ref,
                        "target_type": target_type,
                        "edge_type": edge_type,
                        "ordering": "unordered",
                        "evidence_class": evidence_from_line(line),
                        "summary": summary,
                        "source_ref": f"{target_id}:{idx + 1}",
                    },
                )

    return {
        "schema_version": "0.1",
        "target_id": target_id,
        "prune_context_only_noise": False,
        "notes": notes,
        "warnings": unique_ordered(warnings),
        "unsupported_assumptions": [
            "draft notes are not ground truth",
            "no exploitability inference",
            "no exact runtime reconstruction",
            "no automatic semantic recurrence decision",
        ],
    }


def unique_ordered(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.is_file():
        raise SystemExit(f"input not found: {input_path}")
    text = input_path.read_text(encoding="utf-8", errors="ignore")
    drafted = draft_from_markdown(text, args.target_id)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    out_path.write_text(json.dumps(drafted, indent=indent, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
