"""
Evidence-grounded LLM triage packet builder and task generator.

This module does not perform exploit generation or deterministic finding
discovery. It consumes existing analysis outputs and emits normalized packets
plus task-specific reasoning jobs for future LLM backends.

Examples:
  python3 src/review/llm_triage.py --target-id MR90X --print
  python3 src/review/llm_triage.py --target-id AX72 --backend heuristic --print
  python3 src/review/llm_triage.py \
      --target-id MR90X \
      --output research/review/llm_triage/mr90x_triage_bundle.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


SRC_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_ROOT.parent
DEFAULT_ANALYSIS_ROOT = PROJECT_ROOT / "research" / "regeneration" / "full_corpus_20260508"
SCHEMA_VERSION = "1.0"


TASK_TYPES = (
    "severity-ranking",
    "false-positive-detection",
    "runtime-priority",
    "family-significance",
    "next-reverse-target",
)


COMPONENT_ROLE_MAP = {
    "client_mgmt": "downstream-mutation-sink",
    "meshd": "orchestration-hub",
    "sync_server": "synchronization-broker",
    "tmp_stack": "transport-and-marshaling-stack",
    "helper_layer": "helper-semantic-parser",
    "runtime": "runtime-validation-context",
    "h2": "provenance-case-study",
    "overview": "target-overview",
}

REACHABLE_SURFACE_MAP = {
    "client_mgmt": "ubus-local",
    "meshd": "localhost-ipc",
    "sync_server": "ubus-local",
    "tmp_stack": "transport-parser",
    "helper_layer": "helper-internal",
    "runtime": "unknown",
    "h2": "unknown",
    "overview": "unknown",
}

TRUST_CLASS_MAP = {
    "client_mgmt": "normalized-mutation-sink",
    "meshd": "orchestration-amplifier",
    "sync_server": "native-textual-staging",
    "tmp_stack": "transport-parser",
    "helper_layer": "helper-semantic-parser",
    "runtime": "cross-component-provenance",
    "h2": "cross-component-provenance",
    "overview": "unknown",
}

PROVENANCE_DEPTH_MAP = {
    "client_mgmt": "sink",
    "meshd": "orchestration",
    "sync_server": "native-staging",
    "tmp_stack": "transport-only",
    "helper_layer": "semantic-parse",
    "runtime": "cross-layer",
    "h2": "cross-layer",
    "overview": "cross-layer",
}


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str | Path, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _safe_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except Exception:
        return str(path)


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "target"


def _default_target_dir(analysis_root: Path, target_id: str) -> Path:
    direct = analysis_root / "models" / target_id
    if direct.is_dir():
        return direct
    normalized = {
        "MR90X": analysis_root / "models" / "MR90X",
        "AX72": analysis_root / "models" / "AX72",
        "X6000R": analysis_root / "models" / "X6000R",
    }
    return normalized.get(target_id, direct)


def _family_context_paths(analysis_root: Path, family: str) -> List[Path]:
    paths: List[Path] = []
    if family.lower() == "onemesh":
        paths.extend(sorted((analysis_root / "families" / "OneMesh").glob("*")))
        recurrence = analysis_root / "corpus_wide" / "recurrence"
        for name in (
            "onemesh_orchestration_recurrence.md",
            "helper_parsing_recurrence_matrix.md",
            "shell_mediated_ubus_recurrence.md",
            "textual_identity_propagation_patterns.md",
            "distributed_trust_boundary_patterns.md",
            "recurring_orchestration_anti_patterns.md",
            "strongest_cross_firmware_findings.md",
            "trust_collapse_prevalence_report.md",
        ):
            p = recurrence / name
            if p.exists():
                paths.append(p)
    return paths


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _content_signals(text: str) -> dict:
    lower = text.lower()
    return {
        "mentions_binary_confirmed": "binary-confirmed" in lower or "confirmed:" in lower,
        "mentions_inferred": "inferred:" in lower,
        "mentions_runtime_unknown": "runtime-only unknown" in lower or "runtime-only unknowns" in lower,
        "mentions_exact_reuse": "byte-identical" in lower or "exact helper reuse" in lower or "identical sha256" in lower,
        "mentions_semantic_recurrence": "semantic recurrence" in lower or "architectural recurrence" in lower or "recurrence" in lower,
        "mentions_auth": "auth" in lower,
        "mentions_framework_auth": "framework-inherited" in lower,
        "mentions_strict_validation": "strict normalization" in lower or "strict mac validation" in lower or "validation" in lower,
        "mentions_shell": "shell" in lower or "popen" in lower or "system(" in lower or "shell-mediated" in lower,
        "mentions_ubus": "ubus" in lower,
        "mentions_uci": "uci" in lower,
        "mentions_json_decode": "json.decode(data)" in lower or "json decode" in lower,
        "mentions_shared_memory": "shared-memory" in lower or "shared memory" in lower,
        "mentions_runtime_plan": "runtime validation" in lower or "runtime observation" in lower,
        "mentions_helper": "helper" in lower,
    }


@dataclass
class EvidenceReference:
    path: str
    kind: str
    summary: str
    locator: str = ""

    def to_dict(self) -> dict:
        payload = {
            "path": self.path,
            "kind": self.kind,
            "summary": self.summary,
        }
        if self.locator:
            payload["locator"] = self.locator
        return payload


class FindingBuilder:
    def __init__(self, target_id: str, firmware_family: str, source_dir: Path):
        self.target_id = target_id
        self.firmware_family = firmware_family
        self.source_dir = source_dir

    def build(self) -> List[dict]:
        findings: List[dict] = []
        for component_dir in sorted(p for p in self.source_dir.iterdir() if p.is_dir()):
            refs = sorted(
                p for p in component_dir.rglob("*") if p.is_file() and p.suffix in {".md", ".json"}
            )
            if not refs:
                continue
            findings.append(self._build_component_finding(component_dir, refs))
        return findings

    def _build_component_finding(self, component_dir: Path, refs: List[Path]) -> dict:
        component_name = component_dir.name
        component_role = COMPONENT_ROLE_MAP.get(component_name, "analysis-component")
        reachable_surface = REACHABLE_SURFACE_MAP.get(component_name, "unknown")
        trust_boundary_class = TRUST_CLASS_MAP.get(component_name, "unknown")
        provenance_depth = PROVENANCE_DEPTH_MAP.get(component_name, "cross-layer")

        sink_evidence: set[str] = set()
        auth_evidence = "unclear"
        recurrence_level = "none"
        recurrence_kind: set[str] = set()
        runtime_required = False
        confidence = "medium"
        notes: List[str] = []
        evidence_refs: List[EvidenceReference] = []

        high_signals = 0
        low_signals = 0

        for ref in refs:
            text = _read_text(ref)
            signals = _content_signals(text)
            summary_parts = [component_name]
            if signals["mentions_shell"]:
                sink_evidence.add("shell-exec")
                summary_parts.append("shell evidence")
            if signals["mentions_ubus"]:
                sink_evidence.add("ubus-fanout")
                summary_parts.append("ubus evidence")
            if signals["mentions_uci"]:
                sink_evidence.add("uci-persistence")
                summary_parts.append("uci evidence")
            if signals["mentions_shared_memory"]:
                sink_evidence.add("shared-memory-update")
                summary_parts.append("shared-memory evidence")
            if signals["mentions_json_decode"]:
                sink_evidence.add("json-decode")
                summary_parts.append("json semantic parse")
            if signals["mentions_helper"]:
                sink_evidence.add("helper-launch")
            if "file" in ref.name.lower() or "state" in ref.name.lower():
                sink_evidence.add("file-state-write")

            if signals["mentions_framework_auth"]:
                auth_evidence = "framework-inherited-auth"
            elif signals["mentions_strict_validation"] and auth_evidence == "unclear":
                auth_evidence = "strict-sink-validation"
            elif signals["mentions_auth"] and auth_evidence == "unclear":
                auth_evidence = "no-local-auth-evidence"

            if signals["mentions_exact_reuse"]:
                recurrence_level = "exact"
                recurrence_kind.update({"helper-reuse", "binary-reuse"})
            elif signals["mentions_semantic_recurrence"] and recurrence_level != "exact":
                recurrence_level = "semantic"
                recurrence_kind.add("architectural-recurrence")

            if signals["mentions_runtime_unknown"] or signals["mentions_runtime_plan"]:
                runtime_required = True

            if signals["mentions_binary_confirmed"]:
                high_signals += 1
            if signals["mentions_inferred"] or signals["mentions_runtime_unknown"]:
                low_signals += 1

            evidence_refs.append(
                EvidenceReference(
                    path=_safe_rel(ref),
                    kind="analysis-note" if ref.suffix == ".md" else "analysis-data",
                    summary=", ".join(summary_parts) if len(summary_parts) > 1 else f"{component_name} evidence",
                )
            )

        if high_signals >= 2:
            confidence = "high"
        elif low_signals > high_signals:
            confidence = "low"

        if component_name in {"meshd", "sync_server", "helper_layer"}:
            recurrence_kind.add("trust-boundary-recurrence")
        if component_name == "tmp_stack":
            recurrence_kind.add("architectural-recurrence")

        if component_name == "overview":
            notes.append("Overview findings should be used as context and not over-weighted against component-grounded files.")
        if component_name == "runtime":
            notes.append("Runtime notes identify uncertainty reduction opportunities rather than direct sink effects.")

        return {
            "finding_id": f"{_slugify(self.target_id)}-{_slugify(component_name)}",
            "target_id": self.target_id,
            "firmware_family": self.firmware_family,
            "component_name": component_name,
            "component_role": component_role,
            "reachable_surface": reachable_surface,
            "auth_evidence": auth_evidence,
            "sink_evidence": sorted(sink_evidence),
            "trust_boundary_class": trust_boundary_class,
            "orchestration_involvement": component_name in {"meshd", "sync_server", "helper_layer", "h2", "overview"},
            "helper_involvement": component_name in {"helper_layer", "sync_server", "runtime"},
            "recurrence_level": recurrence_level,
            "recurrence_kind": sorted(recurrence_kind) or ["none"],
            "provenance_depth": provenance_depth,
            "runtime_required": runtime_required,
            "confidence": confidence,
            "analyst_notes": notes,
            "evidence_references": [ref.to_dict() for ref in evidence_refs],
        }


def build_packet(
    target_id: str,
    source_dir: Path,
    analysis_root: Path,
    firmware_family: str,
) -> dict:
    builder = FindingBuilder(target_id=target_id, firmware_family=firmware_family, source_dir=source_dir)
    findings = builder.build()
    recurrence_context = [
        {
            "path": _safe_rel(path),
            "kind": "family-context",
            "summary": path.stem.replace("_", " "),
        }
        for path in _family_context_paths(analysis_root, firmware_family)
        if path.is_file()
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "target": {
            "target_id": target_id,
            "firmware_family": firmware_family,
            "source_dir": _safe_rel(source_dir),
            "notes": [
                "Evidence-grounded triage packet. Use cited references instead of unsupported reachability assumptions."
            ],
        },
        "context": {
            "analysis_mode": "evidence-grounded-triage",
            "scope": "security-orchestration-analysis",
            "component_count": len(findings),
            "evidence_file_count": sum(len(f["evidence_references"]) for f in findings),
        },
        "findings": findings,
        "global_recurrence_context": recurrence_context,
    }


def build_reasoning_tasks(packet: dict, task_types: Iterable[str]) -> List[dict]:
    tasks = []
    for task_type in task_types:
        tasks.append(
            {
                "task_type": task_type,
                "schema_version": SCHEMA_VERSION,
                "target_id": packet["target"]["target_id"],
                "prompt_template_id": task_type,
                "packet": packet,
            }
        )
    return tasks


class TriageBackend:
    name = "base"

    def run(self, packet: dict, tasks: List[dict]) -> List[dict]:
        raise NotImplementedError


class EmitOnlyBackend(TriageBackend):
    name = "emit-only"

    def run(self, packet: dict, tasks: List[dict]) -> List[dict]:
        return tasks


class HeuristicBackend(TriageBackend):
    name = "heuristic"

    ACTION_ORDER = {
        "deep-reverse": 0,
        "runtime-validate": 1,
        "track-for-family-study": 2,
        "defer": 3,
        "likely-false-positive": 4,
    }

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
        "unclear": 5,
    }

    HIGH_VALUE_BOUNDARIES = {
        "helper-semantic-parser",
        "native-textual-staging",
        "orchestration-amplifier",
        "normalized-mutation-sink",
    }

    def _label_from_score(self, score: int) -> str:
        if score >= 85:
            return "high"
        if score >= 55:
            return "medium"
        return "low"

    def _severity_from_security(self, score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 50:
            return "medium"
        if score >= 30:
            return "low"
        return "informational"

    def _family_significance_label(self, score: int) -> str:
        if score >= 85:
            return "architecture-level"
        if score >= 70:
            return "exact-recurrence"
        if score >= 45:
            return "semantic-recurrence"
        return "isolated"

    def _clamp(self, value: int) -> int:
        return max(0, min(100, value))

    def _score_finding(self, finding: dict) -> dict:
        sink_evidence = set(finding.get("sink_evidence") or [])
        recurrence_level = finding.get("recurrence_level") or "none"
        recurrence_kind = set(finding.get("recurrence_kind") or [])
        trust_class = finding.get("trust_boundary_class") or "unknown"
        component_name = finding.get("component_name") or "unknown"
        confidence_label = finding.get("confidence") or "medium"
        runtime_required = bool(finding.get("runtime_required"))
        auth_evidence = finding.get("auth_evidence") or "unclear"

        security = 20
        family = 10
        runtime = 0
        false_positive = 35
        calibration_notes: List[str] = []

        if "shell-exec" in sink_evidence:
            security += 25
            runtime += 10
            false_positive -= 12
            calibration_notes.append("Shell-adjacent behavior receives a stronger direct priority boost.")
        if "ubus-fanout" in sink_evidence:
            security += 15
            false_positive -= 5
        if "uci-persistence" in sink_evidence:
            security += 14
            false_positive -= 6
        if "shared-memory-update" in sink_evidence:
            security += 10
            runtime += 6
            false_positive -= 4
        if "json-decode" in sink_evidence:
            security += 6
            runtime += 10
        if "helper-launch" in sink_evidence:
            security += 4
            runtime += 4

        if trust_class == "normalized-mutation-sink":
            security += 16
        elif trust_class == "orchestration-amplifier":
            security += 18
            family += 12
        elif trust_class == "native-textual-staging":
            security += 14
            runtime += 18
            family += 10
        elif trust_class == "helper-semantic-parser":
            security += 10
            runtime += 18
            family += 16
        elif trust_class == "transport-parser":
            security -= 14
            runtime -= 10
            false_positive += 12
            calibration_notes.append("Transport-parser-only findings get lower direct deep-dive priority.")
        elif trust_class == "unknown":
            security -= 8
            false_positive += 10

        if component_name == "overview":
            security -= 30
            runtime -= 20
            false_positive += 35
            calibration_notes.append("Overview/context-only findings are heavily penalized.")
        if component_name == "runtime":
            security -= 12
            family += 4
            false_positive += 6
        if component_name == "h2":
            family += 8
            runtime += 8

        if recurrence_level == "exact":
            family += 40
            security += 5
            false_positive += 2
            calibration_notes.append("Exact reuse remains strong family evidence but gets only a moderate security boost.")
        elif recurrence_level == "semantic":
            family += 22
            security += 3
        elif recurrence_level == "weak-string":
            family += 10
            security += 1
            false_positive += 8

        if "trust-boundary-recurrence" in recurrence_kind:
            family += 10
        if "helper-reuse" in recurrence_kind:
            family += 12
            if component_name == "helper_layer" and not runtime_required and "shell-exec" not in sink_evidence:
                security -= 6
                false_positive += 8
                calibration_notes.append("Exact helper reuse is downweighted as direct security priority when it mostly indicates family recurrence.")
        if "architectural-recurrence" in recurrence_kind:
            family += 8

        if runtime_required and trust_class in self.HIGH_VALUE_BOUNDARIES:
            runtime += 28
            security += 10
            false_positive -= 6
            calibration_notes.append("Runtime-required high-value trust boundaries are boosted.")
        elif runtime_required:
            runtime += 14

        if auth_evidence == "strict-sink-validation":
            security -= 4
            false_positive -= 3
        elif auth_evidence == "framework-inherited-auth":
            security += 3
            runtime += 6
        elif auth_evidence == "no-local-auth-evidence":
            security += 4

        if confidence_label == "high":
            security += 6
            family += 4
            false_positive -= 10
        elif confidence_label == "low":
            security -= 8
            false_positive += 12

        refs = finding.get("evidence_references") or []
        if len(refs) <= 1:
            false_positive += 6
        else:
            false_positive -= 4

        # Strengthen the specific helper -> sync-server and sync-server -> meshd boundary classes
        if component_name == "sync_server":
            security += 8
            runtime += 8
            calibration_notes.append("Synchronization broker gets extra weight as the helper-to-native staging boundary.")
        if component_name == "meshd" and "shell-exec" in sink_evidence:
            security += 8
            runtime += 5
            calibration_notes.append("Shell-mediated orchestration hubs receive stronger priority.")

        security = self._clamp(security)
        family = self._clamp(family)
        runtime = self._clamp(runtime)
        false_positive = self._clamp(false_positive)

        severity = self._severity_from_security(security)

        if component_name == "overview":
            action = "defer"
        elif false_positive >= 70 and family < 60:
            action = "likely-false-positive"
        elif runtime >= 65:
            action = "runtime-validate"
        elif security >= 65:
            action = "deep-reverse"
        elif family >= 65:
            action = "track-for-family-study"
        elif security >= 40:
            action = "deep-reverse"
        else:
            action = "defer"

        # Duplicate-like recurrence copies: keep family significance, lower direct action.
        if component_name in {"helper_layer", "tmp_stack"} and family >= 60 and security < 60 and not runtime_required:
            action = "track-for-family-study"
            false_positive = self._clamp(false_positive + 10)
            calibration_notes.append("Lower direct priority for near-duplicate recurrence copies.")

        return {
            "finding_id": finding["finding_id"],
            "component_name": component_name,
            "component_role": finding["component_role"],
            "trust_boundary_class": trust_class,
            "priority": "high" if action in {"deep-reverse", "runtime-validate"} else "medium" if action == "track-for-family-study" else "low",
            "recommended_action": action,
            "severity_candidate": severity,
            "security_priority_score": security,
            "family_significance_score": family,
            "runtime_value_score": runtime,
            "false_positive_risk_score": false_positive,
            "confidence": {
                "label": self._label_from_score(100 - false_positive if security >= 40 else 50),
                "score": self._clamp(50 + security // 4 + family // 8 + runtime // 8 - false_positive // 5),
            },
            "family_significance": self._family_significance_label(family),
            "likely_false_positive": false_positive >= 70 and action != "track-for-family-study",
            "runtime_validation_priority": "high" if runtime >= 70 else "medium" if runtime >= 45 else "low" if runtime > 0 else "not-needed-yet",
            "scoring_rationale": (
                f"security={security}, family={family}, runtime={runtime}, false_positive={false_positive}; "
                f"trust={trust_class}, recurrence={recurrence_level}, sinks={sorted(sink_evidence)}"
            ),
            "calibration_notes": calibration_notes,
            "evidence_used": [ref["path"] for ref in refs[:3]],
        }

    def _pick_reverse_target(self, assessments: List[dict]) -> dict:
        ranked = sorted(
            assessments,
            key=lambda row: (
                self.ACTION_ORDER.get(row["recommended_action"], 9),
                -row["runtime_value_score"],
                -row["security_priority_score"],
                -row["family_significance_score"],
            ),
        )
        chosen = ranked[0]
        reasons = {
            "helper_layer": "Helper semantic parsing is the first meaning-changing layer and often collapses schema ambiguity fastest.",
            "sync_server": "Synchronization brokers are high-value helper-to-native staging boundaries.",
            "meshd": "The orchestration hub best exposes shell-mediated fan-out and cross-component trust propagation.",
            "client_mgmt": "The downstream sink best validates whether upstream findings reach privileged mutation.",
            "tmp_stack": "The transport stack is useful only after higher-level orchestration uncertainty is reduced.",
            "overview": "Overview is context-only and should not normally be the first reverse target.",
        }
        return {
            "component_name": chosen["component_name"],
            "reason": reasons.get(chosen["component_name"], "Chosen by calibrated heuristic ranking."),
        }

    def run(self, packet: dict, tasks: List[dict]) -> List[dict]:
        findings = packet.get("findings") or []
        assessments = [self._score_finding(finding) for finding in findings]
        reverse_target = self._pick_reverse_target(assessments)
        results = []
        for task in tasks:
            if task["task_type"] == "severity-ranking":
                chosen = max(
                    assessments,
                    key=lambda row: (row["security_priority_score"], -row["false_positive_risk_score"]),
                )
            elif task["task_type"] == "false-positive-detection":
                chosen = max(assessments, key=lambda row: row["false_positive_risk_score"])
            elif task["task_type"] == "runtime-priority":
                chosen = max(assessments, key=lambda row: row["runtime_value_score"])
            elif task["task_type"] == "family-significance":
                chosen = max(assessments, key=lambda row: row["family_significance_score"])
            else:
                chosen = max(
                    assessments,
                    key=lambda row: (
                        self.ACTION_ORDER.get(row["recommended_action"], 9) * -1,
                        row["runtime_value_score"],
                        row["security_priority_score"],
                    ),
                )
            results.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "task_type": task["task_type"],
                    "priority": chosen["priority"],
                    "severity_candidate": chosen["severity_candidate"],
                    "analyst_action": chosen["recommended_action"],
                    "recommended_action": chosen["recommended_action"],
                    "family_significance": chosen["family_significance"],
                    "likely_false_positive": chosen["likely_false_positive"],
                    "runtime_validation_priority": chosen["runtime_validation_priority"],
                    "next_reverse_target": reverse_target,
                    "evidence_used": chosen["evidence_used"],
                    "confidence": chosen["confidence"],
                    "security_priority_score": chosen["security_priority_score"],
                    "family_significance_score": chosen["family_significance_score"],
                    "runtime_value_score": chosen["runtime_value_score"],
                    "false_positive_risk_score": chosen["false_positive_risk_score"],
                    "scoring_rationale": chosen["scoring_rationale"],
                    "calibration_notes": chosen["calibration_notes"],
                    "assumptions": [
                        "Heuristic mode uses only packet metadata and evidence labels.",
                        "Recurrence contributes much more to family significance than to direct security priority.",
                        "No runtime reachability is assumed unless already encoded in the packet.",
                    ],
                    "unresolved_gaps": [
                        "Runtime validation remains necessary where the packet marks runtime_required.",
                        "Exact exploitability is not determined by this triage layer."
                    ],
                    "rationale": chosen["scoring_rationale"],
                    "top_finding_id": chosen["finding_id"],
                    "finding_assessments": assessments,
                }
            )
        return results


BACKENDS = {
    EmitOnlyBackend.name: EmitOnlyBackend,
    HeuristicBackend.name: HeuristicBackend,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build evidence-grounded LLM triage packets and tasks.")
    parser.add_argument("--analysis-root", default=str(DEFAULT_ANALYSIS_ROOT))
    parser.add_argument("--target-id", required=True, help="Model/target identifier such as MR90X or AX72")
    parser.add_argument("--source-dir", help="Override source analysis directory")
    parser.add_argument("--family", default="OneMesh")
    parser.add_argument("--task", choices=("all",) + TASK_TYPES, default="all")
    parser.add_argument("--backend", choices=tuple(BACKENDS), default="emit-only")
    parser.add_argument("--output", help="Write JSON bundle to this path")
    parser.add_argument("--print", action="store_true", dest="print_payload")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analysis_root = Path(args.analysis_root).resolve()
    source_dir = Path(args.source_dir).resolve() if args.source_dir else _default_target_dir(analysis_root, args.target_id).resolve()
    if not source_dir.is_dir():
        raise SystemExit(f"source analysis directory not found: {source_dir}")

    packet = build_packet(
        target_id=args.target_id,
        source_dir=source_dir,
        analysis_root=analysis_root,
        firmware_family=args.family,
    )
    task_types = list(TASK_TYPES) if args.task == "all" else [args.task]
    tasks = build_reasoning_tasks(packet, task_types)
    backend = BACKENDS[args.backend]()
    results = backend.run(packet, tasks)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "backend": args.backend,
        "packet": packet,
        "tasks": tasks,
        "results": results,
    }

    if args.output:
        write_json(args.output, payload)
    if args.print_payload or not args.output:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
