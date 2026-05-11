#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"

REPORTS = {
    "inventory": "broad_candidate_inventory.md",
    "ranking": "cve_candidate_ranking.md",
    "reachability": "candidate_reachability_matrix.md",
    "sinks": "sensitive_sink_catalog.md",
    "secrets": "hardcoded_secret_catalog.md",
    "ubus_lua": "ubus_lua_auth_gap_candidates.md",
    "cmd": "command_execution_candidates.md",
    "upgrade": "firmware_update_candidates.md",
    "queue": "next_deep_dive_queue.md",
}

SEMANTIC_RESULTS = "semantic_graph_results.json"


@dataclass
class Candidate:
    candidate_id: str
    kind: str
    vendor: str
    model: str
    version: str
    corpus_id: str
    architecture_family: str
    component: str
    file_path: str
    component_role: str
    reachable_surface: str
    suspected_input_source: str
    dangerous_sink: str
    auth_evidence: str
    persistence_evidence: str
    recurrence_key: str
    recurrence_count: int = 1
    confidence: str = "Medium"
    cve_potential: str = "Low"
    why_it_matters: str = ""
    source: str = ""
    extra: dict | None = None


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def iter_results(workspace: Path):
    yield from sorted((workspace / "runs").rglob("results.json"))


def role_from_path(path: str) -> str:
    lowered = path.lower()
    if "/usr/lib/lua/" in lowered:
        return "Lua controller"
    if any(token in lowered for token in ["/rpc/", "modem.so", "tor", "wg_client", "b2r"]):
        return "HTTP RPC helper"
    if any(token in lowered for token in ["httpd", "boa", "lighttpd", "uhttpd", "cgi"]):
        return "Web management handler"
    if any(token in lowered for token in ["tmpsvr", "tdpserver", "cloud-pfclient", "cloud-brd", "tmp-luci"]):
        return "Cloud/relay management component"
    if any(token in lowered for token in ["meshd", "sync-server", "easymesh", "ieee1905"]):
        return "Mesh/sync orchestration component"
    if any(token in lowered for token in ["sysupgrade", "upgraded", "common.sh", "tmpcli", "one_click_upgrade"]):
        return "Firmware update component"
    return "Management component"


def reachable_surface(candidate: dict) -> str:
    if candidate.get("web_reachable"):
        return "HTTP/LAN"
    if candidate.get("web_exposed"):
        return "HTTP-or-web-adjacent"
    attack = candidate.get("attack_surface") or {}
    sockets = attack.get("sockets") or []
    ipc = attack.get("ipc") or []
    endpoints = candidate.get("endpoints") or []
    if endpoints:
        return "HTTP/API endpoint"
    if any("port:" in str(x) for x in sockets):
        return "socket/LAN"
    if ipc:
        return "IPC/local control plane"
    return "local-or-unclear"


def input_source(candidate: dict) -> str:
    endpoint = candidate.get("endpoint_input")
    if endpoint and endpoint != "unconfirmed":
        return str(endpoint)
    if candidate.get("input_type"):
        return str(candidate.get("input_type"))
    if candidate.get("confirmed_input") and candidate.get("confirmed_input") != "unconfirmed":
        return str(candidate.get("confirmed_input"))
    return "unconfirmed"


def sink_summary(candidate: dict) -> str:
    sinks = candidate.get("all_sinks") or []
    if sinks:
        return ", ".join(str(x) for x in sinks[:3])
    return str(candidate.get("confirmed_sink") or candidate.get("sink") or "unknown")


def auth_summary(candidate: dict) -> str:
    bits = []
    if candidate.get("auth_boundary"):
        bits.append(str(candidate["auth_boundary"]))
    if candidate.get("auth_bypass"):
        bits.append(f"auth_bypass={candidate['auth_bypass']}")
    if candidate.get("missing_links"):
        bits.append("missing:" + ",".join(candidate["missing_links"][:2]))
    return "; ".join(bits) or "unknown"


def persistence_summary(candidate: dict) -> str:
    config = candidate.get("config_keys") or []
    if config:
        return "config keys: " + ", ".join(str(x) for x in config[:3])
    attack = candidate.get("attack_surface") or {}
    cfg_files = attack.get("config_files") or []
    if cfg_files:
        return "config files: " + ", ".join(str(x) for x in cfg_files[:3])
    return "none-observed"


def confidence_from_candidate(candidate: dict) -> str:
    if candidate.get("level") == "HIGH" or candidate.get("confidence") == "HIGH":
        return "High"
    if candidate.get("level") == "MEDIUM" or candidate.get("confidence") == "MEDIUM":
        return "Medium"
    return "Low"


def cve_potential_from_candidate(candidate: dict) -> str:
    flow = candidate.get("flow_type")
    auth = candidate.get("auth_boundary")
    web = bool(candidate.get("web_exposed") or candidate.get("web_reachable"))
    priv = candidate.get("priv")
    if flow in {"cmd_injection", "file_cmd_injection"} and web and auth in {"pre-auth", "bypassable"} and priv == "root":
        return "Critical"
    if flow in {"cmd_injection", "file_cmd_injection", "shell_var_injection"} and (web or auth in {"pre-auth", "bypassable"}):
        return "High"
    if flow in {"buffer_overflow", "dlopen_injection"} and (web or auth in {"pre-auth", "bypassable"}):
        return "High"
    if flow in {"cmd_injection", "shell_var_injection", "buffer_overflow", "net_copy_partial"}:
        return "Medium"
    return "Low"


def should_keep_candidate(candidate: dict) -> bool:
    if candidate.get("level") == "HIGH":
        return True
    if (candidate.get("score") or 0) >= 50:
        return True
    if candidate.get("web_exposed") or candidate.get("web_reachable"):
        return True
    if candidate.get("auth_boundary") in {"pre-auth", "bypassable"}:
        return True
    if candidate.get("flow_type") in {"cmd_injection", "file_cmd_injection", "shell_var_injection"} and (candidate.get("score") or 0) >= 25:
        return True
    return False


def source_code_candidate(bundle: dict, candidate: dict) -> Candidate:
    meta = bundle["target_metadata"]
    family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"
    name = candidate.get("name") or candidate.get("raw_name") or Path(candidate.get("binary_path") or "").name
    recurrence_key = f"code::{name}::{candidate.get('flow_type')}"
    why = candidate.get("vuln_summary") or "candidate flow requires manual validation"
    return Candidate(
        candidate_id=f"{meta['corpus_id']}::{candidate.get('id') or name}",
        kind="code",
        vendor=meta.get("vendor") or "UNKNOWN",
        model=meta.get("model") or "UNKNOWN",
        version=meta.get("version") or "UNKNOWN",
        corpus_id=meta.get("corpus_id") or "UNKNOWN",
        architecture_family=family,
        component=name,
        file_path=str(candidate.get("binary_path") or ""),
        component_role=role_from_path(str(candidate.get("binary_path") or "")),
        reachable_surface=reachable_surface(candidate),
        suspected_input_source=input_source(candidate),
        dangerous_sink=sink_summary(candidate),
        auth_evidence=auth_summary(candidate),
        persistence_evidence=persistence_summary(candidate),
        recurrence_key=recurrence_key,
        confidence=confidence_from_candidate(candidate),
        cve_potential=cve_potential_from_candidate(candidate),
        why_it_matters=why,
        source="results.candidates",
        extra={
            "score": candidate.get("score"),
            "level": candidate.get("level"),
            "flow_type": candidate.get("flow_type"),
            "recommended_next_action": candidate.get("recommended_next_action"),
            "web_exposed": candidate.get("web_exposed"),
            "web_reachable": candidate.get("web_reachable"),
        },
    )


def source_exploit_candidate(bundle: dict, cand: dict) -> Candidate:
    meta = bundle["target_metadata"]
    family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"
    recurrence_key = f"exploit::{cand.get('candidate_name')}::{cand.get('flow')}"
    potential = "High"
    if "http.formvalue() → os.execute()" in str(cand.get("flow")):
        potential = "Critical"
    return Candidate(
        candidate_id=f"{meta['corpus_id']}::exploit::{cand.get('candidate_name')}",
        kind="exploit-hint",
        vendor=meta.get("vendor") or "UNKNOWN",
        model=meta.get("model") or "UNKNOWN",
        version=meta.get("version") or "UNKNOWN",
        corpus_id=meta.get("corpus_id") or "UNKNOWN",
        architecture_family=family,
        component=str(cand.get("candidate_name") or cand.get("handler") or "unknown"),
        file_path=str(cand.get("binary_path") or ""),
        component_role=role_from_path(str(cand.get("binary_path") or "")),
        reachable_surface=str(cand.get("endpoint") or cand.get("input_method") or "HTTP-or-unknown"),
        suspected_input_source=str(cand.get("input_param") or cand.get("flow") or "unknown"),
        dangerous_sink=str(cand.get("sink") or "unknown"),
        auth_evidence=str(cand.get("auth_evidence") or "unknown"),
        persistence_evidence="none-observed",
        recurrence_key=recurrence_key,
        confidence="High" if cand.get("verdict") == "LIKELY" else "Medium",
        cve_potential=potential,
        why_it_matters=str(cand.get("reason") or "script-level candidate with direct input-to-sink hint"),
        source="results.exploit_candidates",
        extra={"verdict": cand.get("verdict"), "flow": cand.get("flow")},
    )


def source_crypto_finding(bundle: dict, finding: dict) -> Candidate:
    meta = bundle["target_metadata"]
    family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"
    sev = finding.get("severity") or "MEDIUM"
    return Candidate(
        candidate_id=f"{meta['corpus_id']}::crypto::{finding.get('path')}",
        kind="secret",
        vendor=meta.get("vendor") or "UNKNOWN",
        model=meta.get("model") or "UNKNOWN",
        version=meta.get("version") or "UNKNOWN",
        corpus_id=meta.get("corpus_id") or "UNKNOWN",
        architecture_family=family,
        component=Path(finding.get("path") or "secret").name,
        file_path=finding.get("path") or "",
        component_role="Credential / crypto artifact",
        reachable_surface="stored-secret",
        suspected_input_source="filesystem artifact",
        dangerous_sink=finding.get("type") or "secret material",
        auth_evidence="not applicable",
        persistence_evidence="persistent file",
        recurrence_key=f"secret::{finding.get('type')}::{Path(finding.get('path') or '').name}",
        confidence="High" if sev in {"CRITICAL", "HIGH"} else "Medium",
        cve_potential="Medium",
        why_it_matters=str(finding.get("evidence") or "hardcoded or embedded secret material"),
        source="results.crypto_findings",
        extra={"severity": sev, "type": finding.get("type"), "encrypted": finding.get("encrypted")},
    )


def source_upgrade_finding(bundle: dict, finding: dict) -> Candidate:
    meta = bundle["target_metadata"]
    family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"
    sev = finding.get("severity") or "MEDIUM"
    potential = "High" if sev == "CRITICAL" else "Medium"
    return Candidate(
        candidate_id=f"{meta['corpus_id']}::upgrade::{finding.get('path')}",
        kind="firmware-update",
        vendor=meta.get("vendor") or "UNKNOWN",
        model=meta.get("model") or "UNKNOWN",
        version=meta.get("version") or "UNKNOWN",
        corpus_id=meta.get("corpus_id") or "UNKNOWN",
        architecture_family=family,
        component=Path(finding.get("path") or "upgrade").name,
        file_path=finding.get("path") or "",
        component_role="Firmware update / import path",
        reachable_surface="management-triggered-or-local",
        suspected_input_source="firmware image / downloaded artifact",
        dangerous_sink=finding.get("pattern") or "unsigned flash",
        auth_evidence="reachability not proven by this scan",
        persistence_evidence="flash write / sysupgrade path",
        recurrence_key=f"upgrade::{finding.get('type')}::{Path(finding.get('path') or '').name}",
        confidence="High" if sev in {"CRITICAL", "HIGH"} else "Medium",
        cve_potential=potential,
        why_it_matters=str(finding.get("evidence") or "firmware write path lacks strong integrity proof"),
        source="results.upgrade_findings",
        extra={"severity": sev, "type": finding.get("type")},
    )


def source_semantic_gap(row: dict, graph: dict, edge: dict) -> Candidate:
    return Candidate(
        candidate_id=f"{row['target']['corpus_id']}::semantic::{edge['src']}->{edge['dst']}",
        kind="semantic-gap",
        vendor=row["target"]["vendor"],
        model=row["target"]["model"],
        version=row["target"]["version"],
        corpus_id=row["target"]["corpus_id"],
        architecture_family=row["architecture_family"],
        component=f"{edge['src']} -> {edge['dst']}",
        file_path=edge.get("source_locator") or "",
        component_role="ubus/Lua/localhost trust boundary",
        reachable_surface="localhost-or-control-plane",
        suspected_input_source=edge.get("relationship_type") or "control plane state",
        dangerous_sink=", ".join(edge.get("semantic_tags") or []),
        auth_evidence=f"validation={edge.get('validation_tier')}; confidence={edge.get('confidence')}",
        persistence_evidence=", ".join(tag for tag in edge.get("semantic_tags") or [] if tag in {"UCI_PERSISTENCE", "PROPAGATES_TRUST"}) or "none-observed",
        recurrence_key=f"semantic::{edge['src']}->{edge['dst']}::{','.join(sorted(edge.get('semantic_tags') or []))}",
        confidence="High" if edge.get("validation_tier") in {"confirmed", "high-confidence"} else "Medium",
        cve_potential="High" if edge.get("runtime_validation_required") else "Medium",
        why_it_matters="static semantic graph shows local relay / Lua / ubus trust handoff that may expand privileges if reachable",
        source="semantic_graph_results",
        extra={"semantic_tags": edge.get("semantic_tags"), "trust_indicators": edge.get("trust_collapse_indicators"), "runtime_required": edge.get("runtime_validation_required")},
    )


def recurrence_counts(candidates: list[Candidate]) -> Counter:
    return Counter(c.recurrence_key for c in candidates)


def apply_recurrence(candidates: list[Candidate]) -> None:
    counts = recurrence_counts(candidates)
    for cand in candidates:
        cand.recurrence_count = counts[cand.recurrence_key]


def rank_score(cand: Candidate) -> int:
    base = {"Critical": 100, "High": 70, "Medium": 40, "Low": 10}[cand.cve_potential]
    conf = {"High": 20, "Medium": 10, "Low": 0}[cand.confidence]
    recur = min(20, (cand.recurrence_count - 1) * 4)
    source_bonus = 20 if cand.kind == "exploit-hint" else 0
    if cand.kind == "semantic-gap" and cand.extra and cand.extra.get("runtime_required"):
        source_bonus += 4
    if cand.kind == "code" and cand.reachable_surface in {"HTTP/LAN", "HTTP/API endpoint", "http://device:80/cgi-bin/ (HTTP server self-handling)"}:
        source_bonus += 10
    if cand.kind == "firmware-update":
        source_bonus -= 45
        if cand.component in {"tmpcli", "sync.lua", "upgrade", "one_click_upgrade"}:
            source_bonus += 15
    if cand.kind == "semantic-gap":
        source_bonus -= 20
    if cand.kind == "secret":
        source_bonus -= 10
    if cand.kind == "firmware-update" and (cand.extra or {}).get("severity") == "CRITICAL":
        source_bonus += 4
    if cand.kind == "secret" and (cand.extra or {}).get("severity") == "CRITICAL":
        source_bonus += 6
    return base + conf + recur + source_bonus


def tool_choice(cand: Candidate) -> tuple[str, str, str]:
    role = cand.component_role
    path = cand.file_path
    if cand.kind == "semantic-gap":
        return ("Codex", "not needed", "compare static graph evidence and narrow the missing auth/runtime edge")
    if role == "Lua controller" or path.endswith(".lua") or "/usr/lib/oui-httpd/rpc/" in path:
        return ("Codex", "not needed", "trace controller or RPC helper input-to-sink path and auth checks")
    if cand.kind in {"secret", "firmware-update"} and path.endswith((".sh", ".lua", ".cfg", ".pem")):
        return ("Codex", "not needed", "confirm config/import/update or secret exposure semantics")
    if path:
        return ("Claude Code + Ghidra MCP", path, "recover parser/handler flow and validate sink reachability")
    return ("Codex", "not needed", "triage artifact manually")


def best_queue(candidates: list[Candidate]) -> list[Candidate]:
    seen = set()
    out = []
    for cand in sorted(candidates, key=lambda c: (-rank_score(c), c.vendor, c.model, c.component)):
        key = (cand.recurrence_key, cand.kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(cand)
        if len(out) >= 12:
            break
    return out


def render_inventory(candidates: list[Candidate]) -> str:
    lines = [
        "# Broad Candidate Inventory",
        "",
        "This inventory is a broad triage layer. Entries below are candidate signals, not confirmed vulnerabilities.",
        "",
    ]
    grouped: dict[str, list[Candidate]] = defaultdict(list)
    for cand in candidates:
        grouped[cand.corpus_id].append(cand)
    for corpus_id, rows in sorted(grouped.items()):
        sample = rows[0]
        lines += [
            f"## {sample.vendor} {sample.model} {sample.version}",
            "",
            f"- `corpus_id`: `{corpus_id}`",
            f"- `architecture_family`: `{sample.architecture_family}`",
            "",
            "| Component | Class | Surface | Auth | Sink | CVE Potential | Recurrence | Why It May Matter |",
            "| --- | --- | --- | --- | --- | --- | ---: | --- |",
        ]
        for cand in sorted(rows, key=lambda c: (-rank_score(c), c.component))[:8]:
            lines.append(
                f"| `{cand.component}` | `{cand.kind}` | `{cand.reachable_surface}` | `{cand.auth_evidence}` | "
                f"`{cand.dangerous_sink}` | `{cand.cve_potential}` | {cand.recurrence_count} | {cand.why_it_matters} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_ranking(candidates: list[Candidate]) -> str:
    lines = [
        "# CVE Candidate Ranking",
        "",
        "| Rank | Candidate | Target | Class | Surface | Potential | Confidence | Recurrence | Reason |",
        "| ---: | --- | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    top = best_queue(candidates)[:10]
    for idx, cand in enumerate(top, start=1):
        lines.append(
            f"| {idx} | `{cand.component}` | {cand.vendor} {cand.model} {cand.version} | `{cand.kind}` | "
            f"`{cand.reachable_surface}` | `{cand.cve_potential}` | `{cand.confidence}` | {cand.recurrence_count} | {cand.why_it_matters} |"
        )
    return "\n".join(lines)


def render_reachability(candidates: list[Candidate]) -> str:
    lines = [
        "# Candidate Reachability Matrix",
        "",
        "| Candidate | Target | Role | Reachable Surface | Input Source | Auth Evidence | Persistence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cand in sorted(candidates, key=lambda c: (-rank_score(c), c.vendor, c.model))[:80]:
        lines.append(
            f"| `{cand.component}` | {cand.vendor} {cand.model} | {cand.component_role} | `{cand.reachable_surface}` | "
            f"`{cand.suspected_input_source}` | `{cand.auth_evidence}` | `{cand.persistence_evidence}` |"
        )
    return "\n".join(lines)


def render_sinks(candidates: list[Candidate]) -> str:
    counts = Counter()
    examples = {}
    for cand in candidates:
        for sink in [x.strip() for x in cand.dangerous_sink.split(",") if x.strip()]:
            counts[sink] += 1
            examples.setdefault(sink, cand)
    lines = [
        "# Sensitive Sink Catalog",
        "",
        "| Sink | Count | Example Target | Example Component |",
        "| --- | ---: | --- | --- |",
    ]
    for sink, count in counts.most_common(40):
        ex = examples[sink]
        lines.append(f"| `{sink}` | {count} | {ex.vendor} {ex.model} | `{ex.component}` |")
    return "\n".join(lines)


def render_secrets(candidates: list[Candidate]) -> str:
    rows = [c for c in candidates if c.kind == "secret"]
    lines = [
        "# Hardcoded Secret Catalog",
        "",
        "| Target | Path | Type | Confidence | Why It Matters |",
        "| --- | --- | --- | --- | --- |",
    ]
    for cand in sorted(rows, key=lambda c: (-rank_score(c), c.vendor, c.model, c.file_path)):
        secret_type = (cand.extra or {}).get("type") or cand.dangerous_sink
        lines.append(
            f"| {cand.vendor} {cand.model} {cand.version} | `{cand.file_path}` | `{secret_type}` | `{cand.confidence}` | {cand.why_it_matters} |"
        )
    return "\n".join(lines)


def render_ubus_lua(candidates: list[Candidate]) -> str:
    rows = [c for c in candidates if c.kind == "semantic-gap" or c.component_role == "Lua controller"]
    lines = [
        "# Ubus / Lua Auth Gap Candidates",
        "",
        "| Target | Component | Surface | Auth Evidence | Sink / Tags | Recurrence | Why It Matters |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for cand in sorted(rows, key=lambda c: (-rank_score(c), c.vendor, c.model, c.component))[:40]:
        lines.append(
            f"| {cand.vendor} {cand.model} {cand.version} | `{cand.component}` | `{cand.reachable_surface}` | "
            f"`{cand.auth_evidence}` | `{cand.dangerous_sink}` | {cand.recurrence_count} | {cand.why_it_matters} |"
        )
    return "\n".join(lines)


def render_cmd(candidates: list[Candidate]) -> str:
    rows = [c for c in candidates if c.kind in {"code", "exploit-hint"} and c.dangerous_sink != "unknown"]
    lines = [
        "# Command Execution Candidates",
        "",
        "| Target | Component | Role | Input | Sink | Potential | Recurrence |",
        "| --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for cand in sorted(rows, key=lambda c: (-rank_score(c), c.vendor, c.model, c.component))[:60]:
        lines.append(
            f"| {cand.vendor} {cand.model} {cand.version} | `{cand.component}` | {cand.component_role} | "
            f"`{cand.suspected_input_source}` | `{cand.dangerous_sink}` | `{cand.cve_potential}` | {cand.recurrence_count} |"
        )
    return "\n".join(lines)


def render_upgrade(candidates: list[Candidate]) -> str:
    rows = [c for c in candidates if c.kind == "firmware-update"]
    lines = [
        "# Firmware Update Candidates",
        "",
        "| Target | Path | Potential | Confidence | Recurrence | Why It Matters |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for cand in sorted(rows, key=lambda c: (-rank_score(c), c.vendor, c.model, c.file_path))[:80]:
        lines.append(
            f"| {cand.vendor} {cand.model} {cand.version} | `{cand.file_path}` | `{cand.cve_potential}` | "
            f"`{cand.confidence}` | {cand.recurrence_count} | {cand.why_it_matters} |"
        )
    return "\n".join(lines)


def render_queue(candidates: list[Candidate]) -> str:
    lines = [
        "# Next Deep Dive Queue",
        "",
        "| Candidate | Target | Best Next Tool | Exact File To Load In Ghidra | Reason For Priority | Expected Validation Goal | Avoid Duplicate Note |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cand in best_queue(candidates):
        tool, ghidra_path, goal = tool_choice(cand)
        avoid = "related MR90X relay path already analyzed" if "mr90x" in cand.corpus_id and cand.kind == "semantic-gap" else (
            "same family already covered; focus on recurrence or auth proof" if cand.recurrence_count > 1 else "none"
        )
        lines.append(
            f"| `{cand.component}` | {cand.vendor} {cand.model} {cand.version} | `{tool}` | `{ghidra_path}` | "
            f"{cand.why_it_matters} | {goal} | {avoid} |"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Broad vulnerability-candidate triage across preserved firmware corpus.")
    ap.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE))
    args = ap.parse_args()

    workspace = Path(args.workspace_root)
    semantic_payload = load_json(workspace / SEMANTIC_RESULTS) if (workspace / SEMANTIC_RESULTS).exists() else {"graphs": []}
    semantic_by_corpus = {graph["corpus_id"]: graph for graph in semantic_payload.get("graphs", [])}

    candidates: list[Candidate] = []
    for result_path in iter_results(workspace):
        bundle = load_json(result_path)
        meta = bundle.get("target_metadata") or {}
        if not meta:
            continue
        rootfs = Path((bundle.get("analysis") or {}).get("system_path") or "")
        if not rootfs.exists():
            continue
        for raw in bundle.get("candidates") or []:
            if should_keep_candidate(raw):
                candidates.append(source_code_candidate(bundle, raw))
        for raw in bundle.get("exploit_candidates") or []:
            candidates.append(source_exploit_candidate(bundle, raw))
        for raw in bundle.get("crypto_findings") or []:
            if (raw.get("severity") or "MEDIUM") in {"CRITICAL", "HIGH", "MEDIUM"}:
                candidates.append(source_crypto_finding(bundle, raw))
        for raw in bundle.get("upgrade_findings") or []:
            if (raw.get("severity") or "MEDIUM") in {"CRITICAL", "HIGH"}:
                candidates.append(source_upgrade_finding(bundle, raw))
        graph = semantic_by_corpus.get(meta.get("corpus_id"))
        if graph:
            for edge in graph.get("edges", []):
                tags = set(edge.get("semantic_tags") or [])
                if {"BYPASSES_AUTH", "SESSION_WITHOUT_AUTH", "UBUS_CONTROL", "LOCALHOST_TRUST"} & tags:
                    candidates.append(source_semantic_gap({"target": meta, "architecture_family": graph.get("architecture_family")}, graph, edge))

    apply_recurrence(candidates)

    write(workspace / REPORTS["inventory"], render_inventory(candidates))
    write(workspace / REPORTS["ranking"], render_ranking(candidates))
    write(workspace / REPORTS["reachability"], render_reachability(candidates))
    write(workspace / REPORTS["sinks"], render_sinks(candidates))
    write(workspace / REPORTS["secrets"], render_secrets(candidates))
    write(workspace / REPORTS["ubus_lua"], render_ubus_lua(candidates))
    write(workspace / REPORTS["cmd"], render_cmd(candidates))
    write(workspace / REPORTS["upgrade"], render_upgrade(candidates))
    write(workspace / REPORTS["queue"], render_queue(candidates))

    print(f"Curated candidates: {len(candidates)}")
    for name in REPORTS.values():
        print(workspace / name)


if __name__ == "__main__":
    main()
