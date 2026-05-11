#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"


@dataclass
class HandlerRecord:
    corpus_id: str
    vendor: str
    model: str
    version: str
    architecture_family: str
    controller_path: str
    route_path: str
    handler_name: str
    entry_kind: str
    explicit_local_auth: str
    local_auth_evidence: list[str]
    framework_auth_evidence: list[str]
    dangerous_operations: list[str]
    dangerous_categories: list[str]
    reachable_surface: str
    auth_model: str
    why_it_matters: str


ENTRY_RE = re.compile(
    r'entry\(\{(?P<route>[^}]*)\}\s*,\s*(?P<kind>call|post)\("(?P<handler>[^"]+)"\)',
    re.MULTILINE,
)
ROUTE_TOKEN_RE = re.compile(r'"([^"]+)"')
FUNC_START_RE = re.compile(r"^function\s+([A-Za-z0-9_\.]+)\s*\(")

LOCAL_AUTH_PATTERNS = [
    (re.compile(r"sysauth"), "sysauth reference"),
    (re.compile(r"sauth"), "sauth reference"),
    (re.compile(r"authsession"), "authsession reference"),
    (re.compile(r"authtoken"), "authtoken reference"),
    (re.compile(r"check[_]?auth"), "check_auth style helper"),
    (re.compile(r"session"), "session logic"),
    (re.compile(r"access"), "access check"),
    (re.compile(r"http\.formvalue\(\"token\""), "request token check"),
    (re.compile(r"ubus.*access"), "ubus access check"),
]

DANGEROUS_PATTERNS = [
    (re.compile(r"os\.execute\s*\("), "os.execute", "command-exec"),
    (re.compile(r"io\.popen\s*\("), "io.popen", "command-exec"),
    (re.compile(r"nixio\.exec\s*\("), "nixio.exec", "command-exec"),
    (re.compile(r"fork_exec\s*\("), "fork_exec", "command-exec"),
    (re.compile(r"luci\.util\.exec\s*\("), "luci.util.exec", "command-exec"),
    (re.compile(r"\bubus\b"), "ubus", "ubus"),
    (re.compile(r"cursor:(set|commit|delete|section|add)"), "uci cursor write", "uci-write"),
    (re.compile(r"uci:(set|commit|delete|section|add)"), "uci write", "uci-write"),
    (re.compile(r"sysupgrade|upgrade|restore|backup|upload"), "firmware/update operation", "upgrade"),
    (re.compile(r"password|passwd|private[_-]?key|token|secret|ssh"), "credential operation", "credential"),
]

FRAMEWORK_DISPATCHER_PATTERNS = [
    (re.compile(r"sysauth"), "dispatcher sysauth"),
    (re.compile(r"check_authentication"), "dispatcher authentication helper"),
    (re.compile(r"cookie:sysauth"), "dispatcher sysauth cookie method"),
    (re.compile(r"authtoken"), "dispatcher authtoken"),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def iter_results(workspace: Path):
    yield from sorted((workspace / "runs").rglob("results.json"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def build_function_map(text: str) -> dict[str, str]:
    lines = text.splitlines()
    starts: list[tuple[str, int]] = []
    for idx, line in enumerate(lines):
        m = FUNC_START_RE.match(line.strip())
        if m:
            name = m.group(1).split(".")[-1]
            starts.append((name, idx))
    bodies: dict[str, str] = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(lines)
        bodies[name] = "\n".join(lines[start:end])
    return bodies


def route_strings(route_blob: str) -> list[str]:
    return ROUTE_TOKEN_RE.findall(route_blob)


def framework_auth_evidence(rootfs: Path) -> list[str]:
    evidence: list[str] = []
    dispatcher = rootfs / "usr/lib/lua/luci/dispatcher.lua"
    if dispatcher.exists():
        text = read_text(dispatcher)
        for rx, label in FRAMEWORK_DISPATCHER_PATTERNS:
            if rx.search(text):
                evidence.append(label)
    admin_index = rootfs / "usr/lib/lua/luci/controller/admin/index.lua"
    if admin_index.exists():
        text = read_text(admin_index)
        if "Set-Cookie" in text and "sysauth" in text:
            evidence.append("admin index sysauth cookie handling")
    return sorted(set(evidence))


def local_auth_evidence(body: str) -> list[str]:
    found = []
    for rx, label in LOCAL_AUTH_PATTERNS:
        if rx.search(body):
            found.append(label)
    return sorted(set(found))


def dangerous_ops(body: str) -> tuple[list[str], list[str]]:
    ops: list[str] = []
    cats: list[str] = []
    for rx, label, category in DANGEROUS_PATTERNS:
        if rx.search(body):
            ops.append(label)
            cats.append(category)
    return sorted(set(ops)), sorted(set(cats))


def reachable_surface(route: str, framework_evidence: list[str]) -> str:
    tokens = [t for t in route.split("/") if t]
    if not tokens:
        return "unclear"
    if tokens[0] == "admin":
        return "web-admin"
    if "rpc" in tokens:
        return "rpc/web-api"
    if tokens[0] in {"api", "cgi-bin"}:
        return "api-like"
    if framework_evidence:
        return "web-route"
    return "unclear"


def auth_model(
    route: str,
    local_auth: list[str],
    framework_evidence: list[str],
    dangerous_categories: list[str],
) -> str:
    tokens = [t for t in route.split("/") if t]
    if local_auth:
        return "explicit local auth"
    if tokens and tokens[0] == "admin" and framework_evidence:
        return "framework-inherited auth only"
    if dangerous_categories and not framework_evidence:
        return "likely auth gap"
    return "unclear auth model"


def why_it_matters(categories: list[str], auth_model_value: str) -> str:
    if not categories:
        return "route exists but no dangerous operation was matched"
    if auth_model_value == "framework-inherited auth only":
        return "dangerous management logic appears to rely on LuCI framework auth rather than a route-local authorization check"
    if auth_model_value == "likely auth gap":
        return "dangerous management logic was found without clear local or framework auth evidence in preserved artifacts"
    if auth_model_value == "explicit local auth":
        return "dangerous management logic is present, but the handler also contains local auth or session logic"
    return "dangerous management logic is present, but the effective auth model remains unclear"


def collect_records(workspace: Path) -> list[HandlerRecord]:
    records: list[HandlerRecord] = []
    seen_targets: set[str] = set()

    for results_path in iter_results(workspace):
        bundle = load_json(results_path)
        meta = bundle.get("target_metadata") or {}
        corpus_id = meta.get("corpus_id")
        if not corpus_id or corpus_id in seen_targets:
            continue
        seen_targets.add(corpus_id)

        system_path = bundle.get("analysis", {}).get("system_path")
        if not system_path:
            continue
        rootfs = (PROJECT_ROOT / system_path).resolve()
        controllers_dir = rootfs / "usr/lib/lua/luci/controller"
        if not controllers_dir.exists():
            continue

        framework_evd = framework_auth_evidence(rootfs)
        family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"

        for controller_path in sorted(controllers_dir.rglob("*.lua")):
            text = read_text(controller_path)
            if not text:
                continue
            funcs = build_function_map(text)
            for match in ENTRY_RE.finditer(text):
                route = "/".join(route_strings(match.group("route")))
                handler = match.group("handler")
                body = funcs.get(handler, "")
                local_evd = local_auth_evidence(body)
                ops, cats = dangerous_ops(body)
                surface = reachable_surface(route, framework_evd)
                model = auth_model(route, local_evd, framework_evd, cats)
                records.append(
                    HandlerRecord(
                        corpus_id=corpus_id,
                        vendor=meta.get("vendor") or "UNKNOWN",
                        model=meta.get("model") or "UNKNOWN",
                        version=meta.get("version") or "UNKNOWN",
                        architecture_family=family,
                        controller_path=str(controller_path.relative_to(rootfs)),
                        route_path="/" + route if route else "",
                        handler_name=handler,
                        entry_kind=match.group("kind"),
                        explicit_local_auth="present" if local_evd else "absent",
                        local_auth_evidence=local_evd,
                        framework_auth_evidence=framework_evd,
                        dangerous_operations=ops,
                        dangerous_categories=cats,
                        reachable_surface=surface,
                        auth_model=model,
                        why_it_matters=why_it_matters(cats, model),
                    )
                )
    return records


def records_with_danger(records: list[HandlerRecord]) -> list[HandlerRecord]:
    return [r for r in records if r.dangerous_operations]


def high_risk(records: list[HandlerRecord]) -> list[HandlerRecord]:
    ranked: list[tuple[int, HandlerRecord]] = []
    for rec in records_with_danger(records):
        score = 0
        if rec.auth_model == "likely auth gap":
            score += 5
        if rec.auth_model == "framework-inherited auth only":
            score += 4
        if rec.reachable_surface in {"web-admin", "rpc/web-api", "api-like"}:
            score += 3
        if "command-exec" in rec.dangerous_categories:
            score += 4
        if "upgrade" in rec.dangerous_categories:
            score += 3
        if "credential" in rec.dangerous_categories:
            score += 2
        if "uci-write" in rec.dangerous_categories or "ubus" in rec.dangerous_categories:
            score += 2
        ranked.append((score, rec))
    return [rec for _, rec in sorted(ranked, key=lambda item: (-item[0], item[1].corpus_id, item[1].route_path))[:80]]


def recurrence_patterns(records: list[HandlerRecord]) -> dict[str, list[HandlerRecord]]:
    groups: dict[str, list[HandlerRecord]] = defaultdict(list)
    for rec in records_with_danger(records):
        key = f"{Path(rec.controller_path).name}|{rec.handler_name}|{','.join(rec.dangerous_categories)}|{rec.auth_model}"
        groups[key].append(rec)
    return {k: v for k, v in groups.items() if len(v) >= 2}


def fmt_evidence(items: list[str]) -> str:
    return ", ".join(items) if items else "none"


def report_inventory(records: list[HandlerRecord]) -> str:
    dangerous = records_with_danger(records)
    auth_counts = Counter(r.auth_model for r in dangerous)
    vendor_counts = Counter(r.vendor for r in dangerous)
    fam_counts = Counter(r.architecture_family for r in dangerous)
    lines = [
        "# LuCI Authentication Inheritance Inventory",
        "",
        "## Summary",
        "",
        f"- scanned handler entries: `{len(records)}`",
        f"- handlers with dangerous operations: `{len(dangerous)}`",
        "",
        "## Dangerous Handler Auth Models",
        "",
    ]
    for key, value in sorted(auth_counts.items()):
        lines.append(f"- `{key}`: `{value}`")
    lines += ["", "## Vendor Distribution", ""]
    for key, value in vendor_counts.most_common():
        lines.append(f"- `{key}`: `{value}`")
    lines += ["", "## Architecture Family Distribution", ""]
    for key, value in fam_counts.most_common():
        lines.append(f"- `{key}`: `{value}`")
    lines += ["", "## Sample Dangerous Handlers", ""]
    for rec in high_risk(records)[:25]:
        lines.append(
            f"- `{rec.vendor} {rec.model} {rec.version}` `{rec.route_path}` -> `{rec.handler_name}` "
            f"[{rec.auth_model}; ops={fmt_evidence(rec.dangerous_operations)}]"
        )
    return "\n".join(lines)


def report_auth_gaps(records: list[HandlerRecord]) -> str:
    lines = ["# LuCI Auth Gap Candidates", ""]
    selected = [
        r for r in high_risk(records)
        if r.auth_model in {"likely auth gap", "unclear auth model", "framework-inherited auth only"}
    ]
    for rec in selected:
        lines += [
            f"## {rec.vendor} {rec.model} {rec.version} :: {rec.route_path}",
            "",
            f"- controller: `{rec.controller_path}`",
            f"- handler: `{rec.handler_name}` (`{rec.entry_kind}`)",
            f"- auth model: `{rec.auth_model}`",
            f"- local auth evidence: `{fmt_evidence(rec.local_auth_evidence)}`",
            f"- framework auth evidence: `{fmt_evidence(rec.framework_auth_evidence)}`",
            f"- dangerous operations: `{fmt_evidence(rec.dangerous_operations)}`",
            f"- reachable surface: `{rec.reachable_surface}`",
            f"- why it matters: {rec.why_it_matters}",
            "",
        ]
    return "\n".join(lines)


def report_sink_matrix(records: list[HandlerRecord]) -> str:
    lines = [
        "# LuCI Management Sink Matrix",
        "",
        "| Vendor | Model | Route | Handler | Auth model | Dangerous ops | Surface |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for rec in high_risk(records):
        lines.append(
            f"| {rec.vendor} | {rec.model} | `{rec.route_path}` | `{rec.handler_name}` | "
            f"{rec.auth_model} | {fmt_evidence(rec.dangerous_operations)} | {rec.reachable_surface} |"
        )
    return "\n".join(lines)


def report_patterns(records: list[HandlerRecord]) -> str:
    patterns = recurrence_patterns(records)
    lines = ["# LuCI Recurring Auth Patterns", "", "## Recurring Families", ""]
    for key, group in sorted(patterns.items(), key=lambda item: (-len(item[1]), item[0])):
        sample = group[0]
        lines += [
            f"### {Path(sample.controller_path).name} / {sample.handler_name}",
            "",
            f"- recurrence count: `{len(group)}`",
            f"- auth model: `{sample.auth_model}`",
            f"- dangerous categories: `{fmt_evidence(sample.dangerous_categories)}`",
            f"- vendors: `{', '.join(sorted({g.vendor for g in group}))}`",
            f"- models: `{', '.join(sorted({g.model for g in group})[:6])}`",
            f"- sample route: `{sample.route_path}`",
            "",
        ]
    return "\n".join(lines)


def report_high_risk(records: list[HandlerRecord]) -> str:
    lines = ["# High Risk LuCI Handlers", ""]
    for rec in high_risk(records)[:40]:
        lines += [
            f"## {rec.vendor} {rec.model} {rec.version} :: {rec.route_path}",
            "",
            f"- controller: `{rec.controller_path}`",
            f"- handler: `{rec.handler_name}`",
            f"- auth model: `{rec.auth_model}`",
            f"- explicit local auth: `{rec.explicit_local_auth}`",
            f"- framework auth evidence: `{fmt_evidence(rec.framework_auth_evidence)}`",
            f"- dangerous operations: `{fmt_evidence(rec.dangerous_operations)}`",
            f"- dangerous categories: `{fmt_evidence(rec.dangerous_categories)}`",
            f"- reachable surface: `{rec.reachable_surface}`",
            f"- note: {rec.why_it_matters}",
            "",
        ]
    return "\n".join(lines)


def save_json(workspace: Path, records: list[HandlerRecord]) -> None:
    out = workspace / "luci_auth_inheritance_results.json"
    out.write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args()

    workspace = args.workspace_root
    records = collect_records(workspace)
    save_json(workspace, records)

    write_text(workspace / "luci_auth_inheritance_inventory.md", report_inventory(records))
    write_text(workspace / "luci_auth_gap_candidates.md", report_auth_gaps(records))
    write_text(workspace / "luci_management_sink_matrix.md", report_sink_matrix(records))
    write_text(workspace / "luci_recurring_auth_patterns.md", report_patterns(records))
    write_text(workspace / "high_risk_luci_handlers.md", report_high_risk(records))


if __name__ == "__main__":
    main()
