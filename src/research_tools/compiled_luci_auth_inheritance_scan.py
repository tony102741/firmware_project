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


BYTECODE_HEADERS = (b"\x1bLua", b"LuaQ")
ENTRY_MARKERS = {"entry"}
STOP_MARKERS = {"call", "post", "template", "cbi", "firstchild", "arcombine", "alias"}
ROUTE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_:-]+$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class BytecodeRecord:
    corpus_id: str
    vendor: str
    model: str
    version: str
    architecture_family: str
    controller_path: str
    module_name: str
    recovered_routes: list[str]
    recovered_handlers: list[str]
    entry_kinds: list[str]
    local_auth_evidence: list[str]
    framework_auth_evidence: list[str]
    dangerous_signals: list[str]
    dangerous_categories: list[str]
    recoverability: str
    auth_model: str
    reachable_surface: str
    semantics_status: str
    why_it_matters: str


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def iter_results(workspace: Path):
    yield from sorted((workspace / "runs").rglob("results.json"))


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def is_bytecode(data: bytes) -> bool:
    return any(data.startswith(header) for header in BYTECODE_HEADERS)


def printable_strings(data: bytes, min_len: int = 4) -> list[str]:
    cur: list[str] = []
    out: list[str] = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def framework_auth_evidence(rootfs: Path) -> list[str]:
    evidence: list[str] = []
    for rel in [
        "usr/lib/lua/luci/dispatcher.lua",
        "usr/lib/lua/luci/sauth.lua",
        "usr/lib/lua/luci/controller/admin/index.lua",
    ]:
        p = rootfs / rel
        if not p.exists():
            continue
        strings = printable_strings(read_bytes(p))
        joined = "\n".join(strings)
        if "sysauth" in joined:
            evidence.append(f"{rel}:sysauth")
        if "check_authentication" in joined:
            evidence.append(f"{rel}:check_authentication")
        if "cookie:sysauth" in joined:
            evidence.append(f"{rel}:cookie:sysauth")
        if "authtoken" in joined:
            evidence.append(f"{rel}:authtoken")
        if "Set-Cookie" in joined and "sysauth" in joined:
            evidence.append(f"{rel}:sysauth-cookie")
    return sorted(set(evidence))


LOCAL_AUTH_KEYWORDS = {
    "sysauth": "sysauth reference",
    "sauth": "sauth reference",
    "authtoken": "authtoken reference",
    "authsession": "authsession reference",
    "session": "session reference",
    "access": "access reference",
    "check_ip_in_lan": "LAN check helper",
    "check_authentication": "check_authentication helper",
    "token": "token reference",
}


def local_auth_evidence(strings: list[str]) -> list[str]:
    found = []
    lower = [s.lower() for s in strings]
    for key, label in LOCAL_AUTH_KEYWORDS.items():
        if any(key in s for s in lower):
            found.append(label)
    return sorted(set(found))


DANGEROUS_SIGNAL_MAP = {
    "os.execute": ("os.execute", "command-exec"),
    "io.popen": ("io.popen", "command-exec"),
    "nixio.exec": ("nixio.exec", "command-exec"),
    "fork_exec": ("fork_exec", "command-exec"),
    "execute": ("execute", "command-exec"),
    "ubus": ("ubus", "ubus"),
    "commit": ("commit", "uci-write"),
    "cursor": ("cursor", "uci-write"),
    "upgrade": ("upgrade", "upgrade"),
    "firmware": ("firmware", "upgrade"),
    "backup": ("backup", "credential"),
    "restore": ("restore", "upgrade"),
    "password": ("password", "credential"),
    "passwd": ("passwd", "credential"),
    "private_key": ("private_key", "credential"),
    "ssh": ("ssh", "credential"),
    "token": ("token", "credential"),
}


def dangerous_signals(strings: list[str]) -> tuple[list[str], list[str]]:
    found: list[str] = []
    cats: list[str] = []
    lower = [s.lower() for s in strings]
    for key, (label, cat) in DANGEROUS_SIGNAL_MAP.items():
        if any(key in s for s in lower):
            found.append(label)
            cats.append(cat)
    return sorted(set(found)), sorted(set(cats))


def recover_routes_and_handlers(strings: list[str]) -> tuple[list[str], list[str], list[str]]:
    routes: list[str] = []
    handlers: list[str] = []
    kinds: list[str] = []
    for idx, token in enumerate(strings):
        if token not in ENTRY_MARKERS:
            continue
        route_tokens: list[str] = []
        kind = ""
        handler = ""
        for look in strings[idx + 1 : idx + 20]:
            if look in STOP_MARKERS:
                kind = look
                continue
            if kind and not handler and IDENT_RE.match(look):
                handler = look
                break
            if not kind and ROUTE_TOKEN_RE.match(look) and look not in {"MODULE", "SECTION", "PARAM", "TYPE"}:
                route_tokens.append(look)
        if route_tokens:
            route = "/" + "/".join(route_tokens)
            if route not in routes:
                routes.append(route)
        if handler and handler not in handlers:
            handlers.append(handler)
        if kind and kind not in kinds:
            kinds.append(kind)
    return routes[:40], handlers[:60], kinds


def recoverability(routes: list[str], handlers: list[str], framework_evd: list[str], danger: list[str]) -> str:
    if routes and handlers and framework_evd and danger:
        return "partially recoverable"
    if routes or handlers or danger:
        return "string-only recoverable"
    return "opaque"


def reachable_surface(routes: list[str]) -> str:
    if any(route.startswith("/admin/") for route in routes):
        return "web-admin"
    if any("/rpc" in route for route in routes):
        return "rpc/web-api"
    if routes:
        return "web-route"
    return "unclear"


def auth_model(routes: list[str], local_auth: list[str], framework_evd: list[str], danger_cats: list[str]) -> str:
    if local_auth and any(x in " ".join(local_auth).lower() for x in ["sysauth", "authtoken", "check_authentication", "lan check"]):
        return "explicit local auth"
    if any(route.startswith("/admin/") for route in routes) and framework_evd:
        return "framework-inherited auth only"
    if danger_cats and not framework_evd:
        return "likely auth gap"
    return "unclear auth model"


def semantics_status(recov: str, routes: list[str], danger: list[str]) -> str:
    if recov == "partially recoverable":
        return "recovered semantics + inferred auth model"
    if routes or danger:
        return "string-level recovery only"
    return "opaque bytecode"


def why_it_matters(auth_model_value: str, routes: list[str], danger_cats: list[str]) -> str:
    if not danger_cats:
        return "controller bytecode recovered, but no dangerous management signal was identified"
    if auth_model_value == "framework-inherited auth only":
        return "bytecode strings suggest dangerous management handlers are routed under framework-protected LuCI paths without route-local auth evidence"
    if auth_model_value == "likely auth gap":
        return "dangerous management signals were recovered without clear local or framework auth evidence"
    if auth_model_value == "explicit local auth":
        return "controller bytecode contains both dangerous operations and explicit auth/session terminology"
    return "dangerous management semantics were recovered, but effective authorization remains ambiguous"


def collect_records(workspace: Path) -> list[BytecodeRecord]:
    records: list[BytecodeRecord] = []
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
        ctrl_dir = rootfs / "usr/lib/lua/luci/controller"
        if not ctrl_dir.exists():
            continue
        family = (bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown"
        framework_evd = framework_auth_evidence(rootfs)

        for controller in sorted(ctrl_dir.rglob("*.lua")):
            data = read_bytes(controller)
            if not data or not is_bytecode(data):
                continue
            strings = printable_strings(data)
            module_name = next((s for s in strings if s.startswith("luci.controller.")), "")
            routes, handlers, kinds = recover_routes_and_handlers(strings)
            local_evd = local_auth_evidence(strings)
            danger, cats = dangerous_signals(strings)
            recov = recoverability(routes, handlers, framework_evd, danger)
            auth = auth_model(routes, local_evd, framework_evd, cats)
            records.append(
                BytecodeRecord(
                    corpus_id=corpus_id,
                    vendor=meta.get("vendor") or "UNKNOWN",
                    model=meta.get("model") or "UNKNOWN",
                    version=meta.get("version") or "UNKNOWN",
                    architecture_family=family,
                    controller_path=str(controller.relative_to(rootfs)),
                    module_name=module_name,
                    recovered_routes=routes,
                    recovered_handlers=handlers,
                    entry_kinds=kinds,
                    local_auth_evidence=local_evd,
                    framework_auth_evidence=framework_evd,
                    dangerous_signals=danger,
                    dangerous_categories=cats,
                    recoverability=recov,
                    auth_model=auth,
                    reachable_surface=reachable_surface(routes),
                    semantics_status=semantics_status(recov, routes, danger),
                    why_it_matters=why_it_matters(auth, routes, cats),
                )
            )
    return records


def save_json(workspace: Path, records: list[BytecodeRecord]) -> None:
    (workspace / "compiled_luci_auth_results.json").write_text(
        json.dumps([asdict(r) for r in records], indent=2),
        encoding="utf-8",
    )


def report_inventory(records: list[BytecodeRecord]) -> str:
    lines = ["# Compiled LuCI Inventory", "", "## Summary", ""]
    lines.append(f"- compiled controller files: `{len(records)}`")
    lines.append(f"- targets with compiled controllers: `{len({r.corpus_id for r in records})}`")
    lines.append("")
    lines.append("## Vendor Distribution")
    lines.append("")
    for key, val in Counter(r.vendor for r in records).most_common():
        lines.append(f"- `{key}`: `{val}`")
    lines.append("")
    lines.append("## Recoverability")
    lines.append("")
    for key, val in Counter(r.recoverability for r in records).most_common():
        lines.append(f"- `{key}`: `{val}`")
    lines.append("")
    lines.append("## Sample Modules")
    lines.append("")
    for rec in records[:30]:
        lines.append(
            f"- `{rec.vendor} {rec.model} {rec.version}` `{rec.controller_path}` "
            f"[routes={len(rec.recovered_routes)}, handlers={len(rec.recovered_handlers)}, auth={rec.auth_model}]"
        )
    return "\n".join(lines)


def report_auth_patterns(records: list[BytecodeRecord]) -> str:
    lines = ["# Compiled LuCI Auth Patterns", "", "## Auth Model Distribution", ""]
    for key, val in Counter(r.auth_model for r in records if r.dangerous_signals).most_common():
        lines.append(f"- `{key}`: `{val}`")
    lines += ["", "## Representative Controllers", ""]
    for rec in sorted(
        [r for r in records if r.dangerous_signals],
        key=lambda r: (r.vendor, r.model, r.controller_path),
    )[:60]:
        lines += [
            f"### {rec.vendor} {rec.model} {rec.version} :: {Path(rec.controller_path).name}",
            "",
            f"- module: `{rec.module_name or 'unknown'}`",
            f"- auth model: `{rec.auth_model}`",
            f"- recoverability: `{rec.recoverability}`",
            f"- recovered routes: `{', '.join(rec.recovered_routes[:6]) or 'none'}`",
            f"- recovered handlers: `{', '.join(rec.recovered_handlers[:8]) or 'none'}`",
            f"- framework auth evidence: `{', '.join(rec.framework_auth_evidence) or 'none'}`",
            f"- local auth evidence: `{', '.join(rec.local_auth_evidence) or 'none'}`",
            f"- dangerous signals: `{', '.join(rec.dangerous_signals) or 'none'}`",
            "",
        ]
    return "\n".join(lines)


def report_high_risk(records: list[BytecodeRecord]) -> str:
    def score(rec: BytecodeRecord) -> int:
        s = 0
        if rec.auth_model == "likely auth gap":
            s += 5
        if rec.auth_model == "framework-inherited auth only":
            s += 4
        if rec.reachable_surface == "web-admin":
            s += 3
        if "command-exec" in rec.dangerous_categories:
            s += 4
        if "upgrade" in rec.dangerous_categories:
            s += 3
        if "credential" in rec.dangerous_categories:
            s += 2
        if "ubus" in rec.dangerous_categories or "uci-write" in rec.dangerous_categories:
            s += 2
        if rec.recoverability == "partially recoverable":
            s += 2
        return s

    selected = sorted(
        [r for r in records if r.dangerous_signals],
        key=lambda r: (-score(r), r.vendor, r.model, r.controller_path),
    )[:80]
    lines = ["# Compiled LuCI High Risk Handlers", ""]
    for rec in selected:
        lines += [
            f"## {rec.vendor} {rec.model} {rec.version} :: {Path(rec.controller_path).name}",
            "",
            f"- controller: `{rec.controller_path}`",
            f"- module: `{rec.module_name or 'unknown'}`",
            f"- auth model: `{rec.auth_model}`",
            f"- semantics status: `{rec.semantics_status}`",
            f"- recoverability: `{rec.recoverability}`",
            f"- recovered routes: `{', '.join(rec.recovered_routes[:6]) or 'none'}`",
            f"- recovered handlers: `{', '.join(rec.recovered_handlers[:10]) or 'none'}`",
            f"- dangerous signals: `{', '.join(rec.dangerous_signals) or 'none'}`",
            f"- dangerous categories: `{', '.join(rec.dangerous_categories) or 'none'}`",
            f"- why it matters: {rec.why_it_matters}",
            "",
        ]
    return "\n".join(lines)


def report_recoverability(records: list[BytecodeRecord]) -> str:
    lines = [
        "# Compiled LuCI Recoverability Matrix",
        "",
        "| Vendor | Model | Controller | Recoverability | Auth model | Surface | Signals |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for rec in sorted(records, key=lambda r: (r.vendor, r.model, r.controller_path)):
        lines.append(
            f"| {rec.vendor} | {rec.model} | `{Path(rec.controller_path).name}` | {rec.recoverability} | "
            f"{rec.auth_model} | {rec.reachable_surface} | {', '.join(rec.dangerous_signals[:5]) or 'none'} |"
        )
    return "\n".join(lines)


def report_cross_vendor(records: list[BytecodeRecord]) -> str:
    groups: dict[str, list[BytecodeRecord]] = defaultdict(list)
    for rec in records:
        key = f"{Path(rec.controller_path).name}|{','.join(rec.dangerous_categories)}|{rec.auth_model}"
        groups[key].append(rec)
    lines = ["# Cross Vendor LuCI Auth Recurrence", "", "## Recurring Controller Families", ""]
    for key, group in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(group) < 2:
            continue
        sample = group[0]
        vendors = sorted({g.vendor for g in group})
        lines += [
            f"### {Path(sample.controller_path).name}",
            "",
            f"- recurrence count: `{len(group)}`",
            f"- vendors: `{', '.join(vendors)}`",
            f"- auth model: `{sample.auth_model}`",
            f"- dangerous categories: `{', '.join(sample.dangerous_categories) or 'none'}`",
            f"- sample routes: `{', '.join(sample.recovered_routes[:4]) or 'none'}`",
            "",
        ]
    return "\n".join(lines)


def report_expanded_gap_candidates(workspace: Path, compiled: list[BytecodeRecord]) -> str:
    plain_path = workspace / "luci_auth_inheritance_results.json"
    plain = []
    if plain_path.exists():
        plain = json.loads(plain_path.read_text(encoding="utf-8"))
    lines = ["# Expanded LuCI Auth Gap Candidates", "", "## Plain-Text High Signal", ""]
    for row in plain[:60]:
        if row.get("dangerous_operations") and row.get("auth_model") in {
            "framework-inherited auth only",
            "likely auth gap",
            "unclear auth model",
        }:
            lines.append(
                f"- `{row['vendor']} {row['model']} {row['version']}` `{row['route_path']}` "
                f"-> `{row['handler_name']}` [{row['auth_model']}; ops={', '.join(row['dangerous_operations'])}]"
            )
    lines += ["", "## Compiled LuCI Expansion", ""]
    for rec in sorted(
        [r for r in compiled if r.dangerous_signals and r.auth_model in {"framework-inherited auth only", "likely auth gap", "unclear auth model"}],
        key=lambda r: (r.vendor, r.model, r.controller_path),
    )[:120]:
        lines.append(
            f"- `{rec.vendor} {rec.model} {rec.version}` `{Path(rec.controller_path).name}` "
            f"[{rec.auth_model}; recoverability={rec.recoverability}; routes={', '.join(rec.recovered_routes[:3]) or 'none'}; signals={', '.join(rec.dangerous_signals[:4])}]"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args()
    workspace = args.workspace_root
    records = collect_records(workspace)
    save_json(workspace, records)
    write_text(workspace / "compiled_luci_inventory.md", report_inventory(records))
    write_text(workspace / "compiled_luci_auth_patterns.md", report_auth_patterns(records))
    write_text(workspace / "compiled_luci_high_risk_handlers.md", report_high_risk(records))
    write_text(workspace / "compiled_luci_recoverability_matrix.md", report_recoverability(records))
    write_text(workspace / "cross_vendor_luci_auth_recurrence.md", report_cross_vendor(records))
    write_text(workspace / "expanded_luci_auth_gap_candidates.md", report_expanded_gap_candidates(workspace, records))


if __name__ == "__main__":
    main()
