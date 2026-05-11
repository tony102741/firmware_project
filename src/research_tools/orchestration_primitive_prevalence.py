"""
Corpus-wide orchestration primitive prevalence analysis.

Usage:
  python3 src/research_tools/orchestration_primitive_prevalence.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from research_tools.binary_inheritance_report import (
    DEFAULT_WORKSPACE,
    TARGET_NAMES,
    detect_kind,
    file_description,
    iter_results,
    parse_dyn_imports,
    parse_readelf_dynamic,
    parse_strings,
    rel_after_root,
    rel_rank,
    resolve_system_root,
    sha256_path,
    stable_id,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_FILES = [
    "orchestration_primitive_prevalence.md",
    "execution_wrapper_recurrence.md",
    "deferred_execution_patterns.md",
    "management_plane_execution_semantics.md",
    "state_machine_orchestration_clusters.md",
    "corpus_level_execution_abstractions.md",
]

PRIMITIVE_ORDER = [
    "shell-execution-wrapper",
    "binsh-execution",
    "config-to-command",
    "ubus-workflow",
    "uci-config-polling",
    "deferred-reconnect",
    "helper-driven-execution",
    "event-loop-orchestration",
    "policy-driven-execution",
    "state-machine-orchestration",
    "management-plane-state-persistence",
]

FAMILY_PREFERENCE = {
    "openwrt-vendor-management-stack": 0,
    "openwrt-shell-helper-sdk": 1,
    "openwrt-mtk-lua-wireless": 2,
    "legacy-boa-apmib": 3,
    "mixed-embedded-control-plane": 4,
    "dual-httpd-lighttpd-nvram": 5,
    "lighttpd-cgi-mtk": 6,
    "opaque-or-partial": 7,
}

HELPER_REF_TOKENS = {
    "config_generate",
    "system.lua",
    "smp.sh",
    "smp-mt76.sh",
    "opkg",
    "mtkwifi.lua",
    "ndppd",
    "autoupgrade.lua",
    "getfirm",
    "dut_auto_upgrade",
    "connmode",
    "cwmp",
    "meshd",
    "firmware.lua",
    "offline_download_monitor.lua",
    "modem.so",
    "mirror_downloader",
    "one_click_upgrade",
    "easycwmp",
    "easycwmpd",
}

ORCHESTRATION_NAME_HINTS = [
    "upgrade",
    "config",
    "conn",
    "mesh",
    "cwmp",
    "firmware",
    "download",
    "offline",
    "system",
    "modem",
    "failover",
    "ping",
    "checkip",
    "notify",
    "schedule",
    "smartvpn",
    "wifi",
    "smp",
    "easycwmp",
    "mtkwifi",
    "tor",
    "wg_",
    "sysconf",
    "ndppd",
    "opkg",
    "route",
]


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def architecture_sort_key(family: str) -> tuple[int, str]:
    return (FAMILY_PREFERENCE.get(family, 99), family)


def normalize_seed_name(name: str | None) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    if "http://" in raw or "https://" in raw or raw.startswith("/"):
        return ""
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    raw = raw.rsplit("::", 1)[-1]
    raw = raw.strip()
    if not raw:
        return ""
    return Path(raw).name


def is_orchestration_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in {x.lower() for x in TARGET_NAMES}:
        return True
    if lowered in {x.lower() for x in HELPER_REF_TOKENS}:
        return True
    return any(hint in lowered for hint in ORCHESTRATION_NAME_HINTS)


def extract_seed_names(bundle: dict) -> set[str]:
    names = {name for name in TARGET_NAMES}
    for field in [
        "management_inventory",
        "helper_script_inventory",
        "execution_wrapper_features",
        "service_topology",
    ]:
        obj = bundle.get(field) or {}
        for key in [
            "management_handlers",
            "helpers",
            "execution_helpers",
            "orchestration_helpers",
            "execution_wrappers",
            "orchestration_hooks",
        ]:
            for value in obj.get(key) or []:
                norm = normalize_seed_name(value)
                if norm and is_orchestration_name(norm):
                    names.add(norm)
    return names


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def has_regex(text: str, pattern: str) -> bool:
    return bool(re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE))


def tokenize_signal_text(text: str) -> str:
    return text.lower()


def detect_feature_flags(kind: str, text: str, imports: list[str], dyn: dict, basename: str) -> tuple[set[str], dict[str, list[str]]]:
    features: set[str] = set()
    evidence: dict[str, list[str]] = defaultdict(list)
    blob = tokenize_signal_text(text)
    imports_lower = {x.lower() for x in imports}
    libs_lower = {x.lower() for x in (dyn.get("needed_libs") or [])}

    shell_wrapper = False
    if any(tok in blob for tok in ["/bin/sh", "os.execute", "io.popen", "session::system", "system(", "popen("]):
        shell_wrapper = True
        evidence["shell-execution-wrapper"].append("string-wrapper")
    if {"system", "popen", "execve", "execl", "execlp", "execvp"} & imports_lower:
        shell_wrapper = True
        evidence["shell-execution-wrapper"].append("import-wrapper")
    if shell_wrapper:
        features.add("shell-execution-wrapper")

    if "/bin/sh" in blob or ('execve' in imports_lower and '/bin/sh' in blob):
        features.add("binsh-execution")
        evidence["binsh-execution"].append("/bin/sh")

    config_markers = [
        "uci get",
        "uci set",
        "uci commit",
        "uci_get_state",
        "config_load",
        "config_get",
        "config_foreach",
        "nvrammanager",
        "nvram get",
        "apmib",
        "getmib",
        "flash get",
        "jsonfilter",
    ]
    has_config = any(tok in blob for tok in config_markers) or "libuci.so" in libs_lower
    if has_config and (shell_wrapper or "/usr/sbin/" in blob or "/usr/bin/" in blob or basename in {"getfirm", "dut_auto_upgrade", "config_generate"}):
        features.add("config-to-command")
        evidence["config-to-command"].append("config+execution")

    ubus_markers = ["ubus call", "ubus send", "ubus listen", "rpcd", "libubus.so", "libubox.so", "ubus_invoke", "ubus_connect"]
    if any(tok in blob for tok in ubus_markers) or {"ubus_connect", "ubus_lookup_id", "ubus_invoke"} & imports_lower or "libubus.so" in libs_lower:
        features.add("ubus-workflow")
        evidence["ubus-workflow"].append("ubus-marker")

    polling_markers = ["while true", "for ;;", "uloop", "poll(", "epoll", "select(", "crond", ".cron", "respawn", "inotifywait"]
    has_polling = any(tok in blob for tok in polling_markers)
    if not has_polling and has_regex(blob, r"\bsleep\s+[0-9]+\b"):
        has_polling = True
    if has_config and has_polling:
        features.add("uci-config-polling")
        evidence["uci-config-polling"].append("config+polling")

    reconnect_markers = ["reconnect", "failover", "retry", "backoff", "delaycount", "wan_speed_busy", "pingcheck", "checkip", "dual_sim", "mesh_connect", "offline_download"]
    has_reconnect = any(tok in blob for tok in reconnect_markers) or basename in {"connmode", "meshd"}
    if has_reconnect and (has_config or has_polling or "state" in blob):
        features.add("deferred-reconnect")
        evidence["deferred-reconnect"].append("reconnect-logic")

    helper_chain = False
    if "/usr/bin/" in blob or "/usr/sbin/" in blob or "lua -e" in blob or "require(" in blob or "procd_open_instance" in blob:
        helper_chain = True
        evidence["helper-driven-execution"].append("path-or-launch")
    else:
        for token in HELPER_REF_TOKENS:
            if token.lower() in blob and token.lower() != basename.lower():
                helper_chain = True
                evidence["helper-driven-execution"].append(token)
                break
    if helper_chain and (shell_wrapper or has_config or "ubus-workflow" in features):
        features.add("helper-driven-execution")

    strong_state_markers = ["transition", "backhaul", "connmode", "meshd", "cwmp", "easymesh", "failover", "offline_download", "topology"]
    has_state = any(tok in blob for tok in strong_state_markers) or basename in {"connmode", "meshd", "cwmp", "offline_download_monitor.lua"}
    if has_state and (has_polling or "ubus-workflow" in features or has_reconnect):
        features.add("event-loop-orchestration")
        evidence["event-loop-orchestration"].append("state+loop")
        features.add("state-machine-orchestration")
        evidence["state-machine-orchestration"].append("state-transition")

    policy_markers = ["upgrade_ready", "wan_speed_busy", "threshold", "policy", "delaycount", "auto_upgrade", "one_click_upgrade", "dual_sim_failover", "offline_download", "pc_schedule"]
    policy_hits = sum(1 for tok in policy_markers if tok in blob)
    if policy_hits >= 1 and (shell_wrapper or has_config or helper_chain):
        features.add("policy-driven-execution")
        evidence["policy-driven-execution"].append("policy-checks")

    persistence_markers = ["uci commit", "uci_commit_flash", "nvrammanager", "nvram get", "persist", "save_config", "touch /tmp/auto_update_lock", "touch /tmp/", "applogin_flag", "lock.lua"]
    if any(tok in blob for tok in persistence_markers) and (has_config or has_reconnect or shell_wrapper):
        features.add("management-plane-state-persistence")
        evidence["management-plane-state-persistence"].append("state-persistence")

    return features, evidence


@dataclass
class OrchestrationArtifact:
    corpus_id: str
    vendor: str
    model: str
    version: str
    architecture_family: str
    control_plane: str
    run_id: str
    basename: str
    relpath: str
    kind: str
    path: Path
    sha256: str
    file_desc: str
    features: set[str] = field(default_factory=set)
    feature_evidence: dict[str, list[str]] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    needed_libs: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.vendor} {self.model} {self.version}"

    @property
    def semantics_signature(self) -> str:
        return ",".join(sorted(self.features))


def collect_bundles(workspace_root: Path) -> list[dict]:
    rows = []
    for _, bundle in iter_results(workspace_root):
        meta = bundle.get("target_metadata") or {}
        corpus_id = str(meta.get("corpus_id") or "").strip()
        if not corpus_id:
            continue
        rows.append(bundle)
    return rows


def collect_artifacts(workspace_root: Path) -> tuple[list[OrchestrationArtifact], list[dict]]:
    bundles = collect_bundles(workspace_root)
    artifacts: list[OrchestrationArtifact] = []
    for bundle in bundles:
        meta = bundle.get("target_metadata") or {}
        corpus_id = str(meta.get("corpus_id") or "")
        family = str((bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        control_plane = str((bundle.get("service_topology") or {}).get("control_plane") or "unknown")
        system_root = resolve_system_root(bundle)
        if not system_root or not system_root.exists():
            continue
        seed_names = extract_seed_names(bundle)
        per_target: dict[tuple[str, str], OrchestrationArtifact] = {}
        for path in system_root.rglob("*"):
            if not path.is_file():
                continue
            basename = path.name
            if basename not in seed_names:
                continue
            kind = detect_kind(path)
            if kind not in {"elf", "lua", "script", "text"}:
                continue
            relpath = rel_after_root(system_root, path)
            desc = file_description(path)
            imports: list[str] = []
            dyn: dict = {}
            signal_text = ""
            if kind == "elf":
                imports = parse_dyn_imports(path)
                dyn = parse_readelf_dynamic(path)
                signal_text = "\n".join(parse_strings(path))
            else:
                signal_text = load_text(path)
            features, evidence = detect_feature_flags(kind, signal_text, imports, dyn, basename)
            if not features:
                continue
            art = OrchestrationArtifact(
                corpus_id=corpus_id,
                vendor=str(meta.get("vendor") or "UNKNOWN"),
                model=str(meta.get("model") or "UNKNOWN"),
                version=str(meta.get("version") or "UNKNOWN"),
                architecture_family=family,
                control_plane=control_plane,
                run_id=str(meta.get("run_id") or ""),
                basename=basename,
                relpath=relpath,
                kind=kind,
                path=path,
                sha256=sha256_path(path),
                file_desc=desc,
                features=features,
                feature_evidence={k: sorted(set(v)) for k, v in evidence.items()},
                imports=imports,
                needed_libs=sorted(set(dyn.get("needed_libs") or [])),
            )
            key = (basename, art.sha256)
            existing = per_target.get(key)
            if existing is None or rel_rank(art.relpath) < rel_rank(existing.relpath):
                per_target[key] = art
        artifacts.extend(sorted(per_target.values(), key=lambda a: (a.corpus_id, a.basename, a.relpath)))
    return artifacts, bundles


def render_artifact_bullets(rows: list[OrchestrationArtifact], limit: int = 10) -> list[str]:
    out = []
    for art in rows[:limit]:
        out.append(
            f"- `{art.label}` / family=`{art.architecture_family}` / control=`{art.control_plane}` / file=`{art.relpath}` / features=`{art.semantics_signature}`"
        )
    if len(rows) > limit:
        out.append(f"- `... {len(rows) - limit} more`")
    return out or ["- `(none)`"]


def build_reports(workspace_root: Path, artifacts: list[OrchestrationArtifact], bundles: list[dict]) -> dict[str, list[str]]:
    total_targets = len({str((b.get("target_metadata") or {}).get("corpus_id") or "") for b in bundles})
    target_feature_sets = defaultdict(set)
    family_feature_targets = defaultdict(set)
    basename_feature_counts = Counter()
    wrapper_signature_counts = Counter()
    helper_ecosystem_targets = set()
    family_targets = defaultdict(set)
    control_plane_targets = defaultdict(set)
    execution_mode_targets = defaultdict(set)
    command_template_targets = defaultdict(set)

    for bundle in bundles:
        meta = bundle.get("target_metadata") or {}
        corpus_id = str(meta.get("corpus_id") or "")
        family = str((bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        family_targets[family].add(corpus_id)
        control_plane = str((bundle.get("service_topology") or {}).get("control_plane") or "unknown")
        control_plane_targets[control_plane].add(corpus_id)
        wrappers = (bundle.get("execution_wrapper_features") or {}).get("execution_wrappers") or []
        if wrappers:
            wrapper_signature_counts[",".join(sorted(str(x) for x in wrappers))] += 1
        helper_inventory = bundle.get("helper_script_inventory") or {}
        helper_count = len(set(helper_inventory.get("helpers") or []))
        if helper_count >= 2 or len(wrappers) >= 2:
            helper_ecosystem_targets.add(corpus_id)
        cmdf = bundle.get("command_materialization_features") or {}
        for mode, count in (cmdf.get("execution_modes") or {}).items():
            if count:
                execution_mode_targets[str(mode)].add(corpus_id)
        for template, count in (cmdf.get("command_templates") or {}).items():
            if count:
                command_template_targets[str(template)].add(corpus_id)

    for art in artifacts:
        for feature in art.features:
            target_feature_sets[feature].add(art.corpus_id)
            family_feature_targets[(art.architecture_family, feature)].add(art.corpus_id)
            basename_feature_counts[(art.basename, feature)] += 1

    feature_artifacts = defaultdict(list)
    basename_clusters = defaultdict(list)
    state_machine_clusters = defaultdict(list)
    for art in artifacts:
        for feature in art.features:
            feature_artifacts[feature].append(art)
        basename_clusters[(art.basename, art.architecture_family, art.semantics_signature)].append(art)
        if {"state-machine-orchestration", "event-loop-orchestration", "deferred-reconnect"} & art.features:
            key = (
                art.architecture_family,
                art.control_plane,
                ",".join(sorted(x for x in art.features if x in {"state-machine-orchestration", "event-loop-orchestration", "deferred-reconnect", "ubus-workflow", "policy-driven-execution"})),
            )
            state_machine_clusters[key].append(art)

    feature_summary_lines = []
    for feature in PRIMITIVE_ORDER:
        feature_summary_lines.append(
            f"- `{feature}`: `{len(target_feature_sets[feature])}/{total_targets}` targets, `{len(feature_artifacts[feature])}` artifacts"
        )

    family_lines = []
    for family in sorted(family_targets, key=architecture_sort_key):
        bits = []
        for feature in PRIMITIVE_ORDER:
            count = len(family_feature_targets[(family, feature)])
            if count:
                bits.append(f"{feature}={count}")
        family_lines.append(
            f"- `{family}`: `{len(family_targets[family])}` targets / {', '.join(bits) if bits else 'no scanned orchestration primitives'}"
        )

    top_wrapper_lines = [
        f"- `{sig}`: `{count}` targets"
        for sig, count in wrapper_signature_counts.most_common(15)
    ] or ["- `(none)`"]

    deferred_targets = execution_mode_targets.get("deferred", set())
    direct_targets = execution_mode_targets.get("direct", set())
    mgmt_targets = execution_mode_targets.get("management-plane", set())
    materialized_targets = execution_mode_targets.get("materialized", set())

    reports: dict[str, list[str]] = {}
    reports["orchestration_primitive_prevalence.md"] = [
        "# Orchestration Primitive Prevalence",
        "",
        f"- corpus targets: `{total_targets}`",
        f"- artifacts with orchestration semantics: `{len(artifacts)}`",
        f"- targets with multi-helper ecosystems: `{len(helper_ecosystem_targets)}/{total_targets}`",
        f"- targets with deferred execution metadata: `{len(deferred_targets)}/{total_targets}`",
        f"- targets with direct execution metadata: `{len(direct_targets)}/{total_targets}`",
        f"- targets with management-plane execution metadata: `{len(mgmt_targets)}/{total_targets}`",
        f"- targets with materialized execution metadata: `{len(materialized_targets)}/{total_targets}`",
        "",
        "## Primitive Prevalence",
        "",
        *feature_summary_lines,
        "",
        "## Architecture Family Spread",
        "",
        *family_lines,
    ]

    reports["execution_wrapper_recurrence.md"] = [
        "# Execution Wrapper Recurrence",
        "",
        f"- wrapper signatures observed: `{len(wrapper_signature_counts)}`",
        "",
        "## Top Wrapper Signatures",
        "",
        *top_wrapper_lines,
        "",
        "## Reusable Wrapper Families",
        "",
    ]
    wrapper_family_groups = defaultdict(list)
    for art in artifacts:
        if art.basename in {"system.lua", "config_generate", "smp.sh", "smp-mt76.sh", "opkg", "mtkwifi.lua", "ndppd"}:
            wrapper_family_groups[art.basename].append(art)
    for basename, rows in sorted(wrapper_family_groups.items(), key=lambda item: (-len({r.corpus_id for r in item[1]}), item[0])):
        targets = len({r.corpus_id for r in rows})
        vendors = sorted({r.vendor for r in rows})
        reports["execution_wrapper_recurrence.md"].append(f"## `{basename}` `{stable_id('wrapper', basename)}`")
        reports["execution_wrapper_recurrence.md"].append(
            f"- targets: `{targets}` / vendors: `{', '.join(vendors)}` / architectures: `{', '.join(sorted({r.architecture_family for r in rows}, key=architecture_sort_key))}`"
        )
        reports["execution_wrapper_recurrence.md"].append(
            f"- semantics: `{', '.join(sorted({feat for r in rows for feat in r.features}))}`"
        )
        reports["execution_wrapper_recurrence.md"].extend(render_artifact_bullets(rows))
        reports["execution_wrapper_recurrence.md"].append("")
    if reports["execution_wrapper_recurrence.md"][-1] != "":
        pass

    reports["deferred_execution_patterns.md"] = [
        "# Deferred Execution Patterns",
        "",
        f"- metadata deferred targets: `{len(deferred_targets)}`",
        f"- `/bin/sh` template targets: `{len(command_template_targets.get('/bin/sh', set()))}`",
        f"- `system.$cfg` template targets: `{len(command_template_targets.get('system.$cfg', set()))}`",
        f"- config-to-command primitive targets: `{len(target_feature_sets['config-to-command'])}`",
        f"- policy-driven execution targets: `{len(target_feature_sets['policy-driven-execution'])}`",
        "",
        "## Dominant Deferred Families",
        "",
    ]
    deferred_clusters = []
    for (basename, family, sig), rows in basename_clusters.items():
        if "config-to-command" not in sig and "policy-driven-execution" not in sig and "helper-driven-execution" not in sig:
            continue
        deferred_clusters.append((basename, family, sig, rows))
    deferred_clusters.sort(key=lambda item: (-len({r.corpus_id for r in item[3]}), item[0], architecture_sort_key(item[1])))
    for basename, family, sig, rows in deferred_clusters[:20]:
        reports["deferred_execution_patterns.md"].append(f"## `{basename}` `{stable_id('deferred', basename, family, sig)}`")
        reports["deferred_execution_patterns.md"].append(
            f"- architecture: `{family}` / targets: `{len({r.corpus_id for r in rows})}` / semantics: `{sig}`"
        )
        reports["deferred_execution_patterns.md"].extend(render_artifact_bullets(rows))
        reports["deferred_execution_patterns.md"].append("")

    reports["management_plane_execution_semantics.md"] = [
        "# Management-Plane Execution Semantics",
        "",
        "## Execution Mode Prevalence",
        "",
        f"- `deferred`: `{len(deferred_targets)}/{total_targets}`",
        f"- `management-plane`: `{len(mgmt_targets)}/{total_targets}`",
        f"- `direct`: `{len(direct_targets)}/{total_targets}`",
        f"- `materialized`: `{len(materialized_targets)}/{total_targets}`",
        "",
        "## Control-Plane Families",
        "",
    ]
    for control_plane, targets in sorted(control_plane_targets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        matching = [art for art in artifacts if art.control_plane == control_plane]
        sem = Counter()
        for art in matching:
            for feat in art.features:
                sem[feat] += 1
        reports["management_plane_execution_semantics.md"].append(
            f"- `{control_plane}`: `{len(targets)}` targets / top semantics=`{', '.join(f'{k}:{v}' for k,v in sem.most_common(5)) or 'none'}`"
        )

    reports["state_machine_orchestration_clusters.md"] = [
        "# State-Machine Orchestration Clusters",
        "",
        f"- state-machine targets: `{len(target_feature_sets['state-machine-orchestration'])}`",
        f"- deferred reconnect targets: `{len(target_feature_sets['deferred-reconnect'])}`",
        f"- ubus workflow targets: `{len(target_feature_sets['ubus-workflow'])}`",
        "",
    ]
    cluster_rows = sorted(
        state_machine_clusters.items(),
        key=lambda item: (-len({r.corpus_id for r in item[1]}), architecture_sort_key(item[0][0]), item[0][1], item[0][2]),
    )
    for (family, control_plane, sig), rows in cluster_rows[:20]:
        reports["state_machine_orchestration_clusters.md"].append(
            f"## `{stable_id('state-cluster', family, control_plane, sig)}`"
        )
        reports["state_machine_orchestration_clusters.md"].append(
            f"- architecture: `{family}` / control-plane: `{control_plane}` / semantics: `{sig}` / targets: `{len({r.corpus_id for r in rows})}`"
        )
        reports["state_machine_orchestration_clusters.md"].extend(render_artifact_bullets(rows))
        reports["state_machine_orchestration_clusters.md"].append("")

    reports["corpus_level_execution_abstractions.md"] = [
        "# Corpus-Level Execution Abstractions",
        "",
        "## Architecture-Level Abstractions",
        "",
    ]
    for family in sorted(family_targets, key=architecture_sort_key):
        family_arts = [art for art in artifacts if art.architecture_family == family]
        wrappers = Counter(art.basename for art in family_arts if "shell-execution-wrapper" in art.features or "helper-driven-execution" in art.features)
        reports["corpus_level_execution_abstractions.md"].append(f"## `{family}`")
        reports["corpus_level_execution_abstractions.md"].append(
            f"- targets: `{len(family_targets[family])}` / artifacts: `{len(family_arts)}`"
        )
        reports["corpus_level_execution_abstractions.md"].append(
            f"- top abstractions: `{', '.join(f'{name}:{count}' for name, count in wrappers.most_common(6)) or 'none'}`"
        )
        feature_counts = Counter()
        for art in family_arts:
            for feat in art.features:
                feature_counts[feat] += 1
        reports["corpus_level_execution_abstractions.md"].append(
            f"- semantic mix: `{', '.join(f'{name}:{count}' for name, count in feature_counts.most_common(8)) or 'none'}`"
        )
        reports["corpus_level_execution_abstractions.md"].append("")

    return reports


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE))
    args = parser.parse_args()

    workspace_root = Path(args.workspace_root).resolve()
    artifacts, bundles = collect_artifacts(workspace_root)
    reports = build_reports(workspace_root, artifacts, bundles)
    for name, lines in reports.items():
        write_md(workspace_root / name, lines)
    print(
        json.dumps(
            {
                "workspace_root": str(workspace_root),
                "bundles": len(bundles),
                "artifacts": len(artifacts),
                "reports": REPORT_FILES,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
