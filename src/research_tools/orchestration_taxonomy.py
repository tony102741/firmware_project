"""
Construct a corpus-wide taxonomy for management-plane execution abstractions.

Usage:
  python3 src/research_tools/orchestration_taxonomy.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from research_tools.binary_inheritance_report import DEFAULT_WORKSPACE, stable_id
from research_tools.orchestration_primitive_prevalence import (
    OrchestrationArtifact,
    architecture_sort_key,
    collect_artifacts,
)


REPORT_FILES = [
    "orchestration_taxonomy.md",
    "execution_abstraction_models.md",
    "helper_ecosystem_taxonomy.md",
    "management_plane_architecture_patterns.md",
    "deferred_execution_models.md",
]

ARCH_FAMILIES = [
    "openwrt-vendor-management-stack",
    "openwrt-shell-helper-sdk",
    "openwrt-mtk-lua-wireless",
    "legacy-boa-apmib",
    "mixed-embedded-control-plane",
]

MODEL_ORDER = [
    "direct-shell-wrapper",
    "deferred-execution-engine",
    "policy-driven-reconnect-engine",
    "helper-triggered-execution",
    "event-loop-orchestration",
    "state-machine-driven-execution",
    "config-materialization-workflow",
    "ubus-rpcd-orchestration",
    "lua-helper-orchestration",
    "daemon-helper-split-orchestration",
]


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def render_artifacts(rows: list[OrchestrationArtifact], limit: int = 8) -> list[str]:
    out = []
    for art in rows[:limit]:
        out.append(
            f"- `{art.label}` / family=`{art.architecture_family}` / control=`{art.control_plane}` / file=`{art.relpath}`"
        )
    if len(rows) > limit:
        out.append(f"- `... {len(rows) - limit} more`")
    return out or ["- `(none)`"]


def classify_model(art: OrchestrationArtifact) -> set[str]:
    feats = art.features
    models = set()
    if "shell-execution-wrapper" in feats and len(feats) <= 3:
        models.add("direct-shell-wrapper")
    if "config-to-command" in feats:
        models.add("config-materialization-workflow")
    if "deferred-reconnect" in feats or ("helper-driven-execution" in feats and "config-to-command" in feats):
        models.add("deferred-execution-engine")
    if "deferred-reconnect" in feats and "policy-driven-execution" in feats:
        models.add("policy-driven-reconnect-engine")
    if "helper-driven-execution" in feats:
        models.add("helper-triggered-execution")
    if "event-loop-orchestration" in feats:
        models.add("event-loop-orchestration")
    if "state-machine-orchestration" in feats:
        models.add("state-machine-driven-execution")
    if "ubus-workflow" in feats:
        models.add("ubus-rpcd-orchestration")
    if art.kind == "lua" and ("helper-driven-execution" in feats or "policy-driven-execution" in feats):
        models.add("lua-helper-orchestration")
    if art.basename in {"connmode", "meshd", "cwmp", "ndppd", "dut_auto_upgrade"} or (
        art.basename in {"cwmpd", "easycwmpd"} and "helper-driven-execution" in feats
    ):
        models.add("daemon-helper-split-orchestration")
    return models


def trigger_source(art: OrchestrationArtifact) -> str:
    feats = art.features
    if "ubus-workflow" in feats:
        return "ubus-or-rpcd"
    if art.basename in {"offline_download_monitor.lua", "firmware.lua", "autoupgrade.lua", "system.lua"}:
        return "management-ui-or-lua-controller"
    if "config-to-command" in feats:
        return "config-derived"
    if "deferred-reconnect" in feats:
        return "policy-or-connectivity"
    return "helper-local"


def state_persistence_model(art: OrchestrationArtifact) -> str:
    if "management-plane-state-persistence" in art.features and "config-to-command" in art.features:
        return "persistent-config-state"
    if "management-plane-state-persistence" in art.features:
        return "transient-file-or-flag-state"
    if "state-machine-orchestration" in art.features:
        return "in-memory-or-daemon-state"
    return "minimal-or-implicit"


def helper_interaction_style(art: OrchestrationArtifact) -> str:
    if art.basename in {"connmode", "meshd", "cwmp", "ndppd", "cwmpd", "easycwmpd"}:
        return "daemon-helper-split"
    if art.kind == "lua":
        return "lua-dispatch-helper"
    if art.basename in {"config_generate", "system.lua", "smp.sh", "smp-mt76.sh", "opkg"}:
        return "shared-wrapper-utility"
    return "single-helper-or-script"


def shell_materialization_mechanism(art: OrchestrationArtifact) -> str:
    feats = art.features
    if art.basename == "config_generate":
        return "config-emission-wrapper"
    if "binsh-execution" in feats and art.kind in {"script", "text"}:
        return "shell-script-wrapper"
    if art.kind == "lua" and "shell-execution-wrapper" in feats:
        return "lua-shell-bridge"
    if art.kind == "elf" and "shell-execution-wrapper" in feats:
        return "daemon-or-binary-exec-wrapper"
    return "non-shell-or-implicit"


def ipc_structure(art: OrchestrationArtifact) -> str:
    if "ubus-workflow" in art.features:
        return "ubus-rpcd"
    if art.control_plane == "opaque-or-minimal":
        return "opaque-local-control"
    if art.kind == "lua":
        return "luci-local-dispatch"
    return "local-script-or-daemon"


def lifecycle_model(art: OrchestrationArtifact) -> str:
    if "event-loop-orchestration" in art.features:
        return "loop-or-scheduled"
    if "policy-driven-execution" in art.features:
        return "policy-gated"
    if "helper-driven-execution" in art.features:
        return "helper-dispatch"
    return "single-shot"


def reconnect_semantics(art: OrchestrationArtifact) -> str:
    if "deferred-reconnect" in art.features and "policy-driven-execution" in art.features:
        return "policy-gated-reconnect"
    if "deferred-reconnect" in art.features:
        return "retry-failover-reconnect"
    if art.basename in {"connmode", "meshd", "cwmp", "pingcheck", "checkip"}:
        return "connectivity-monitoring"
    return "none-observed"


def taxonomy_dimensions(art: OrchestrationArtifact) -> dict[str, str]:
    return {
        "trigger_source": trigger_source(art),
        "state_persistence": state_persistence_model(art),
        "helper_interaction": helper_interaction_style(art),
        "shell_materialization": shell_materialization_mechanism(art),
        "ipc_structure": ipc_structure(art),
        "lifecycle": lifecycle_model(art),
        "reconnect_semantics": reconnect_semantics(art),
    }


def build_reports(workspace_root: Path, artifacts: list[OrchestrationArtifact], bundles: list[dict]) -> dict[str, list[str]]:
    total_targets = len({str((b.get("target_metadata") or {}).get("corpus_id") or "") for b in bundles})
    model_targets = defaultdict(set)
    model_artifacts = defaultdict(list)
    family_targets = defaultdict(set)
    family_model_targets = defaultdict(set)
    vendor_model_targets = defaultdict(set)
    primitive_clusters = defaultdict(list)
    helper_ecosystems = defaultdict(list)
    policy_engines = defaultdict(list)
    state_machine_reuse = defaultdict(list)
    dims_counter = defaultdict(Counter)

    for bundle in bundles:
        meta = bundle.get("target_metadata") or {}
        corpus_id = str(meta.get("corpus_id") or "")
        family = str((bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        family_targets[family].add(corpus_id)

    for art in artifacts:
        models = classify_model(art)
        dims = taxonomy_dimensions(art)
        for k, v in dims.items():
            dims_counter[k][v] += 1
        for model in models:
            model_targets[model].add(art.corpus_id)
            model_artifacts[model].append(art)
            family_model_targets[(art.architecture_family, model)].add(art.corpus_id)
            vendor_model_targets[(art.vendor, model)].add(art.corpus_id)
        primitive_key = (art.basename, art.architecture_family, ",".join(sorted(models)))
        primitive_clusters[primitive_key].append(art)
        if "helper-triggered-execution" in models or "daemon-helper-split-orchestration" in models:
            helper_ecosystems[(art.architecture_family, art.control_plane)].append(art)
        if "policy-driven-reconnect-engine" in models or "policy-driven-execution" in art.features:
            policy_engines[(art.architecture_family, art.basename)].append(art)
        if "state-machine-driven-execution" in models:
            state_machine_reuse[(art.architecture_family, art.basename)].append(art)

    reports: dict[str, list[str]] = {}

    reports["orchestration_taxonomy.md"] = [
        "# Orchestration Taxonomy",
        "",
        f"- corpus targets: `{total_targets}`",
        f"- orchestration artifacts: `{len(artifacts)}`",
        "",
        "## Execution Abstraction Models",
        "",
    ]
    for model in MODEL_ORDER:
        reports["orchestration_taxonomy.md"].append(
            f"- `{model}`: `{len(model_targets[model])}/{total_targets}` targets, `{len(model_artifacts[model])}` artifacts"
        )
    reports["orchestration_taxonomy.md"].extend(["", "## Taxonomy Dimensions", ""])
    for dim in [
        "trigger_source",
        "state_persistence",
        "helper_interaction",
        "shell_materialization",
        "ipc_structure",
        "lifecycle",
        "reconnect_semantics",
    ]:
        reports["orchestration_taxonomy.md"].append(f"### `{dim}`")
        for value, count in dims_counter[dim].most_common():
            reports["orchestration_taxonomy.md"].append(f"- `{value}`: `{count}` artifacts")
        reports["orchestration_taxonomy.md"].append("")

    reports["execution_abstraction_models.md"] = [
        "# Execution Abstraction Models",
        "",
    ]
    for model in MODEL_ORDER:
        arts = model_artifacts[model]
        if not arts:
            continue
        reports["execution_abstraction_models.md"].append(f"## `{model}` `{stable_id('tax-model', model)}`")
        reports["execution_abstraction_models.md"].append(
            f"- targets: `{len(model_targets[model])}` / families: `{', '.join(sorted({a.architecture_family for a in arts}, key=architecture_sort_key))}` / vendors: `{', '.join(sorted({a.vendor for a in arts}))}`"
        )
        top_names = Counter(a.basename for a in arts)
        reports["execution_abstraction_models.md"].append(
            f"- dominant primitives: `{', '.join(f'{name}:{count}' for name, count in top_names.most_common(8))}`"
        )
        reports["execution_abstraction_models.md"].extend(render_artifacts(arts))
        reports["execution_abstraction_models.md"].append("")

    reports["helper_ecosystem_taxonomy.md"] = [
        "# Helper Ecosystem Taxonomy",
        "",
    ]
    for (family, control_plane), arts in sorted(helper_ecosystems.items(), key=lambda item: (-len({a.corpus_id for a in item[1]}), architecture_sort_key(item[0][0]))):
        targets = len({a.corpus_id for a in arts})
        reports["helper_ecosystem_taxonomy.md"].append(
            f"## `{stable_id('helper-eco', family, control_plane)}`"
        )
        reports["helper_ecosystem_taxonomy.md"].append(
            f"- architecture: `{family}` / control-plane: `{control_plane}` / targets: `{targets}`"
        )
        top_names = Counter(a.basename for a in arts)
        reports["helper_ecosystem_taxonomy.md"].append(
            f"- helper ecosystem: `{', '.join(f'{name}:{count}' for name, count in top_names.most_common(10))}`"
        )
        model_mix = Counter(m for a in arts for m in classify_model(a))
        reports["helper_ecosystem_taxonomy.md"].append(
            f"- model mix: `{', '.join(f'{name}:{count}' for name, count in model_mix.most_common(8))}`"
        )
        reports["helper_ecosystem_taxonomy.md"].extend(render_artifacts(arts))
        reports["helper_ecosystem_taxonomy.md"].append("")

    reports["management_plane_architecture_patterns.md"] = [
        "# Management-Plane Architecture Patterns",
        "",
    ]
    for family in ARCH_FAMILIES:
        arts = [a for a in artifacts if a.architecture_family == family]
        if not arts:
            continue
        reports["management_plane_architecture_patterns.md"].append(f"## `{family}`")
        reports["management_plane_architecture_patterns.md"].append(
            f"- targets: `{len(family_targets[family])}` / artifacts: `{len(arts)}`"
        )
        model_mix = Counter(m for a in arts for m in classify_model(a))
        reports["management_plane_architecture_patterns.md"].append(
            f"- abstraction mix: `{', '.join(f'{name}:{count}' for name, count in model_mix.most_common(8))}`"
        )
        dims = Counter()
        for a in arts:
            dims[taxonomy_dimensions(a)["ipc_structure"]] += 1
        reports["management_plane_architecture_patterns.md"].append(
            f"- IPC/control-plane style: `{', '.join(f'{name}:{count}' for name, count in dims.most_common())}`"
        )
        top_primitives = Counter(a.basename for a in arts)
        reports["management_plane_architecture_patterns.md"].append(
            f"- recurring primitives: `{', '.join(f'{name}:{count}' for name, count in top_primitives.most_common(8))}`"
        )
        reports["management_plane_architecture_patterns.md"].append("")

    reports["deferred_execution_models.md"] = [
        "# Deferred Execution Models",
        "",
    ]
    deferred_like = defaultdict(list)
    for (basename, family, model_sig), arts in primitive_clusters.items():
        if "deferred-execution-engine" in model_sig or "config-materialization-workflow" in model_sig or "policy-driven-reconnect-engine" in model_sig:
            deferred_like[(basename, family, model_sig)] = arts
    for (basename, family, model_sig), arts in sorted(
        deferred_like.items(),
        key=lambda item: (-len({a.corpus_id for a in item[1]}), item[0][0], architecture_sort_key(item[0][1])),
    ):
        reports["deferred_execution_models.md"].append(
            f"## `{basename}` `{stable_id('deferred-model', basename, family, model_sig)}`"
        )
        reports["deferred_execution_models.md"].append(
            f"- architecture: `{family}` / targets: `{len({a.corpus_id for a in arts})}` / abstraction models: `{model_sig}`"
        )
        dim_mix = Counter(taxonomy_dimensions(a)["trigger_source"] for a in arts)
        reports["deferred_execution_models.md"].append(
            f"- trigger sources: `{', '.join(f'{name}:{count}' for name, count in dim_mix.most_common())}`"
        )
        reports["deferred_execution_models.md"].extend(render_artifacts(arts))
        reports["deferred_execution_models.md"].append("")

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
                "artifacts": len(artifacts),
                "reports": REPORT_FILES,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
