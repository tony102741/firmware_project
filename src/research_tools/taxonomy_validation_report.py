"""
Validate management-plane orchestration taxonomy consistency and reproducibility.

Usage:
  python3 src/research_tools/taxonomy_validation_report.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from research_tools.binary_inheritance_report import DEFAULT_WORKSPACE, iter_results
from research_tools.orchestration_primitive_prevalence import collect_artifacts
from research_tools.orchestration_taxonomy import (
    ARCH_FAMILIES,
    MODEL_ORDER,
    classify_model,
    taxonomy_dimensions,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_FILES = [
    "taxonomy_validation.md",
    "clustering_consistency.md",
    "abstraction_model_overlap.md",
    "semantic_separability.md",
    "taxonomy_vs_sink_prevalence.md",
    "reproducibility_validation.md",
]


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_fresh(workspace_root: Path):
    artifacts, bundles = collect_artifacts(workspace_root)
    bundle_by_id = {}
    for _, bundle in iter_results(workspace_root):
        meta = bundle.get("target_metadata") or {}
        cid = str(meta.get("corpus_id") or "").strip()
        if cid:
            bundle_by_id[cid] = bundle
    return artifacts, bundles, bundle_by_id


def load_legacy_latest(exclude_root: Path) -> dict[str, dict]:
    out = {}
    for path in sorted((PROJECT_ROOT / "runs").glob("**/results.json")):
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path
        if exclude_root.resolve() in resolved.parents:
            continue
        try:
            bundle = load_json(path)
        except Exception:
            continue
        meta = bundle.get("target_metadata") or {}
        cid = str(meta.get("corpus_id") or "").strip()
        if not cid:
            continue
        prev = out.get(cid)
        if prev is None or str(path) > str(prev["path"]):
            out[cid] = {"path": path, "bundle": bundle}
    return out


def target_taxonomy_summary(artifacts, bundle_by_id):
    per_target_models = defaultdict(set)
    per_target_primitives = defaultdict(Counter)
    per_target_dimensions = defaultdict(lambda: defaultdict(Counter))
    per_target_family = {}
    per_target_vendor = {}
    for cid, bundle in bundle_by_id.items():
        per_target_family[cid] = str((bundle.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        per_target_vendor[cid] = str((bundle.get("target_metadata") or {}).get("vendor") or "UNKNOWN")
    for art in artifacts:
        cid = art.corpus_id
        models = classify_model(art)
        per_target_models[cid].update(models)
        per_target_primitives[cid][art.basename] += 1
        dims = taxonomy_dimensions(art)
        for k, v in dims.items():
            per_target_dimensions[cid][k][v] += 1
    return {
        "models": per_target_models,
        "primitives": per_target_primitives,
        "dimensions": per_target_dimensions,
        "family": per_target_family,
        "vendor": per_target_vendor,
    }


def sink_template_sets(bundle_by_id):
    out = defaultdict(set)
    for cid, bundle in bundle_by_id.items():
        cmdf = bundle.get("command_materialization_features") or {}
        for tpl, count in (cmdf.get("command_templates") or {}).items():
            if count:
                out[cid].add(str(tpl))
    return out


def wrapper_sets(bundle_by_id):
    out = defaultdict(set)
    for cid, bundle in bundle_by_id.items():
        wrappers = (bundle.get("execution_wrapper_features") or {}).get("execution_wrappers") or []
        for w in wrappers:
            out[cid].add(str(w))
    return out


def helper_sets(bundle_by_id):
    out = defaultdict(set)
    for cid, bundle in bundle_by_id.items():
        inv = bundle.get("helper_script_inventory") or {}
        for key in ["helpers", "execution_helpers", "orchestration_helpers"]:
            for h in inv.get(key) or []:
                out[cid].add(str(h))
        for h in (bundle.get("execution_wrapper_features") or {}).get("execution_wrappers") or []:
            out[cid].add(str(h))
    return out


def weighted_purity(groups: dict[str, set[str]], labels: dict[str, str]) -> tuple[float, list[tuple[str, int, float, str]]]:
    total = 0
    score = 0.0
    rows = []
    for name, items in groups.items():
        members = [cid for cid in items if cid in labels]
        if not members:
            continue
        counts = Counter(labels[cid] for cid in members)
        dominant_label, dom_count = counts.most_common(1)[0]
        purity = dom_count / len(members)
        total += len(members)
        score += len(members) * purity
        rows.append((name, len(members), purity, dominant_label))
    return (score / total if total else 0.0), sorted(rows, key=lambda x: (-x[2], -x[1], x[0]))


def group_by_model(target_models: dict[str, set[str]]) -> dict[str, set[str]]:
    out = defaultdict(set)
    for cid, models in target_models.items():
        for model in models:
            out[model].add(cid)
    return out


def group_by_sink(target_sinks: dict[str, set[str]]) -> dict[str, set[str]]:
    out = defaultdict(set)
    for cid, sinks in target_sinks.items():
        for sink in sinks:
            out[sink].add(cid)
    return out


def avg_pairwise_similarity(ids: list[str], sets_map: dict[str, set[str]]) -> float:
    pairs = 0
    total = 0.0
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            pairs += 1
            total += jaccard(sets_map.get(ids[i], set()), sets_map.get(ids[j], set()))
    return total / pairs if pairs else 0.0


def build_reports(workspace_root: Path):
    artifacts, bundles, fresh_bundles = load_fresh(workspace_root)
    legacy_latest = load_legacy_latest(workspace_root)
    fresh = target_taxonomy_summary(artifacts, fresh_bundles)
    fresh_sink_sets = sink_template_sets(fresh_bundles)
    fresh_wrapper_sets = wrapper_sets(fresh_bundles)
    fresh_helper_sets = helper_sets(fresh_bundles)

    total_targets = len(fresh_bundles)
    family_labels = fresh["family"]
    vendor_labels = fresh["vendor"]
    model_groups = group_by_model(fresh["models"])
    sink_groups = group_by_sink(fresh_sink_sets)

    model_purity_family, model_family_rows = weighted_purity(model_groups, family_labels)
    sink_purity_family, sink_family_rows = weighted_purity(sink_groups, family_labels)
    model_purity_vendor, model_vendor_rows = weighted_purity(model_groups, vendor_labels)
    sink_purity_vendor, sink_vendor_rows = weighted_purity(sink_groups, vendor_labels)

    dim_entropy = {}
    dim_norm_entropy = {}
    all_dim_counts = defaultdict(Counter)
    for cid, dims in fresh["dimensions"].items():
        for dim, counter in dims.items():
            all_dim_counts[dim].update(counter)
    for dim, counter in all_dim_counts.items():
        entropy = shannon_entropy(counter)
        dim_entropy[dim] = entropy
        base = math.log2(len(counter)) if len(counter) > 1 else 1.0
        dim_norm_entropy[dim] = entropy / base if base else 0.0

    model_overlap = []
    for i, a in enumerate(MODEL_ORDER):
        for b in MODEL_ORDER[i + 1 :]:
            ja = jaccard(model_groups.get(a, set()), model_groups.get(b, set()))
            if ja > 0:
                model_overlap.append((a, b, ja, len(model_groups.get(a, set()) & model_groups.get(b, set()))))
    model_overlap.sort(key=lambda x: (-x[2], -x[3], x[0], x[1]))

    helper_consistency_rows = []
    model_consistency_rows = []
    sink_consistency_rows = []
    for family in ARCH_FAMILIES + sorted(set(family_labels.values()) - set(ARCH_FAMILIES)):
        ids = sorted([cid for cid, fam in family_labels.items() if fam == family])
        if len(ids) < 2:
            continue
        helper_consistency_rows.append((family, len(ids), avg_pairwise_similarity(ids, fresh_helper_sets)))
        model_consistency_rows.append((family, len(ids), avg_pairwise_similarity(ids, fresh["models"])))
        sink_consistency_rows.append((family, len(ids), avg_pairwise_similarity(ids, fresh_sink_sets)))
    helper_consistency_rows.sort(key=lambda x: (-x[2], -x[1], x[0]))
    model_consistency_rows.sort(key=lambda x: (-x[2], -x[1], x[0]))
    sink_consistency_rows.sort(key=lambda x: (-x[2], -x[1], x[0]))

    primitive_counts = Counter()
    for cid, counter in fresh["primitives"].items():
        for primitive in counter:
            primitive_counts[primitive] += 1
    top_primitive_concentration = primitive_counts.most_common(10)
    top_primitive_share = sum(count for _, count in top_primitive_concentration) / max(1, sum(primitive_counts.values()))

    state_machine_targets = {cid for cid, models in fresh["models"].items() if "state-machine-driven-execution" in models}
    state_machine_by_family = Counter(family_labels[cid] for cid in state_machine_targets)

    fresh_rootfs = {}
    for cid, bundle in fresh_bundles.items():
        flags = bundle.get("extraction_quality_flags") or {}
        fresh_rootfs[cid] = bool(flags.get("rootfs_recovered"))
    rootfs_ids = {cid for cid, ok in fresh_rootfs.items() if ok}
    non_rootfs_ids = set(fresh_bundles) - rootfs_ids

    def avg_model_count(ids: set[str]) -> float:
        vals = [len(fresh["models"].get(cid, set())) for cid in ids]
        return (sum(vals) / len(vals)) if vals else 0.0

    comparable_rows = []
    family_agree = 0
    wrapper_agree = 0
    sink_agree = 0
    model_jaccard_total = 0.0
    helper_jaccard_total = 0.0
    comparable = 0
    for cid, legacy in legacy_latest.items():
        if cid not in fresh_bundles:
            continue
        lb = legacy["bundle"]
        lmeta = lb.get("target_metadata") or {}
        if not lmeta:
            continue
        lflags = lb.get("extraction_quality_flags") or {}
        if not lflags.get("rootfs_recovered"):
            continue
        lfamily = str((lb.get("architecture_profile") or {}).get("architecture_family") or "unknown")
        ffamily = family_labels.get(cid, "unknown")
        comparable += 1
        if lfamily == ffamily:
            family_agree += 1
        lw = set((lb.get("execution_wrapper_features") or {}).get("execution_wrappers") or [])
        fw = fresh_wrapper_sets.get(cid, set())
        if lw == fw:
            wrapper_agree += 1
        ls = set((lb.get("command_materialization_features") or {}).get("command_templates") or {})
        fs = fresh_sink_sets.get(cid, set())
        if ls == fs:
            sink_agree += 1
        # Legacy taxonomy proxy from bundle metadata only.
        legacy_models = set()
        if (lb.get("command_materialization_features") or {}).get("execution_modes", {}).get("deferred"):
            legacy_models.add("deferred-execution-engine")
        if lw:
            legacy_models.add("helper-triggered-execution")
        if "system.$cfg" in ls or "eval-getmib" in ls or "rm-productinfo-template" in ls:
            legacy_models.add("config-materialization-workflow")
        if (lb.get("service_topology") or {}).get("control_plane") in {"ubus-control-plane", "rpcd+ubus-control-plane"}:
            legacy_models.add("ubus-rpcd-orchestration")
        if any("lua" in x for x in (lb.get("management_inventory") or {}).get("management_handlers", []) or []):
            legacy_models.add("lua-helper-orchestration")
        fm = fresh["models"].get(cid, set())
        model_jaccard_total += jaccard(fm, legacy_models)
        lh = set()
        inv = lb.get("helper_script_inventory") or {}
        for key in ["helpers", "execution_helpers", "orchestration_helpers"]:
            for h in inv.get(key) or []:
                lh.add(str(h))
        lh.update(lw)
        helper_jaccard_total += jaccard(fresh_helper_sets.get(cid, set()), lh)
        comparable_rows.append(
            (cid, ffamily, lfamily, jaccard(fm, legacy_models), jaccard(fresh_helper_sets.get(cid, set()), lh))
        )

    comparable_rows.sort(key=lambda x: (x[1] != x[2], x[3], x[4], x[0]))

    reports = {}
    reports["taxonomy_validation.md"] = [
        "# Taxonomy Validation",
        "",
        f"- fresh targets: `{total_targets}`",
        f"- taxonomy artifacts: `{len(artifacts)}`",
        f"- model-family weighted purity: `{model_purity_family:.3f}`",
        f"- sink-family weighted purity: `{sink_purity_family:.3f}`",
        f"- model-vendor weighted purity: `{model_purity_vendor:.3f}`",
        f"- sink-vendor weighted purity: `{sink_purity_vendor:.3f}`",
        f"- top-10 primitive concentration: `{top_primitive_share:.3f}`",
        "",
        "## Primary Readout",
        "",
        f"- taxonomy family coherence exceeds sink grouping by `{model_purity_family - sink_purity_family:+.3f}`",
        f"- taxonomy vendor coherence exceeds sink grouping by `{model_purity_vendor - sink_purity_vendor:+.3f}`",
        f"- rootfs-retained targets average `{avg_model_count(rootfs_ids):.2f}` abstraction models vs `{avg_model_count(non_rootfs_ids):.2f}` for non-rootfs targets",
    ]

    reports["clustering_consistency.md"] = [
        "# Clustering Consistency",
        "",
        "## Family Coherence",
        "",
        *[
            f"- `{family}`: helper-set Jaccard=`{helper:.3f}` / model-set Jaccard=`{model:.3f}` / sink-set Jaccard=`{sink:.3f}`"
            for (family, _, helper), (_, _, model), (_, _, sink) in zip(
                sorted(helper_consistency_rows, key=lambda x: x[0]),
                sorted(model_consistency_rows, key=lambda x: x[0]),
                sorted(sink_consistency_rows, key=lambda x: x[0]),
            )
        ],
        "",
        "## Primitive Concentration",
        "",
        *[f"- `{name}`: `{count}` targets" for name, count in top_primitive_concentration],
    ]

    reports["abstraction_model_overlap.md"] = [
        "# Abstraction Model Overlap",
        "",
        "## Top Pairwise Overlaps",
        "",
        *[
            f"- `{a}` ∩ `{b}`: Jaccard=`{score:.3f}` / shared targets=`{shared}`"
            for a, b, score, shared in model_overlap[:20]
        ],
        "",
        "## Overlap Risk Notes",
        "",
        "- High overlap is expected between `deferred-execution-engine`, `helper-triggered-execution`, and `config-materialization-workflow` because they describe layered orchestration roles rather than mutually exclusive classes.",
        "- Lower overlap with `lua-helper-orchestration` and `policy-driven-reconnect-engine` indicates better semantic separability for those specialized models.",
    ]

    reports["semantic_separability.md"] = [
        "# Semantic Separability",
        "",
        "## Dimension Entropy",
        "",
        *[
            f"- `{dim}`: entropy=`{dim_entropy[dim]:.3f}` / normalized=`{dim_norm_entropy[dim]:.3f}`"
            for dim in [
                "trigger_source",
                "state_persistence",
                "helper_interaction",
                "shell_materialization",
                "ipc_structure",
                "lifecycle",
                "reconnect_semantics",
            ]
        ],
        "",
        "## Interpretation",
        "",
        "- Lower normalized entropy on `ipc_structure` and `shell_materialization` means those dimensions are more architecture-anchored and stable.",
        "- Higher entropy on `trigger_source` and `helper_interaction` means those dimensions capture meaningful variation inside the same architecture family rather than collapsing to one label.",
    ]

    reports["taxonomy_vs_sink_prevalence.md"] = [
        "# Taxonomy vs Sink Prevalence",
        "",
        f"- taxonomy family purity: `{model_purity_family:.3f}`",
        f"- sink family purity: `{sink_purity_family:.3f}`",
        f"- taxonomy vendor purity: `{model_purity_vendor:.3f}`",
        f"- sink vendor purity: `{sink_purity_vendor:.3f}`",
        "",
        "## Dominant Taxonomy Clusters",
        "",
        *[
            f"- `{name}`: size=`{size}` / purity=`{purity:.3f}` / dominant family=`{fam}`"
            for name, size, purity, fam in model_family_rows[:12]
        ],
        "",
        "## Dominant Sink Clusters",
        "",
        *[
            f"- `{name}`: size=`{size}` / purity=`{purity:.3f}` / dominant family=`{fam}`"
            for name, size, purity, fam in sink_family_rows[:12]
        ],
        "",
        "## Evaluation",
        "",
        "- Taxonomy grouping is stronger if it produces higher family/vendor purity while retaining interpretable multi-dimensional semantics.",
        "- Raw sink grouping is weaker when generic `/bin/sh` or `system` style templates collapse unrelated architectures into the same bucket.",
    ]

    reports["reproducibility_validation.md"] = [
        "# Reproducibility Validation",
        "",
        f"- comparable fresh-vs-legacy targets with preserved legacy rootfs: `{comparable}`",
        f"- architecture-family agreement: `{family_agree}/{comparable}`",
        f"- execution-wrapper exact agreement: `{wrapper_agree}/{comparable}`",
        f"- sink-template exact agreement: `{sink_agree}/{comparable}`",
        f"- average taxonomy-model Jaccard: `{(model_jaccard_total / comparable) if comparable else 0.0:.3f}`",
        f"- average helper-ecosystem Jaccard: `{(helper_jaccard_total / comparable) if comparable else 0.0:.3f}`",
        "",
        "## Comparable Targets",
        "",
        *[
            f"- `{cid}`: family fresh=`{ff}` / legacy=`{lf}` / model Jaccard=`{mj:.3f}` / helper Jaccard=`{hj:.3f}`"
            for cid, ff, lf, mj, hj in comparable_rows[:20]
        ],
        "",
        "## Distortion Risks",
        "",
        f"- opaque-or-partial fresh targets: `{sum(1 for fam in family_labels.values() if fam == 'opaque-or-partial')}`",
        f"- non-rootfs fresh targets: `{len(non_rootfs_ids)}`",
        "- Weak-signal families should not drive prevalence claims; they should be treated as excluded or partial-confidence slices in paper-facing charts.",
    ]

    return reports


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", default=str(DEFAULT_WORKSPACE))
    args = parser.parse_args()
    workspace_root = Path(args.workspace_root).resolve()
    reports = build_reports(workspace_root)
    for name, lines in reports.items():
        write_md(workspace_root / name, lines)
    print(json.dumps({"workspace_root": str(workspace_root), "reports": REPORT_FILES}, indent=2))


if __name__ == "__main__":
    main()
