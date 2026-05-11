"""
Generate corpus-level tool-improvement reports.

Outputs:
  - corpus completion report
  - candidate quality report
  - false-positive regression report
  - tool-improvement backlog
  - CVE smell queue
  - top targets shortlist
  - tool improvement log
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ARCH_MARKERS = {
    "uhttpd": ["bin/uhttpd", "usr/sbin/uhttpd", "sbin/uhttpd"],
    "boa": ["bin/boa", "usr/sbin/boa", "sbin/boa"],
    "lighttpd": ["usr/sbin/lighttpd", "sbin/lighttpd"],
    "httpd": ["bin/httpd", "usr/sbin/httpd", "sbin/httpd"],
    "nginx": ["usr/sbin/nginx", "sbin/nginx"],
    "luci": ["usr/lib/lua/luci", "www/luci-static"],
    "cgi-bin": ["www/cgi-bin", "usr/lib/cgi-bin", "cgi-bin"],
    "boafrm": ["www/boafrm", "web/boafrm"],
    "procd": ["sbin/procd"],
    "rpcd": ["sbin/rpcd", "usr/sbin/rpcd"],
    "ubus": ["sbin/ubus", "bin/ubus", "usr/sbin/ubus"],
    "uci": ["sbin/uci", "bin/uci"],
    "etc-config": ["etc/config"],
    "etc-initd": ["etc/init.d"],
    "apmib": ["bin/flash", "lib/libapmib.so", "lib/libapmib"],
    "nvram": ["usr/sbin/nvram", "sbin/nvram", "bin/nvram"],
    "mtk-wifi": ["sbin/iwpriv", "lib/wifi", "etc/wireless"],
}

ARCH_HELPERS = [
    "config_generate",
    "smp.sh",
    "smp-mt76.sh",
    "wifi_check_country",
    "getfirm",
    "offline_download_monitor.lua",
    "mtkwifi.lua",
    "autoupgrade.lua",
    "system.lua",
    "easycwmp",
    "dut_auto_upgrade",
    "opkg",
    "ndppd",
    "connmode",
    "firmware.lua",
    "easymesh_network.lua",
]


KNOWN_FP_REGRESSIONS = [
    {
        "firmware": "MR90X (EU)",
        "component": "uhttpd",
        "reason": "Constant command path should not be promoted by exploratory smell collection.",
    },
    {
        "firmware": "MR90X (EU)",
        "component": "miniupnpd",
        "reason": "Bounded-copy SOAP/UPnP parsing without attacker-controlled length should not be promoted as memory corruption.",
    },
    {
        "firmware": "Archer AX23",
        "component": "firmware.lua",
        "reason": "Fixed process-inspection pipelines and cross-function endpoint contamination should not be promoted as command injection.",
    },
    {
        "firmware": "Archer AX23",
        "component": "tdpServer",
        "reason": "Encrypted or key-gated protocol helpers with fixed hardware-query commands should not be treated as unauthenticated command paths.",
    },
    {
        "firmware": "GL-MT3000",
        "component": "wg_client",
        "reason": "Numeric-only command parameters should not be promoted by exploratory smell collection.",
    },
]

KNOWN_ISSUE_SUPPRESSIONS = [
    {
        "model_substr": "A3002RU",
        "component_substr": "formUploadFile",
        "reason": "Known issue already analyzed; do not rediscover in CVE smell queue.",
    },
    {
        "model_substr": "A3002RU",
        "component_substr": "boa",
        "reason": "Known issue already analyzed; do not rediscover in CVE smell queue.",
    },
]


def _norm(text: str | None) -> str:
    raw = str(text or "").lower()
    return "".join(ch for ch in raw if ch.isalnum())


def _stable_id(*parts: str, size: int = 12) -> str:
    joined = "||".join(str(part or "") for part in parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:size]


def _component_family(name: str | None) -> str:
    raw = str(name or "").strip().lower()
    if not raw:
        return "unknown"
    raw = raw.split(":")[0]
    if ".lua/" in raw:
        return raw
    raw = raw.split("::")[0]
    raw = raw.split("(")[0]
    return raw.strip()


def _command_template(candidate: dict) -> str:
    sink = str(candidate.get("confirmed_sink") or "").lower()
    all_sinks = " || ".join(str(x).lower() for x in (candidate.get("all_sinks") or []))
    text = " ".join([
        sink,
        all_sinks,
        str(candidate.get("vuln_summary") or "").lower(),
    ])
    if "system.$cfg" in text:
        return "system.$cfg"
    if "eval `$getmib" in text or ("getmib" in text and "eval" in text):
        return "eval-getmib"
    if "session::system(" in text:
        return "session::system"
    if "os.execute" in text:
        return "os.execute"
    if "io.popen" in text or re.search(r"\bpopen\b", text):
        return "popen"
    if "iwpriv" in text and " set " in text:
        return "iwpriv-set"
    if "grep -v grep" in text and "awk" in text:
        return "grep-awk-pipeline"
    if "curl --user" in text:
        return "curl-user-template"
    if "wget -o /tmp/$filename" in text or "wget -o /tmp/" in text:
        return "wget-output-template"
    if "rm -rf $tmpdir/$subdev" in text:
        return "rm-subdev-template"
    if "rm -f $productinfo" in text:
        return "rm-productinfo-template"
    if "echo %s" in text and (">" in text):
        return "echo-percent-redirect"
    if "/bin/sh" in text:
        return "/bin/sh"
    if "system" in text:
        return "system"
    if "exec" in text:
        return "exec"
    return str(candidate.get("flow_type") or "unknown").lower()


def _source_type(candidate: dict) -> str:
    confirmed_input = str(candidate.get("confirmed_input") or "").lower()
    endpoint = str(candidate.get("endpoint_input") or "").lower()
    config_keys = " ".join(str(x).lower() for x in (candidate.get("config_keys") or []))
    name = str(candidate.get("name") or candidate.get("raw_name") or "").lower()
    if confirmed_input == "query_string":
        return "http-query"
    if any(tok in endpoint for tok in ("/upload", "/restore", "/firmware", "multipart")):
        return "upload-metadata"
    if endpoint not in {"", "unconfirmed"}:
        return "management-endpoint"
    if any(tok in config_keys for tok in ("apmib_get", "apmib_set", "mib", "getmib", "flash", "uci", "nvram")):
        return "config-mib"
    if any(tok in name for tok in ("repeater", "site-survey", "easymesh", "mesh", "wps", "wireless")):
        return "wireless-control-plane"
    if candidate.get("config_keys"):
        return "config-derived"
    return "unconfirmed"


def _sink_type(candidate: dict) -> str:
    sink = str(candidate.get("confirmed_sink") or "").lower()
    all_sinks = " ".join(str(x).lower() for x in (candidate.get("all_sinks") or []))
    text = " ".join([sink, all_sinks])
    if any(tok in text for tok in ("os.execute", "system", "/bin/sh", "popen", "io.popen", "exec")):
        return "shell-exec"
    if any(tok in text for tok in ("strcpy", "sprintf", "strcat", "memcpy", "memmove", "sscanf", "fprintf", "printf")):
        return "copy-format"
    return "unknown"


def _execution_mode(candidate: dict) -> str:
    source_type = _source_type(candidate)
    template = _command_template(candidate)
    endpoint = str(candidate.get("endpoint_input") or "").lower()
    if source_type == "http-query":
        return "direct"
    if source_type in {"config-mib", "config-derived"} or "getmib" in template:
        return "deferred"
    if source_type == "upload-metadata":
        return "materialized"
    if endpoint not in {"", "unconfirmed"}:
        return "management-plane"
    return "operational"


def _recurrence_confidence(candidate: dict) -> str:
    verdict = _candidate_verdict(candidate)
    smell = _derive_smell_strength(candidate)
    if verdict == "cve-ready":
        return "cve-ready"
    if verdict == "promising":
        return "manually-prioritized-candidate"
    if smell == "strong-smell":
        return "strong-candidate"
    if smell == "medium-smell":
        return "medium-candidate"
    if _candidate_verdict_reason(candidate).startswith("reject:"):
        return "suppressed"
    return "idiom-only"


def _false_positive_reason(candidate: dict) -> str:
    verdict_reason = _candidate_verdict_reason(candidate)
    if verdict_reason.startswith("reject:") or "false-positive-risk:" in verdict_reason:
        return verdict_reason
    risks = candidate.get("false_positive_risks") or []
    if risks:
        return f"risk:{sorted(str(r) for r in risks)[0]}"
    return ""


def _parse_recovered_components(bundle: dict) -> list[str]:
    analysis = bundle.get("analysis") or {}
    reason = str(analysis.get("reason") or "").lower()
    candidates = bundle.get("candidates") or []
    names = []
    for cand in candidates:
        if cand.get("web_exposed") or cand.get("handler_surface"):
            names.append(_component_family(cand.get("name") or cand.get("raw_name")))
    components = []
    if "uhttpd" in reason:
        components.append("uhttpd")
    if "boa" in reason:
        components.append("boa")
    if "httpd" in reason:
        components.append("httpd")
    if "lighttpd" in reason:
        components.append("lighttpd")
    if "/www" in reason or "/cgi-bin" in reason:
        components.append("web-assets")
    components.extend(sorted({name for name in names if name and name != "unknown"})[:8])
    return sorted(dict.fromkeys(components))


def _resolve_analysis_root(results_path: Path | None, analysis_path: str | None) -> Path | None:
    if not analysis_path:
        return None
    raw = Path(str(analysis_path))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        if results_path:
            candidates.append((results_path.parent / raw).resolve())
        candidates.append((PROJECT_ROOT / raw).resolve())
        candidates.append((Path("/") / raw).resolve())
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _root_has_any(root: Path, rel_paths: list[str]) -> bool:
    return any((root / rel).exists() for rel in rel_paths)


def _root_glob_exists(root: Path, pattern: str) -> bool:
    try:
        next(root.rglob(pattern))
        return True
    except StopIteration:
        return False
    except Exception:
        return False


def _infer_architecture_family(markers: set[str], helper_names: list[str], success_quality: str) -> str:
    helper_set = set(helper_names)
    if success_quality in {"fallback-success", "missing"} or not markers:
        return "opaque-or-partial"
    if {"boa", "apmib"} <= markers:
        return "legacy-boa-apmib"
    if {"httpd", "lighttpd", "nvram"} <= markers:
        return "dual-httpd-lighttpd-nvram"
    if {"luci", "uci", "ubus"} <= markers and "mtkwifi.lua" in helper_set:
        return "openwrt-mtk-lua-wireless"
    if {"luci", "uci", "ubus", "uhttpd"} <= markers and {"config_generate", "smp.sh"} & helper_set:
        return "openwrt-shell-helper-sdk"
    if {"luci", "uci", "ubus", "uhttpd"} <= markers and {"getfirm", "wifi_check_country", "ndppd"} & helper_set:
        return "openwrt-vendor-management-stack"
    if {"luci", "uci", "ubus", "nginx"} <= markers:
        return "openwrt-nginx-service-stack"
    if {"lighttpd", "cgi-bin", "mtk-wifi"} <= markers:
        return "lighttpd-cgi-mtk"
    if {"luci", "uci", "ubus"} <= markers:
        return "openwrt-derived-generic"
    return "mixed-embedded-control-plane"


def _architecture_provenance_level(
    architecture_family: str,
    markers: set[str],
    helper_names: list[str],
    vendor: str,
) -> tuple[str, str]:
    helper_set = set(helper_names)
    if architecture_family == "opaque-or-partial":
        return "speculative-similarity", "insufficient filesystem recovery; architecture inference is based on partial artifacts only"
    if architecture_family == "legacy-boa-apmib":
        return "probable-shared-lineage", "boa plus apmib is a strong legacy SDK signature, but this pass does not prove OEM provenance"
    if architecture_family == "openwrt-shell-helper-sdk" and {"config_generate", "smp.sh"} <= helper_set:
        return "probable-shared-lineage", "shared OpenWrt-style layout plus repeated shell-helper names suggests reused SDK or OEM helper layers"
    if architecture_family == "openwrt-vendor-management-stack" and {"getfirm", "wifi_check_country", "ndppd"} & helper_set:
        return "probable-shared-lineage", "the same management handlers and config workflow recur within a consistent OpenWrt-derived layout"
    if architecture_family == "openwrt-mtk-lua-wireless":
        return "heuristic-similarity", "Mediatek wireless Lua and OpenWrt-style layout recur, but provenance remains architecture-level only"
    if architecture_family in {"dual-httpd-lighttpd-nvram", "lighttpd-cgi-mtk"}:
        return "heuristic-similarity", "service topology and config style recur, but exact reuse may reflect convergent vendor design"
    if architecture_family == "openwrt-nginx-service-stack":
        return "heuristic-similarity", "layout strongly resembles an OpenWrt-derived service stack with custom web fronting"
    if {"luci", "uci", "ubus"} <= markers:
        return "heuristic-similarity", "shared control-plane building blocks indicate architectural reuse more than exact code provenance"
    return "speculative-similarity", f"markers for {vendor or 'unknown vendor'} are too generic to claim stronger lineage"


def _scan_architecture_profile(item: dict) -> dict:
    corpus = item.get("corpus") or {}
    bundle = item.get("bundle") or {}
    results_path = item.get("results_path")
    analysis = bundle.get("analysis") or {}
    root = _resolve_analysis_root(results_path, analysis.get("system_path"))
    markers = []
    helper_names = []
    if root and root.exists():
        for name, rel_paths in ARCH_MARKERS.items():
            if _root_has_any(root, rel_paths):
                markers.append(name)
        for helper in ARCH_HELPERS:
            if _root_glob_exists(root, helper):
                helper_names.append(helper)
    marker_set = set(markers)
    web_stack = [
        name for name in ("boa", "uhttpd", "lighttpd", "httpd", "nginx", "luci", "cgi-bin", "boafrm")
        if name in marker_set
    ]
    config_layers = [name for name in ("apmib", "uci", "nvram", "etc-config", "ubus") if name in marker_set]
    execution_wrappers = [
        name for name in ("system.lua", "config_generate", "smp.sh", "smp-mt76.sh", "mtkwifi.lua", "opkg", "ndppd", "easycwmp")
        if name in helper_names
    ]
    orchestration_hooks = [
        name for name in ("autoupgrade.lua", "dut_auto_upgrade", "firmware.lua", "easymesh_network.lua", "offline_download_monitor.lua", "getfirm", "connmode")
        if name in helper_names
    ]
    if "procd" in marker_set:
        init_framework = "procd+init.d"
    elif "etc-initd" in marker_set:
        init_framework = "init.d"
    else:
        init_framework = "unknown"
    if {"rpcd", "ubus"} <= marker_set:
        service_topology = "rpcd+ubus-control-plane"
    elif "ubus" in marker_set:
        service_topology = "ubus-control-plane"
    elif "cgi-bin" in marker_set or "boafrm" in marker_set:
        service_topology = "cgi-handler-control-plane"
    else:
        service_topology = "opaque-or-minimal"
    family = _infer_architecture_family(marker_set, helper_names, str(corpus.get("success_quality") or "missing"))
    provenance_level, rationale = _architecture_provenance_level(
        family,
        marker_set,
        helper_names,
        str(corpus.get("vendor") or ""),
    )
    helper_signature = ",".join(sorted(helper_names[:8])) or "none"
    marker_signature = ",".join(sorted(markers)) or "none"
    return {
        "system_root": str(root) if root else "",
        "rootfs_recovered": bool(root and root.exists()),
        "filesystem_markers": sorted(markers),
        "web_stack": web_stack,
        "config_layers": config_layers,
        "init_framework": init_framework,
        "service_topology": service_topology,
        "helper_conventions": sorted(helper_names),
        "execution_wrappers": execution_wrappers,
        "orchestration_hooks": orchestration_hooks,
        "helper_signature": helper_signature,
        "marker_signature": marker_signature,
        "architecture_family": family,
        "provenance_level": provenance_level,
        "provenance_rationale": rationale,
        "architecture_cluster_hint": f"ac-{_stable_id(family, marker_signature, helper_signature)}",
    }


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        return []
    return [
        json.loads(line)
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: str | Path, data) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _resolve_result_path(manifest_path: Path, result_path: str | None) -> Path | None:
    if not result_path:
        return None
    raw = Path(str(result_path))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append((PROJECT_ROOT / raw).resolve())
        candidates.append((manifest_path.parent / raw).resolve())
        candidates.append((PROJECT_ROOT / "runs" / raw.name).resolve())
        candidates.append((Path("/tmp") / raw.name).resolve())
    seen = set()
    for candidate in candidates:
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        if candidate.is_file():
            return candidate
    return None


def build_manifest_index(runs_root: Path) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for manifest_path in runs_root.rglob("manifest.json"):
        try:
            manifest = load_json(manifest_path)
        except Exception:
            continue
        run_id = str(manifest.get("run_id") or manifest_path.parent.name or "")
        if not run_id:
            continue
        resolved = _resolve_result_path(
            manifest_path,
            manifest.get("canonical_result_path") or manifest.get("result_path"),
        )
        row = {
            "manifest_path": manifest_path,
            "manifest": manifest,
            "results_path": resolved,
        }
        keys = {
            run_id,
            manifest_path.parent.name,
            Path(run_id).name,
            manifest_path.parent.parent.name,
            Path(manifest_path.parent.parent.name).stem,
            _norm(manifest_path.parent.parent.name),
            _norm(Path(manifest_path.parent.parent.name).stem),
        }
        for key in keys:
            if key:
                index[key].append(row)
    for rows in index.values():
        rows.sort(
            key=lambda row: (
                1 if row.get("results_path") else 0,
                str(row["manifest_path"].parent.name),
            ),
            reverse=True,
        )
    return index


def _find_manifest_row(manifest_index: dict[str, list[dict]], corpus_row: dict) -> dict | None:
    keys = [
        str(corpus_row.get("run_id") or ""),
        str(corpus_row.get("local_filename") or ""),
        Path(str(corpus_row.get("local_filename") or "")).stem,
        str(corpus_row.get("model") or ""),
        _norm(corpus_row.get("local_filename")),
        _norm(Path(str(corpus_row.get("local_filename") or "")).stem),
        _norm(corpus_row.get("model")),
    ]
    seen = set()
    for key in keys:
        if not key or key in seen:
            continue
        seen.add(key)
        rows = manifest_index.get(key) or []
        if rows:
            return rows[0]
    return None


def build_loose_results_index() -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = defaultdict(list)
    paths = list(Path("/tmp").glob("*results*.json"))
    paths.extend(sorted((PROJECT_ROOT / "runs").glob("**/results.json")))
    for path in paths:
        keys = {
            _norm(path.name),
            _norm(path.stem),
        }
        for parent in path.parts[-5:]:
            if len(parent) >= 4:
                keys.add(_norm(parent))
        for token in path.stem.replace("-", "_").split("_"):
            if len(token) >= 4:
                keys.add(_norm(token))
        for key in keys:
            if key:
                index[key].append(path)
    return index


def build_batch_results_index(batch_summary: dict | None) -> dict[str, Path]:
    index: dict[str, Path] = {}
    if not batch_summary:
        return index
    for row in batch_summary.get("results") or []:
        raw = row.get("results_json")
        if not raw:
            continue
        path = Path(str(raw))
        if not path.is_file():
            continue
        for key in (
            str(row.get("corpus_id") or "").strip(),
            str(row.get("sample") or "").strip(),
            str(Path(str(row.get("sample") or "")).stem).strip(),
        ):
            if key:
                index[key] = path
    return index


def build_canonical_results_index() -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in sorted((PROJECT_ROOT / "runs").glob("**/results.json")):
        try:
            bundle = load_json(path)
        except Exception:
            continue
        target = bundle.get("target_metadata") or {}
        input_obj = bundle.get("input") or {}
        originals = [
            str(target.get("corpus_id") or "").strip(),
            str(target.get("local_filename") or "").strip(),
            str(bundle.get("run_id") or "").strip(),
            str(Path(str((input_obj.get("original") or {}).get("path") or "")).name).strip(),
            str(Path(str((input_obj.get("resolved") or {}).get("path") or "")).name).strip(),
        ]
        for raw in originals:
            if raw:
                index[raw] = path
                index[_norm(raw)] = path
    return index


def _row_result_tokens(corpus_row: dict) -> list[str]:
    model = str(corpus_row.get("model") or "")
    local_filename = str(corpus_row.get("local_filename") or "")
    corpus_id = str(corpus_row.get("corpus_id") or "")
    tokens = {
        _norm(model),
        _norm(local_filename),
        _norm(Path(local_filename).stem),
        _norm(corpus_id),
    }
    for raw in [model, Path(local_filename).stem, corpus_id]:
        for token in str(raw).replace("-", " ").replace("_", " ").split():
            if len(token) >= 4:
                tokens.add(_norm(token))
    return [token for token in tokens if token]


def _find_loose_results(loose_index: dict[str, list[Path]], corpus_row: dict) -> Path | None:
    candidates: list[Path] = []
    seen = set()
    for token in _row_result_tokens(corpus_row):
        for path in loose_index.get(token) or []:
            text = str(path)
            if text in seen:
                continue
            seen.add(text)
            candidates.append(path)
    if len(candidates) == 1:
        return candidates[0]
    ranked = sorted(
        candidates,
        key=lambda path: (
            sum(1 for token in _row_result_tokens(corpus_row) if token and token in _norm(path.name)),
            path.name,
        ),
        reverse=True,
    )
    if ranked and sum(1 for token in _row_result_tokens(corpus_row) if token in _norm(ranked[0].name)) >= 1:
        return ranked[0]
    return None


def load_corpus_bundles(corpus_rows: list[dict], batch_summary: dict | None = None) -> list[dict]:
    manifest_index = build_manifest_index(PROJECT_ROOT / "runs")
    loose_index = build_loose_results_index()
    batch_index = build_batch_results_index(batch_summary)
    canonical_index = build_canonical_results_index()
    bundles = []
    for row in corpus_rows:
        manifest_row = _find_manifest_row(manifest_index, row)
        run_id = str(row.get("run_id") or "").strip()
        run_id_results = (PROJECT_ROOT / "runs" / run_id / "results.json") if run_id else None
        results_path = (
            (run_id_results if run_id_results and run_id_results.is_file() else None)
            or
            canonical_index.get(str(row.get("corpus_id") or "").strip())
            or canonical_index.get(_norm(str(row.get("corpus_id") or "").strip()))
            or canonical_index.get(str(row.get("local_filename") or "").strip())
            or canonical_index.get(_norm(str(row.get("local_filename") or "").strip()))
            or canonical_index.get(str(Path(str(row.get("local_filename") or "")).name).strip())
            or canonical_index.get(_norm(str(Path(str(row.get("local_filename") or "")).name).strip()))
            or
            batch_index.get(str(row.get("corpus_id") or "").strip())
            or batch_index.get(str(row.get("local_filename") or "").strip())
            or batch_index.get(str(Path(str(row.get("local_filename") or "")).stem).strip())
        )
        if results_path is None:
            results_path = manifest_row.get("results_path") if manifest_row else None
        manifest = manifest_row.get("manifest") if manifest_row else None
        manifest_path = manifest_row.get("manifest_path") if manifest_row else None
        if results_path is None:
            results_path = _find_loose_results(loose_index, row)
        if not results_path or not results_path.is_file():
            bundles.append({
                "corpus": row,
                "results_path": None,
                "manifest_path": manifest_path,
                "manifest": manifest,
                "bundle": None,
            })
            continue
        try:
            bundle = load_json(results_path)
        except Exception:
            bundle = None
        bundles.append({
            "corpus": row,
            "results_path": results_path,
            "manifest_path": manifest_path,
            "manifest": manifest,
            "bundle": bundle,
        })
    return bundles


def build_target_summaries(bundles: list[dict]) -> list[dict]:
    rows = []
    for item in bundles:
        corpus = item.get("corpus") or {}
        bundle = item.get("bundle") or {}
        analysis = bundle.get("analysis") or {}
        candidates = bundle.get("candidates") or []
        emitted_target = bundle.get("target_metadata") or {}
        fallback_architecture = _scan_architecture_profile(item)
        emitted_architecture_profile = bundle.get("architecture_profile") or {}
        architecture_profile = emitted_architecture_profile or fallback_architecture
        command_patterns = Counter()
        config_mib_flows = Counter()
        target_candidates = []
        for cand in candidates:
            command_patterns[_command_template(cand)] += 1
            source_type = _source_type(cand)
            execution_mode = _execution_mode(cand)
            if source_type in {"config-mib", "config-derived"} or execution_mode == "deferred":
                config_mib_flows[f"{source_type}->{_command_template(cand)}"] += 1
            target_candidates.append({
                "component": str(cand.get("name") or cand.get("raw_name") or "unknown"),
                "component_family": _component_family(cand.get("name") or cand.get("raw_name")),
                "command_template": _command_template(cand),
                "source_type": source_type,
                "sink_type": _sink_type(cand),
                "execution_mode": execution_mode,
                "candidate_confidence": _recurrence_confidence(cand),
                "candidate_score": int(cand.get("score") or 0),
                "priority_score": _candidate_review_priority(cand)[0],
                "verdict": _candidate_verdict(cand),
                "verdict_reason": _candidate_verdict_reason(cand),
                "false_positive_reason": _false_positive_reason(cand),
            })
        rows.append({
            "corpus_id": emitted_target.get("corpus_id") or corpus.get("corpus_id"),
            "vendor": emitted_target.get("vendor") or corpus.get("vendor"),
            "model": emitted_target.get("model") or corpus.get("model"),
            "version": emitted_target.get("version") or corpus.get("version"),
            "extraction_status": corpus.get("extraction_status") or "missing",
            "analysis_status": corpus.get("analysis_status") or "missing",
            "success_quality": corpus.get("success_quality") or "missing",
            "probe_readiness": corpus.get("probe_readiness") or "missing",
            "blob_family": corpus.get("blob_family") or "none",
            "suspected_stack": corpus.get("suspected_stack") or [],
            "arch": corpus.get("arch") or "",
            "analysis_mode": analysis.get("mode") or "unknown",
            "analysis_reason": analysis.get("reason") or "unknown",
            "recovered_components": _parse_recovered_components(bundle),
            "target_metadata": emitted_target,
            "architecture_profile": architecture_profile,
            "architecture_family": architecture_profile.get("architecture_family") or fallback_architecture.get("architecture_family") or "unknown",
            "architecture_fingerprint": architecture_profile.get("architecture_fingerprint") or "",
            "management_inventory": bundle.get("management_inventory") or {},
            "service_topology": bundle.get("service_topology") or {},
            "config_backend": bundle.get("config_backend") or {},
            "helper_script_inventory": bundle.get("helper_script_inventory") or {},
            "command_materialization_features": bundle.get("command_materialization_features") or {},
            "execution_wrapper_features": bundle.get("execution_wrapper_features") or {},
            "extraction_quality_flags": bundle.get("extraction_quality_flags") or {},
            "artifact_schema_version": bundle.get("artifact_schema_version") or "",
            "architecture_artifact_source": "emitted" if emitted_architecture_profile else "report-time-fallback",
            "fallback_architecture_profile": fallback_architecture,
            "command_materialization_patterns": command_patterns.most_common(8),
            "config_mib_flows": config_mib_flows.most_common(8),
            "candidate_rows": target_candidates,
        })
    rows.sort(key=lambda row: (str(row.get("vendor") or ""), str(row.get("model") or ""), str(row.get("version") or "")))
    return rows


def build_recurrence_clusters(target_summaries: list[dict]) -> list[dict]:
    clusters: dict[tuple[str, str, str, str, str], dict] = {}
    for target in target_summaries:
        for cand in target.get("candidate_rows") or []:
            key = (
                cand.get("component_family") or "unknown",
                cand.get("command_template") or "unknown",
                cand.get("source_type") or "unknown",
                cand.get("sink_type") or "unknown",
                cand.get("execution_mode") or "unknown",
            )
            cluster = clusters.setdefault(key, {
                "cluster_id": f"rc-{_stable_id(*key)}",
                "component_family": key[0],
                "command_template": key[1],
                "source_type": key[2],
                "sink_type": key[3],
                "execution_mode": key[4],
                "vendors": set(),
                "models": set(),
                "versions": set(),
                "firmwares": set(),
                "confidence": Counter(),
                "verdicts": Counter(),
                "false_positive_reasons": Counter(),
                "examples": [],
            })
            firmware_label = f"{target.get('vendor')} {target.get('model')} {target.get('version')}"
            cluster["vendors"].add(str(target.get("vendor") or ""))
            cluster["models"].add(str(target.get("model") or ""))
            cluster["versions"].add(str(target.get("version") or ""))
            cluster["firmwares"].add(firmware_label)
            cluster["confidence"][cand.get("candidate_confidence") or "unknown"] += 1
            cluster["verdicts"][cand.get("verdict") or "unknown"] += 1
            if cand.get("false_positive_reason"):
                cluster["false_positive_reasons"][cand["false_positive_reason"]] += 1
            if len(cluster["examples"]) < 6:
                cluster["examples"].append({
                    "firmware": firmware_label,
                    "component": cand.get("component"),
                    "candidate_confidence": cand.get("candidate_confidence"),
                    "verdict_reason": cand.get("verdict_reason"),
                    "priority_score": cand.get("priority_score"),
                })
            cand["recurrence_cluster_id"] = cluster["cluster_id"]

    rows = []
    for cluster in clusters.values():
        rows.append({
            "cluster_id": cluster["cluster_id"],
            "component_family": cluster["component_family"],
            "command_template": cluster["command_template"],
            "source_type": cluster["source_type"],
            "sink_type": cluster["sink_type"],
            "execution_mode": cluster["execution_mode"],
            "vendor_count": len(cluster["vendors"]),
            "model_count": len(cluster["models"]),
            "version_count": len(cluster["versions"]),
            "firmware_count": len(cluster["firmwares"]),
            "confidence": dict(cluster["confidence"]),
            "verdicts": dict(cluster["verdicts"]),
            "false_positive_reasons": dict(cluster["false_positive_reasons"]),
            "examples": cluster["examples"],
        })
    rows.sort(key=lambda row: (-int(row["firmware_count"]), -int(row["vendor_count"]), row["cluster_id"]))
    return rows


def build_architecture_clusters(target_summaries: list[dict]) -> list[dict]:
    clusters: dict[tuple[str, str, str, str, str], dict] = {}
    for target in target_summaries:
        profile = target.get("architecture_profile") or {}
        topology = target.get("service_topology") or {}
        helper_inventory = target.get("helper_script_inventory") or {}
        key = (
            str(profile.get("architecture_family") or "unknown"),
            str(topology.get("init_framework") or profile.get("init_framework") or "unknown"),
            str(topology.get("control_plane") or profile.get("service_topology") or "unknown"),
            str(profile.get("marker_signature") or "none"),
            str(helper_inventory.get("helper_signature") or profile.get("helper_signature") or "none"),
        )
        cluster = clusters.setdefault(key, {
            "cluster_id": f"ac-{_stable_id(*key)}",
            "architecture_family": key[0],
            "init_framework": key[1],
            "service_topology": key[2],
            "marker_signature": key[3],
            "helper_signature": key[4],
            "vendors": set(),
            "models": set(),
            "versions": set(),
            "firmwares": set(),
            "success_quality": Counter(),
            "provenance": Counter(),
            "helpers": Counter(),
            "markers": Counter(),
            "example_targets": [],
        })
        firmware_label = f"{target.get('vendor')} {target.get('model')} {target.get('version')}"
        cluster["vendors"].add(str(target.get("vendor") or ""))
        cluster["models"].add(str(target.get("model") or ""))
        cluster["versions"].add(str(target.get("version") or ""))
        cluster["firmwares"].add(firmware_label)
        cluster["success_quality"][str(target.get("success_quality") or "missing")] += 1
        cluster["provenance"][str(profile.get("provenance_level") or "unknown")] += 1
        for helper in profile.get("helper_conventions") or []:
            cluster["helpers"][str(helper)] += 1
        for marker in profile.get("filesystem_markers") or []:
            cluster["markers"][str(marker)] += 1
        if len(cluster["example_targets"]) < 6:
            cluster["example_targets"].append({
                "firmware": firmware_label,
                "vendor": target.get("vendor"),
                "model": target.get("model"),
                "version": target.get("version"),
                "success_quality": target.get("success_quality"),
                "recovered_components": target.get("recovered_components") or [],
            })
    rows = []
    for cluster in clusters.values():
        rows.append({
            "cluster_id": cluster["cluster_id"],
            "architecture_family": cluster["architecture_family"],
            "init_framework": cluster["init_framework"],
            "service_topology": cluster["service_topology"],
            "marker_signature": cluster["marker_signature"],
            "helper_signature": cluster["helper_signature"],
            "vendor_count": len(cluster["vendors"]),
            "model_count": len(cluster["models"]),
            "version_count": len(cluster["versions"]),
            "firmware_count": len(cluster["firmwares"]),
            "success_quality": dict(cluster["success_quality"]),
            "provenance": dict(cluster["provenance"]),
            "top_helpers": dict(cluster["helpers"].most_common(8)),
            "top_markers": dict(cluster["markers"].most_common(10)),
            "example_targets": cluster["example_targets"],
        })
    rows.sort(key=lambda row: (-int(row["firmware_count"]), -int(row["vendor_count"]), row["cluster_id"]))
    return rows


def architecture_clusters_report(target_summaries: list[dict], architecture_clusters: list[dict]) -> tuple[list[dict], list[str]]:
    lines = ["# Architecture Clusters", ""]
    if not architecture_clusters:
        lines.append("(no architecture clusters built)")
        return architecture_clusters, lines
    family_counts = Counter(row.get("architecture_family") or "unknown" for row in target_summaries)
    lines.extend([
        f"- total clusters: `{len(architecture_clusters)}`",
        f"- architecture families: `{dict(family_counts)}`",
        f"- targets summarized: `{len(target_summaries)}`",
        "",
    ])
    for row in architecture_clusters[:20]:
        lines.extend([
            f"## {row['cluster_id']}",
            f"- architecture_family: `{row['architecture_family']}`",
            f"- init_framework: `{row['init_framework']}`",
            f"- service_topology: `{row['service_topology']}`",
            f"- recurrence: `firmwares={row['firmware_count']}, vendors={row['vendor_count']}, models={row['model_count']}, versions={row['version_count']}`",
            f"- provenance mix: `{row['provenance']}`",
            f"- success_quality: `{row['success_quality']}`",
            f"- marker_signature: `{row['marker_signature']}`",
            f"- helper_signature: `{row['helper_signature']}`",
            f"- top_helpers: `{row['top_helpers']}`",
        ])
        for ex in row.get("example_targets") or []:
            lines.append(f"- example: `{ex['firmware']} / {ex['success_quality']} / {', '.join(ex.get('recovered_components') or []) or 'no-components'}`")
        lines.append("")
    return architecture_clusters, lines


def sdk_lineage_hypotheses_report(target_summaries: list[dict], architecture_clusters: list[dict]) -> tuple[list[dict], list[str]]:
    hypotheses = []
    for row in architecture_clusters:
        if int(row.get("firmware_count") or 0) < 2:
            continue
        vendors = sorted({str(ex.get("vendor") or "") for ex in (row.get("example_targets") or []) if ex.get("vendor")})
        if row.get("architecture_family") == "opaque-or-partial":
            continue
        if int(row.get("vendor_count") or 0) >= 2:
            if row.get("provenance", {}).get("probable-shared-lineage"):
                level = "probable-shared-lineage"
                why = "same helper and service layout recur across multiple vendors"
            else:
                level = "heuristic-similarity"
                why = "multiple vendors share architecture markers, but helper overlap is weaker"
        else:
            level = "heuristic-similarity"
            why = "same vendor and family show repeat architecture across versions"
        hypotheses.append({
            "cluster_id": row["cluster_id"],
            "architecture_family": row["architecture_family"],
            "provenance_level": level,
            "vendor_count": row["vendor_count"],
            "firmware_count": row["firmware_count"],
            "vendors": vendors,
            "helper_signature": row["helper_signature"],
            "marker_signature": row["marker_signature"],
            "why": why,
        })
    hypotheses.sort(key=lambda row: (
        {"probable-shared-lineage": 0, "heuristic-similarity": 1, "speculative-similarity": 2}.get(row["provenance_level"], 9),
        -int(row["vendor_count"]),
        -int(row["firmware_count"]),
        row["cluster_id"],
    ))
    lines = [
        "# SDK Lineage Hypotheses",
        "",
        "- No cluster in this pass is elevated to `confirmed SDK reuse`; provenance remains architecture-level unless external vendor or OEM evidence is added.",
        "",
    ]
    for row in hypotheses[:20]:
        lines.extend([
            f"## {row['cluster_id']}",
            f"- architecture_family: `{row['architecture_family']}`",
            f"- provenance_level: `{row['provenance_level']}`",
            f"- recurrence: `vendors={row['vendor_count']}, firmwares={row['firmware_count']}`",
            f"- vendors: `{row['vendors']}`",
            f"- marker_signature: `{row['marker_signature']}`",
            f"- helper_signature: `{row['helper_signature']}`",
            f"- rationale: `{row['why']}`",
            "",
        ])
    return hypotheses, lines


def orchestration_reuse_patterns_report(target_summaries: list[dict], architecture_clusters: list[dict], recurrence_clusters: list[dict]) -> tuple[list[dict], list[str]]:
    by_family = defaultdict(lambda: {
        "targets": 0,
        "vendors": set(),
        "helpers": Counter(),
        "templates": Counter(),
        "sources": Counter(),
        "execution_modes": Counter(),
    })
    for target in target_summaries:
        family = str(target.get("architecture_family") or "unknown")
        slot = by_family[family]
        slot["targets"] += 1
        slot["vendors"].add(str(target.get("vendor") or ""))
        for helper in (target.get("architecture_profile") or {}).get("helper_conventions") or []:
            slot["helpers"][str(helper)] += 1
        for cand in target.get("candidate_rows") or []:
            slot["templates"][str(cand.get("command_template") or "unknown")] += 1
            slot["sources"][str(cand.get("source_type") or "unknown")] += 1
            slot["execution_modes"][str(cand.get("execution_mode") or "unknown")] += 1
    rows = []
    for family, slot in by_family.items():
        rows.append({
            "architecture_family": family,
            "target_count": slot["targets"],
            "vendor_count": len(slot["vendors"]),
            "top_helpers": dict(slot["helpers"].most_common(8)),
            "top_command_templates": dict(slot["templates"].most_common(8)),
            "top_source_types": dict(slot["sources"].most_common(6)),
            "top_execution_modes": dict(slot["execution_modes"].most_common(6)),
        })
    rows.sort(key=lambda row: (-int(row["target_count"]), -int(row["vendor_count"]), row["architecture_family"]))
    lines = ["# Orchestration Reuse Patterns", ""]
    for row in rows[:12]:
        lines.extend([
            f"## {row['architecture_family']}",
            f"- targets: `{row['target_count']}` / vendors: `{row['vendor_count']}`",
            f"- top_helpers: `{row['top_helpers']}`",
            f"- top_command_templates: `{row['top_command_templates']}`",
            f"- top_source_types: `{row['top_source_types']}`",
            f"- top_execution_modes: `{row['top_execution_modes']}`",
            "",
        ])
    return rows, lines


def extraction_bias_analysis_report(target_summaries: list[dict], architecture_clusters: list[dict]) -> tuple[dict, list[str]]:
    by_family = defaultdict(Counter)
    by_quality = Counter()
    for target in target_summaries:
        family = str(target.get("architecture_family") or "unknown")
        quality = str(target.get("success_quality") or "missing")
        by_family[family][quality] += 1
        by_quality[quality] += 1
    rows = {
        family: dict(counter)
        for family, counter in sorted(by_family.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    }
    lines = [
        "# Extraction Bias Analysis",
        "",
        f"- success_quality_totals: `{dict(by_quality)}`",
        "",
        "## Family Bias",
    ]
    for family, counter in rows.items():
        total = sum(counter.values())
        lines.append(f"- `{family}`: `targets={total}` / `{counter}`")
    lines.extend([
        "",
        "## Bias Notes",
        "- `opaque-or-partial` targets are structurally underrepresented in architecture inference and recurrence measurements.",
        "- OpenWrt-derived families are overrepresented because rootfs recovery is more complete and helper scripts survive extraction cleanly.",
        "- Blob-success and fallback-success targets should be separated in any paper-facing prevalence charts.",
    ])
    return {"family_quality_counts": rows, "success_quality_totals": dict(by_quality)}, lines


def architecture_level_false_positive_notes_report(target_summaries: list[dict]) -> tuple[list[dict], list[str]]:
    by_family = defaultdict(lambda: {
        "candidate_rows": 0,
        "false_positive_reasons": Counter(),
        "verdict_reasons": Counter(),
        "templates": Counter(),
    })
    for target in target_summaries:
        family = str(target.get("architecture_family") or "unknown")
        slot = by_family[family]
        for cand in target.get("candidate_rows") or []:
            slot["candidate_rows"] += 1
            if cand.get("false_positive_reason"):
                slot["false_positive_reasons"][str(cand["false_positive_reason"])] += 1
            slot["verdict_reasons"][str(cand.get("verdict_reason") or "unknown")] += 1
            slot["templates"][str(cand.get("command_template") or "unknown")] += 1
    rows = []
    for family, slot in by_family.items():
        rows.append({
            "architecture_family": family,
            "candidate_rows": slot["candidate_rows"],
            "false_positive_reasons": dict(slot["false_positive_reasons"].most_common(8)),
            "verdict_reasons": dict(slot["verdict_reasons"].most_common(8)),
            "templates": dict(slot["templates"].most_common(8)),
        })
    rows.sort(key=lambda row: (-int(row["candidate_rows"]), row["architecture_family"]))
    lines = ["# Architecture-Level False-Positive Notes", ""]
    for row in rows[:12]:
        lines.extend([
            f"## {row['architecture_family']}",
            f"- candidate_rows: `{row['candidate_rows']}`",
            f"- false_positive_reasons: `{row['false_positive_reasons']}`",
            f"- verdict_reasons: `{row['verdict_reasons']}`",
            f"- dominant_templates: `{row['templates']}`",
            "",
        ])
    return rows, lines


def architecture_artifact_schema_report(target_summaries: list[dict]) -> list[str]:
    emitted = sum(1 for row in target_summaries if row.get("architecture_artifact_source") == "emitted")
    lines = [
        "# Architecture Artifact Schema",
        "",
        "- Artifact source of truth is now the analysis bundle rather than report-time filesystem rescans.",
        f"- Targets with emitted architecture metadata: `{emitted}/{len(target_summaries)}`",
        "",
        "## Required Bundle Fields",
        "- `target_metadata`: canonical vendor/model/version/corpus_id metadata normalized from the input artifact.",
        "- `architecture_profile`: architecture family, deterministic fingerprint, marker signature, helper signature, provenance level.",
        "- `management_inventory`: detected web servers, frontends, handler families, management endpoints, analysis reason.",
        "- `service_topology`: init framework, control plane, web stack, orchestration hooks, topology signature.",
        "- `config_backend`: config abstraction family and markers such as `uci`, `nvram`, `apmib`, `ubus`.",
        "- `helper_script_inventory`: normalized helper names plus execution and orchestration helper subsets.",
        "- `command_materialization_features`: command templates, source types, and execution-mode distributions.",
        "- `execution_wrapper_features`: normalized execution wrapper names and deterministic wrapper signature.",
        "- `extraction_quality_flags`: rootfs visibility, vendor-partition visibility, web-asset presence, marker/helper counts.",
        "",
        "## Stability Rules",
        "- All identifiers must be sorted before signature construction.",
        "- Fingerprints must use only canonicalized strings and fixed field ordering.",
        "- Report scripts should consume emitted fields first and only fall back for older bundles.",
    ]
    return lines


def architecture_fingerprint_design_report(target_summaries: list[dict]) -> list[str]:
    lines = [
        "# Architecture Fingerprint Design",
        "",
        "- Fingerprints are deterministic IDs built from `architecture_family`, `marker_signature`, `helper_signature`, `control_plane`, and `config_backend.family`.",
        "- Marker signatures are derived from stable filesystem artifacts such as web servers, `luci`, `ubus`, `uci`, `apmib`, `nvram`, and `mtk-wifi` markers.",
        "- Helper signatures are derived from a fixed normalized helper inventory: `config_generate`, `smp*.sh`, `system.lua`, `mtkwifi.lua`, `opkg`, `ndppd`, `easycwmp`, and related orchestration helpers.",
        "- The design intentionally avoids candidate scores, timestamps, and report ordering so fingerprints remain stable across reruns with identical extraction state.",
        "",
        "## Noisy Inputs To Avoid",
        "- candidate ranking scores",
        "- analyst verdicts",
        "- non-normalized filenames",
        "- absolute temporary paths",
        "- inferred-only service labels without filesystem support",
    ]
    return lines


def metadata_normalization_notes_report(target_summaries: list[dict]) -> list[str]:
    normalization_sources = Counter(
        (row.get("target_metadata") or {}).get("normalization_source") or "missing"
        for row in target_summaries
    )
    missing = [
        row for row in target_summaries
        if not (row.get("target_metadata") or {}).get("corpus_id")
    ]
    lines = [
        "# Metadata Normalization Notes",
        "",
        f"- normalization sources: `{dict(normalization_sources)}`",
        f"- targets missing normalized corpus_id in emitted metadata: `{len(missing)}`",
        "",
        "## Current Status",
        "- The analysis stage now reuses the corpus filename normalizer instead of inventing report-local vendor/model/version strings.",
        "- Report-side vendor/model/version grouping should prefer emitted `target_metadata` and only fall back to corpus rows for older bundles.",
        "- Helper names are lowercased and sorted before signature construction.",
        "",
        "## Remaining Cleanup",
        "- Corpus inventory still contains historically inferred notes and suspected stacks that do not always match emitted architecture metadata.",
        "- Any future paper-facing dataset export should regenerate corpus rows from canonical emitted target metadata where possible.",
    ]
    return lines


def cluster_stability_report(target_summaries: list[dict]) -> list[str]:
    comparable = []
    for row in target_summaries:
        emitted = row.get("architecture_profile") or {}
        fallback = row.get("fallback_architecture_profile") or {}
        if row.get("architecture_artifact_source") != "emitted":
            continue
        if not (
            (row.get("extraction_quality_flags") or {}).get("rootfs_recovered")
            or bool(fallback.get("rootfs_recovered"))
        ):
            continue
        comparable.append({
            "firmware": f"{row.get('vendor')} {row.get('model')} {row.get('version')}",
            "emitted_family": emitted.get("architecture_family") or "",
            "fallback_family": fallback.get("architecture_family") or "",
            "emitted_marker_signature": emitted.get("marker_signature") or "",
            "fallback_marker_signature": fallback.get("marker_signature") or "",
            "emitted_helper_signature": emitted.get("helper_signature") or "",
            "fallback_helper_signature": fallback.get("helper_signature") or "",
            "fingerprint_present": bool(emitted.get("architecture_fingerprint")),
        })
    family_match = sum(1 for row in comparable if row["emitted_family"] == row["fallback_family"])
    marker_match = sum(1 for row in comparable if row["emitted_marker_signature"] == row["fallback_marker_signature"])
    helper_match = sum(1 for row in comparable if row["emitted_helper_signature"] == row["fallback_helper_signature"])
    missing_emitted = [row for row in target_summaries if row.get("architecture_artifact_source") != "emitted"]
    emitted_without_rootfs = [
        row for row in target_summaries
        if row.get("architecture_artifact_source") == "emitted"
        and not (row.get("extraction_quality_flags") or {}).get("rootfs_recovered")
    ]
    lines = [
        "# Cluster Stability Report",
        "",
        f"- comparable emitted vs legacy-fallback targets: `{len(comparable)}`",
        f"- family agreement: `{family_match}/{len(comparable) if comparable else 0}`",
        f"- marker-signature agreement: `{marker_match}/{len(comparable) if comparable else 0}`",
        f"- helper-signature agreement: `{helper_match}/{len(comparable) if comparable else 0}`",
        f"- targets still requiring report-time fallback: `{len(missing_emitted)}`",
        f"- emitted targets lacking preserved rootfs for stable comparison: `{len(emitted_without_rootfs)}`",
        "",
        "## Stability Notes",
        "- Current stability numbers measure agreement between emitted analysis-stage metadata and the older report-time inference path.",
        "- Direct rerun variance is not yet measurable from this single current bundle set; that requires preserving multiple runs per same corpus target.",
        "- Any mismatch here indicates either earlier report-time drift or an extraction-sensitive marker that should not drive clustering alone.",
    ]
    if missing_emitted:
        lines.extend([
            "",
            "## Fallback Targets",
            *[
                f"- `{row['vendor']} {row['model']} {row['version']}` / `{row.get('success_quality')}`"
                for row in missing_emitted[:20]
            ],
        ])
    return lines


def reproducibility_notes_report(target_summaries: list[dict]) -> list[str]:
    completeness = Counter()
    required = [
        "architecture_profile",
        "management_inventory",
        "service_topology",
        "config_backend",
        "helper_script_inventory",
        "command_materialization_features",
        "execution_wrapper_features",
        "extraction_quality_flags",
        "target_metadata",
    ]
    for row in target_summaries:
        present = sum(1 for key in required if row.get(key))
        completeness[present] += 1
    emitted = sum(1 for row in target_summaries if row.get("architecture_artifact_source") == "emitted")
    emitted_with_rootfs = sum(
        1 for row in target_summaries
        if row.get("architecture_artifact_source") == "emitted"
        and (row.get("extraction_quality_flags") or {}).get("rootfs_recovered")
    )
    lines = [
        "# Reproducibility Notes",
        "",
        f"- targets with emitted architecture artifacts: `{emitted}/{len(target_summaries)}`",
        f"- emitted artifacts with preserved rootfs visibility: `{emitted_with_rootfs}/{len(target_summaries)}`",
        f"- metadata completeness histogram: `{dict(completeness)}`",
        "",
        "## Removed Report-Time Assumptions",
        "- Architecture family no longer has to be inferred exclusively from report-time filesystem scans for fresh bundles.",
        "- Vendor/model/version grouping can now use emitted normalized target metadata.",
        "- Helper inventories and fingerprints are now serialized into the bundle, reducing drift from changing report code.",
        "",
        "## Remaining Sources Of Instability",
        "- Old results bundles without emitted artifacts still require fallback inference.",
        "- Some migrated bundles now contain emitted fields but no longer have preserved rootfs state, so their architecture fingerprints are intentionally conservative.",
        "- Blob-success and fallback-success targets remain extraction-sensitive and should not anchor architecture prevalence claims.",
        "- Some recovered-component labels in reports still depend on candidate names and `analysis.reason` until service inventory is also serialized explicitly.",
    ]
    return lines


def pipeline_quality_report(
    corpus_rows: list[dict],
    target_summaries: list[dict],
    clusters: list[dict],
    bundles: list[dict],
) -> tuple[dict, list[str]]:
    by_vendor_model_version = Counter(
        (str(row.get("vendor") or ""), str(row.get("model") or ""), str(row.get("version") or ""))
        for row in corpus_rows
    )
    duplicate_triplets = [triplet for triplet, count in by_vendor_model_version.items() if count > 1]
    fallback_targets = [row for row in target_summaries if row.get("success_quality") == "fallback-success"]
    blob_targets = [row for row in target_summaries if row.get("success_quality") == "blob-success"]
    no_component_targets = [row for row in target_summaries if not row.get("recovered_components")]
    all_candidates = [cand for row in target_summaries for cand in (row.get("candidate_rows") or [])]
    raw_candidates = len(all_candidates)
    unique_cluster_members = len({
        (
            cand.get("component_family"),
            cand.get("command_template"),
            cand.get("source_type"),
            cand.get("sink_type"),
            cand.get("execution_mode"),
        )
        for cand in all_candidates
    })
    suppressed = [cand for cand in all_candidates if cand.get("false_positive_reason")]
    unclear_grouping = [cluster for cluster in clusters if cluster.get("firmware_count", 0) >= 3 and cluster.get("vendor_count", 0) == 1]
    out = {
        "targets_total": len(target_summaries),
        "raw_candidate_rows": raw_candidates,
        "unique_recurrence_clusters": len(clusters),
        "unique_cluster_signatures": unique_cluster_members,
        "suppressed_candidate_rows": len(suppressed),
        "blob_success_targets": len(blob_targets),
        "fallback_success_targets": len(fallback_targets),
        "targets_without_recovered_components": len(no_component_targets),
        "duplicate_vendor_model_version_triplets": len(duplicate_triplets),
        "single_vendor_large_clusters": len(unclear_grouping),
        "weak_points": [
            "naive sibling-parameter scans are noisy without request/form-context filtering",
            "blob-success and fallback-success targets still distort recurrence counts toward rootfs-available vendors",
            "raw candidate rows overcount repeated idioms; recurrence clustering should be primary measurement unit",
            "recovered component labeling still depends heavily on analysis.reason and candidate names rather than explicit web/server inventory",
            "historical runs still require canonical path backfill for fully reproducible report regeneration",
        ],
    }
    lines = [
        "# Pipeline Quality Report",
        "",
        f"- targets_total: `{out['targets_total']}`",
        f"- raw_candidate_rows: `{out['raw_candidate_rows']}`",
        f"- unique_recurrence_clusters: `{out['unique_recurrence_clusters']}`",
        f"- unique_cluster_signatures: `{out['unique_cluster_signatures']}`",
        f"- suppressed_candidate_rows: `{out['suppressed_candidate_rows']}`",
        f"- blob_success_targets: `{out['blob_success_targets']}`",
        f"- fallback_success_targets: `{out['fallback_success_targets']}`",
        f"- targets_without_recovered_components: `{out['targets_without_recovered_components']}`",
        f"- duplicate_vendor_model_version_triplets: `{out['duplicate_vendor_model_version_triplets']}`",
        f"- single_vendor_large_clusters: `{out['single_vendor_large_clusters']}`",
        "",
        "## Weak Points",
    ]
    for point in out["weak_points"]:
        lines.append(f"- {point}")
    if fallback_targets:
        lines.extend([
            "",
            "## Incomplete Extraction Targets",
        ])
        for row in fallback_targets[:10]:
            lines.append(f"- `{row['vendor']} {row['model']} {row['version']}`: `{row['success_quality']}` / `{row['probe_readiness']}`")
    return out, lines


def recurrence_clusters_report(target_summaries: list[dict], clusters: list[dict]) -> tuple[list[dict], list[str]]:
    lines = ["# Recurrence Clusters", ""]
    if not clusters:
        lines.append("(no recurrence clusters built)")
        return clusters, lines
    lines.extend([
        f"- total clusters: `{len(clusters)}`",
        f"- targets summarized: `{len(target_summaries)}`",
        "",
    ])
    for row in clusters[:20]:
        lines.extend([
            f"## {row['cluster_id']}",
            f"- component_family: `{row['component_family']}`",
            f"- command_template: `{row['command_template']}`",
            f"- source_type: `{row['source_type']}`",
            f"- sink_type: `{row['sink_type']}`",
            f"- execution_mode: `{row['execution_mode']}`",
            f"- recurrence: `firmwares={row['firmware_count']}, vendors={row['vendor_count']}, models={row['model_count']}, versions={row['version_count']}`",
            f"- confidence mix: `{row['confidence']}`",
            f"- verdict mix: `{row['verdicts']}`",
            f"- false-positive reasons: `{row['false_positive_reasons'] or {}}`",
        ])
        for ex in row.get("examples") or []:
            lines.append(
                f"- example: `{ex['firmware']} / {ex['component']} / {ex['candidate_confidence']} / {ex['verdict_reason']}`"
            )
        lines.append("")
    return clusters, lines


def candidate_ranking_notes_report(target_summaries: list[dict], clusters: list[dict]) -> tuple[dict, list[str]]:
    all_candidates = [cand for row in target_summaries for cand in (row.get("candidate_rows") or [])]
    confidence_counts = Counter(cand.get("candidate_confidence") or "unknown" for cand in all_candidates)
    verdict_counts = Counter(cand.get("verdict") or "unknown" for cand in all_candidates)
    by_template = Counter(cand.get("command_template") or "unknown" for cand in all_candidates)
    strongest = []
    seen_clusters = set()
    for cand in sorted(
        all_candidates,
        key=lambda cand: (-int(cand.get("priority_score") or 0), -int(cand.get("candidate_score") or 0), cand.get("component") or ""),
    ):
        cluster_id = cand.get("recurrence_cluster_id") or f"single-{cand.get('component')}"
        if cluster_id in seen_clusters:
            continue
        seen_clusters.add(cluster_id)
        strongest.append(cand)
        if len(strongest) >= 15:
            break
    out = {
        "candidate_rows": len(all_candidates),
        "confidence_counts": dict(confidence_counts),
        "verdict_counts": dict(verdict_counts),
        "top_command_templates": dict(by_template.most_common(12)),
        "top_examples": strongest,
    }
    lines = [
        "# Candidate Ranking Notes",
        "",
        f"- candidate_rows: `{len(all_candidates)}`",
        f"- confidence_counts: `{dict(confidence_counts)}`",
        f"- verdict_counts: `{dict(verdict_counts)}`",
        f"- top_command_templates: `{dict(by_template.most_common(12))}`",
        "",
        "## Ranking Guidance",
        "- Treat recurrence clusters as the primary counting unit for paper-facing statistics; raw candidate rows are too duplicative.",
        "- Keep `candidate_confidence` distinct from `verdict`: confidence tracks evidence quality, while verdict tracks suppression or promotion decisions.",
        "- Use `priority_score` for manual validation ordering, not for vulnerability claims.",
        "- Do not mix recurring implementation idioms with manually verified vulnerabilities in the same headline counts.",
        "",
        "## Top Ranking Examples",
    ]
    for cand in strongest[:12]:
        lines.append(
            f"- `{cand['component']}`: `confidence={cand['candidate_confidence']}`, `priority={cand['priority_score']}`, `template={cand['command_template']}`, `source={cand['source_type']}`, `execution={cand['execution_mode']}`, `verdict={cand['verdict']}`"
        )
    return out, lines


def false_positive_taxonomy_report(target_summaries: list[dict]) -> tuple[dict, list[str]]:
    all_candidates = [cand for row in target_summaries for cand in (row.get("candidate_rows") or [])]
    reason_counts = Counter(cand.get("false_positive_reason") for cand in all_candidates if cand.get("false_positive_reason"))
    verdict_reason_counts = Counter(cand.get("verdict_reason") for cand in all_candidates)
    template_counts = Counter(
        cand.get("command_template")
        for cand in all_candidates
        if cand.get("false_positive_reason")
    )
    out = {
        "false_positive_reason_counts": dict(reason_counts),
        "verdict_reason_counts": dict(verdict_reason_counts.most_common(20)),
        "suppressed_templates": dict(template_counts.most_common(12)),
    }
    lines = [
        "# False-Positive Taxonomy",
        "",
        f"- false_positive_reason_counts: `{dict(reason_counts)}`",
        f"- top_verdict_reasons: `{dict(verdict_reason_counts.most_common(20))}`",
        f"- suppressed_templates: `{dict(template_counts.most_common(12))}`",
        "",
        "## Taxonomy Notes",
        "- `reject:constant-or-unproven-exec-argument` captures fixed shell strings and import-only sinks that should not be promoted.",
        "- `low-priority:false-positive-risk:*` captures cases where a sink exists but attacker control, exact input, or dispatch proof is weak.",
        "- `risk:key_gated_protocol_surface` should remain separate from exploitability claims; protocol gating is not security validation.",
        "- `reject:declaration-only-sink` is useful for suppressing shell declarations and environment strings that are not active execution.",
    ]
    return out, lines


def next_manual_validation_targets_report(target_summaries: list[dict], clusters: list[dict]) -> tuple[list[dict], list[str]]:
    all_candidates = []
    by_cluster = {row["cluster_id"]: row for row in clusters}
    regression_pairs = {(r["firmware"], r["component"].lower()) for r in KNOWN_FP_REGRESSIONS}
    for target in target_summaries:
        firmware = f"{target.get('vendor')} {target.get('model')} {target.get('version')}"
        for cand in target.get("candidate_rows") or []:
            if cand.get("candidate_confidence") not in {"strong-candidate", "manually-prioritized-candidate", "medium-candidate"}:
                continue
            if _suppressed_known_issue(str(target.get("model") or ""), str(cand.get("component") or "")):
                continue
            if any(
                fw == firmware and comp in str(cand.get("component") or "").lower()
                for fw, comp in regression_pairs
            ):
                continue
            if cand.get("false_positive_reason", "").startswith("reject:constant"):
                continue
            cluster = by_cluster.get(cand.get("recurrence_cluster_id") or "")
            recurrence_bonus = int(cluster.get("firmware_count") or 0) if cluster else 0
            if cand.get("candidate_confidence") == "medium-candidate" and recurrence_bonus < 2:
                continue
            if cand.get("false_positive_reason") and cand.get("candidate_confidence") != "manually-prioritized-candidate":
                continue
            confidence_bonus = {
                "manually-prioritized-candidate": 80,
                "strong-candidate": 45,
                "medium-candidate": 0,
            }.get(cand.get("candidate_confidence") or "", 0)
            manual_score = int(cand.get("priority_score") or 0) + recurrence_bonus * 10 + confidence_bonus
            all_candidates.append({
                "firmware": firmware,
                "component": cand.get("component"),
                "cluster_id": cand.get("recurrence_cluster_id"),
                "candidate_confidence": cand.get("candidate_confidence"),
                "priority_score": cand.get("priority_score"),
                "manual_score": manual_score,
                "command_template": cand.get("command_template"),
                "source_type": cand.get("source_type"),
                "execution_mode": cand.get("execution_mode"),
                "verdict": cand.get("verdict"),
                "false_positive_reason": cand.get("false_positive_reason"),
                "cluster_recurrence": int(cluster.get("firmware_count") or 0) if cluster else 1,
            })
    all_candidates.sort(key=lambda row: (-int(row["manual_score"]), row["firmware"], row["component"]))
    top = []
    seen = set()
    for row in all_candidates:
        key = row.get("cluster_id") or (row["firmware"], row["component"])
        if key in seen:
            continue
        seen.add(key)
        top.append(row)
        if len(top) >= 15:
            break
    lines = [
        "# Next Manual Validation Targets",
        "",
        "- Manual validation targets are ranked by candidate confidence, recurrence breadth, and priority score, not by CVE readiness.",
        "",
    ]
    for row in top:
        lines.extend([
            f"## {row['firmware']} / {row['component']}",
            f"- cluster_id: `{row['cluster_id'] or 'none'}`",
            f"- candidate_confidence: `{row['candidate_confidence']}`",
            f"- priority_score: `{row['priority_score']}`",
            f"- cluster_recurrence: `{row['cluster_recurrence']}`",
            f"- command_template: `{row['command_template']}`",
            f"- source_type: `{row['source_type']}`",
            f"- execution_mode: `{row['execution_mode']}`",
            f"- verdict: `{row['verdict']}`",
            f"- false_positive_reason: `{row['false_positive_reason'] or 'none'}`",
            "",
        ])
    return top, lines


def corpus_completion_report(corpus_rows: list[dict], blind_summary: dict, bundles: list[dict]) -> tuple[dict, list[str]]:
    extraction = Counter(row.get("extraction_status") or "missing" for row in corpus_rows)
    analysis = Counter(row.get("analysis_status") or "missing" for row in corpus_rows)
    success_quality = Counter(row.get("success_quality") or "missing" for row in corpus_rows)
    probe = Counter(row.get("probe_readiness") or "missing" for row in corpus_rows)
    bundle_present = sum(1 for row in bundles if row.get("bundle"))
    manifest_present = sum(1 for row in bundles if row.get("manifest"))
    results_missing = [
        row["corpus"].get("corpus_id")
        for row in bundles
        if row.get("results_path") is None
    ]
    out = {
        "corpus_rows": len(corpus_rows),
        "reviewed_ids": blind_summary.get("reviewed_ids"),
        "missing_review_ids": blind_summary.get("missing_review_ids") or [],
        "extraction_status": dict(extraction),
        "analysis_status": dict(analysis),
        "success_quality": dict(success_quality),
        "probe_readiness": dict(probe),
        "bundles_found": bundle_present,
        "manifests_found": manifest_present,
        "bundles_missing": results_missing,
    }
    lines = [
        "# Corpus Completion Report",
        "",
        f"- corpus rows: `{len(corpus_rows)}`",
        f"- reviewed ids: `{blind_summary.get('reviewed_ids')}`",
        f"- missing review ids: `{len(blind_summary.get('missing_review_ids') or [])}`",
        f"- extraction_status: `{dict(extraction)}`",
        f"- analysis_status: `{dict(analysis)}`",
        f"- success_quality: `{dict(success_quality)}`",
        f"- probe_readiness: `{dict(probe)}`",
        f"- manifests found: `{manifest_present}`",
        f"- results bundles found: `{bundle_present}`",
        f"- results bundles missing: `{len(results_missing)}`",
    ]
    if results_missing:
        lines.extend([
            "",
            "## Missing Bundles",
            *[f"- `{cid}`" for cid in results_missing[:20]],
        ])
    return out, lines


def _batch_summary_snapshot(batch_summary: dict | None) -> dict:
    if not batch_summary:
        return {}
    return {
        "total": int(batch_summary.get("total") or 0),
        "counts": dict(batch_summary.get("counts") or {}),
        "success_quality_counts": dict(batch_summary.get("success_quality_counts") or {}),
        "probe_readiness_counts": dict(batch_summary.get("probe_readiness_counts") or {}),
        "blob_family_counts": dict(batch_summary.get("blob_family_counts") or {}),
    }


def candidate_quality_report(bundles: list[dict], manual_eval: dict | None) -> tuple[dict, list[str]]:
    verdicts = Counter()
    verdict_reasons = Counter()
    flow_types = Counter()
    missing_links = Counter()
    fp_risks = Counter()
    next_actions = Counter()
    candidates_total = 0
    bundles_with_candidates = 0
    manifest_modes = Counter()
    manifest_reasons = Counter()

    for item in bundles:
        bundle = item.get("bundle") or {}
        manifest = item.get("manifest") or {}
        analysis = manifest.get("analysis") or {}
        if analysis.get("mode"):
            manifest_modes[str(analysis.get("mode"))] += 1
        if analysis.get("reason"):
            manifest_reasons[str(analysis.get("reason"))] += 1
        candidates = bundle.get("candidates") or []
        if candidates:
            bundles_with_candidates += 1
        candidates_total += len(candidates)
        for cand in candidates:
            verdicts[_candidate_verdict(cand)] += 1
            verdict_reasons[_candidate_verdict_reason(cand)] += 1
            flow_types[(cand.get("flow_type") or "unknown").lower()] += 1
            next_actions[_candidate_next_action(cand)] += 1
            for link in cand.get("missing_links") or []:
                missing_links[str(link)] += 1
            for risk in cand.get("false_positive_risks") or []:
                fp_risks[str(risk)] += 1

    out = {
        "bundles_with_candidates": bundles_with_candidates,
        "candidates_total": candidates_total,
        "verdicts": dict(verdicts),
        "verdict_reasons": dict(verdict_reasons),
        "flow_types": dict(flow_types),
        "top_missing_links": missing_links.most_common(12),
        "top_false_positive_risks": fp_risks.most_common(12),
        "recommended_next_action": dict(next_actions),
        "manifest_modes": dict(manifest_modes),
        "top_manifest_reasons": manifest_reasons.most_common(10),
        "manual_eval": manual_eval or {},
    }
    lines = [
        "# Candidate Quality Report",
        "",
        f"- bundles with candidates: `{bundles_with_candidates}`",
        f"- total candidates: `{candidates_total}`",
        f"- verdicts: `{dict(verdicts)}`",
        f"- top verdict reasons: `{dict(verdict_reasons.most_common(8))}`",
        f"- flow_types: `{dict(flow_types)}`",
        f"- recommended_next_action: `{dict(next_actions)}`",
        f"- manifest_modes: `{dict(manifest_modes)}`",
        "",
        "## Top Missing Links",
        *[f"- `{name}`: `{count}`" for name, count in missing_links.most_common(12)],
        "",
        "## Top False-Positive Risks",
        *[f"- `{name}`: `{count}`" for name, count in fp_risks.most_common(12)],
        "",
        "## Top Manifest Reasons",
        *[f"- `{name}`: `{count}`" for name, count in manifest_reasons.most_common(10)],
    ]
    if manual_eval:
        lines.extend([
            "",
            "## Manual Eval Snapshot",
            f"- gold_rows: `{manual_eval.get('gold_rows')}`",
            f"- prediction_rows: `{manual_eval.get('prediction_rows')}`",
        ])
    return out, lines


def _find_candidate(bundle: dict, component: str) -> dict | None:
    component_lower = component.lower()
    for cand in bundle.get("candidates") or []:
        name = str(cand.get("name") or "").lower()
        raw_name = str(cand.get("raw_name") or "").lower()
        if component_lower in name or component_lower in raw_name:
            return cand
    return None


def false_positive_regression_report(bundles: list[dict]) -> tuple[dict, list[str]]:
    rows = []
    lines = ["# False-Positive Regression Report", ""]
    for reg in KNOWN_FP_REGRESSIONS:
        firmware_norm = _norm(reg["firmware"])
        item = next((
            x for x in bundles
            if x.get("bundle") and firmware_norm in _norm(x["corpus"].get("model"))
        ), None)
        cand = _find_candidate(item.get("bundle") or {}, reg["component"]) if item else None
        if cand:
            verdict = _candidate_verdict(cand)
            passed = verdict == "reject"
        else:
            verdict = "not-present"
            passed = True
        rows.append({
            "firmware": reg["firmware"],
            "component": reg["component"],
            "expected": "reject",
            "actual": verdict,
            "passed": passed,
            "reason": reg["reason"],
        })
        lines.extend([
            f"## {reg['firmware']} / {reg['component']}",
            f"- expected: `reject`",
            f"- actual: `{verdict}`",
            f"- passed: `{passed}`",
            f"- reason: `{reg['reason']}`",
            "",
        ])
    return {"rows": rows}, lines


def _suppressed_known_issue(model: str, component: str) -> bool:
    for row in KNOWN_ISSUE_SUPPRESSIONS:
        if row["model_substr"].lower() in model.lower() and row["component_substr"].lower() in component.lower():
            return True
    return False


def _has_numeric_only_hint(candidate: dict) -> bool:
    text = " ".join(
        str(candidate.get(key) or "")
        for key in (
            "name",
            "raw_name",
            "vuln_summary",
            "next_steps",
            "binary_path",
        )
    ).lower()
    config_keys = " ".join(str(k).lower() for k in (candidate.get("config_keys") or []))
    return any(token in text for token in ("numeric-only", "timeout %d", "atoi(", "formatted with %d")) or (
        "group_id" in config_keys and "peer_id" in config_keys and "peer_count" in config_keys
    )


def _is_constant_command_fp(candidate: dict) -> bool:
    risks = set(candidate.get("false_positive_risks") or [])
    if {
        "constant_sink_argument",
        "constant_or_unproven_exec_argument",
        "sink_import_only",
        "cross_function_token_contamination",
        "key_gated_protocol_surface",
    } & risks:
        return True
    sink_text = " ".join(str(s) for s in (candidate.get("all_sinks") or []))
    return "kickoff_web()" in sink_text and "lua -e" in sink_text


def _is_declaration_only_sink(candidate: dict) -> bool:
    sinks = " || ".join(str(s) for s in (candidate.get("all_sinks") or []))
    lower = sinks.lower()
    if not lower:
        return False
    decl_hits = any(tok in lower for tok in ("shell=/bin/sh", "#!/bin/sh", "-/bin/sh"))
    real_hits = any(tok in lower for tok in ("system(", "popen", "os.execute", "io.popen", "execl", "execv", "execvp", "sprintf(", "strcpy(", "strcat(", "memcpy(", "memmove(", "sscanf("))
    return decl_hits and not real_hits


def _candidate_verdict(candidate: dict) -> str:
    verdict = str(candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    if verdict:
        return verdict

    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return "reject"

    flow_type = str(candidate.get("flow_type") or "").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))

    if flow_type in {"container_signal", "blob_signal"}:
        return "low-priority"

    if (
        confirmed_input != "unconfirmed"
        and has_sink
        and auth != "unknown"
        and not {"exact_input_unknown", "dispatch_unknown", "chain_gap_unknown"} & missing_links
        and not {"input_to_sink_unproven", "literal_logging_sink_only"} & fp_risks
    ):
        return "promising"

    if has_sink and has_input_hint and has_surface:
        return "needs-reversing"

    if has_sink and (has_input_hint or has_surface):
        return "low-priority"

    return "reject"


def _candidate_verdict_reason(candidate: dict) -> str:
    verdict = str(candidate.get("cve_verdict") or candidate.get("verdict") or "").lower()
    if verdict and verdict != "reject":
        return f"engine-verdict:{verdict}"

    flow_type = str(candidate.get("flow_type") or "").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))

    if _is_constant_command_fp(candidate):
        return "reject:constant-or-unproven-exec-argument"
    if _has_numeric_only_hint(candidate):
        return "reject:numeric-only-or-formatted-value"
    if _is_declaration_only_sink(candidate):
        return "reject:declaration-only-sink"
    if flow_type in {"container_signal", "blob_signal"}:
        return "low-priority:container-or-blob-triage"
    if (
        confirmed_input != "unconfirmed"
        and has_sink
        and auth != "unknown"
        and not {"exact_input_unknown", "dispatch_unknown", "chain_gap_unknown"} & missing_links
        and not {"input_to_sink_unproven", "literal_logging_sink_only"} & fp_risks
    ):
        return "promising:concrete-input-sink-auth-structure"
    if has_sink and has_input_hint and has_surface:
        return "needs-reversing:surface-present-chain-incomplete"
    if has_sink and (has_input_hint or has_surface):
        if fp_risks:
            return f"low-priority:false-positive-risk:{sorted(fp_risks)[0]}"
        if missing_links:
            return f"low-priority:missing-link:{sorted(missing_links)[0]}"
        return "low-priority:weak-input-or-surface-evidence"
    if has_sink:
        return "reject:sink-without-input-proof"
    if has_input_hint:
        return "reject:input-without-sink-proof"
    return "reject:no-actionable-input-or-sink-evidence"


def _candidate_next_action(candidate: dict) -> str:
    action = str(candidate.get("recommended_next_action") or "").lower()
    if action:
        return action

    flow_type = str(candidate.get("flow_type") or "").lower()
    verdict = _candidate_verdict(candidate)
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])

    if flow_type in {"container_signal", "blob_signal"}:
        return "recover-payload-format"
    if "exact_input_unknown" in missing_links or "no_exact_input" in fp_risks:
        return "confirm-input-source"
    if "dispatch_unknown" in missing_links:
        return "confirm-dispatch-path"
    if "chain_gap_unknown" in missing_links or "input_to_sink_unproven" in fp_risks:
        return "bridge-input-to-sink"
    if str(candidate.get("sanitization") or "").lower() == "present":
        return "audit-sanitization-boundary"
    if verdict in {"promising", "cve-ready"}:
        return "confirm-exploit-primitive"
    if flow_type in {"buffer_overflow", "format_string", "heap_overflow", "file_path_injection"}:
        return "confirm-copy-site"
    return "review-artifacts"


def _candidate_input_rank(candidate: dict) -> int:
    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "unconfirmed").lower()
    attacker_arg = str(candidate.get("attacker_controlled_argument") or "unconfirmed").lower()
    if confirmed_input != "unconfirmed":
        return 4
    if attacker_arg in {"confirmed", "likely"}:
        return 3
    if endpoint_input not in {"", "unconfirmed"} or candidate.get("endpoints"):
        return 2
    if candidate.get("config_keys"):
        return 1
    return 0


def _candidate_sink_rank(candidate: dict) -> int:
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    sink_text = " ".join(str(x).lower() for x in (candidate.get("all_sinks") or []))
    if confirmed_sink != "unconfirmed":
        if any(tok in confirmed_sink for tok in ("/bin/sh", "system", "popen", "os.execute", "io.popen", "exec")):
            return 4
        if any(tok in confirmed_sink for tok in ("strcpy", "sprintf", "strcat", "memcpy", "memmove", "sscanf")):
            return 3
        return 2
    if any(tok in sink_text for tok in ("/bin/sh", "system", "popen", "os.execute", "io.popen", "exec")):
        return 2
    if sink_text:
        return 1
    return 0


def _candidate_parser_upload_rank(candidate: dict) -> int:
    flow_type = str(candidate.get("flow_type") or "").lower()
    text = " ".join(
        [
            str(candidate.get("name") or "").lower(),
            str(candidate.get("raw_name") or "").lower(),
            str(candidate.get("endpoint_input") or "").lower(),
            " ".join(str(x).lower() for x in (candidate.get("endpoints") or [])),
            " ".join(str(x).lower() for x in (candidate.get("config_keys") or [])),
        ]
    )
    uploadish = any(tok in text for tok in ("upload", "restore", "firmware", "backup", "multipart", "config.bin", "firmware.bin"))
    parserish = flow_type in {"buffer_overflow", "heap_overflow", "format_string", "file_path_injection", "net_copy_partial"}
    if uploadish and parserish:
        return 4
    if uploadish:
        return 3
    if parserish:
        return 2
    return 0


def _candidate_reachability_rank(candidate: dict) -> int:
    auth = str(candidate.get("auth_boundary") or candidate.get("auth_bypass") or "unknown").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "").lower()
    if candidate.get("web_exposed"):
        return 4
    if auth in {"pre-auth", "bypassable"} and endpoint_input not in {"", "unconfirmed"}:
        return 3
    if candidate.get("web_reachable") or candidate.get("handler_surface"):
        return 2
    if endpoint_input not in {"", "unconfirmed"} or candidate.get("endpoints"):
        return 1
    return 0


def _candidate_missing_proof_rank(candidate: dict) -> int:
    missing = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    penalty = len(missing) + len(fp_risks & {
        "constant_or_unproven_exec_argument",
        "sink_import_only",
        "cross_function_token_contamination",
        "input_to_sink_unproven",
    })
    return max(0, 4 - penalty)


def _candidate_review_priority(candidate: dict) -> tuple[int, dict]:
    factors = {
        "input_controllability": _candidate_input_rank(candidate),
        "sink_proximity": _candidate_sink_rank(candidate),
        "parser_upload_exposure": _candidate_parser_upload_rank(candidate),
        "web_rpc_reachability": _candidate_reachability_rank(candidate),
        "missing_proof": _candidate_missing_proof_rank(candidate),
    }
    score = (
        factors["input_controllability"] * 30
        + factors["sink_proximity"] * 26
        + factors["parser_upload_exposure"] * 20
        + factors["web_rpc_reachability"] * 22
        + factors["missing_proof"] * 14
        + min(int(candidate.get("score") or 0), 100)
    )
    return score, factors


def _derive_smell_strength(candidate: dict) -> str:
    verdict = _candidate_verdict(candidate)
    if verdict == "cve-ready":
        return "cve-candidate"

    if _is_constant_command_fp(candidate) or _has_numeric_only_hint(candidate) or _is_declaration_only_sink(candidate):
        return "reject"

    confirmed_input = str(candidate.get("confirmed_input") or "unconfirmed").lower()
    confirmed_sink = str(candidate.get("confirmed_sink") or "unconfirmed").lower()
    attacker_arg = str(candidate.get("attacker_controlled_argument") or "unconfirmed").lower()
    auth = str(candidate.get("auth_boundary") or "unknown").lower()
    flow_type = str(candidate.get("flow_type") or "").lower()
    endpoint_input = str(candidate.get("endpoint_input") or "unconfirmed").lower()
    missing_links = set(candidate.get("missing_links") or [])
    fp_risks = set(candidate.get("false_positive_risks") or [])
    has_sink = confirmed_sink != "unconfirmed" or bool(candidate.get("all_sinks"))
    has_input_hint = (
        confirmed_input != "unconfirmed"
        or endpoint_input not in {"", "unconfirmed"}
        or bool(candidate.get("endpoints"))
        or bool(candidate.get("config_keys"))
    )
    has_surface = bool(candidate.get("web_exposed") or candidate.get("web_reachable") or candidate.get("handler_surface"))
    parserish = flow_type in {"buffer_overflow", "heap_overflow", "format_string", "file_path_injection"}
    uploadish = any(
        token in " ".join(
            [
                str(candidate.get("name") or "").lower(),
                str(candidate.get("raw_name") or "").lower(),
                endpoint_input,
                " ".join(str(x).lower() for x in (candidate.get("endpoints") or [])),
                " ".join(str(x).lower() for x in (candidate.get("config_keys") or [])),
            ]
        )
        for token in ("upload", "restore", "firmware", "config", "multipart", "backup")
    )
    has_exec_string = any(
        token in " ".join(str(s).lower() for s in (candidate.get("all_sinks") or []))
        for token in ("system", "popen", "/bin/sh", "os.execute", "io.popen", "sprintf", "strcpy", "strcat", "memcpy")
    )

    if verdict in {"promising", "needs-reversing"}:
        return "strong-smell"

    if (
        has_sink
        and has_input_hint
        and has_surface
        and attacker_arg in {"confirmed", "likely", "unconfirmed"}
        and not {"literal_logging_sink_only", "sink_import_only", "cross_function_token_contamination", "key_gated_protocol_surface"} & fp_risks
        and auth in {"pre-auth", "post-auth", "bypassable", "unknown"}
        and not {"too_many_unknowns"} <= missing_links
    ):
        if parserish or uploadish or has_exec_string:
            return "strong-smell" if confirmed_input != "unconfirmed" or attacker_arg in {"confirmed", "likely"} else "medium-smell"

    if has_sink and (has_input_hint or has_surface or parserish or uploadish):
        return "medium-smell"

    if has_sink or has_input_hint:
        return "weak-smell"

    return "reject"


def cve_smell_queue(bundles: list[dict]) -> tuple[list[dict], list[str]]:
    items = []
    regression_pairs = {(r["firmware"], r["component"]) for r in KNOWN_FP_REGRESSIONS}
    seen = set()
    for item in bundles:
        corpus = item["corpus"]
        bundle = item.get("bundle") or {}
        model = str(corpus.get("model") or "")
        fw_name = f"{corpus.get('vendor') or '?'} {model} {corpus.get('version') or ''}".strip()
        for cand in bundle.get("candidates") or []:
            name = str(cand.get("name") or cand.get("raw_name") or "")
            dedupe_key = (_norm(fw_name), _norm(name))
            if dedupe_key in seen:
                continue
            smell = _derive_smell_strength(cand)
            verdict = _candidate_verdict(cand)
            if verdict == "promising" and smell not in {"strong-smell", "cve-candidate"}:
                smell = "strong-smell"
            if smell not in {"medium-smell", "strong-smell", "cve-candidate"}:
                continue
            if _suppressed_known_issue(model, name):
                continue
            if any(
                fw == reg_fw and comp.lower() in name.lower()
                for reg_fw, comp in regression_pairs
                for fw in [fw_name, str(corpus.get("model") or "")]
            ):
                continue
            priority_score, rank_factors = _candidate_review_priority(cand)
            if priority_score < 120 and verdict != "promising":
                continue
            seen.add(dedupe_key)
            items.append({
                "firmware": fw_name,
                "component": name,
                "suspected_issue": cand.get("flow_type") or "unknown",
                "verdict": verdict,
                "verdict_reason": _candidate_verdict_reason(cand),
                "recommended_next_action": _candidate_next_action(cand),
                "evidence": {
                    "endpoint_input": cand.get("endpoint_input"),
                    "confirmed_sink": cand.get("confirmed_sink"),
                    "auth_boundary": cand.get("auth_boundary"),
                    "missing_links": cand.get("missing_links") or [],
                    "false_positive_risks": cand.get("false_positive_risks") or [],
                },
                "missing_proof": ", ".join(cand.get("missing_links") or []) or "none",
                "recommended_deep_analysis_tool": (
                    "Claude Code" if smell in {"strong-smell", "cve-candidate"} else "Codex only"
                ),
                "confidence": smell,
                "priority_score": priority_score,
                "rank_factors": rank_factors,
            })
    items.sort(
        key=lambda x: (
            {"cve-candidate": 0, "strong-smell": 1, "medium-smell": 2}.get(x["confidence"], 9),
            -int(x.get("priority_score") or 0),
            x.get("firmware") or "",
            x.get("component") or "",
        )
    )
    lines = ["# CVE Smell Queue", ""]
    if not items:
        lines.append("(no new candidates passed the conservative smell filter)")
    else:
        for row in items[:12]:
            lines.extend([
                f"## {row['firmware']} / {row['component']}",
                f"- suspected issue: `{row['suspected_issue']}`",
                f"- verdict: `{row.get('verdict')}`",
                f"- verdict reason: `{row.get('verdict_reason')}`",
                f"- recommended next action: `{row.get('recommended_next_action')}`",
                f"- evidence: `endpoint={row['evidence'].get('endpoint_input') or 'unconfirmed'}, sink={row['evidence'].get('confirmed_sink') or 'unconfirmed'}, auth={row['evidence'].get('auth_boundary') or 'unknown'}`",
                f"- ranking factors: `input={row['rank_factors'].get('input_controllability')}, sink={row['rank_factors'].get('sink_proximity')}, parser/upload={row['rank_factors'].get('parser_upload_exposure')}, reachability={row['rank_factors'].get('web_rpc_reachability')}, missing-proof={row['rank_factors'].get('missing_proof')}`",
                f"- priority score: `{row.get('priority_score')}`",
                f"- missing proof: `{row['missing_proof']}`",
                f"- recommended deep-analysis tool: `{row['recommended_deep_analysis_tool']}`",
                f"- confidence: `{row['confidence']}`",
                "",
            ])
    return items, lines


def _top_target_score(row: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    issue = str(row.get("suspected_issue") or "").lower()
    component = str(row.get("component") or "").lower()
    ev = row.get("evidence") or {}
    endpoint = str(ev.get("endpoint_input") or "").lower()
    sink = str(ev.get("confirmed_sink") or "").lower()
    auth = str(ev.get("auth_boundary") or "").lower()
    missing = set(ev.get("missing_links") or [])

    text = " ".join([issue, component, endpoint, sink])

    if any(tok in text for tok in ("upload", "restore", "firmware", "backup", "multipart", "parser", "config.bin", "firmware.bin")):
        score += 90
        reasons.append("upload-parser-surface")
    if any(tok in sink for tok in ("/bin/sh", "system", "popen", "os.execute", "io.popen", "exec")):
        score += 70
        reasons.append("command-sink")
    if any(tok in sink for tok in ("strcpy", "sprintf", "strcat", "memcpy", "memmove", "sscanf")):
        score += 50
        reasons.append("copy-primitive")
    if endpoint and endpoint != "unconfirmed":
        score += 45
        reasons.append("endpoint-known")
    if any(tok in endpoint for tok in ("/cgi", "/config", "/admin", "/rpc", "/upload", "/restore", "/firmware")):
        score += 20
        reasons.append("web-rpc-surface")
    if auth in {"pre-auth", "unknown"}:
        score += 15
        reasons.append("network-reachability-not-ruled-out")
    if not missing:
        score += 10
        reasons.append("partial-chain-tighter")
    if row.get("confidence") == "strong-smell":
        score += 25
        reasons.append("strong-smell")
    if row.get("verdict") == "promising":
        score += 40
        reasons.append("analyst-promoted")
    score += int(row.get("priority_score") or 0)
    rank_factors = row.get("rank_factors") or {}
    if int(rank_factors.get("input_controllability") or 0) >= 3:
        reasons.append("high-input-control")
    if int(rank_factors.get("sink_proximity") or 0) >= 3:
        reasons.append("sink-nearby")
    if int(rank_factors.get("parser_upload_exposure") or 0) >= 3:
        reasons.append("upload-parser-exposure")
    if int(rank_factors.get("web_rpc_reachability") or 0) >= 3:
        reasons.append("web-rpc-reachable")

    if not endpoint and not sink:
        score -= 80
        reasons.append("weak-surface-metadata")
    if "gl-mt3000" in str(row.get("firmware") or "").lower() and not endpoint:
        score -= 20
        reasons.append("no-endpoint-on-script-heavy-surface")

    return score, reasons


def top_targets_report(smells: list[dict]) -> tuple[list[dict], list[str]]:
    ranked = []
    seen = set()
    for row in smells:
        key = (row.get("firmware"), row.get("component"))
        if key in seen:
            continue
        seen.add(key)
        score, reasons = _top_target_score(row)
        enriched = dict(row)
        enriched["priority_score"] = score
        enriched["priority_reasons"] = reasons
        ranked.append(enriched)

    ranked.sort(key=lambda x: (-int(x["priority_score"]), x.get("firmware") or "", x.get("component") or ""))
    top = ranked[:5]
    lines = ["# Top Targets", ""]
    if not top:
        lines.append("(no medium+ smell candidates available)")
    else:
        for idx, row in enumerate(top, 1):
            ev = row.get("evidence") or {}
            lines.extend([
                f"## Rank {idx}",
                f"- firmware: `{row.get('firmware')}`",
                f"- component: `{row.get('component')}`",
                f"- suspected_issue: `{row.get('suspected_issue')}`",
                f"- confidence: `{row.get('confidence')}`",
                f"- priority_score: `{row.get('priority_score')}`",
                f"- endpoint/input: `{ev.get('endpoint_input') or 'unconfirmed'}`",
                f"- sink: `{ev.get('confirmed_sink') or 'unconfirmed'}`",
                f"- auth: `{ev.get('auth_boundary') or 'unknown'}`",
                f"- ranking factors: `input={row.get('rank_factors', {}).get('input_controllability')}, sink={row.get('rank_factors', {}).get('sink_proximity')}, parser/upload={row.get('rank_factors', {}).get('parser_upload_exposure')}, reachability={row.get('rank_factors', {}).get('web_rpc_reachability')}, missing-proof={row.get('rank_factors', {}).get('missing_proof')}`",
                f"- missing_links: `{', '.join(ev.get('missing_links') or []) or 'none'}`",
                f"- why prioritized: `{', '.join(row.get('priority_reasons') or [])}`",
                f"- recommended tool: `{row.get('recommended_deep_analysis_tool')}`",
                "",
            ])
    return top, lines


def tool_improvement_log_report(
    corpus_out: dict,
    quality_out: dict,
    fp_out: dict,
    backlog_out: list[dict],
    batch_snapshot: dict | None = None,
) -> list[str]:
    today = datetime.now().date().isoformat()
    lines = [
        "# Tool Improvement Log",
        "",
        f"## {today}",
        "",
        "### Pipeline / Extraction",
        "- Added generic embedded-payload salvage for `gzip`, `zip`, `xz`, and `lzma` signatures when classic filesystem detection fails.",
        "- Added recursion guards so carved payloads and compressed salvage outputs do not recursively trigger the same recovery path forever.",
        "- Widened opaque nested-blob handling so large extensionless high-entropy payloads are still explored instead of being dropped too early.",
        "- Corpus-level reporting now resolves `canonical_result_path` before transient `result_path`, so current successful runs are not lost when older `/tmp` outputs disappear.",
        "",
        "### Opaque-Format Triage",
        "- Added `source_kind` and `extraction_hints` to exported `container_targets` so opaque cases preserve extraction context in structured results.",
        "- Propagated that context into review packets so `best_next_action` on blob/container cases is driven by actual extraction state rather than generic fallback logic.",
        "- Added a dedicated opaque extraction status report so partial/opaque firmware stay visible as structured recovery targets instead of anonymous failures.",
        "",
        "### Corpus / Reporting",
        f"- Corpus status: `rows={corpus_out.get('corpus_rows')}`, `bundles_found={corpus_out.get('bundles_found')}`, `manifests_found={corpus_out.get('manifests_found')}`.",
        f"- Candidate quality snapshot: `bundles_with_candidates={quality_out.get('bundles_with_candidates')}`, `candidates_total={quality_out.get('candidates_total')}`.",
        f"- False-positive regression snapshot: `{len(fp_out.get('rows') or [])}` tracked regression rows, no regression failure introduced in this iteration.",
    ]
    if batch_snapshot:
        lines.extend([
            f"- Batch status: `total={batch_snapshot.get('total')}`, `counts={batch_snapshot.get('counts')}`.",
            f"- Success quality counts: `{batch_snapshot.get('success_quality_counts')}`.",
            f"- Probe readiness counts: `{batch_snapshot.get('probe_readiness_counts')}`.",
        ])
    lines.extend([
        "",
        "### Current Highest-Value Backlog",
    ])
    for row in (backlog_out or [])[:5]:
        lines.append(f"- P{row.get('priority')}: {row.get('task')}")
    lines.append("")
    return lines


def backlog_report(corpus_rows: list[dict], quality: dict, fp_report: dict) -> tuple[list[dict], list[str]]:
    extraction_gaps = Counter(row.get("blob_family") or "none" for row in corpus_rows if row.get("success_quality") == "blob-success")
    tasks = [
        {
            "priority": 1,
            "task": "Backfill canonical runs/.../results.json for older corpus samples",
            "why_it_matters": "Corpus-wide quality and regression reports still depend on a small subset of preserved result bundles; historical samples need stable canonical artifacts.",
        },
        {
            "priority": 2,
            "task": "Reconstruct TP-Link segmented bundles into a browsable web/rootfs layout",
            "why_it_matters": "C80-class images still stop at blob-success; web assets are present but not stitched into a usable analysis tree.",
        },
        {
            "priority": 3,
            "task": "Decode TP-Link/MERCUSYS cloud container headers beyond fixed offset carve",
            "why_it_matters": "MR70X-class images now triage reliably but still never promote into a richer extracted layout.",
        },
        {
            "priority": 4,
            "task": "Promote successful Tenda salted decrypts into auto-rootfs checks instead of probe-only outputs",
            "why_it_matters": "The tool now finds plausible decrypt outputs cheaply, but does not yet convert them into higher-quality extraction states.",
        },
        {
            "priority": 5,
            "task": "Raise candidate readability around low-priority vs reject decisions",
            "why_it_matters": "Corpus-wide verdict separation improved, but many opaque-format candidates still need clearer human-facing rationale.",
        },
        {
            "priority": 6,
            "task": "Refresh corpus-wide candidate-quality regression on a larger batch summary than the current mini CVE batch",
            "why_it_matters": "The stored CVE batch summary is too small to represent the full corpus; broader queue summaries should be regenerated from current runs.",
        },
    ]
    lines = [
        "# Tool Improvement Backlog",
        "",
        f"- blob-success families: `{dict(extraction_gaps)}`",
        f"- verdicts: `{quality.get('verdicts')}`",
        f"- regression rows: `{len(fp_report.get('rows') or [])}`",
        "",
    ]
    for row in tasks:
        lines.extend([
            f"## Priority {row['priority']}",
            f"- task: {row['task']}",
            f"- why it matters: {row['why_it_matters']}",
            "",
        ])
    return tasks, lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--blind-summary")
    ap.add_argument("--batch-summary")
    ap.add_argument("--manual-eval", default="research/review/manual/manual_review_eval.master_20260422_plus_linksys_plus_alignment_plus_touched6.json")
    ap.add_argument("--corpus-md", required=True)
    ap.add_argument("--corpus-json", required=True)
    ap.add_argument("--quality-md", required=True)
    ap.add_argument("--quality-json", required=True)
    ap.add_argument("--fp-md", required=True)
    ap.add_argument("--fp-json", required=True)
    ap.add_argument("--backlog-md", required=True)
    ap.add_argument("--backlog-json", required=True)
    ap.add_argument("--smell-md", required=True)
    ap.add_argument("--smell-json", required=True)
    ap.add_argument("--top-targets-md", required=True)
    ap.add_argument("--top-targets-json", required=True)
    ap.add_argument("--log-md", required=True)
    ap.add_argument("--pipeline-quality-md")
    ap.add_argument("--pipeline-quality-json")
    ap.add_argument("--recurrence-clusters-md")
    ap.add_argument("--recurrence-clusters-json")
    ap.add_argument("--candidate-ranking-notes-md")
    ap.add_argument("--candidate-ranking-notes-json")
    ap.add_argument("--false-positive-taxonomy-md")
    ap.add_argument("--false-positive-taxonomy-json")
    ap.add_argument("--next-manual-validation-targets-md")
    ap.add_argument("--next-manual-validation-targets-json")
    ap.add_argument("--architecture-clusters-md")
    ap.add_argument("--architecture-clusters-json")
    ap.add_argument("--sdk-lineage-hypotheses-md")
    ap.add_argument("--sdk-lineage-hypotheses-json")
    ap.add_argument("--orchestration-reuse-patterns-md")
    ap.add_argument("--orchestration-reuse-patterns-json")
    ap.add_argument("--extraction-bias-analysis-md")
    ap.add_argument("--extraction-bias-analysis-json")
    ap.add_argument("--architecture-level-false-positive-notes-md")
    ap.add_argument("--architecture-level-false-positive-notes-json")
    ap.add_argument("--architecture-artifact-schema-md")
    ap.add_argument("--reproducibility-notes-md")
    ap.add_argument("--architecture-fingerprint-design-md")
    ap.add_argument("--metadata-normalization-notes-md")
    ap.add_argument("--cluster-stability-report-md")
    args = ap.parse_args()

    corpus_rows = load_jsonl(args.corpus)
    blind_summary = load_json(args.blind_summary) if args.blind_summary and Path(args.blind_summary).is_file() else {}
    batch_summary = load_json(args.batch_summary) if args.batch_summary and Path(args.batch_summary).is_file() else {}
    manual_eval = load_json(args.manual_eval) if Path(args.manual_eval).is_file() and Path(args.manual_eval).stat().st_size > 0 else {}
    bundles = load_corpus_bundles(corpus_rows, batch_summary=batch_summary)

    corpus_out, corpus_lines = corpus_completion_report(corpus_rows, blind_summary, bundles)
    quality_out, quality_lines = candidate_quality_report(bundles, manual_eval)
    fp_out, fp_lines = false_positive_regression_report(bundles)
    backlog_out, backlog_lines = backlog_report(corpus_rows, quality_out, fp_out)
    smell_out, smell_lines = cve_smell_queue(bundles)
    top_out, top_lines = top_targets_report(smell_out)
    target_summaries = build_target_summaries(bundles)
    recurrence_clusters = build_recurrence_clusters(target_summaries)
    recurrence_out, recurrence_lines = recurrence_clusters_report(target_summaries, recurrence_clusters)
    architecture_clusters = build_architecture_clusters(target_summaries)
    architecture_out, architecture_lines = architecture_clusters_report(target_summaries, architecture_clusters)
    pipeline_quality_out, pipeline_quality_lines = pipeline_quality_report(
        corpus_rows,
        target_summaries,
        recurrence_out,
        bundles,
    )
    ranking_out, ranking_lines = candidate_ranking_notes_report(target_summaries, recurrence_out)
    fp_taxonomy_out, fp_taxonomy_lines = false_positive_taxonomy_report(target_summaries)
    manual_out, manual_lines = next_manual_validation_targets_report(target_summaries, recurrence_out)
    lineage_out, lineage_lines = sdk_lineage_hypotheses_report(target_summaries, architecture_clusters)
    orchestration_out, orchestration_lines = orchestration_reuse_patterns_report(
        target_summaries,
        architecture_clusters,
        recurrence_clusters,
    )
    extraction_bias_out, extraction_bias_lines = extraction_bias_analysis_report(target_summaries, architecture_clusters)
    arch_fp_out, arch_fp_lines = architecture_level_false_positive_notes_report(target_summaries)
    architecture_schema_lines = architecture_artifact_schema_report(target_summaries)
    reproducibility_lines = reproducibility_notes_report(target_summaries)
    fingerprint_design_lines = architecture_fingerprint_design_report(target_summaries)
    normalization_lines = metadata_normalization_notes_report(target_summaries)
    cluster_stability_lines = cluster_stability_report(target_summaries)
    log_lines = tool_improvement_log_report(
        corpus_out,
        quality_out,
        fp_out,
        backlog_out,
        batch_snapshot=_batch_summary_snapshot(batch_summary),
    )

    write_json(args.corpus_json, corpus_out)
    write_md(args.corpus_md, corpus_lines)
    write_json(args.quality_json, quality_out)
    write_md(args.quality_md, quality_lines)
    write_json(args.fp_json, fp_out)
    write_md(args.fp_md, fp_lines)
    write_json(args.backlog_json, backlog_out)
    write_md(args.backlog_md, backlog_lines)
    write_json(args.smell_json, smell_out)
    write_md(args.smell_md, smell_lines)
    write_json(args.top_targets_json, top_out)
    write_md(args.top_targets_md, top_lines)
    write_md(args.log_md, log_lines)
    if args.pipeline_quality_json:
        write_json(args.pipeline_quality_json, pipeline_quality_out)
    if args.pipeline_quality_md:
        write_md(args.pipeline_quality_md, pipeline_quality_lines)
    if args.recurrence_clusters_json:
        write_json(args.recurrence_clusters_json, recurrence_out)
    if args.recurrence_clusters_md:
        write_md(args.recurrence_clusters_md, recurrence_lines)
    if args.candidate_ranking_notes_json:
        write_json(args.candidate_ranking_notes_json, ranking_out)
    if args.candidate_ranking_notes_md:
        write_md(args.candidate_ranking_notes_md, ranking_lines)
    if args.false_positive_taxonomy_json:
        write_json(args.false_positive_taxonomy_json, fp_taxonomy_out)
    if args.false_positive_taxonomy_md:
        write_md(args.false_positive_taxonomy_md, fp_taxonomy_lines)
    if args.next_manual_validation_targets_json:
        write_json(args.next_manual_validation_targets_json, manual_out)
    if args.next_manual_validation_targets_md:
        write_md(args.next_manual_validation_targets_md, manual_lines)
    if args.architecture_clusters_json:
        write_json(args.architecture_clusters_json, architecture_out)
    if args.architecture_clusters_md:
        write_md(args.architecture_clusters_md, architecture_lines)
    if args.sdk_lineage_hypotheses_json:
        write_json(args.sdk_lineage_hypotheses_json, lineage_out)
    if args.sdk_lineage_hypotheses_md:
        write_md(args.sdk_lineage_hypotheses_md, lineage_lines)
    if args.orchestration_reuse_patterns_json:
        write_json(args.orchestration_reuse_patterns_json, orchestration_out)
    if args.orchestration_reuse_patterns_md:
        write_md(args.orchestration_reuse_patterns_md, orchestration_lines)
    if args.extraction_bias_analysis_json:
        write_json(args.extraction_bias_analysis_json, extraction_bias_out)
    if args.extraction_bias_analysis_md:
        write_md(args.extraction_bias_analysis_md, extraction_bias_lines)
    if args.architecture_level_false_positive_notes_json:
        write_json(args.architecture_level_false_positive_notes_json, arch_fp_out)
    if args.architecture_level_false_positive_notes_md:
        write_md(args.architecture_level_false_positive_notes_md, arch_fp_lines)
    if args.architecture_artifact_schema_md:
        write_md(args.architecture_artifact_schema_md, architecture_schema_lines)
    if args.reproducibility_notes_md:
        write_md(args.reproducibility_notes_md, reproducibility_lines)
    if args.architecture_fingerprint_design_md:
        write_md(args.architecture_fingerprint_design_md, fingerprint_design_lines)
    if args.metadata_normalization_notes_md:
        write_md(args.metadata_normalization_notes_md, normalization_lines)
    if args.cluster_stability_report_md:
        write_md(args.cluster_stability_report_md, cluster_stability_lines)

    print(json.dumps({
        "corpus_rows": len(corpus_rows),
        "bundles_scanned": sum(1 for row in bundles if row.get("bundle")),
        "smell_rows": len(smell_out),
        "top_rows": len(top_out),
        "recurrence_clusters": len(recurrence_out),
        "architecture_clusters": len(architecture_out),
    }, indent=2))


if __name__ == "__main__":
    main()
