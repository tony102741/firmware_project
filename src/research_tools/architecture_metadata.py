from __future__ import annotations

import hashlib
import os
import re
import sys
from collections import Counter
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from corpus_tools.corpus_sync import infer_entry


SCHEMA_VERSION = "2026-05-08.arch.v1"

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
    # OpenWrt UCI config
    "etc-config": [
        "etc/config",
        # ipTIME overlay layout: static defaults live under default/etc/
        "default/etc/iconfig.cfg",
        "default/etc/config",
        # ASUS / Synology: vendor configs under usr/etc/
        "usr/etc",
        # Universal Unix fallback — any complete rootfs has passwd
        "etc/passwd",
        "default/etc/passwd",
    ],
    "etc-initd": ["etc/init.d", "default/etc/init.d"],
    "apmib": ["bin/flash", "lib/libapmib.so", "lib/libapmib"],
    "nvram": ["usr/sbin/nvram", "sbin/nvram", "bin/nvram"],
    "mtk-wifi": ["sbin/iwpriv", "lib/wifi", "etc/wireless"],
}

HELPER_NAMES = [
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

EXECUTION_HELPERS = [
    "system.lua",
    "config_generate",
    "smp.sh",
    "smp-mt76.sh",
    "mtkwifi.lua",
    "opkg",
    "ndppd",
    "easycwmp",
]

ORCHESTRATION_HELPERS = [
    "autoupgrade.lua",
    "dut_auto_upgrade",
    "firmware.lua",
    "easymesh_network.lua",
    "offline_download_monitor.lua",
    "getfirm",
    "connmode",
]

INVENTORY_DIRS = [
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "etc",
    "etc/init.d",
    "etc/config",
    "www",
    "www/cgi-bin",
    "usr/lib/lua",
    "lib",
    "lib/wifi",
]


def stable_id(*parts: str, size: int = 12) -> str:
    joined = "||".join(str(part or "") for part in parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:size]


def _safe_rel(path: str | os.PathLike | None) -> str:
    if not path:
        return ""
    try:
        return os.path.relpath(str(path), os.getcwd()).replace("\\", "/")
    except Exception:
        return str(path)


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


def _candidate_name(candidate: dict) -> str:
    return str(candidate.get("name") or candidate.get("raw_name") or "").strip()


def _candidate_sinks(candidate: dict) -> list[str]:
    return list(candidate.get("all_sinks") or candidate.get("sinks") or [])


def command_template(candidate: dict) -> str:
    sink = str(candidate.get("confirmed_sink") or "").lower()
    all_sinks = " || ".join(str(x).lower() for x in _candidate_sinks(candidate))
    text = " ".join([sink, all_sinks, str(candidate.get("vuln_summary") or "").lower()])
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
    if "echo %s" in text and ">" in text:
        return "echo-percent-redirect"
    if "/bin/sh" in text:
        return "/bin/sh"
    if "system" in text:
        return "system"
    if "exec" in text:
        return "exec"
    return str(candidate.get("flow_type") or "unknown").lower()


def source_type(candidate: dict) -> str:
    confirmed_input = str(candidate.get("confirmed_input") or "").lower()
    endpoint = str(candidate.get("endpoint_input") or "").lower()
    config_keys = " ".join(str(x).lower() for x in (candidate.get("config_keys") or []))
    name = _candidate_name(candidate).lower()
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


def execution_mode(candidate: dict) -> str:
    src = source_type(candidate)
    template = command_template(candidate)
    endpoint = str(candidate.get("endpoint_input") or "").lower()
    if src == "http-query":
        return "direct"
    if src in {"config-mib", "config-derived"} or "getmib" in template:
        return "deferred"
    if src == "upload-metadata":
        return "materialized"
    if endpoint not in {"", "unconfirmed"}:
        return "management-plane"
    return "operational"


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


def _normalize_helper_name(name: str) -> str:
    return str(name or "").strip().lower()


def normalize_target_metadata(
    input_path: str | None,
    original_input_path: str | None = None,
    input_type: str | None = None,
    run_id: str | None = None,
) -> dict:
    chosen = original_input_path or input_path
    if not chosen:
        return {
            "normalization_source": "missing-input",
            "vendor": "UNKNOWN",
            "model": "UNKNOWN",
            "version": "UNKNOWN",
            "corpus_id": "",
            "local_filename": "",
            "local_path": "",
            "input_type": input_type or "unknown",
            "product_class": "router",
            "run_id": run_id or "",
        }
    path = Path(chosen)
    inputs_root = Path("inputs").resolve()
    entry = infer_entry(path.resolve(), inputs_root=inputs_root)
    return {
        "normalization_source": "corpus_sync.infer_entry",
        "vendor": entry.get("vendor"),
        "model": entry.get("model"),
        "version": entry.get("version"),
        "corpus_id": entry.get("corpus_id"),
        "local_filename": entry.get("local_filename"),
        "local_path": entry.get("local_path"),
        "input_type": entry.get("input_type") or input_type or "unknown",
        "product_class": entry.get("product_class") or "router",
        "release_date": entry.get("release_date") or "",
        "suspected_stack": entry.get("suspected_stack") or [],
        "arch_hint": entry.get("arch") or "",
        "run_id": run_id or "",
    }


def _infer_architecture_family(markers: set[str], helper_names: list[str], rootfs_recovered: bool) -> str:
    helper_set = set(helper_names)
    if not rootfs_recovered or not markers:
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


def _provenance_level(family: str, markers: set[str], helper_names: list[str]) -> tuple[str, str]:
    helper_set = set(helper_names)
    if family == "opaque-or-partial":
        return "speculative-similarity", "insufficient rootfs visibility for stronger architecture claims"
    if family == "legacy-boa-apmib":
        return "probable-shared-lineage", "boa plus apmib is a stable legacy SDK-style signature"
    if family == "openwrt-shell-helper-sdk" and {"config_generate", "smp.sh"} & helper_set:
        return "probable-shared-lineage", "shared helper scripts and OpenWrt-style service layout recur together"
    if family == "openwrt-vendor-management-stack" and {"getfirm", "wifi_check_country", "ndppd"} & helper_set:
        return "probable-shared-lineage", "same management helpers recur inside a shared OpenWrt-style control plane"
    if family in {"openwrt-mtk-lua-wireless", "dual-httpd-lighttpd-nvram", "lighttpd-cgi-mtk", "openwrt-nginx-service-stack"}:
        return "heuristic-similarity", "filesystem layout and helper ecosystem imply architecture reuse without proving OEM provenance"
    if {"luci", "uci", "ubus"} <= markers:
        return "heuristic-similarity", "shared control-plane building blocks indicate a common management architecture"
    return "speculative-similarity", "markers are too generic for stronger provenance claims"


def collect_architecture_artifacts(
    system_path: str | os.PathLike | None,
    vendor_path: str | os.PathLike | None = None,
    candidates: list[dict] | None = None,
    analysis_reason: str | None = None,
    target_metadata: dict | None = None,
) -> dict:
    root = Path(system_path) if system_path else None
    vendor_root = Path(vendor_path) if vendor_path else None
    roots = [p for p in (root, vendor_root) if p and p.exists()]
    rootfs_recovered = bool(root and root.exists())
    markers = sorted(
        name for name, rel_paths in ARCH_MARKERS.items()
        if any(_root_has_any(base, rel_paths) for base in roots)
    )
    helper_inventory = sorted(
        _normalize_helper_name(helper)
        for helper in HELPER_NAMES
        if any(_root_glob_exists(base, helper) for base in roots)
    )
    marker_set = set(markers)
    helper_set = set(helper_inventory)

    web_servers = [name for name in ("boa", "uhttpd", "lighttpd", "httpd", "nginx") if name in marker_set]
    web_frontends = [name for name in ("luci", "cgi-bin", "boafrm") if name in marker_set]
    config_markers = [name for name in ("apmib", "uci", "nvram", "etc-config", "ubus") if name in marker_set]
    execution_wrappers = [name for name in EXECUTION_HELPERS if name in helper_set]
    orchestration_hooks = [name for name in ORCHESTRATION_HELPERS if name in helper_set]

    if "procd" in marker_set:
        init_framework = "procd+init.d"
    elif "etc-initd" in marker_set:
        init_framework = "init.d"
    else:
        init_framework = "unknown"

    if {"rpcd", "ubus"} <= marker_set:
        control_plane = "rpcd+ubus-control-plane"
    elif "ubus" in marker_set:
        control_plane = "ubus-control-plane"
    elif "cgi-bin" in marker_set or "boafrm" in marker_set:
        control_plane = "cgi-handler-control-plane"
    else:
        control_plane = "opaque-or-minimal"

    if {"apmib"} <= marker_set:
        config_family = "apmib"
    elif {"uci", "ubus"} <= marker_set and "nvram" in marker_set:
        config_family = "mixed-uci-nvram"
    elif {"uci"} <= marker_set:
        config_family = "uci"
    elif {"nvram"} <= marker_set:
        config_family = "nvram"
    elif config_markers:
        config_family = "mixed-or-unknown"
    else:
        config_family = "unknown"

    management_handlers = sorted({
        _component_family(_candidate_name(cand))
        for cand in (candidates or [])
        if cand.get("web_exposed") or cand.get("handler_surface") or cand.get("endpoint_input")
    })
    management_endpoints = sorted({
        str(cand.get("endpoint_input") or "").strip()
        for cand in (candidates or [])
        if str(cand.get("endpoint_input") or "").strip() and str(cand.get("endpoint_input") or "").strip() != "unconfirmed"
    })[:20]
    command_patterns = Counter(command_template(cand) for cand in (candidates or []))
    source_patterns = Counter(source_type(cand) for cand in (candidates or []))
    execution_patterns = Counter(execution_mode(cand) for cand in (candidates or []))
    inventory = {}
    if root and root.exists():
        for rel in INVENTORY_DIRS:
            full = root / rel
            if full.exists():
                if full.is_dir():
                    try:
                        inventory[rel] = sum(1 for _ in full.iterdir())
                    except OSError:
                        inventory[rel] = -1
                else:
                    inventory[rel] = 1

    family = _infer_architecture_family(marker_set, helper_inventory, rootfs_recovered)
    provenance_level, provenance_rationale = _provenance_level(family, marker_set, helper_inventory)
    marker_signature = ",".join(markers) or "none"
    helper_signature = ",".join(helper_inventory) or "none"
    wrapper_signature = ",".join(execution_wrappers) or "none"
    fingerprint = f"af-{stable_id(family, marker_signature, helper_signature, control_plane, config_family)}"

    web_assets_present = any(
        _root_has_any(base, ["www", "www/cgi-bin", "usr/lib/lua/luci", "web"])
        for base in roots
    )
    management_inventory = {
        "schema_version": SCHEMA_VERSION,
        "web_servers_detected": web_servers,
        "web_frontends_detected": web_frontends,
        "management_handlers": management_handlers[:20],
        "management_endpoints": management_endpoints,
        "analysis_reason": str(analysis_reason or ""),
    }
    service_topology = {
        "schema_version": SCHEMA_VERSION,
        "init_framework": init_framework,
        "control_plane": control_plane,
        "web_stack": web_servers + web_frontends,
        "orchestration_hooks": orchestration_hooks,
        "topology_signature": f"{init_framework}|{control_plane}|{','.join(web_servers + web_frontends) or 'none'}",
    }
    config_backend = {
        "schema_version": SCHEMA_VERSION,
        "family": config_family,
        "markers": config_markers,
    }
    helper_script_inventory = {
        "schema_version": SCHEMA_VERSION,
        "helpers": helper_inventory,
        "execution_helpers": execution_wrappers,
        "orchestration_helpers": orchestration_hooks,
        "helper_signature": helper_signature,
    }
    command_materialization_features = {
        "schema_version": SCHEMA_VERSION,
        "command_templates": dict(command_patterns.most_common(16)),
        "source_types": dict(source_patterns.most_common(12)),
        "execution_modes": dict(execution_patterns.most_common(12)),
    }
    execution_wrapper_features = {
        "schema_version": SCHEMA_VERSION,
        "execution_wrappers": execution_wrappers,
        "wrapper_signature": wrapper_signature,
    }
    extraction_quality_flags = {
        "schema_version": SCHEMA_VERSION,
        "rootfs_recovered": rootfs_recovered,
        "vendor_partition_present": bool(vendor_root and vendor_root.exists()),
        "web_assets_present": web_assets_present,
        "marker_count": len(markers),
        "helper_count": len(helper_inventory),
        "candidate_count": len(candidates or []),
        "quality_class": (
            "rootfs-observable"
            if rootfs_recovered and markers
            else "partial-or-opaque"
        ),
    }
    filesystem_inventory = {
        "schema_version": SCHEMA_VERSION,
        "inventory_counts": inventory,
        "system_root": _safe_rel(system_path),
        "vendor_root": _safe_rel(vendor_path),
    }
    extraction_evidence = {
        "schema_version": SCHEMA_VERSION,
        "analysis_reason": str(analysis_reason or ""),
        "system_root_exists": bool(root and root.exists()),
        "vendor_root_exists": bool(vendor_root and vendor_root.exists()),
        "web_assets_present": web_assets_present,
        "filesystem_marker_signature": marker_signature,
        "helper_signature": helper_signature,
    }
    architecture_profile = {
        "schema_version": SCHEMA_VERSION,
        "architecture_family": family,
        "architecture_fingerprint": fingerprint,
        "marker_signature": marker_signature,
        "helper_signature": helper_signature,
        "filesystem_markers": markers,
        "provenance_level": provenance_level,
        "provenance_rationale": provenance_rationale,
        "rootfs_recovered": rootfs_recovered,
        "target_corpus_id": (target_metadata or {}).get("corpus_id") or "",
    }
    return {
        "architecture_profile": architecture_profile,
        "management_inventory": management_inventory,
        "service_topology": service_topology,
        "config_backend": config_backend,
        "helper_script_inventory": helper_script_inventory,
        "filesystem_inventory": filesystem_inventory,
        "command_materialization_features": command_materialization_features,
        "execution_wrapper_features": execution_wrapper_features,
        "extraction_quality_flags": extraction_quality_flags,
        "extraction_evidence": extraction_evidence,
        "target_metadata": target_metadata or {},
        "artifact_paths": {
            "system_path": _safe_rel(system_path),
            "vendor_path": _safe_rel(vendor_path),
        },
    }
