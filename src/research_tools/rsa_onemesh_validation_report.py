"""
Validate rsa2048 default state and OneMesh trust exposure across TP-Link/MERCUSYS
management-stack firmware in the reproducible corpus.

Usage:
  python3 src/research_tools/rsa_onemesh_validation_report.py \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_md(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def best_bundles(workspace_root: Path) -> list[dict]:
    out = []
    for results_path in sorted(workspace_root.glob("runs/**/results.json")):
        bundle = load_json(results_path)
        meta = bundle.get("target_metadata") or {}
        arch = bundle.get("architecture_profile") or {}
        vendor = meta.get("vendor")
        family = arch.get("architecture_family")
        if vendor not in {"TP-Link", "MERCUSYS"}:
            continue
        if family != "openwrt-vendor-management-stack":
            continue
        system_path = (bundle.get("analysis") or {}).get("system_path")
        if not system_path:
            continue
        rootfs = PROJECT_ROOT / system_path
        if not rootfs.exists():
            continue
        out.append({"bundle": bundle, "rootfs": rootfs, "results_path": results_path})
    return out


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def file_exists(rootfs: Path, rel: str) -> bool:
    return (rootfs / rel).exists()


def find_first(rootfs: Path, rels: list[str]) -> Path | None:
    for rel in rels:
        path = rootfs / rel
        if path.exists():
            return path
    return None


def contains(path: Path | None, needle: str) -> bool:
    if path is None or not path.exists():
        return False
    try:
        return needle.encode("utf-8") in path.read_bytes()
    except Exception:
        return needle in read_text(path)


def gather_target(entry: dict) -> dict:
    bundle = entry["bundle"]
    rootfs = entry["rootfs"]
    meta = bundle.get("target_metadata") or {}
    system_cfg = rootfs / "etc/config/system"
    system_cfg_text = read_text(system_cfg)

    luarsa = find_first(rootfs, ["etc/init.d/luarsa_keys_gen", "etc_ro/init.d/luarsa_keys_gen"])
    sync_server = find_first(rootfs, ["etc/init.d/sync-server", "etc_ro/init.d/sync-server"])
    tdp_init = find_first(rootfs, ["etc/init.d/tdpServer", "etc_ro/init.d/tdpServer"])
    meshd_init = find_first(rootfs, ["etc/init.d/meshd", "etc_ro/init.d/meshd"])
    easymesh_re = find_first(rootfs, ["etc/init.d/easymesh_re"])
    onemesh_lua = find_first(rootfs, ["usr/lib/lua/luci/controller/admin/onemesh.lua"])
    easymesh_lua = find_first(rootfs, ["usr/lib/lua/luci/controller/admin/easymesh.lua"])
    tdp_bin = find_first(rootfs, ["usr/bin/tdpServer"])
    meshd_bin = find_first(rootfs, ["usr/bin/meshd"])

    luarsa_text = read_text(luarsa) if luarsa else ""
    sync_text = read_text(sync_server) if sync_server else ""
    tdp_init_text = read_text(tdp_init) if tdp_init else ""
    meshd_init_text = read_text(meshd_init) if meshd_init else ""

    rsa_exists = "rsa2048_enable" in system_cfg_text
    rsa_default = None
    if rsa_exists:
        for line in system_cfg_text.splitlines():
            if "rsa2048_enable" in line:
                rsa_default = line.strip().split()[-1]
                break

    sync_fallback_on = 'onemesh_enable="on"' in sync_text
    sync_master_check = 'onemesh_role' in sync_text and 'master' in sync_text
    legacy_lua_64 = contains(onemesh_lua, "openssl genrsa -out /tmp/onemesh_rsa_private_key.pem 64")
    meshkeys_ref = contains(onemesh_lua, "meshkeys")
    rsa2048_ref = contains(onemesh_lua, "rsa2048_enable")
    client_list_ref = contains(onemesh_lua, "/tmp/sync-server/onemesh_client_list")
    key_exchange_refs = all(
        contains(onemesh_lua, token)
        for token in [
            "master_get_slave_key",
            "master_set_slave_key",
            "slave_offer_enc_slave_key",
            "master_accept_enc_slave_key",
            "master_decrypt_enc_slave_key",
        ]
    )
    static_aes_key = contains(tdp_bin, "TPONEMESH_Kf!xn?gj6pMAt-wBNV_TDP")
    tdp_enabled = "START=50" in tdp_init_text and "/usr/bin/tdpServer" in tdp_init_text if tdp_init else False
    meshd_enabled = (
        ("START=" in meshd_init_text and not meshd_init_text.lstrip().startswith("#START"))
        if meshd_init
        else False
    )
    onemesh_default = "confirmed-on-default" if sync_fallback_on and sync_master_check else "uncertain"
    if not sync_server and not onemesh_lua:
        onemesh_default = "absent"
    if sync_server and not sync_fallback_on:
        onemesh_default = "configured-only"

    if not rsa_exists and luarsa and "rsa2048_enable" in luarsa_text and legacy_lua_64:
        legacy_state = "reachable-legacy-default-when-config-absent"
    elif rsa_exists and rsa_default == "true":
        legacy_state = "2048-default-configured"
    elif legacy_lua_64:
        legacy_state = "legacy-path-present"
    else:
        legacy_state = "unknown"

    if tdp_enabled and sync_fallback_on and legacy_lua_64 and static_aes_key:
        vuln_state = "confirmed-vulnerable-by-default"
    elif legacy_lua_64 and (sync_fallback_on or meshd_enabled):
        vuln_state = "reachable-legacy-only-path"
    else:
        vuln_state = "uncertain-deployment-state"

    return {
        "vendor": meta.get("vendor", "UNKNOWN"),
        "model": meta.get("model", "UNKNOWN"),
        "version": meta.get("version", ""),
        "corpus_id": meta.get("corpus_id", ""),
        "rootfs_path": str(rootfs),
        "rsa2048_exists": rsa_exists,
        "rsa2048_default": rsa_default or "",
        "rsa2048_absent_by_default": not rsa_exists,
        "legacy_rsa_reachable": legacy_lua_64 or ("rsa2048_enable" in luarsa_text),
        "legacy_rsa_state": legacy_state,
        "tdp_present": bool(tdp_bin),
        "tdp_enabled": tdp_enabled,
        "onemesh_default_state": onemesh_default,
        "sync_fallback_on": sync_fallback_on,
        "sync_master_check": sync_master_check,
        "meshd_enabled": meshd_enabled,
        "easymesh_re_enabled": bool(easymesh_re and "START=98" in read_text(easymesh_re)),
        "static_aes_key": static_aes_key,
        "meshkeys_ref": meshkeys_ref,
        "client_list_ref": client_list_ref,
        "key_exchange_refs": key_exchange_refs,
        "lua_orchestration_reuse": bool(onemesh_lua and easymesh_lua),
        "vuln_state": vuln_state,
        "helper_paths": [str(p.relative_to(rootfs)) for p in [luarsa, sync_server, tdp_init, meshd_init, easymesh_re, onemesh_lua, easymesh_lua, tdp_bin, meshd_bin] if p],
    }


def md_table(rows: list[list[str]]) -> list[str]:
    if not rows:
        return []
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for idx, row in enumerate(rows):
        lines.append("| " + " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)) + " |")
        if idx == 0:
            lines.append("| " + " | ".join("-" * widths[i] for i in range(len(widths))) + " |")
    return lines


def generate_reports(workspace_root: Path, targets: list[dict]) -> None:
    rows = [[
        "Target", "rsa2048_enable", "Absent", "Legacy RSA", "tdpServer", "OneMesh default", "AES key", "Assessment"
    ]]
    for t in targets:
        rows.append([
            f"{t['vendor']} {t['model']} {t['version']}",
            t["rsa2048_default"] or "absent",
            "yes" if t["rsa2048_absent_by_default"] else "no",
            t["legacy_rsa_state"],
            "enabled" if t["tdp_enabled"] else ("present-disabled" if t["tdp_present"] else "absent"),
            t["onemesh_default_state"],
            "yes" if t["static_aes_key"] else "no",
            t["vuln_state"],
        ])
    rsa_lines = [
        "# Legacy RSA Default-State Analysis",
        "",
        "Factory `etc/config/system` does not define `system.system.rsa2048_enable` on the validated TP-Link/MERCUSYS management-stack samples in this corpus slice. The 2048-bit path is referenced by init and Lua code, but the config key is absent-by-default.",
        "",
        *md_table(rows),
    ]
    write_md(workspace_root / "rsa2048_default_validation.md", rsa_lines)

    onemesh_lines = [
        "# OneMesh Deployment Exposure",
        "",
        "The same OneMesh trust pipeline recurs across TP-Link and MERCUSYS: Lua controller key-exchange helpers, `/tmp/sync-server/onemesh_client_list`, `meshkeys` persistence references, and 64-bit RSA generation strings.",
        "",
    ]
    for t in targets:
        onemesh_lines.extend([
            f"## {t['vendor']} {t['model']} {t['version']}",
            f"- `onemesh_default_state`: `{t['onemesh_default_state']}`",
            f"- `sync_fallback_on`: `{t['sync_fallback_on']}`",
            f"- `legacy_rsa_reachable`: `{t['legacy_rsa_reachable']}`",
            f"- `static_aes_key`: `{t['static_aes_key']}`",
            f"- `meshkeys_ref`: `{t['meshkeys_ref']}`",
            f"- `client_list_ref`: `{t['client_list_ref']}`",
            f"- `key_exchange_refs`: `{t['key_exchange_refs']}`",
            "",
        ])
    write_md(workspace_root / "onemesh_crypto_exposure.md", onemesh_lines)

    tdp_lines = [
        "# tdpServer Deployment Recurrence",
        "",
        "Static deployment is consistent across the validated TP-Link router builds and absent from the validated MERCUSYS builds in this corpus slice.",
        "",
    ]
    for t in targets:
        tdp_lines.extend([
            f"## {t['vendor']} {t['model']} {t['version']}",
            f"- `tdp_present`: `{t['tdp_present']}`",
            f"- `tdp_enabled`: `{t['tdp_enabled']}`",
            f"- `helper_paths`: `{', '.join([p for p in t['helper_paths'] if 'tdpServer' in p]) or 'none'}`",
            "",
        ])
    write_md(workspace_root / "tdpserver_deployment_recurrence.md", tdp_lines)

    trust_lines = [
        "# Management Plane Trust Recurrence",
        "",
        "Across the validated management-stack targets, the recurring pattern is: absent-by-default `rsa2048_enable` config, Lua OneMesh key-exchange helpers, `meshkeys` persistence references, and sync-server fallback that treats missing `onemesh.onemesh.enable` as `on`.",
        "",
    ]
    for t in targets:
        trust_lines.extend([
            f"## {t['vendor']} {t['model']} {t['version']}",
            f"- `lua_orchestration_reuse`: `{t['lua_orchestration_reuse']}`",
            f"- `sync_fallback_on`: `{t['sync_fallback_on']}`",
            f"- `meshd_enabled`: `{t['meshd_enabled']}`",
            f"- `easymesh_re_enabled`: `{t['easymesh_re_enabled']}`",
            "",
        ])
    write_md(workspace_root / "management_plane_trust_recurrence.md", trust_lines)

    vuln_lines = [
        "# Vulnerable By Default Assessment",
        "",
        "This assessment separates confirmed vulnerable-by-default deployment from weaker reachability-only evidence.",
        "",
    ]
    for category in [
        "confirmed-vulnerable-by-default",
        "reachable-legacy-only-path",
        "uncertain-deployment-state",
    ]:
        vuln_lines.append(f"## {category}")
        for t in targets:
            if t["vuln_state"] == category:
                vuln_lines.append(f"- `{t['vendor']} {t['model']} {t['version']}`")
        vuln_lines.append("")
    write_md(workspace_root / "vulnerable_by_default_assessment.md", vuln_lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args()
    targets = [gather_target(entry) for entry in best_bundles(args.workspace_root)]
    targets.sort(key=lambda t: (t["vendor"], t["model"], t["version"]))
    generate_reports(args.workspace_root, targets)


if __name__ == "__main__":
    main()
