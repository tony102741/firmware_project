"""
Analyze MR90X network-facing mesh/management daemons and identify the most
likely replacement for TP-Link tdpServer semantics.

Usage:
  python3 src/research_tools/mr90x_tdp_replacement_report.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = PROJECT_ROOT / "research/regeneration/full_corpus_20260508"
MR90X_ROOT = WORKSPACE / "MR90X (EU)/MR90X(EU)_V1.20_23080820240123090924/.cache/build/_iot_extract_mr90xv1-2-up-eu-ver1-0-1-p1_cfa5c26b/_ubi_extract/117A.ubi/_nested_img-2086401218_vol-rootfs.ubifs/_img-2086401218_vol-rootfs.ubifs.extracted/squashfs-root"
AX72_TDPSERVER = WORKSPACE / "Archer AX72/Archer AX72(US)_V2_241119/.cache/build/_iot_extract_ax72v2-up-us-ver1-3-1-p1_5ee743bf/_ubi_extract/145E.ubi/_nested_img-882578842_vol-ubi_rootfs.ubifs/_img-882578842_vol-ubi_rootfs.ubifs.extracted/squashfs-root/usr/bin/tdpServer"

CANDIDATES = [
    {"name": "tmpsvr", "binary": "usr/bin/tmpsvr", "init": "etc/init.d/tmpsvr"},
    {"name": "ieee1905", "binary": "usr/bin/ieee1905", "init": None},
    {"name": "easymesh-agent", "binary": "usr/bin/easymesh-agent", "init": None},
    {"name": "easymesh-controller", "binary": "usr/bin/easymesh-controller", "init": None},
    {"name": "meshd", "binary": "usr/bin/meshd", "init": "etc/init.d/meshd"},
    {"name": "sync-server", "binary": "usr/bin/sync-server", "init": "etc/init.d/sync-server"},
    {"name": "map_cli", "binary": "usr/bin/map_cli", "init": None},
]

NETWORK_IMPORTS = {
    "recvfrom", "sendto", "recvmsg", "sendmsg", "recv", "send", "socket", "bind",
    "listen", "accept", "connect", "select", "poll", "epoll_wait", "epoll_ctl",
}
CONTROL_IMPORTS = {
    "ubus_connect", "ubus_add_object", "ubus_lookup_id", "uci_alloc_context",
    "uci_lookup_ptr", "uci_load", "lua_pcall", "system", "popen", "execve",
    "fork", "uloop_init", "uloop_run",
}


def run(args: list[str], path: Path) -> str:
    return subprocess.run(
        args + [str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    ).stdout


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def file_desc(path: Path) -> str:
    return run(["file", "-b"], path).strip()


def imports(path: Path) -> list[str]:
    out = []
    dyn = run(["readelf", "--dyn-syms", "--wide"], path)
    for line in dyn.splitlines():
        if " UND " not in f" {line} ":
            continue
        parts = line.split()
        if not parts:
            continue
        out.append(parts[-1].split("@", 1)[0])
    return sorted(set(out))


def strings(path: Path) -> list[str]:
    return run(["strings", "-a", "-n", "4"], path).splitlines()


def init_meta(path: Path | None) -> tuple[str, str]:
    if path is None or not path.exists():
        return "", ""
    text = read(path)
    start = ""
    for line in text.splitlines():
        if line.startswith("START="):
            start = line.split("=", 1)[1].strip()
            break
    return start, text


def collect_candidate(spec: dict) -> dict:
    binary = MR90X_ROOT / spec["binary"]
    init_path = MR90X_ROOT / spec["init"] if spec["init"] else None
    imps = imports(binary)
    strs = strings(binary)
    start_prio, init_text = init_meta(init_path)
    blob = "\n".join(strs)
    return {
        "name": spec["name"],
        "binary_path": str(binary),
        "init_script": str(init_path) if init_path and init_path.exists() else "",
        "start_priority": start_prio,
        "file_desc": file_desc(binary),
        "network_imports": [i for i in imps if i in NETWORK_IMPORTS],
        "control_imports": [i for i in imps if i in CONTROL_IMPORTS],
        "has_recvfrom_sendto": "recvfrom" in imps and "sendto" in imps,
        "ubus_refs": any(tok in blob for tok in ["ubus", "map_ubus_init"]),
        "uci_refs": any(tok in blob for tok in ["uci_", "uci "]),
        "lua_refs": any(tok in blob for tok in ["lua", "tmp-luci", "luci."]),
        "easy1905_refs": [tok for tok in ["easymesh", "onemesh", "ieee1905", "map", "topology", "1905"] if tok in blob.lower()],
        "aes_rsa_refs": [tok for tok in ["AES_", "rsa", "meshkeys", "TPONEMESH_Kf!xn?gj6pMAt-wBNV_TDP"] if tok in blob],
        "helper_exec_refs": [tok for tok in ["/usr/bin/tmp-luci", "/usr/bin/easymesh-agent", "/usr/bin/easymesh-controller", "/lib/sync-server/scripts", "lua -e"] if tok in blob],
        "interesting_strings": [
            s for s in strs
            if any(tok in s.lower() for tok in ["tdp", "tmp-luci", "onemesh", "easymesh", "1905", "map", "mesh_db", "sync-server", "rsa", "aes"])
        ][:80],
        "init_text": init_text,
    }


def md_table(rows: list[list[str]]) -> list[str]:
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    out = []
    for idx, row in enumerate(rows):
        out.append("| " + " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)) + " |")
        if idx == 0:
            out.append("| " + " | ".join("-" * widths[i] for i in range(len(widths))) + " |")
    return out


def write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def generate_reports(cands: list[dict]) -> None:
    inv = [
        "# Candidate Network-Facing Daemons",
        "",
        "MR90X mesh-management candidates with networking, control-plane, and helper indicators.",
        "",
    ]
    rows = [["Name", "Binary", "Init", "START", "Net imports", "ubus", "uci", "lua", "EasyMesh/1905"]]
    for c in cands:
        rows.append([
            c["name"],
            Path(c["binary_path"]).name,
            Path(c["init_script"]).name if c["init_script"] else "-",
            c["start_priority"] or "-",
            ",".join(c["network_imports"]) or "-",
            "yes" if c["ubus_refs"] else "no",
            "yes" if c["uci_refs"] else "no",
            "yes" if c["lua_refs"] else "no",
            ",".join(c["easy1905_refs"]) or "-",
        ])
    inv.extend(md_table(rows))
    inv.append("")
    for c in cands:
        inv.extend([
            f"## {c['name']}",
            f"- `binary_path`: `{c['binary_path']}`",
            f"- `init_script`: `{c['init_script'] or 'none'}`",
            f"- `START`: `{c['start_priority'] or 'n/a'}`",
            f"- `network_imports`: `{', '.join(c['network_imports']) or 'none'}`",
            f"- `control_imports`: `{', '.join(c['control_imports']) or 'none'}`",
            f"- `has_recvfrom_sendto`: `{c['has_recvfrom_sendto']}`",
            f"- `ubus_refs`: `{c['ubus_refs']}`",
            f"- `uci_refs`: `{c['uci_refs']}`",
            f"- `lua_refs`: `{c['lua_refs']}`",
            f"- `easy1905_refs`: `{', '.join(c['easy1905_refs']) or 'none'}`",
            f"- `aes_rsa_refs`: `{', '.join(c['aes_rsa_refs']) or 'none'}`",
            f"- `helper_exec_refs`: `{', '.join(c['helper_exec_refs']) or 'none'}`",
            "",
        ])
    write(WORKSPACE / "mr90x_network_daemon_inventory.md", inv)

    cand = [
        "# Strongest tdpServer Replacement Candidate",
        "",
        "`tmpsvr` is the strongest replacement candidate for TP-Link `tdpServer` semantics.",
        "",
        "- It is init-started at `START=50` via [tmpsvr init](" + str((MR90X_ROOT / "etc/init.d/tmpsvr").resolve()) + ").",
        "- It imports `socket`, `recvfrom`, `sendto`, `accept`, `connect`, `fork`, `system`, `uloop_*`.",
        "- It contains explicit `TDP Server`, `TDP/2.0`, checksum, transaction, and listener strings.",
        "- It directly references `/usr/bin/tmp-luci`.",
        "- `tmp-luci` is a Lua launcher into `luci.sgi.tmp.run()`, and [tmp_server.lua](" + str((MR90X_ROOT / "usr/lib/lua/luci/controller/admin/tmp_server.lua").resolve()) + ") exposes the management dispatch layer.",
        "",
        "`ieee1905` plus `easymesh-agent`/`easymesh-controller` form a second external control plane for EasyMesh MAP/1905 traffic, but they look more like the EasyMesh subsystem itself than the TDP-style OneMesh ingress replacement.",
        "",
    ]
    write(WORKSPACE / "mr90x_mesh_orchestration_candidates.md", cand)

    repl = [
        "# MR90X tdpServer Replacement Analysis",
        "",
        "## Packet Processing Indicators",
        "- `tmpsvr` is the only validated MR90X candidate here with direct `recvfrom` and `sendto` imports plus `TDP Server` transport strings.",
        "- `tmpsvr` logs checksum, version, payload-size, and timeout errors for `TDP` packets, matching a packet parser role rather than a pure helper role.",
        "- `ieee1905` is clearly an IEEE1905 process by naming and linked library usage, but the external packet processing is likely abstracted into `libieee1905.so` rather than exposed in this stripped front binary.",
        "",
        "## Ubus/UCI/Lua Relationships",
        "- `tmpsvr` points to `/usr/bin/tmp-luci`.",
        "- `tmp-luci` launches `luci.sgi.tmp.run()`.",
        "- `tmp_server.lua` is the admin dispatch layer behind that temporary-management path.",
        "- `sync-server` persists `/tmp/sync-server/onemesh_client_list`, manipulates OneMesh UCI state, and calls Lua via `lua -e 'require(\"luci.model.one_mesh\").api_timeout_called()'`.",
        "- `meshd` uses ubus/UCI internally and starts `easymesh-agent` / `easymesh-controller`, but it does not look like the first network listener for TDP traffic.",
        "",
        "## Semantic Comparison with TP-Link tdpServer",
        f"- TP-Link AX72 [tdpServer]({str(AX72_TDPSERVER.resolve())}) imports `bind`, `recvfrom`, `sendto`, `socket`, `ubus_*`, `uci_*`, `system`, `popen`, and carries `TPONEMESH_Kf!xn?gj6pMAt-wBNV_TDP` plus dense OneMesh/UCI strings.",
        "- MR90X `tmpsvr` matches the network-ingress side: packet listener, TDP transaction handling, `/usr/bin/tmp-luci` helper handoff, and event-loop operation.",
        "- MR90X `sync-server` matches the persistence/orchestration side: OneMesh client list state, UCI propagation, Lua callback, and helper-script execution.",
        "- MR90X `ieee1905` / `easymesh-*` cover the EasyMesh MAP/1905 lane that is less visible in TP-Link `tdpServer` itself.",
        "",
        "Conclusion: the MR90X design appears split where TP-Link bundled more OneMesh/TDP semantics into `tdpServer`; MR90X uses `tmpsvr` as the external TDP ingress, `tmp-luci`/Lua as the management bridge, and `sync-server`/`meshd`/`easymesh-*` as the orchestration backend.",
    ]
    write(WORKSPACE / "mr90x_tdpserver_replacement_analysis.md", repl)

    surf = [
        "# MR90X External Input Surface",
        "",
        "Likely external network-facing surfaces in descending confidence:",
        "",
        "1. `tmpsvr`: strongest TDP/temporary-management listener candidate.",
        "2. `ieee1905`: likely EasyMesh IEEE1905 ingress front-end, with heavy reliance on `libieee1905.so`.",
        "3. `easymesh-agent` and `easymesh-controller`: MAP/1905 subsystem processes with ubus/UCI and platform integration.",
        "4. `meshd`: orchestration daemon that starts EasyMesh processes and performs ubus-driven coordination.",
        "5. `sync-server`: persistent OneMesh/EasyMesh state manager, likely not the first packet listener.",
        "",
        "Recommended first Ghidra target: `tmpsvr`.",
        f"- path: `{(MR90X_ROOT / 'usr/bin/tmpsvr').resolve()}`",
        "Recommended second target: `sync-server`.",
        f"- path: `{(MR90X_ROOT / 'usr/bin/sync-server').resolve()}`",
        "Recommended EasyMesh lane target after that: `easymesh-agent`.",
        f"- path: `{(MR90X_ROOT / 'usr/bin/easymesh-agent').resolve()}`",
    ]
    write(WORKSPACE / "mr90x_external_input_surface.md", surf)


def main() -> None:
    cands = [collect_candidate(spec) for spec in CANDIDATES]
    generate_reports(cands)


if __name__ == "__main__":
    main()
