#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from component_dossier import build_dossier


ROOTFS = Path(
    "/home/user/firmware_project/research/regeneration/full_corpus_20260508/"
    "MR90X (EU)/MR90X(EU)_V1.20_23080820240123090924/.cache/build/"
    "_iot_extract_mr90xv1-2-up-eu-ver1-0-1-p1_cfa5c26b/_ubi_extract/117A.ubi/"
    "_nested_img-2086401218_vol-rootfs.ubifs/"
    "_img-2086401218_vol-rootfs.ubifs.extracted/squashfs-root"
)
WORKSPACE = Path("/home/user/firmware_project/ghidra_targets/mr90x_tmpsvr_stack")

COMPONENTS = [
    "usr/bin/tmpsvr",
    "usr/bin/sync-server",
    "usr/bin/meshd",
    "usr/bin/ieee1905",
    "usr/bin/easymesh-agent",
    "usr/bin/easymesh-controller",
]

CONTEXT = [
    "usr/bin/tmp-luci",
    "usr/lib/lua/luci/controller/admin/tmp_server.lua",
    "usr/lib/lua/luci/model/one_mesh.lua",
    "usr/lib/lua/luci/model/easy_mesh.lua",
    "etc/config/system",
    "etc/config/network",
    "etc/config/accountmgnt",
    "etc/easymesh_cfg.json",
    "etc/init.d/easymesh_re",
    "etc/rc.d/S98easymesh_re",
    "etc/rc.d/K90easymesh_re",
    "lib/sync-server/scripts/request",
    "lib/sync-server/scripts/request_clients",
    "lib/sync-server/scripts/sync_wifi",
    "lib/sync-server/scripts/trans_main_wcfg",
    "lib/sync-server/scripts/trans_backup_wcfg",
]

INIT_FILES = [
    "etc/init.d/tmpsvr",
    "etc/init.d/sync-server",
    "etc/init.d/meshd",
    "etc/rc.d/S50tmpsvr",
    "etc/rc.d/S50meshd",
    "etc/rc.d/S51sync-server",
]


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main() -> None:
    build_dossier(
        rootfs=ROOTFS,
        workspace=WORKSPACE,
        target_name="MR90X tmpsvr stack",
        components=COMPONENTS,
        context=CONTEXT,
        init_files=INIT_FILES,
    )

    write(
        WORKSPACE / "init_boot_order.md",
        "\n".join(
            [
                "# Init Boot Order",
                "",
                "| Init Script | START | Role |",
                "| --- | ---: | --- |",
                "| `etc/init.d/tmpsvr` | `50` | external TMP/TDP ingress service |",
                "| `etc/init.d/meshd` | `50` | EasyMesh orchestration coordinator |",
                "| `etc/init.d/sync-server` | `51` | OneMesh state propagation and helper execution hub |",
                "| `etc/init.d/easymesh_re` | `98` | repeater/EasyMesh UI adaptation helper |",
                "",
                "## Boot Hypothesis",
                "",
                "1. `tmpsvr` opens the ingress surface at `START=50`.",
                "2. `meshd` comes up in the same early phase to prepare mesh orchestration.",
                "3. `sync-server` follows to persist and relay mesh state.",
                "4. `easymesh_re` runs later for mode-specific adaptation.",
                "",
            ]
        ),
    )

    write(
        WORKSPACE / "lua_helper_relationships.md",
        "\n".join(
            [
                "# Lua Helper Relationships",
                "",
                "- `usr/bin/tmp-luci` is the Lua launcher between `tmpsvr` and `luci.sgi.tmp`.",
                "- `usr/lib/lua/luci/controller/admin/tmp_server.lua` is the TMP dispatch surface for mobile-app and admin handlers.",
                "- `usr/lib/lua/luci/model/one_mesh.lua` and `easy_mesh.lua` provide model-side mesh state helpers consumed by the management stack.",
                "- `lib/sync-server/scripts/request*` and `sync_wifi` are downstream state relay helpers used by `sync-server`.",
                "",
            ]
        ),
    )

    write(
        WORKSPACE / "orchestration_relationships.md",
        "\n".join(
            [
                "# Orchestration Relationships",
                "",
                "## Concise Call-Chain Hypothesis",
                "",
                "`external TDP packet -> tmpsvr -> /usr/bin/tmp-luci -> luci.sgi.tmp -> tmp_server.lua dispatch -> UCI/Lua state updates -> sync-server persistence/scripts -> meshd / easymesh-agent / easymesh-controller`",
                "",
                "## Process Relationship Diagram",
                "",
                "```text",
                "network client",
                "    |",
                "    v",
                "tmpsvr  --exec-->  tmp-luci  --Lua-->  tmp_server.lua",
                "    |                                  |",
                "    |                                  +--> UCI / runtime state",
                "    |",
                "    +--------------------------------------> sync-server",
                "                                               |",
                "                                               +--> request / request_clients / sync_wifi",
                "                                               +--> onemesh state persistence",
                "",
                "meshd  --exec--> easymesh-agent",
                "   |",
                "   +--exec--> easymesh-controller",
                "   +--ubus/UCI coordination",
                "```",
                "",
            ]
        ),
    )

    write(
        WORKSPACE / "ghidra_loading_order.md",
        "\n".join(
            [
                "# Ghidra Loading Order",
                "",
                "1. `usr/bin/tmpsvr`",
                "2. `usr/bin/sync-server`",
                "3. `usr/bin/meshd`",
                "4. `usr/bin/easymesh-agent`",
                "5. `usr/bin/easymesh-controller`",
                "6. `usr/bin/ieee1905`",
                "",
                "## Likely functions to inspect first",
                "",
                "- `tmpsvr`: `tdp_server_init`, `tdp_server_fd_cb`, `tmp_server_open`, `session_new_or_reuse`, `tdp_trans_feed`, `tmp_trans_feed`",
                "- `sync-server`: OneMesh persistence and helper invocation paths",
                "- `meshd`: child-process launch and orchestration setup for EasyMesh daemons",
                "",
            ]
        ),
    )


if __name__ == "__main__":
    main()
