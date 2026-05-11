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
WORKSPACE = Path("/home/user/firmware_project/ghidra_targets/mr90x_tplink_agent_stack")

COMPONENTS = [
    "usr/bin/cloud-pfclient",
    "usr/lib/libtmpv2.so",
    "usr/bin/cloud-brd",
    "usr/bin/cloud-https",
    "usr/bin/cloud-client",
    "usr/bin/tmpsvr",
]

CONTEXT = [
    "usr/bin/tmp-luci",
    "usr/bin/tmpv2/active_web",
    "usr/bin/tmpv2/aging_web",
    "usr/bin/tmpv2/kickoff_web",
    "usr/lib/lua/luci/controller/admin/tmp_server.lua",
    "usr/lib/lua/luci/controller/admin/cloud_account.lua",
    "usr/lib/lua/luci/controller/mobile_app/app_account.lua",
    "usr/lib/lua/luci/controller/mobile_app/cloud_manager.lua",
    "usr/lib/lua/luci/model/accountmgnt.lua",
    "usr/lib/lua/luci/sauth.lua",
    "usr/lib/lua/cloud/cloud_cfg.lua",
    "usr/lib/lua/cloud/hello_cloud_response.lua",
    "usr/lib/lua/cloud/notifyEvent.lua",
    "usr/lib/lua/cloud/passthrough.lua",
    "usr/lib/lua/cloud/push.lua",
    "usr/lib/lua/cloud/setAlias.lua",
    "usr/lib/lua/cloud/unbindDevice.lua",
    "usr/lib/lua/cloud/unbindDeviceWithFeatureInfo.lua",
    "usr/lib/lua/cloud/update.lua",
    "usr/lib/lua/cloud/smart_home/smart_home.lua",
    "usr/lib/lua/cloud/smart_home/smart_home_upload.lua",
    "usr/lib/lua/cloud/tp_apps/alexa.lua",
    "etc/config/accountmgnt",
    "etc/cloud_config.cfg",
    "etc/cloud_https.cfg",
    "etc/rc.d/S50tmpsvr",
    "etc/rc.d/S69domain_login",
    "etc/rc.d/S89cloud_report",
    "etc/rc.d/S97cloud_pfclient",
    "etc/rc.d/S98cloud_brd",
    "etc/rc.d/S99cloud_client",
    "etc/rc.d/S99cloud_https",
]

INIT_FILES = [
    "etc/init.d/tmpsvr",
    "etc/init.d/cloud_client",
    "etc/init.d/cloud_https",
    "etc/init.d/cloud_pfclient",
    "etc/init.d/cloud_brd",
    "etc/init.d/cloud_report",
    "etc/init.d/domain_login",
]


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main() -> None:
    build_dossier(
        rootfs=ROOTFS,
        workspace=WORKSPACE,
        target_name="MR90X tplink_agent stack",
        components=COMPONENTS,
        context=CONTEXT,
        init_files=INIT_FILES,
    )

    write(
        WORKSPACE / "cloud_relay_candidate_inventory.md",
        "\n".join(
            [
                "# Cloud Relay Candidate Inventory",
                "",
                "- `tplink_agent` literal binary is absent from the preserved MR90X rootfs.",
                "- `cloud-pfclient` is the strongest local auth/session bridge candidate.",
                "- `libtmpv2.so` is the strongest reusable TMP/TDP client transport library.",
                "- `cloud-brd` is the strongest outbound TLS cloud relay candidate.",
                "- `cloud-https` is the clearest HTTPS validation/REST helper candidate.",
                "- `cloud-client` looks like a local IPC/ubus cloud broker toward `cloud-brd`.",
                "",
                "## Init Order",
                "",
                "| Service | START | Role |",
                "| --- | ---: | --- |",
                "| `tmpsvr` | `50` | TMP ingress daemon |",
                "| `cloud_pfclient` | `97` | loopback/session relay into TMP |",
                "| `cloud_brd` | `98` | TLS cloud broker |",
                "| `cloud_client` | `99` | local cloud IPC broker |",
                "| `cloud_https` | `99` | HTTPS validation/REST helper |",
                "",
            ]
        ),
    )

    write(
        WORKSPACE / "tplink_agent_context.md",
        "\n".join(
            [
                "# tplink_agent Context",
                "",
                "- `tmpsvr` remains the ingress anchor for TMP/TDP handling.",
                "- `tmp-luci` and `tmp_server.lua` are the downstream Lua bridge.",
                "- `cloud-pfclient` appears to manage token/session state and loopback TMP forwarding.",
                "- `libtmpv2.so` appears to implement the actual TMP/TDP client transport path.",
                "- `cloud-brd`, `cloud-https`, and `cloud-client` form the broader cloud relay/auth stack.",
                "- `accountmgnt` config and cloud Lua modules provide local credential and cloud-account context.",
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
                "1. `usr/bin/cloud-pfclient`",
                "2. `usr/lib/libtmpv2.so`",
                "3. `usr/bin/cloud-brd`",
                "4. `usr/bin/cloud-https`",
                "5. `usr/bin/cloud-client`",
                "6. `usr/bin/tmpsvr`",
                "",
                "## Likely function families",
                "",
                "- `cloud-pfclient`: `get_new_session`, `find_session`, `check_session_timeout`, `session_clear_token`, `passthrough_resetSession`",
                "- `libtmpv2.so`: `tmp_client_connect_direct`, `tmp_client_request`, `tmp_client_request_token`, `tdp_client_prepare_packet`, `tdp_client_send_request`, `tdp_client_recv_reply`",
                "- `cloud-brd`: `cloud_client_handle_request`, `cloud_client_handle_request_noaccount`, `cloud_session_connect_defaultSvr`, `cloud_session_dispatch`, `cloud_worker_start`",
                "- `cloud-https`: `cloud_https_post_handle`, `cloud_https_get_handle`, `https_config_load`",
                "",
            ]
        ),
    )


if __name__ == "__main__":
    main()
