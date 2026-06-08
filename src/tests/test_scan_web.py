"""
Tests for scan_web_surface() covering vendor-specific web root patterns
added in the ipTIME / Xiaomi / Linksys fix round.
"""

import os
import tempfile
import unittest

from src.core.scanner.scan_web import scan_web_surface, _WWW_NAMES, _WEB_ROOT_REL_HINTS


# ── helpers ───────────────────────────────────────────────────────────────────

def _mkfile(path, content=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content or b"#!/bin/sh\n")


def _mkexe(path, content=b""):
    _mkfile(path, content)
    os.chmod(path, 0o755)


# ── pattern membership tests ──────────────────────────────────────────────────

class WwwNamesTests(unittest.TestCase):
    """_WWW_NAMES must contain the vendor-specific directory names we added."""

    def test_cgibin_nohyphen_in_www_names(self):
        self.assertIn("cgibin", _WWW_NAMES)

    def test_cgi_hyphenless_still_present(self):
        self.assertIn("cgi-bin", _WWW_NAMES)

    def test_goform_in_www_names(self):
        self.assertIn("goform", _WWW_NAMES)


class WebRootHintsTests(unittest.TestCase):
    """_WEB_ROOT_REL_HINTS must include ipTIME and Xiaomi anchors."""

    def test_home_httpd_hint_present(self):
        self.assertIn("home/httpd", _WEB_ROOT_REL_HINTS)

    def test_www_cgi_bin_hint_present(self):
        self.assertIn("www/cgi-bin", _WEB_ROOT_REL_HINTS)


# ── functional tests ──────────────────────────────────────────────────────────

class IpTimeCgibinTests(unittest.TestCase):
    """
    ipTIME v14 style: CGI files live in <rootfs>/cgibin/ (no hyphen).
    Before the fix _WWW_NAMES only had 'cgi-bin', missing 'cgibin'.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rootfs(self):
        return self.tmp

    def test_cgibin_cgi_files_detected(self):
        rootfs = self._rootfs()
        _mkexe(os.path.join(rootfs, "usr", "sbin", "httpd"))
        _mkexe(os.path.join(rootfs, "cgibin", "timepro.cgi"),
               b"#!/bin/sh\npopen(system())\n")
        _mkexe(os.path.join(rootfs, "cgibin", "d.cgi"))

        web_bins, cgi_files = scan_web_surface(rootfs)

        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("cgibin", "timepro.cgi"), cgi_rels)
        self.assertIn(os.path.join("cgibin", "d.cgi"), cgi_rels)

    def test_httpd_binary_detected_as_web_server(self):
        rootfs = self._rootfs()
        _mkexe(os.path.join(rootfs, "usr", "sbin", "httpd"))
        _mkexe(os.path.join(rootfs, "cgibin", "service.cgi"))

        web_bins, _ = scan_web_surface(rootfs)

        httpd_path = os.path.join(rootfs, "usr", "sbin", "httpd")
        self.assertIn(os.path.normpath(httpd_path), web_bins)


class IpTimeHomeHttpdTests(unittest.TestCase):
    """
    ipTIME v15 style: CGI files live under home/httpd/<ip>/cgi/
    The 'home/httpd' hint ensures the walk anchors there.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_home_httpd_ip_subdir_cgi_detected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "httpd"))
        _mkexe(os.path.join(rootfs, "home", "httpd", "192.168.0.1", "cgi", "d.cgi"))
        _mkexe(os.path.join(rootfs, "home", "httpd", "192.168.0.1", "cgi", "service.cgi"))

        web_bins, cgi_files = scan_web_surface(rootfs)

        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("home", "httpd", "192.168.0.1", "cgi", "d.cgi"), cgi_rels)
        self.assertIn(os.path.join("home", "httpd", "192.168.0.1", "cgi", "service.cgi"), cgi_rels)

    def test_home_httpd_flat_cgi_detected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "httpd"))
        _mkexe(os.path.join(rootfs, "home", "httpd", "cgi", "main.cgi"))

        _, cgi_files = scan_web_surface(rootfs)

        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("home", "httpd", "cgi", "main.cgi"), cgi_rels)


class NginxWebRootTests(unittest.TestCase):
    """
    Xiaomi xiaoqiang style: nginx + www/cgi-bin.
    nginx binary must be found as a web server, and www/cgi-bin must be scanned.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_nginx_binary_detected_as_web_server(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "nginx"))
        _mkexe(os.path.join(rootfs, "www", "cgi-bin", "luci"))

        web_bins, _ = scan_web_surface(rootfs)

        nginx_path = os.path.normpath(os.path.join(rootfs, "usr", "sbin", "nginx"))
        self.assertIn(nginx_path, web_bins)

    def test_www_cgi_bin_lua_files_collected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "nginx"))
        _mkfile(os.path.join(rootfs, "www", "cgi-bin", "api.lua"))
        _mkfile(os.path.join(rootfs, "www", "cgi-bin", "index.html"))

        _, cgi_files = scan_web_surface(rootfs)

        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("www", "cgi-bin", "api.lua"), cgi_rels)


class LinksysWwwTests(unittest.TestCase):
    """
    Linksys JNAP style: lighttpd + www/cgi-bin/*.cgi
    www/ is already in _WWW_NAMES; verify scan correctly reaches www/cgi-bin.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lighttpd_binary_detected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "lighttpd"))
        _mkexe(os.path.join(rootfs, "www", "cgi-bin", "index.cgi"))

        web_bins, _ = scan_web_surface(rootfs)

        lighttpd = os.path.normpath(os.path.join(rootfs, "usr", "sbin", "lighttpd"))
        self.assertIn(lighttpd, web_bins)

    def test_www_cgi_bin_scripts_collected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "lighttpd"))
        _mkexe(os.path.join(rootfs, "www", "cgi-bin", "jnap.cgi"))
        _mkexe(os.path.join(rootfs, "www", "cgi-bin", "ezwifi.cgi"))

        _, cgi_files = scan_web_surface(rootfs)

        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("www", "cgi-bin", "jnap.cgi"), cgi_rels)
        self.assertIn(os.path.join("www", "cgi-bin", "ezwifi.cgi"), cgi_rels)


class RegressionTests(unittest.TestCase):
    """Standard OpenWrt / LuCI patterns must still be detected after the patch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_openwrt_luci_uhttpd_still_detected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "uhttpd"))
        _mkfile(os.path.join(rootfs, "usr", "lib", "lua", "luci", "controller", "admin.lua"))

        web_bins, cgi_files = scan_web_surface(rootfs)

        uhttpd = os.path.normpath(os.path.join(rootfs, "usr", "sbin", "uhttpd"))
        self.assertIn(uhttpd, web_bins)
        cgi_rels = [os.path.relpath(p, rootfs) for p in cgi_files]
        self.assertIn(os.path.join("usr", "lib", "lua", "luci", "controller", "admin.lua"), cgi_rels)

    def test_boa_www_cgi_still_detected(self):
        rootfs = self.tmp
        _mkexe(os.path.join(rootfs, "usr", "sbin", "boa"))
        _mkexe(os.path.join(rootfs, "www", "cgi-bin", "formWsc.cgi"))

        web_bins, cgi_files = scan_web_surface(rootfs)

        boa = os.path.normpath(os.path.join(rootfs, "usr", "sbin", "boa"))
        self.assertIn(boa, web_bins)


class RealDataIntegrationTests(unittest.TestCase):
    """
    Verify scan_web_surface() against actual extracted rootfs directories
    from the regeneration corpus.  Tests are skipped when the corpus data
    is not present (CI / fresh checkouts).
    """

    _REGEN = os.path.normpath(os.path.join(
        os.path.dirname(__file__), "..", "..",
        "research", "regeneration", "full_corpus_20260508",
    ))

    def _root(self, *parts):
        return os.path.normpath(os.path.join(self._REGEN, *parts))

    def _skip_if_missing(self, path):
        if not os.path.isdir(path):
            self.skipTest(f"corpus rootfs not present: {path}")

    # ── ipTIME AX2004M v14 (cgibin/ pattern) ─────────────────────────────────

    def test_iptime_ax2004m_v14_cgibin_detected(self):
        root = self._root(
            "AX2004M", "ax2004m_ml_14_234", ".cache", "build",
            "_iot_extract_ax2004m_ml_14_234_7ae456b0",
            "_ax2004m_ml_14_234.bin.extracted", "squashfs-root",
        )
        self._skip_if_missing(root)
        web_bins, cgi_files = scan_web_surface(root)
        self.assertTrue(
            web_bins or cgi_files,
            "ipTIME AX2004M v14: expected web surface, got none",
        )

    # ── TP-Link XE75 (uhttpd + LuCI) ─────────────────────────────────────────

    def test_tplink_xe75_uhttpd_luci_detected(self):
        root = self._root(
            "XE75 - XE5300 - WE10800",
            "XE75_XE5300_WE10800_SP1--ver1-3-1-P1[20251023-rel43624]",
            ".cache", "build",
            "_iot_extract_xe75-xe5300-we10800-sp1-up-ver1_11266699",
            "_ubi_extract", "1814.ubi",
            "_nested_img-1149320214_vol-ubi_rootfs.ubifs",
            "_img-1149320214_vol-ubi_rootfs.ubifs.extracted",
            "squashfs-root",
        )
        self._skip_if_missing(root)
        web_bins, cgi_files = scan_web_surface(root)
        self.assertGreater(len(cgi_files), 0, "XE75: expected LuCI cgi_files")

    # ── Tenda RX9 Pro (httpd + www) ──────────────────────────────────────────

    def test_tenda_rx9pro_www_detected(self):
        root = self._root(
            "RX9 Pro", "RX9Prov1FirmwareV22030220",
            ".cache", "build",
            "_iot_extract_us_rx9prov1.0in_v22.03.02_db6b8d8a",
            "_US_RX9ProV1.0in_V22.03.02.20_multi_TDE01.bin.extracted",
            "squashfs-root",
        )
        self._skip_if_missing(root)
        web_bins, cgi_files = scan_web_surface(root)
        self.assertTrue(web_bins or cgi_files, "Tenda RX9 Pro: expected web surface")

    # ── MERCUSYS MR60X (uhttpd + LuCI) ───────────────────────────────────────

    def test_mercusys_mr60x_uhttpd_luci_detected(self):
        root = self._root(
            "MR60X",
            "MR60X_V2.20_1.1.0_Build_2025111220251231070005",
            ".cache", "build",
            "_iot_extract_mr60xv2-20-up-ver1-1-0-p1_54999ba7",
            "_MR60Xv2.20-up-ver1-1-0-P1[20251112-rel34837]_2025-11-12_09.52.40.bin.extracted",
            "squashfs-root",
        )
        self._skip_if_missing(root)
        web_bins, cgi_files = scan_web_surface(root)
        self.assertGreater(len(cgi_files), 0, "MR60X: expected LuCI cgi_files")

    # ── Xiaomi AX3000 (nginx + www/cgi-bin) ──────────────────────────────────

    def test_xiaomi_ax3000_nginx_detected(self):
        root = self._root(
            "AX3000", "miwifi_ra82_firmware_db06e_1.4.31_INT",
            ".cache", "build",
            "_iot_extract_miwifi_ra82_firmware_db06e_1.4_2945bac0",
            "_ubi_extract", "2B4.ubi",
            "_nested_img-2070064628_vol-ubi_rootfs.ubifs",
            "_img-2070064628_vol-ubi_rootfs.ubifs.extracted",
            "squashfs-root",
        )
        self._skip_if_missing(root)
        web_bins, cgi_files = scan_web_surface(root)
        nginx_found = any("nginx" in b for b in web_bins)
        self.assertTrue(nginx_found, "Xiaomi AX3000: nginx binary not in web_bins")

    # ── Linksys MX42SH (lighttpd + www/cgi-bin) ──────────────────────────────

    def test_linksys_mx42sh_www_cgibin_detected(self):
        root = self._root(
            "MX42SH", "FW_MX42SH_1.0.10.210447_prod",
            ".cache", "build",
            "_iot_extract_fw_mx42sh_1.0.10_ae749404",
            "_ubi_extract", "600000.ubi",
            "_nested_img-717739728_vol-squashfs.ubifs",
            "_img-717739728_vol-squashfs.ubifs.extracted",
            "squashfs-root",
        )
        self._skip_if_missing(root)
        _, cgi_files = scan_web_surface(root)
        jnap = any("JNAP" in c or "jnap" in c for c in cgi_files)
        self.assertTrue(jnap, "Linksys MX42SH: JNAP cgi not found")


if __name__ == "__main__":
    unittest.main()
