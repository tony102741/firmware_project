#!/usr/bin/env python3
"""
OSS Version Scanner
- rootfs 디렉토리를 스캔해서 OSS 컴포넌트 버전을 추출
- 문자열 패턴 기반 (1단계: 가장 빠른 접근)
"""

import os
import re
import subprocess
import json
import sys
from pathlib import Path
from collections import defaultdict

# OSS 버전 패턴 정의
OSS_PATTERNS = {
    "openssl": [
        r"OpenSSL\s+([\d]+\.[\d]+\.[\d]+[a-z]?)",
        r"OpenSSL\s+([\d]+\.[\d]+\.[\d]+)",
    ],
    "curl": [
        r"curl/([\d]+\.[\d]+\.[\d]+)",
        r"libcurl/([\d]+\.[\d]+\.[\d]+)",
    ],
    "busybox": [
        r"BusyBox\s+v([\d]+\.[\d]+\.[\d]+)",
    ],
    "uhttpd": [
        r"uhttpd\s+([\d]+\.[\d]+\.[\d]+)",
        r"/usr/sbin/uhttpd",
    ],
    "lighttpd": [
        r"lighttpd/([\d]+\.[\d]+\.[\d]+)",
        r"lighttpd\s+([\d]+\.[\d]+\.[\d]+)",
    ],
    "boa": [
        r"Boa/([\d]+\.[\d]+\.[\d]+)",
        r"Boa Webserver",
    ],
    "linux_kernel": [
        r"Linux version ([\d]+\.[\d]+\.[\d]+[\d\.]*)",
    ],
    "uclibc": [
        r"uClibc[\s\-]+([\d]+\.[\d]+\.[\d]+)",
        r"UCLIBC_VERSION_([\d]+\.[\d]+\.[\d]+)",
    ],
    "musl": [
        r"musl libc \(([\d]+\.[\d]+\.[\d]+)\)",
        r"musl/([\d]+\.[\d]+\.[\d]+)",
    ],
    "dropbear": [
        r"Dropbear\s+v([\d]+\.[\d]+)",
        r"Dropbear SSH\s+([\d]+\.[\d]+)",
    ],
    "dnsmasq": [
        r"Dnsmasq\s+version\s+([\d]+\.[\d]+)",
        r"dnsmasq-([\d]+\.[\d]+)",
    ],
    "miniupnpd": [
        r"MiniUPnPd/([\d]+\.[\d]+)",
        r"miniupnpd\s+([\d]+\.[\d]+)",
    ],
    "lua": [
        r"Lua\s+([\d]+\.[\d]+\.[\d]+)",
        r"lua-([\d]+\.[\d]+)",
    ],
    "wolfssl": [
        r"wolfSSL\s+([\d]+\.[\d]+\.[\d]+)",
        r"wolfssl/([\d]+\.[\d]+\.[\d]+)",
    ],
    "mbedtls": [
        r"mbed TLS ([\d]+\.[\d]+\.[\d]+)",
        r"mbedtls-([\d]+\.[\d]+\.[\d]+)",
    ],
    "openwrt": [
        r"OpenWrt\s+([\d]+\.[\d]+[\.\d]*[\-\w]*)",
        r"DISTRIB_DESCRIPTION=.*OpenWrt.*?([\d]+\.[\d]+)",
        r"OpenWrt\s+(\d{2}\.\d{2}[\.\d]*)",
    ],
    "lede": [
        r"LEDE\s+([\d]+\.[\d]+\.[\d]+)",
    ],
}

# 스캔 대상 파일 패턴
SCAN_TARGETS = [
    # ELF 바이너리
    "usr/bin/*", "usr/sbin/*", "bin/*", "sbin/*",
    # 공유 라이브러리
    "usr/lib/*.so*", "lib/*.so*",
    # 설정/버전 파일
    "etc/openwrt_release", "etc/banner", "proc/version",
    "usr/lib/os-release", "etc/os-release",
]


def run_strings(filepath, min_len=6):
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), str(filepath)],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout
        # macOS fallback: try without -n flag style differences
        result2 = subprocess.run(
            ["strings", str(filepath)],
            capture_output=True, text=True, timeout=10
        )
        return result2.stdout
    except Exception:
        return ""


def scan_file(filepath):
    """파일 하나에서 OSS 버전 추출"""
    findings = {}
    content = run_strings(filepath)
    if not content:
        return findings

    for oss, patterns in OSS_PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, content, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else "detected"
                if oss not in findings:
                    findings[oss] = version
                break

    return findings


def scan_rootfs(rootfs_path):
    """rootfs 전체 스캔 (classic rootfs 또는 binwalk blob 추출 모두 지원)"""
    rootfs = Path(rootfs_path)
    if not rootfs.exists():
        print(f"[ERROR] Path not found: {rootfs_path}", file=sys.stderr)
        return {}

    oss_inventory = defaultdict(lambda: {"versions": set(), "found_in": []})
    scanned = 0
    skipped = 0

    # 주요 바이너리 디렉토리 우선 스캔
    priority_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib"]
    scan_paths = []

    for d in priority_dirs:
        target = rootfs / d
        if target.exists():
            for f in target.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    scan_paths.append(f)

    # etc, proc 등 설정 파일
    for cfg in ["etc/openwrt_release", "etc/banner", "etc/os-release"]:
        p = rootfs / cfg
        if p.exists():
            scan_paths.append(p)

    # binwalk blob 모드: classic rootfs가 없으면 *.extracted/**/decompressed.bin 스캔
    if not scan_paths:
        blob_mode = True
        for extracted_dir in rootfs.rglob("*.extracted"):
            if extracted_dir.is_dir():
                for blob in extracted_dir.rglob("decompressed.bin"):
                    if blob.is_file():
                        scan_paths.append(blob)
        if scan_paths:
            print(f"  [blob mode] binwalk 추출 파일 {len(scan_paths)}개 스캔", file=sys.stderr)
    else:
        blob_mode = False

    print(f"  스캔 대상: {len(scan_paths)}개 파일", file=sys.stderr)

    for fp in scan_paths:
        try:
            size = fp.stat().st_size
            if size > 50 * 1024 * 1024:  # 50MB 초과 스킵
                skipped += 1
                continue

            findings = scan_file(fp)
            for oss, version in findings.items():
                rel_path = str(fp.relative_to(rootfs))
                oss_inventory[oss]["versions"].add(version)
                oss_inventory[oss]["found_in"].append(rel_path)
            scanned += 1
        except Exception:
            skipped += 1

    print(f"  완료: {scanned}개 스캔, {skipped}개 스킵", file=sys.stderr)

    # set → list 변환
    result = {}
    for oss, data in oss_inventory.items():
        result[oss] = {
            "versions": sorted(data["versions"]),
            "found_in": sorted(set(data["found_in"]))[:5],  # 최대 5개만
        }

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 oss_version_scanner.py <rootfs_path> [label]")
        sys.exit(1)

    rootfs_path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else Path(rootfs_path).name

    print(f"\n=== OSS Version Scan: {label} ===", file=sys.stderr)
    inventory = scan_rootfs(rootfs_path)

    if not inventory:
        print(json.dumps({"label": label, "oss": {}}))
        return

    print(f"\n[{label}] 발견된 OSS 컴포넌트:")
    for oss, data in sorted(inventory.items()):
        versions = ", ".join(data["versions"]) if data["versions"] else "detected"
        sample = data["found_in"][0] if data["found_in"] else ""
        print(f"  {oss:15s} {versions:30s}  ({sample})")

    print(json.dumps({"label": label, "oss": inventory}, indent=2))


if __name__ == "__main__":
    main()
