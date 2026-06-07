#!/usr/bin/env python3
"""
Batch OSS Version Scan
- pipeline.py로 firmware 추출 후 즉시 OSS 스캔
- 각 결과를 즉시 저장 (pipeline이 캐시를 클리닝하므로)
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
INPUTS_DIR = PROJECT_ROOT / "inputs"
CACHE_BUILD = PROJECT_ROOT / ".cache" / "build"
SCANNER = PROJECT_ROOT / "scripts" / "oss_version_scanner.py"
PIPELINE = PROJECT_ROOT / "src" / "pipeline.py"
OUT_DIR = PROJECT_ROOT / "report" / "oss_scan"

# (product_dir, firmware_filename, label)
TARGETS = [
    ("A3002RU", "A3002RU V3-V3.0.0-B20201208.zip",        "A3002RU-V3-2020"),
    ("A3002RU", "A3002RU-V3.0.0-B20220304.1804.rar",       "A3002RU-V3-2022"),
    ("A3002RU", "A3002RU-V3.0.0-B20230809.1615.rar",       "A3002RU-V3-2023"),
    ("X6000R",  "TOTOLINK_C8380R_X6000R_IP04499_MT7981_SPI_16M256M_V9.4.0cu.1498_B20250826_ALL.zip", "X6000R-V9.4-2025"),
    ("MR60X",   "MR60X_V2.20_1.1.0_Build_2025111220251231070005.zip", "MR60X-V1.1-2025"),
    ("MR70X",   "MR70X_V2_1.2.0_Build_2025090420251106082258.zip",    "MR70X-V1.2-2025"),
    ("RX9 Pro", "RX9Prov1FirmwareV22030220.zip",            "RX9Pro-V22.03"),
    ("TX2Pro",  "US_TX2ProV1.0re_V16.03.30.26_multi_TDE01.zip", "TX2Pro-V16.03"),
    ("AX2004M", "ax2004m_ml_14_234.bin",                    "AX2004M-ml14"),
    ("AX12Pro", "US_AX12ProV3.0hi_V16.03.68.19_TD01.zip",  "AX12Pro-V16.03"),
    ("WR1300 V4","WR1300V4-R98-2.3.8-20250124-115930-flash.zip", "WR1300V4-2.3.8"),
    ("WR3000E",  "WR3000E-R53-2.2.7-20240910-160305-sysupgrade.zip", "WR3000E-2.2.7"),
    ("GL-MT3000","mt3000-4.8.1-0819-1755615825.tar",        "GL-MT3000-4.8.1"),
    ("GL-MT6000","mt6000-4.8.4_release2-879-0330-1774852402.bin", "GL-MT6000-4.8.4"),
    ("GL-X3000", "x3000-4.8.3_release3-902-1106-1762433696.bin",  "GL-X3000-4.8.3"),
    ("MX4200",   "FW_MX4200_2.0.7.216620_prod.img",         "MX4200-2.0.7"),
    ("RAX50",    "RAX50-V1.0.0.30_2.0.20.zip",              "RAX50-V1.0.0"),
    ("RT2600ac", "RT2600ac_1.3.6-0-g3bbf8da.spk",          "RT2600ac-1.3.6"),
    ("RT6600ax", "RT6600ax_1.3.1-86213.spk",               "RT6600ax-1.3.1"),
]


def find_rootfs_in_build() -> list[Path]:
    """빌드 캐시에서 파일이 있는 rootfs 후보를 반환"""
    candidates = []
    if not CACHE_BUILD.exists():
        return candidates

    for d in CACHE_BUILD.iterdir():
        if not d.is_dir():
            continue
        # 1) _raw_fs with content
        raw_fs = d / "_raw_fs"
        if raw_fs.exists() and any(raw_fs.iterdir()):
            candidates.append(raw_fs)
            continue
        # 2) _nested_*/_raw with content
        for nested in d.iterdir():
            if nested.name.startswith("_nested_") and nested.is_dir():
                raw = nested / "_raw"
                if raw.exists() and any(p for p in raw.iterdir() if p.is_dir()):
                    cnt = sum(1 for _ in raw.rglob("*") if _.is_file())
                    if cnt > 10:
                        candidates.append(raw)
                        break

    return candidates


def run_pipeline(product: str, filename: str) -> bool:
    firmware_path = INPUTS_DIR / product / filename
    if not firmware_path.exists():
        print(f"  [SKIP] 파일 없음: {firmware_path}")
        return False

    print(f"  추출 중: {filename}", flush=True)
    result = subprocess.run(
        [sys.executable, str(PIPELINE), "--input", str(firmware_path)],
        capture_output=True, text=True, timeout=600,
        cwd=str(PROJECT_ROOT)
    )
    if result.returncode != 0 and "Extraction complete" not in result.stdout:
        print(f"  [WARN] pipeline 실패 (rc={result.returncode})")
    return True


def run_scanner(rootfs: Path, label: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(rootfs), label],
        capture_output=True, text=True, timeout=300,
        cwd=str(PROJECT_ROOT)
    )
    lines = result.stdout.strip().splitlines()
    json_start = next((i for i, l in enumerate(lines) if l.startswith("{")), None)
    if json_start is not None:
        try:
            return json.loads("\n".join(lines[json_start:]))
        except json.JSONDecodeError:
            pass
    return {"label": label, "oss": {}, "error": "parse_failed"}


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_results = []
    already_done = {p.stem for p in OUT_DIR.glob("*.json") if p.name != "summary.json"}

    print(f"=== Batch OSS Version Scan ===\n대상: {len(TARGETS)}개 firmware\n")
    ts_start = time.monotonic()

    for i, (product, filename, label) in enumerate(TARGETS, 1):
        out_file = OUT_DIR / f"{label}.json"
        if label in already_done:
            print(f"[{i}/{len(TARGETS)}] {label}  [이미 완료, 스킵]")
            with open(out_file) as f:
                all_results.append(json.load(f))
            continue

        print(f"\n[{i}/{len(TARGETS)}] {label}")

        ok = run_pipeline(product, filename)
        if not ok:
            r = {"label": label, "oss": {}, "error": "no_file"}
            all_results.append(r)
            with open(out_file, "w") as f:
                json.dump(r, f, indent=2)
            continue

        rootfs_candidates = find_rootfs_in_build()
        if not rootfs_candidates:
            print(f"  [WARN] rootfs 없음 — 추출 실패/opaque")
            r = {"label": label, "oss": {}, "error": "no_rootfs"}
            all_results.append(r)
            with open(out_file, "w") as f:
                json.dump(r, f, indent=2)
            continue

        # 가장 큰 rootfs 선택
        rootfs = max(rootfs_candidates, key=lambda p: sum(1 for _ in p.rglob("*") if _.is_file()))
        print(f"  rootfs: {rootfs.relative_to(PROJECT_ROOT)}")

        scan_result = run_scanner(rootfs, label)
        oss_count = len(scan_result.get("oss", {}))
        print(f"  OSS: {oss_count}개 발견", flush=True)
        for name, data in scan_result.get("oss", {}).items():
            versions = ", ".join(data.get("versions", ["detected"]))
            print(f"    {name:15s} {versions}")

        all_results.append(scan_result)
        with open(out_file, "w") as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)
        print(f"  저장: {out_file.name}")

    # 요약 저장
    elapsed = time.monotonic() - ts_start
    summary_path = OUT_DIR / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\n=== 완료: {len(TARGETS)}개 ({elapsed:.1f}s) ===")
    print(f"요약: {summary_path}")

    # 크로스 벤더 비교 테이블
    print("\n=== OSS 버전 크로스 비교 ===")
    print(f"{'Label':<25} {'openssl':<18} {'busybox':<12} {'curl':<12} {'openwrt/lede'}")
    print("-" * 90)
    for r in all_results:
        if not r.get("oss"):
            continue
        oss = r["oss"]
        openssl = ", ".join(oss.get("openssl", {}).get("versions", ["-"]))
        busybox = ", ".join(oss.get("busybox", {}).get("versions", ["-"]))
        curl = ", ".join(oss.get("curl", {}).get("versions", ["-"]))
        openwrt = ", ".join(oss.get("openwrt", {}).get("versions", oss.get("lede", {}).get("versions", ["-"])))
        print(f"  {r['label']:<23} {openssl:<18} {busybox:<12} {curl:<12} {openwrt}")


if __name__ == "__main__":
    main()
