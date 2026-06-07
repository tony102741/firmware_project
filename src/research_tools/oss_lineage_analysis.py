#!/usr/bin/env python3
"""
OSS Lineage Analysis
1. 버전 조합 클러스터링
2. SDK fingerprint 후보 탐색
3. EOL survival 기간 계산
4. 벤더 간 공유 OSS lineage 추정
"""

import json
import re
from pathlib import Path
from datetime import date, datetime
from collections import defaultdict
from itertools import combinations

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCAN_DIR = PROJECT_ROOT / "report" / "oss_scan"

# ──────────────────────────────────────────
# 펌웨어 메타데이터 (vendor, chip, build_date)
# ──────────────────────────────────────────
FIRMWARE_META = {
    "A3002RU-V3-2020": {"vendor": "TOTOLINK", "chip": "Realtek RTL8197",   "build": date(2020, 12,  8)},
    "A3002RU-V3-2022": {"vendor": "TOTOLINK", "chip": "Realtek RTL8197",   "build": date(2022,  3,  4)},
    "A3002RU-V3-2023": {"vendor": "TOTOLINK", "chip": "Realtek RTL8197",   "build": date(2023,  8,  9)},
    "X6000R-V9.4-2025":{"vendor": "TOTOLINK", "chip": "MediaTek MT7981",   "build": date(2025,  8, 26)},
    "MR60X-V1.1-2025": {"vendor": "TP-Link",  "chip": "MediaTek MT7986",   "build": date(2025, 11, 12)},
    "RX9Pro-V22.03":   {"vendor": "Tenda",    "chip": "MediaTek MT7621",   "build": date(2022,  3,  2)},
    "AX2004M-ml14":    {"vendor": "Xiaomi",   "chip": "MediaTek MT7622",   "build": date(2023,  6,  1)},  # approx
    "WR1300V4-2.3.8":  {"vendor": "Cudy",     "chip": "MediaTek MT7621",   "build": date(2025,  1, 24)},
    "GL-MT3000-4.8.1": {"vendor": "GL.iNet",  "chip": "MediaTek MT3000",   "build": date(2025,  8, 19)},
    "GL-MT6000-4.8.4": {"vendor": "GL.iNet",  "chip": "MediaTek MT6000",   "build": date(2026,  3, 30)},
    "GL-X3000-4.8.3":  {"vendor": "GL.iNet",  "chip": "Qualcomm IPQ5018",  "build": date(2024, 11,  6)},
    "WR3000E-2.2.7":   {"vendor": "Cudy",     "chip": "MediaTek MT7621",   "build": date(2024,  9, 10)},
}

# EOL 날짜 (YYYY-MM-DD). 없으면 None = 현재도 지원
OSS_EOL = {
    "openssl": {
        "0.9.8": date(2015, 12, 31),
        "1.0.0": date(2015, 12, 31),
        "1.0.2": date(2019, 12, 31),
        "1.1.0": date(2019,  9, 11),
        "1.1.1": date(2023,  9, 11),
        "3.0":   None,  # still supported
        "3.1":   None,
        "3.2":   None,
        "3.3":   None,
    },
    "curl": {
        # curl에는 formal branch EOL 없음. 릴리스 날짜로 대리 지표 사용
        "7.29.0": date(2013,  3, 11),
        "7.36.0": date(2014,  3, 26),
        "7.71.1": date(2020,  7, 29),
        "7.82.0": date(2022,  3,  5),
        "7.83.1": date(2022,  5, 11),
    },
    "busybox": {
        # formal EOL 없음. 릴리스 날짜로 대리
        "1.13.4": date(2009,  4, 12),
        "1.19.4": date(2012,  7, 20),
        "1.25.1": date(2016,  9, 19),
        "1.30.1": date(2019,  1,  4),
        "1.33.2": date(2021,  5, 17),
    },
    "openwrt": {
        "12.09":  date(2014,  1,  1),   # Attitude Adjustment, unofficial EOL
        "17.01.5":date(2020,  1,  1),   # LEDE, unofficial EOL
        "21.02":  date(2024,  4,  1),   # approximate EOL
    },
    "uclibc": {
        "0.9.33": date(2012, 11,  3),
    },
}

# OpenSSL 버전 → 브랜치 추출
def openssl_branch(ver: str) -> str:
    m = re.match(r"(\d+\.\d+)", ver)
    return m.group(1) if m else ver


def load_scan_results() -> dict:
    results = {}
    for fp in SCAN_DIR.glob("*.json"):
        if fp.stem == "summary":
            continue
        with open(fp) as f:
            d = json.load(f)
        if d.get("oss"):
            results[fp.stem] = d["oss"]
    return results


def get_primary_version(oss_data: dict, key: str) -> str | None:
    """여러 버전 중 가장 오래된 것(가장 위험한 것) 반환"""
    versions = oss_data.get(key, {}).get("versions", [])
    if not versions:
        return None
    # 버전 번호 기준 정렬 후 최소값
    def ver_key(v):
        parts = re.findall(r"\d+", v)
        return tuple(int(x) for x in parts) if parts else (999,)
    return min(versions, key=ver_key)


def version_feature_vector(oss_data: dict) -> dict:
    return {
        "openssl":  get_primary_version(oss_data, "openssl"),
        "busybox":  get_primary_version(oss_data, "busybox"),
        "curl":     get_primary_version(oss_data, "curl"),
        "openwrt":  get_primary_version(oss_data, "openwrt") or get_primary_version(oss_data, "lede"),
        "uclibc":   get_primary_version(oss_data, "uclibc"),
        "musl":     get_primary_version(oss_data, "musl"),
        "lua":      get_primary_version(oss_data, "lua"),
        "webserver":("boa" if oss_data.get("boa") else
                     "uhttpd" if oss_data.get("uhttpd") else
                     "lighttpd" if oss_data.get("lighttpd") else None),
        "libc":     ("uclibc" if oss_data.get("uclibc") else
                     "musl"   if oss_data.get("musl")   else "unknown"),
    }


# ═══════════════════════════════════════════════════════
# 1. OSS 버전 조합 클러스터링
# ═══════════════════════════════════════════════════════
def cluster_by_version_combo(all_data: dict) -> dict:
    """(openssl_branch, busybox_major, openwrt_base) 조합으로 클러스터링"""
    clusters = defaultdict(list)

    for label, oss_data in all_data.items():
        fv = version_feature_vector(oss_data)

        # openssl branch
        ssl_br = openssl_branch(fv["openssl"]) if fv["openssl"] else "none"
        # busybox major.minor
        bb = ".".join(fv["busybox"].split(".")[:2]) if fv["busybox"] else "none"
        # openwrt base
        ow = fv["openwrt"].split("-")[0][:5] if fv["openwrt"] else "none"
        # libc
        libc = fv["libc"]

        key = (ssl_br, bb, ow, libc)
        clusters[key].append(label)

    return dict(clusters)


# ═══════════════════════════════════════════════════════
# 2. SDK fingerprint 후보
# ═══════════════════════════════════════════════════════
def sdk_fingerprint(all_data: dict) -> list[dict]:
    """
    동일 vendor/chip 계열로 추정되는 firmware끼리
    공유하는 OSS 버전 조합을 'SDK fingerprint'로 정의
    """
    # (component, version) pair가 몇 개 firmware에서 공유되는지
    pair_count = defaultdict(list)
    for label, oss_data in all_data.items():
        fv = version_feature_vector(oss_data)
        for comp, ver in fv.items():
            if ver:
                pair_count[(comp, ver)].append(label)

    # 2개 이상 firmware에 등장하는 pair 추출
    shared = {k: v for k, v in pair_count.items() if len(v) >= 2}

    # firmware 쌍별로 공유 (component, version) 집합 계산
    fingerprints = []
    labels = list(all_data.keys())
    for a, b in combinations(labels, 2):
        fv_a = version_feature_vector(all_data[a])
        fv_b = version_feature_vector(all_data[b])
        shared_pairs = [
            (c, v) for c, v in fv_a.items()
            if v and fv_b.get(c) == v
        ]
        if len(shared_pairs) >= 2:  # 2개 이상 컴포넌트 공유
            fingerprints.append({
                "fw_a": a,
                "fw_b": b,
                "shared_components": shared_pairs,
                "similarity_score": len(shared_pairs),
            })

    fingerprints.sort(key=lambda x: -x["similarity_score"])
    return fingerprints


# ═══════════════════════════════════════════════════════
# 3. EOL OSS survival 기간
# ═══════════════════════════════════════════════════════
def eol_survival(all_data: dict) -> list[dict]:
    entries = []

    for label, oss_data in all_data.items():
        meta = FIRMWARE_META.get(label, {})
        build_dt = meta.get("build")
        if not build_dt:
            continue
        vendor = meta.get("vendor", "unknown")

        fv = version_feature_vector(oss_data)

        for comp in ["openssl", "busybox", "curl", "openwrt", "uclibc"]:
            ver = fv.get(comp)
            if not ver:
                continue

            # EOL 날짜 찾기
            eol_dt = None
            if comp in OSS_EOL:
                if comp == "openssl":
                    branch = openssl_branch(ver)
                    eol_dt = OSS_EOL["openssl"].get(branch)
                elif comp in ("curl", "busybox", "openwrt", "uclibc"):
                    eol_dt = OSS_EOL[comp].get(ver)

            if eol_dt is None:
                continue

            # build_date에서 EOL_date를 빼면 EOL 이후 몇 일 지난 후에도 쓰고 있는지
            survival_days = (build_dt - eol_dt).days

            entries.append({
                "label":         label,
                "vendor":        vendor,
                "build_date":    build_dt.isoformat(),
                "component":     comp,
                "version":       ver,
                "eol_date":      eol_dt.isoformat(),
                "survival_days": survival_days,  # 양수 = EOL 이후에도 사용 중
                "status":        "POST-EOL" if survival_days > 0 else "pre-EOL",
            })

    entries.sort(key=lambda x: -x["survival_days"])
    return entries


# ═══════════════════════════════════════════════════════
# 4. 벤더 간 OSS lineage 추정
# ═══════════════════════════════════════════════════════
def shared_lineage(all_data: dict) -> dict:
    """
    어떤 (component, version) 조합이 어떤 vendor에 걸쳐 나타나는지.
    같은 조합 = 동일 SDK origin 후보.
    """
    # component+version → {vendor: [labels]}
    lineage: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))

    for label, oss_data in all_data.items():
        vendor = FIRMWARE_META.get(label, {}).get("vendor", "unknown")
        fv = version_feature_vector(oss_data)
        for comp, ver in fv.items():
            if ver:
                lineage[(comp, ver)][vendor].append(label)

    # 2개 이상 vendor에 등장하는 것만
    cross_vendor = {
        k: dict(v) for k, v in lineage.items()
        if len(v) >= 2
    }
    # 정렬: vendor 수 내림차순
    return dict(sorted(cross_vendor.items(), key=lambda x: -len(x[1])))


# ═══════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════
def main():
    all_data = load_scan_results()
    print(f"로드된 펌웨어: {len(all_data)}개\n")

    # ── 1. 클러스터링 ──────────────────────────
    print("═" * 60)
    print("1. OSS 버전 조합 클러스터링")
    print("   기준: (openssl_branch, busybox_major, openwrt_base, libc)")
    print("═" * 60)
    clusters = cluster_by_version_combo(all_data)
    for key, members in sorted(clusters.items(), key=lambda x: -len(x[1])):
        ssl_br, bb, ow, libc = key
        print(f"\n  [{ssl_br} / busybox {bb} / openwrt {ow} / {libc}]  ({len(members)}개)")
        for m in members:
            vendor = FIRMWARE_META.get(m, {}).get("vendor", "?")
            chip   = FIRMWARE_META.get(m, {}).get("chip", "?")
            build  = FIRMWARE_META.get(m, {}).get("build", "?")
            print(f"    • {m:<28} {vendor:<10} {chip:<22} {build}")

    # ── 2. SDK fingerprint ─────────────────────
    print("\n\n" + "═" * 60)
    print("2. SDK Fingerprint 후보  (공유 컴포넌트 ≥ 2)")
    print("═" * 60)
    fps = sdk_fingerprint(all_data)
    seen_groups = set()
    for fp in fps:
        a, b = fp["fw_a"], fp["fw_b"]
        score = fp["similarity_score"]
        shared = fp["shared_components"]
        vendor_a = FIRMWARE_META.get(a, {}).get("vendor", "?")
        vendor_b = FIRMWARE_META.get(b, {}).get("vendor", "?")
        chip_a   = FIRMWARE_META.get(a, {}).get("chip", "?")
        chip_b   = FIRMWARE_META.get(b, {}).get("chip", "?")

        # 같은 vendor 쌍은 그룹으로 묶어서 한 번만 출력
        pair_key = tuple(sorted([a, b]))
        if pair_key in seen_groups:
            continue
        seen_groups.add(pair_key)

        print(f"\n  [{score}개 공유]  {a} ({vendor_a}) ↔ {b} ({vendor_b})")
        print(f"    chip: {chip_a}  vs  {chip_b}")
        for comp, ver in shared:
            print(f"    = {comp:<12} {ver}")

    # ── 3. EOL survival ─────────────────────────
    print("\n\n" + "═" * 60)
    print("3. EOL OSS Survival 기간  (POST-EOL만)")
    print("   survival_days = 펌웨어_빌드일 - EOL일  (양수 = EOL 이후 사용)")
    print("═" * 60)
    survivors = eol_survival(all_data)
    post_eol = [e for e in survivors if e["status"] == "POST-EOL"]
    print(f"\n  총 POST-EOL 항목: {len(post_eol)}개\n")
    print(f"  {'Label':<28} {'Vendor':<10} {'Component':<10} {'Version':<12} {'EOL':<12} {'Build':<12} {'Survival':>10}")
    print("  " + "-" * 100)
    for e in post_eol:
        years = e["survival_days"] / 365.25
        print(f"  {e['label']:<28} {e['vendor']:<10} {e['component']:<10} {e['version']:<12} {e['eol_date']:<12} {e['build_date']:<12} {e['survival_days']:>6}d ({years:.1f}y)")

    # ── 4. Shared Lineage ──────────────────────
    print("\n\n" + "═" * 60)
    print("4. 벤더 간 공유 OSS Lineage  (크로스 벤더 ≥ 2)")
    print("   동일 버전이 여러 vendor에 등장 → 공통 SDK origin 후보")
    print("═" * 60)
    lineage = shared_lineage(all_data)

    # component별로 그룹핑
    by_comp = defaultdict(dict)
    for (comp, ver), vendor_map in lineage.items():
        by_comp[comp][(comp, ver)] = vendor_map

    for comp in ["openssl", "busybox", "curl", "openwrt", "uclibc"]:
        entries = by_comp.get(comp, {})
        if not entries:
            continue
        print(f"\n  ── {comp} ──")
        for (c, ver), vendor_map in sorted(entries.items(), key=lambda x: -len(x[1])):
            vendors = sorted(vendor_map.keys())
            fw_list = [fw for v in vendor_map.values() for fw in v]
            print(f"    {ver:<16} → {len(vendors)}개 vendor: {', '.join(vendors)}")
            for fw in fw_list:
                chip = FIRMWARE_META.get(fw, {}).get("chip", "?")
                build = FIRMWARE_META.get(fw, {}).get("build", "?")
                print(f"       • {fw:<30} chip={chip}  build={build}")

    # ── 요약 JSON 저장 ─────────────────────────
    out = {
        "clusters":          {str(k): v for k, v in clusters.items()},
        "sdk_fingerprints":  fps[:30],
        "eol_survival":      post_eol,
        "shared_lineage":    {f"{c}@{v}": vmap for (c, v), vmap in lineage.items()},
    }
    out_path = PROJECT_ROOT / "report" / "oss_scan" / "lineage_analysis.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n\n→ 결과 저장: {out_path}")


if __name__ == "__main__":
    main()
