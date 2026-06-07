# IoT 펌웨어 OSS 버전 분석 보고서

## 개요

11개 펌웨어, 7개 vendor, 6개 OSS 컴포넌트에 대한 버전 분포 분석.
`scripts/oss_version_scanner.py`를 통해 rootfs에서 strings 기반으로 추출.

## 스캔 결과 요약

| Firmware | Vendor | 빌드연도 | OpenSSL | BusyBox | curl | OpenWrt/LEDE |
|---|---|---|---|---|---|---|
| A3002RU V3 (2020) | TOTOLINK | 2020 | **0.9.8b** ⚠️ | **1.13.4** ⚠️ | - | - |
| A3002RU V3 (2022) | TOTOLINK | 2022 | **0.9.8b** ⚠️ | **1.13.4** ⚠️ | 7.36.0 | - |
| A3002RU V3 (2023) | TOTOLINK | 2023 | **0.9.8b** ⚠️ | **1.13.4** ⚠️ | 7.36.0 | - |
| X6000R V9.4 | TOTOLINK | 2025 | 1.1.1t ✓ | 1.33.2 ✓ | - | 21.02 |
| MR60X V1.1 | TP-Link | 2025 | **1.0.2u** ⚠️ | **1.19.4** ⚠️ | **7.29.0** ⚠️ | **12.09** ⚠️ |
| RX9 Pro V22.03 | Tenda | 2022 | **1.0.2t** ⚠️ | 1.30.1 | - | - |
| AX2004M ml14 | Xiaomi | ~2023 | **1.0.2u** ⚠️ | 1.25.1 | 7.71.1 | - |
| WR1300V4 R98-2.3 | Cudy | 2025 | **1.0.2o** ⚠️ | 1.25.1 | 7.82.0 | **17.01.5** |
| GL-MT3000 4.8.1 | GL.iNet | 2025 | 1.1.1q ✓ | 1.33.2 ✓ | 7.83.1 ✓ | 21.02 ✓ |
| GL-MT6000 4.8.4 | GL.iNet | 2025 | 1.1.1t ✓ | 1.33.2 ✓ | 7.83.1 ✓ | 21.02 ✓ |
| GL-X3000 4.8.3 | GL.iNet | 2025 | 1.1.1q ✓ | 1.33.2 ✓ | 7.83.1 ✓ | 21.02 ✓ |

⚠️ = EOL이거나 출시 당시 이미 구버전

## 핵심 발견

### 1. OpenSSL 1.0.2 시리즈 - 크로스 벤더 지속 취약점

OpenSSL 1.0.2는 **2019년 12월 31일 EOL** (지원 종료).

| 버전 | 등장 vendor | 마지막 확인 시점 |
|---|---|---|
| 0.9.8b (2006년 릴리스) | TOTOLINK A3002RU | 2023년 |
| 1.0.2d (2015년) | TOTOLINK A3002RU | 2023년 |
| 1.0.2o (2018년) | Cudy WR1300V4 | 2025년 |
| 1.0.2t (2019년) | Tenda RX9 Pro | 2022년 |
| 1.0.2u (2019년) | TP-Link MR60X, Xiaomi AX2004M | 2025년 |

**결론**: EOL OpenSSL 1.0.2가 2025년 출시 펌웨어에 여전히 포함됨 (TP-Link, Cudy).
동일 취약점 계열이 TOTOLINK, TP-Link, Tenda, Xiaomi, Cudy에 걸쳐 반복.

### 2. TP-Link MR60X의 극단적 OSS 버전 지연

TP-Link MR60X는 **2025년 11월** 출시 펌웨어이지만:

| 컴포넌트 | 버전 | 릴리스 연도 | 나이 |
|---|---|---|---|
| OpenWrt base | 12.09 | 2013 | **12년** |
| BusyBox | 1.19.4 | 2012 | **13년** |
| curl | 7.29.0 | 2013 | **12년** |
| uclibc | 0.9.33 | 2012 | **13년** |

→ 2025년 출시 제품이 2012~2013년 OpenWrt 생태계를 그대로 유지.

### 3. TOTOLINK A3002RU의 OSS 동결 (3년간)

| 버전/빌드 | OpenSSL | BusyBox | 변경 여부 |
|---|---|---|---|
| V3-20201208 | 0.9.8b | 1.13.4 | 기준 |
| V3-20220304 | 0.9.8b | 1.13.4 | 동일 |
| V3-20230809 | 0.9.8b | 1.13.4 | 동일 |

→ 3년간 동일한 OpenSSL 0.9.8b (17년 전 버전) 유지. `curl 7.36.0` (2014년)만 추가됨.

### 4. GL.iNet의 상대적 우수성

GL.iNet (MT3000/MT6000/X3000) 3종 모두 동일하게:
- OpenSSL 1.1.1q/1.1.1t (2022-2023)
- BusyBox 1.33.2 (2021)
- curl 7.83.1 (2022)
- OpenWrt 21.02-SNAPSHOT

오픈소스 기반 개발 (GitHub 공개)이 OSS 업데이트 주기에 영향을 준 것으로 보임.

### 5. BusyBox 버전 분포로 본 vendor 그룹

```
2008  [1.13.4]  TOTOLINK A3002RU (legacy)
2012  [1.19.4]  TP-Link MR60X (2025 출시!)
2016  [1.25.1]  Xiaomi AX2004M, Cudy WR1300V4
2019  [1.30.1]  Tenda RX9 Pro
2021  [1.33.2]  TOTOLINK X6000R, GL.iNet (recent)
```

## 방법론 노트

### 작동한 추출 형식

| 형식 | 성공 | 비고 |
|---|---|---|
| TOTOLINK `.web` | ✓ | binwalk squashfs 추출 성공 |
| OpenWrt fullimage `.bin` (TOTOLINK, Tenda) | ✓ | `_nested_*/_raw/` 패턴 |
| GL.iNet `.bin`/`.tar` | ✓ | `_nested_root/_raw/` |
| Cudy flash `.zip` | ✓ | `_nested_*/_raw/` |
| Xiaomi `.bin` | ✓ | `_nested_*/_raw/` |
| TP-Link `.bin` (MR60X, AX23 등) | ✗ | squashfs 추출 실패 |
| TP-Link sysupgrade `.zip` (WR3000E) | ✗ | DTB만 추출 |
| ASUS puresqubi `.w` | ✗ | proprietary squashfs |
| NETGEAR `.chk` | ✗ | 미지원 형식 |
| Synology `.pat` | △ | 업데이트 패키지만, rootfs 없음 |

### 스캐너 패턴

`OSS_PATTERNS` dict에 정규식 17개 컴포넌트 커버:
openssl, curl, busybox, uhttpd, lighttpd, boa, linux_kernel, uclibc, musl,
dropbear, dnsmasq, miniupnpd, lua, wolfssl, mbedtls, openwrt, lede

## 연구 시사점

### "Binary OSS reuse security" 관점에서

이 결과는 Seunghoon Woo 교수의 OSS 재사용 보안 연구(V0Finder/MOVERY/V1SCAN/TIVER)의
**바이너리/펌웨어 도메인 확장** 필요성을 실증적으로 보여준다:

1. **OSS 버전 동결 현상**: 2023년 A3002RU가 2006년 OpenSSL을 사용한다는 사실은
   소스코드 없이 바이너리에서만 확인 가능.

2. **크로스 벤더 취약점 전파**: OpenSSL 1.0.2가 5개 vendor에 분포.
   이는 CENTRIS/TIVER가 소스코드에서 감지하는 OSS 재사용 패턴의 바이너리 버전.

3. **제품군 내 OSS 동결 탐지**: A3002RU 3개 버전 모두 동일 OpenSSL.
   이를 자동으로 탐지하는 binary SBOM(Software Bill of Materials) 생성 도구가 필요.

4. **vendor OSS 위생 자동 평가**: GL.iNet vs TP-Link의 극단적 차이를
   automated binary analysis로 정량화할 수 있음.

### 다음 단계

1. TP-Link MR60X의 `openwrt 12.09` 확인: 실제로 2013년 코드베이스인지 검증
2. OpenSSL 1.0.2의 구체적 CVE 매핑 (Heartbleed 이후 패치 상태 포함)
3. 바이너리에서 OSS 버전을 자동 추출하는 방법론의 정확도 평가
   (strings 기반 1단계 → 함수 시그니처 기반 2단계로 확장)
