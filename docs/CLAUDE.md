# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Android OTA firmware ZIP 파일을 자동 분석하여 취약점 후보를 도출하는 도구. 단순 문자열 검색이 아닌 의미 있는 알고리즘(3단계 sink 분류, 패턴 기반 dataflow 체인 검증, 권한 스코어링)으로 false positive를 억제하면서 우선순위화된 취약점 후보를 출력한다.

## Running the Tool

### 전체 파이프라인 (OTA ZIP → 분석)
```bash
# firmware/ 디렉터리에 OTA ZIP 파일을 넣고:
cd /home/user/firmware_project
python3 src/pipeline.py

# rootfs를 재사용하고 싶을 때 (img 재추출 생략):
python3 src/pipeline.py --skip
```

### 분석만 실행 (rootfs 이미 구성된 경우)
```bash
cd /home/user/firmware_project
python3 src/main.py

# LOW 등급까지 모두 출력:
python3 src/main.py --all
```

> **주의**: `main.py`는 `rootfs/`를 CWD 기준 상대 경로로 참조하므로 반드시 프로젝트 루트에서 실행해야 한다.

### 독립 스캐너 실행 (rootfs 이미 구성된 경우)
```bash
cd /home/user/firmware_project
python3 src/scanner/scan_setuid.py   # setuid 파일 목록
python3 src/scanner/scan_perm.py     # world-writable 파일 목록
python3 src/scanner/scan_su.py       # su/busybox 탐지
```

### 외부 의존 도구
- `strings` (binutils) — ELF 문자열 추출
- `7z` (p7zip) — img 언패킹
- `unzip` — OTA ZIP 추출
- `tools/payload-dumper-go/payload-dumper-go` — payload.bin 추출 (pre-built Go 바이너리)

## Directory Layout

```
firmware/          # 분석할 OTA ZIP 파일을 여기에 넣음
work/              # OTA 언압축 결과 및 .img 파일
extracted/         # payload-dumper-go 추출 결과 (clean 시 보존됨)
rootfs/
  system/          # system.img 언패킹 결과
  vendor/          # vendor.img 언패킹 결과
src/
  pipeline.py      # 엔트리포인트: unzip → payload 추출 → img 추출 → 분석
  main.py          # 분석만 실행 (rootfs 이미 준비된 경우)
  parser/
    init_parser.py       # .rc 파일 파싱 → service 목록 수집
  analyzer/
    risk.py              # 분석 루프 조합: ELF 확인·경로 해석·노이즈 필터·결과 조립
    strings_analyzer.py  # ELF strings 추출 + 키워드 필터
    sink_detector.py     # 위험 함수 탐지 (3단계 분류)
    input_classifier.py  # classify_input() / has_input_handler()
    dataflow.py          # analyze_dataflow() / has_dangerous_memcpy_context() + 패턴 상수
    scoring.py           # score_sinks() / calc_score()
    binder_detector.py   # Binder IPC 탐지 (현재 미사용)
    input_detector.py    # 입력 소스 탐지 (현재 미사용)
  scanner/               # 독립 실행 가능; run_filesystem_checks()를 통해 main.py에 통합됨
    scan_setuid.py       # setuid 파일 탐지
    scan_perm.py         # world-writable 파일 탐지
    scan_su.py           # su/busybox 존재 여부 탐지
tools/
  payload-dumper-go/     # Go 기반 payload.bin 추출 도구
```

## Pipeline Architecture

### 1. rootfs 구성 (`pipeline.py`)

`payload-dumper-go` 출력 형식이 버전마다 다르므로 두 형식을 자동 감지:

| 형식 | 조건 | 처리 |
|---|---|---|
| **Format B (modern)** | `work/system/` 디렉터리 존재 | 직접 `rootfs/system`으로 복사 |
| **Format A (legacy)** | `work/system.img` 파일 존재 | `7z` 추출 후 `_find_partition_root()`로 실제 루트 탐색 → 복사 |

`_find_partition_root()`: 7z 추출 결과가 `base/`, `base/system/`, `base/0/system/` 등 다양한 구조일 수 있으므로 `bin/`, `lib/`, `etc/` 등의 지시자로 실제 파티션 루트를 탐색 (최대 3단계).

`collect_images()`: `extracted_*/` 내부에 partition 디렉터리(`system/`, `vendor/`)가 있으면 `work/`로 복사해 Format B 경로가 작동하게 함.

### 2. 취약점 분석 (`src/analyzer/`)

```
init_parser: rootfs/**/*.rc 파싱
  → service { name, exec, user, socket[] }
  → resolve_path() [risk.py]: exec 경로를 rootfs/system 또는 rootfs/vendor로 매핑
  → is_elf() 확인 + strings -n6 추출 [strings_analyzer.py]

risk.py 분석 루프 (모듈별 역할):
  → is_noise_service() 필터                              [risk.py]
  → classify_input(): "binder"(onTransact) | "socket"   [input_classifier.py]
  → detect_sinks(): 3단계 분류 반환                      [sink_detector.py]
  → is_valid_sink(): C++ mangled 심볼·긴 문자열·prose 제거 [sink_detector.py]
  → analyze_dataflow(): 패턴 체인 → (flow_score, type)  [dataflow.py]
  → has_dangerous_memcpy_context(): weak sink 채택 조건  [dataflow.py]
  → score_sinks() + calc_score(): 점수 합산 (cap 25)    [scoring.py]
  → 레벨 분류 → 정렬 출력

main.py 출력:
  → HIGH/MEDIUM(/LOW --all) 결과 출력
  → run_filesystem_checks(): scan_setuid / scan_world_writable / scan_su
     결과 중 분석 결과와 겹치는 바이너리에 [LEVEL] 어노테이션 표시
```

## Sink Tiers (`analyzer/sink_detector.py`)

| 티어 | 예시 | 기본 점수 |
|---|---|---|
| `critical` | `system(`, `popen(`, `execl(`, `/bin/sh` | +7~8 |
| `strong` | `strcpy(`, `sprintf(`, `gets(` | +2~5 |
| `weak` | `__strcpy_chk`, `__memcpy_chk`, `memcpy(` | +1 (조건부 채택) |

`weak` sink는 **dataflow 체인 확인 후에만** 결과에 포함된다.

## Dataflow Patterns (`analyzer/dataflow.py: analyze_dataflow`)

| 패턴 | 조건 | flow_score |
|---|---|---|
| `cmd_injection` | net_input + cmd_ops | 10 |
| `bof+net_length` | net + parse + copy + ntoh | 8 |
| `buffer_overflow` | net + parse + copy | 6 |
| `net_copy_partial` | net + copy (parse 없음) | 3 |

## Scoring & Thresholds

| 요소 | 점수 |
|---|---|
| socket input | +3 |
| binder input | +2 |
| root 권한 | +4 |
| system/radio/media 권한 | +2 |
| bluetooth/wifi/nfc 권한 | +1 |
| world-accessible socket (666/777) | +2 |
| sink score | (티어별 위 표 참조) |
| flow_score | (패턴별 위 표 참조) |

- **HIGH**: score ≥ 15 AND flow_score ≥ 6
- **MEDIUM**: score ≥ 8 AND flow_score ≥ 3
- **LOW**: score ≥ 5
- **최대 score**: 25 (calc_score에서 상한 고정)

## Key Design Decisions

- **`extracted/` 보존**: `pipeline.py --skip` 없이 clean을 실행해도 `extracted/`는 절대 삭제하지 않음. payload 재추출 비용이 크기 때문.
- **weak sink 조건부 채택**: `__strcpy_chk`/`__memcpy_chk`는 Android 전체에 편재하는 컴파일러 삽입 래퍼. `flow_score ≥ 3` AND `has_dangerous_memcpy_context()`(ntohl/ntohs 또는 parse+len 공존) 조건을 모두 충족할 때만 채택.
- **`resolve_path` 설계**: `root_path`는 항상 `rootfs/system`. vendor 바이너리는 `os.path.dirname(root_path)` → `rootfs/vendor`로 파생.
- **노이즈 서비스 목록**: `wpa_supplicant`, `hostapd`, `vndservicemanager`, `bcmbtlinux`, `btsnoop`, `netd`, `adbd`, `healthd`, `lmkd`, `logd`, `statsd`, `tombstoned`, `incidentd`, `traced`, `storaged`, `installd`
- **동일 exec 중복 제거**: 여러 .rc에서 같은 바이너리를 참조할 경우 첫 번째만 분석.
- **`scanner/` 모듈**: `main.py`의 `run_filesystem_checks()`를 통해 통합됨. setuid·world-writable·su 결과를 분석 결과(`exec_map`)와 교차 조회해 위험 조합을 플래그. 독립 실행도 가능.
- **`src/parser/extractor.py`**: 레거시 파일. 현재 파이프라인과 무관한 다른 payload dumper(`payload_dumper/` Python 패키지)를 호출하며, 실제로 사용되지 않음.
- **파티션 탐색 순서** (`find_partition_dir`): `work/<name>/` → `extracted/**/<name>/` → 프로젝트 전체 트리 순으로 폴백. `_looks_like_partition_root()`는 `bin/`, `lib/`, `lib64/`, `etc/` 등의 지시자 디렉터리로 실제 루트를 판별.
