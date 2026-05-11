# TMP Protocol Scaffold Usage

`tools/tmp_protocol_scaffold.py` 는 연구용 TMP/2.0 오프라인 검증 도구입니다.

이 도구는:

- 네트워크 전송을 하지 않습니다
- 기본적으로 dry-run 입니다
- fixture 기반으로 패킷 생성/파싱/검증만 합니다
- 위험한 실제 관리 동작은 지원하지 않습니다

## 가장 많이 쓰는 명령

ASSOC 요청 샘플 보기:

```bash
python3 tools/tmp_protocol_scaffold.py --mode assoc
```

데모 패킷 흐름 보기:

```bash
python3 tools/tmp_protocol_scaffold.py --mode demo --marker TMP_RESEARCH_MARKER
```

fixture 하나 파싱:

```bash
python3 tools/tmp_protocol_scaffold.py --mode parse-fixture --fixture assoc_req
```

fixture 전체 검증:

```bash
python3 tools/tmp_protocol_scaffold.py --validate-fixtures
```

fixture 다시 생성:

```bash
python3 tools/tmp_protocol_scaffold.py --mode write-fixtures
```

## 관련 파일

- 도구:
  - `tools/tmp_protocol_scaffold.py`
- fixture:
  - `research/regeneration/full_corpus_20260508/tmp_packet_fixtures/`
- 설명 문서:
  - `research/regeneration/full_corpus_20260508/tmp_fixture_validation.md`
  - `research/regeneration/full_corpus_20260508/tmp_parser_regression_notes.md`
  - `research/regeneration/full_corpus_20260508/packet_examples.md`

## 왜 `tests/`를 없앴는가

이 프로젝트에서는 일반 소프트웨어 테스트보다는 연구용 오프라인 검증 도구 성격이 더 강합니다.

그래서 `tests/` 디렉터리 대신:

- fixture 파일
- 검증 문서
- 도구 내장 검증 명령

으로 유지하는 편이 구조를 이해하기 더 쉽습니다.
