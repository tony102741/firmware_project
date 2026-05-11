from __future__ import annotations

import json
from pathlib import Path

from tools.tmp_protocol_scaffold import (
    FIXTURE_DIR,
    parse_fixture,
    validate_fixtures,
    write_fixture_directory,
)


def setup_module() -> None:
    write_fixture_directory()


def test_fixture_files_exist() -> None:
    expected = [
        "assoc_req.hex",
        "assoc_accept.hex",
        "placeholder_push.hex",
        "placeholder_pull_request.hex",
        "invalid_crc.hex",
        "truncated_header.hex",
        "fixtures_manifest.json",
        "expected_fields.json",
    ]
    for name in expected:
        assert (FIXTURE_DIR / name).exists(), name


def test_crc_valid_fixtures_pass() -> None:
    for name in ["assoc_req", "assoc_accept", "placeholder_push", "placeholder_pull_request"]:
        result = parse_fixture(name)
        assert result["parse_ok"] is True
        assert result["crc_valid"] is True
        assert result["length_consistent"] is True


def test_invalid_crc_fixture_fails_crc() -> None:
    result = parse_fixture("invalid_crc")
    assert result["parse_ok"] is True
    assert result["crc_valid"] is False
    assert result["length_consistent"] is True


def test_truncated_header_fixture_fails_parse() -> None:
    result = parse_fixture("truncated_header")
    assert result["parse_ok"] is False
    assert "packet too short" in result["error"]
    assert result["length_consistent"] is False


def test_expected_fields_match() -> None:
    expected = json.loads((FIXTURE_DIR / "expected_fields.json").read_text())
    for name in ["assoc_req", "assoc_accept", "placeholder_push", "placeholder_pull_request", "invalid_crc"]:
        result = parse_fixture(name)
        fields = result["fields"]
        assert fields["control_code"] == expected[name]["control_code"]
        assert fields["opcode"] == expected[name]["opcode"]
        assert fields["business_flags"] == expected[name]["business_flags"]
        assert fields["token"] == expected[name]["token"]


def test_validate_fixtures_summary() -> None:
    results = validate_fixtures()
    assert all(entry["all_passed"] for entry in results.values())
