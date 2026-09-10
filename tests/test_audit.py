from __future__ import annotations

import json
from pathlib import Path

import pytest

from oidc_audit import audit, audit_files, audit_jwks
from oidc_audit.jsonio import DuplicateMemberError, load_json, parse_json
from oidc_audit.render import render_json, render_sarif, render_text

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples"


def codes(report_or_findings: object) -> set[str]:
    findings = getattr(report_or_findings, "findings", report_or_findings)
    return {finding.code for finding in findings}  # type: ignore[union-attr]


def test_valid_fixture_is_clean() -> None:
    report = audit_files(EXAMPLES / "discovery.json", jwks_path=EXAMPLES / "jwks.json", token_path=EXAMPLES / "token.jwt")
    assert report.findings == ()
    assert report.exit_code() == 0
    assert report.counts == {"error": 0, "warning": 0, "info": 0}


def test_broken_discovery_explains_protocol_failures() -> None:
    report = audit_files(EXAMPLES / "broken-discovery.json")
    assert {"OIDC-010", "OIDC-008", "OIDC-016"}.issubset(codes(report))
    assert report.exit_code() == 1


def test_broken_jwks_explains_key_failures() -> None:
    document = load_json(EXAMPLES / "broken-jwks.json")
    findings = audit_jwks(document)
    assert {"JWK-004", "JWK-007", "JWK-010", "JWK-016"}.issubset(codes(findings))


def test_duplicate_json_members_are_rejected() -> None:
    with pytest.raises(DuplicateMemberError, match="duplicate JSON member"):
        parse_json('{"issuer":"https://one","issuer":"https://two"}')


def test_nested_duplicate_json_members_are_rejected() -> None:
    with pytest.raises(DuplicateMemberError):
        parse_json('{"keys":[{"kty":"RSA","kty":"EC"}]}')


def test_token_header_matching_is_deterministic() -> None:
    discovery = load_json(EXAMPLES / "discovery.json")
    jwks = load_json(EXAMPLES / "jwks.json")
    token = (EXAMPLES / "token.jwt").read_text(encoding="utf-8")
    report = audit(discovery, jwks=jwks, token=token)
    assert report.findings == ()


def test_token_missing_kid_is_reported_when_rotation_is_ambiguous() -> None:
    discovery = load_json(EXAMPLES / "discovery.json")
    jwks = {
        "keys": [
            {"kty": "RSA", "kid": "one", "alg": "RS256", "n": "sXch", "e": "AQAB"},
            {"kty": "RSA", "kid": "two", "alg": "RS256", "n": "tYdi", "e": "AQAB"},
        ]
    }
    token = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"
    report = audit(discovery, jwks=jwks, token=token)
    assert "TOKEN-013" in codes(report)


def test_jwks_missing_kid_warning_only_applies_to_eligible_keys() -> None:
    findings = audit_jwks(
        {
            "keys": [
                {"kty": "RSA", "alg": "RS256", "n": "sXch", "e": "AQAB"},
                {"kty": "RSA", "alg": "RS256", "kid": "two", "n": "tYdi", "e": "AQAB"},
            ]
        }
    )
    assert "JWK-026" in codes(findings)


def test_token_unknown_kid_is_reported_without_leaking_payload() -> None:
    discovery = load_json(EXAMPLES / "discovery.json")
    jwks = load_json(EXAMPLES / "jwks.json")
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1pc3NpbmcifQ.eyJzZWNyZXQiOiJub3Qtc2hvd24ifQ.c2ln"
    report = audit(discovery, jwks=jwks, token=token)
    assert "TOKEN-010" in codes(report)
    assert "not-shown" not in render_text(report)


def test_expected_issuer_is_compared_exactly() -> None:
    discovery = load_json(EXAMPLES / "discovery.json")
    report = audit(discovery, expected_issuer="https://id.example.test/")
    assert "OIDC-007" in codes(report)


def test_renderers_are_machine_readable() -> None:
    report = audit_files(EXAMPLES / "broken-discovery.json")
    json_report = json.loads(render_json(report))
    sarif_report = json.loads(render_sarif(report))
    assert json_report["version"] == 1
    assert sarif_report["version"] == "2.1.0"
    assert sarif_report["runs"][0]["results"]


def test_warning_report_is_pass_with_warnings_but_strict_can_fail() -> None:
    discovery = load_json(EXAMPLES / "discovery.json")
    discovery["scopes_supported"] = ["profile"]
    report = audit(discovery)
    assert "OIDC-018" in codes(report)
    assert report.exit_code() == 0
    assert report.exit_code("warning") == 1
    assert "PASS WITH WARNINGS" in render_text(report)


def test_unreadable_input_uses_exit_code_two(tmp_path: Path) -> None:
    report = audit_files(tmp_path / "missing.json")
    assert report.input_error is True
    assert report.exit_code() == 2
