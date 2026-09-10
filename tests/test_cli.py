from __future__ import annotations

import json
from pathlib import Path

from oidc_audit.cli import main

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples"


def test_cli_text_success(capsys: object) -> None:
    code = main(
        [
            str(EXAMPLES / "discovery.json"),
            "--jwks",
            str(EXAMPLES / "jwks.json"),
            "--token",
            str(EXAMPLES / "token.jwt"),
        ]
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert code == 0
    assert "OIDC AUDIT: PASS" in captured.out


def test_cli_json_failure_and_strict_warning(capsys: object) -> None:
    code = main([str(EXAMPLES / "discovery.json"), "--jwks", str(EXAMPLES / "jwks.json"), "--format", "json"])
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert code == 0
    assert json.loads(captured.out)["findings"] == []


def test_cli_ignore_suppresses_a_rule(capsys: object) -> None:
    code = main(
        [
            str(EXAMPLES / "broken-discovery.json"),
            "--ignore",
            "OIDC-010",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert code == 1
    assert all(item["code"] != "OIDC-010" for item in json.loads(captured.out)["findings"])


def test_cli_rejects_two_token_sources() -> None:
    try:
        main([str(EXAMPLES / "discovery.json"), "--token", str(EXAMPLES / "token.jwt"), "--token-header", "x"])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("expected argparse to reject mutually exclusive token sources")
