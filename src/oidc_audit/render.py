"""Stable terminal, JSON, and SARIF renderers."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .model import Finding, Report

_SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note"}


def filter_report(report: Report, *, ignore: Iterable[str] = ()) -> Report:
    """Return a report with explicitly ignored rule IDs removed."""

    ignored = set(ignore)
    return Report(
        tuple(finding for finding in report.findings if finding.code not in ignored),
        report.inputs,
        report.input_error,
    )


def render_text(report: Report) -> str:
    """Render a concise human-readable report."""

    counts = report.counts
    if counts["error"]:
        status = "FAIL"
    elif counts["warning"]:
        status = "PASS WITH WARNINGS"
    else:
        status = "PASS"
    lines = [
        f"OIDC AUDIT: {status}",
        f"{counts['error']} error(s), {counts['warning']} warning(s), {counts['info']} info",
    ]
    if report.inputs:
        lines.append("Inputs: " + ", ".join(report.inputs))
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines.append("")
    for finding in report.findings:
        lines.append(_render_finding(finding))
    return "\n".join(lines) + "\n"


def _render_finding(finding: Finding) -> str:
    location = f"{finding.source}:{finding.path}" if finding.source else finding.path
    line = f"[{finding.severity.upper()}] {finding.code} {location} — {finding.message}"
    if finding.hint:
        line += f"\n  hint: {finding.hint}"
    return line


def render_json(report: Report) -> str:
    """Render the versioned JSON report."""

    return json.dumps(report.as_dict(), indent=2, sort_keys=False) + "\n"


def render_sarif(report: Report) -> str:
    """Render SARIF 2.1.0 suitable for code-scanning upload."""

    rule_ids = sorted({finding.code for finding in report.findings})
    rules = [{"id": rule_id} for rule_id in rule_ids]
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.code,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message + (f" Hint: {finding.hint}" if finding.hint else "")},
        }
        if finding.source:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.source},
                        "region": {"snippet": {"text": finding.path}},
                    }
                }
            ]
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oidc-audit",
                        "informationUri": "https://github.com/thisbejim/oidc-audit",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=False) + "\n"


def render(report: Report, format_name: str) -> str:
    """Dispatch to one of the supported output formats."""

    if format_name == "json":
        return render_json(report)
    if format_name == "sarif":
        return render_sarif(report)
    return render_text(report)
