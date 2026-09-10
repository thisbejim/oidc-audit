"""Public data model for oidc-audit reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warning", "info"]

SEVERITY_ORDER: dict[Severity, int] = {"info": 0, "warning": 1, "error": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    """One actionable observation produced by an audit."""

    code: str
    severity: Severity
    message: str
    path: str = "$"
    hint: str | None = None
    source: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        """Return the stable JSON representation used by all renderers."""

        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
            "hint": self.hint,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class Report:
    """An immutable audit report."""

    findings: tuple[Finding, ...]
    inputs: tuple[str, ...] = ()
    input_error: bool = False

    @property
    def counts(self) -> dict[Severity, int]:
        """Count findings by severity, including zeroes for stable output."""

        return {
            "error": sum(f.severity == "error" for f in self.findings),
            "warning": sum(f.severity == "warning" for f in self.findings),
            "info": sum(f.severity == "info" for f in self.findings),
        }

    def at_or_above(self, threshold: Severity) -> tuple[Finding, ...]:
        """Return findings at or above a severity threshold."""

        minimum = SEVERITY_ORDER[threshold]
        return tuple(f for f in self.findings if SEVERITY_ORDER[f.severity] >= minimum)

    def exit_code(self, threshold: Severity = "error") -> int:
        """Return the command exit code for a threshold."""

        if self.input_error:
            return 2
        return 1 if self.at_or_above(threshold) else 0

    def as_dict(self) -> dict[str, object]:
        """Return a machine-readable report."""

        return {
            "version": 1,
            "inputs": list(self.inputs),
            "input_error": self.input_error,
            "counts": self.counts,
            "findings": [finding.as_dict() for finding in self.findings],
        }
