"""Command-line interface for oidc-audit."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .audit import audit_files
from .model import Severity
from .render import filter_report, render

VERSION = "0.1.1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oidc-audit",
        description="Audit OIDC Discovery metadata, JWKS documents, and local JWT headers.",
        epilog="No network request is made. Signature verification and claim trust are intentionally out of scope.",
    )
    parser.add_argument("discovery", help="path to an OpenID Provider Discovery JSON file")
    parser.add_argument("--jwks", metavar="PATH", help="path to a local JWKS JSON file")
    parser.add_argument("--token", metavar="PATH", help="path to a local compact JWT; only its protected header is read")
    parser.add_argument("--token-header", metavar="JWT", help="inline compact JWT for header-only correlation")
    parser.add_argument("--issuer", metavar="URL", help="expected issuer string (compared exactly)")
    parser.add_argument(
        "--format",
        dest="format_name",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--severity",
        choices=("error", "warning", "info"),
        default="error",
        help="minimum severity that fails the command (default: error)",
    )
    parser.add_argument("--strict", action="store_true", help="fail on warnings as well as errors")
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE",
        help="suppress a rule ID (repeatable; e.g. --ignore OIDC-013)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.token and args.token_header:
        parser.error("--token and --token-header are mutually exclusive")
    threshold: Severity = "warning" if args.strict else args.severity
    report = audit_files(
        args.discovery,
        jwks_path=args.jwks,
        token_path=args.token,
        token_header=args.token_header,
        expected_issuer=args.issuer,
    )
    report = filter_report(report, ignore=args.ignore)
    sys.stdout.write(render(report, args.format_name))
    return report.exit_code(threshold)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
