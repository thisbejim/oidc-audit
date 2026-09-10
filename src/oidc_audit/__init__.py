"""Local-first OIDC metadata and JWKS diagnostics."""

from .audit import audit, audit_discovery, audit_files, audit_jwks, audit_token
from .model import Finding, Report

__all__ = [
    "Finding",
    "Report",
    "audit",
    "audit_discovery",
    "audit_files",
    "audit_jwks",
    "audit_token",
]

__version__ = "0.1.1"
