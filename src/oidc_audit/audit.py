"""OIDC Discovery, JWKS, and JWT-header auditing rules."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .jsonio import JsonInputError, load_json, parse_json, path_index, path_key
from .model import Finding, Report, Severity

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_KNOWN_KTY = {"RSA", "EC", "OKP", "oct"}
_KNOWN_CURVES = {
    "EC": {"P-256", "P-384", "P-521", "secp256k1"},
    "OKP": {"Ed25519", "Ed448", "X25519", "X448"},
}
_KEY_OPS = {"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"}
_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
_ENDPOINT_FIELDS = {
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "check_session_iframe",
    "end_session_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "service_documentation",
    "op_policy_uri",
    "op_tos_uri",
}
_ARRAY_FIELDS = {
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "acr_values_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "display_values_supported",
    "claim_types_supported",
    "claims_supported",
    "claims_locales_supported",
    "ui_locales_supported",
}
_REQUIRED_DISCOVERY = {
    "issuer": "OIDC-001",
    "authorization_endpoint": "OIDC-002",
    "jwks_uri": "OIDC-003",
    "response_types_supported": "OIDC-004",
    "subject_types_supported": "OIDC-005",
    "id_token_signing_alg_values_supported": "OIDC-006",
}


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """A minimally normalized JWK used for cross-document checks."""

    index: int
    value: Mapping[str, Any]
    valid: bool

    @property
    def kid(self) -> str | None:
        value = self.value.get("kid")
        return value if isinstance(value, str) else None

    @property
    def alg(self) -> str | None:
        value = self.value.get("alg")
        return value if isinstance(value, str) else None

    @property
    def use(self) -> str | None:
        value = self.value.get("use")
        return value if isinstance(value, str) else None

    def is_signing_candidate(self) -> bool:
        if not self.valid or self.value.get("kty") == "oct":
            return False
        if self.use == "enc":
            return False
        operations = self.value.get("key_ops")
        return not isinstance(operations, list) or "verify" in operations


def _finding(
    code: str,
    severity: Severity,
    message: str,
    path: str,
    *,
    hint: str | None = None,
    source: str | None = None,
) -> Finding:
    return Finding(code, severity, message, path, hint, source)


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "number"


def _require_object(document: Any, *, source: str | None, label: str) -> list[Finding]:
    if isinstance(document, dict):
        return []
    return [
        _finding(
            "JSON-002",
            "error",
            f"{label} must be a JSON object, got {_type_name(document)}",
            "$",
            hint="Supply a JSON object document rather than an array, scalar, or null.",
            source=source,
        )
    ]


def _check_https_url(
    value: Any,
    path: str,
    *,
    source: str | None,
    issuer: bool = False,
) -> list[Finding]:
    if not isinstance(value, str) or not value:
        return [
            _finding(
                "OIDC-010",
                "error",
                f"expected an HTTPS URL, got {_type_name(value)}",
                path,
                hint="Use an absolute https:// URL.",
                source=source,
            )
        ]
    parsed = urlsplit(value)
    problems: list[str] = []
    if parsed.scheme != "https":
        problems.append("scheme is not https")
    if not parsed.netloc:
        problems.append("host is missing")
    if issuer and (parsed.query or parsed.fragment):
        problems.append("issuer must not contain a query or fragment")
    if problems:
        return [
            _finding(
                "OIDC-010",
                "error",
                f"invalid HTTPS URL ({'; '.join(problems)})",
                path,
                hint="OIDC provider metadata uses absolute HTTPS URLs; remove query/fragment parts from issuer.",
                source=source,
            )
        ]
    return []


def _check_array_field(document: Mapping[str, Any], field: str, *, source: str | None) -> list[Finding]:
    if field not in document:
        return []
    value = document[field]
    path = path_key("$", field)
    if not isinstance(value, list):
        return [
            _finding(
                "OIDC-011",
                "error",
                f"metadata member must be an array, got {_type_name(value)}",
                path,
                hint="Represent multi-valued metadata as a JSON array of strings.",
                source=source,
            )
        ]
    findings: list[Finding] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_path = path_index(path, index)
        if not isinstance(item, str) or not item:
            findings.append(
                _finding(
                    "OIDC-012",
                    "error",
                    f"array item must be a non-empty string, got {_type_name(item)}",
                    item_path,
                    hint="Remove empty items and encode each advertised value as a string.",
                    source=source,
                )
            )
            continue
        if item in seen:
            findings.append(
                _finding(
                    "OIDC-013",
                    "warning",
                    f"duplicate advertised value {item!r}",
                    item_path,
                    hint="Keep each advertised capability once to avoid client-specific interpretation.",
                    source=source,
                )
            )
        seen.add(item)
    if isinstance(value, list) and not value:
        findings.append(
            _finding(
                "OIDC-014",
                "error",
                "advertised capability array must not be empty",
                path,
                hint="Omit an optional capability or list at least one supported value.",
                source=source,
            )
        )
    return findings


def audit_discovery(
    document: Any,
    *,
    expected_issuer: str | None = None,
    source: str | None = None,
) -> list[Finding]:
    """Audit one parsed OpenID Provider Discovery document."""

    findings = _require_object(document, source=source, label="Discovery document")
    if findings:
        return findings
    assert isinstance(document, dict)

    for field, code in _REQUIRED_DISCOVERY.items():
        if field not in document:
            findings.append(
                _finding(
                    code,
                    "error",
                    f"required metadata member {field!r} is missing",
                    "$",
                    hint=f"Add {field!r} to the provider configuration document.",
                    source=source,
                )
            )

    issuer = document.get("issuer")
    if "issuer" in document:
        findings.extend(_check_https_url(issuer, "$.issuer", source=source, issuer=True))
        if expected_issuer is not None and issuer != expected_issuer:
            findings.append(
                _finding(
                    "OIDC-007",
                    "error",
                    f"issuer {issuer!r} does not exactly match expected issuer {expected_issuer!r}",
                    "$.issuer",
                    hint="Use the same issuer string in application configuration and provider metadata; do not normalize it silently.",
                    source=source,
                )
            )

    for field in _ENDPOINT_FIELDS:
        if field in document:
            findings.extend(_check_https_url(document[field], path_key("$", field), source=source))

    for field in _ARRAY_FIELDS:
        findings.extend(_check_array_field(document, field, source=source))

    response_types = document.get("response_types_supported")
    if isinstance(response_types, list):
        has_code = any(isinstance(item, str) and "code" in item.split() for item in response_types)
        if "token_endpoint" not in document and has_code:
            findings.append(
                _finding(
                    "OIDC-008",
                    "error",
                    "token_endpoint is missing although a code response type is advertised",
                    "$.token_endpoint",
                    hint="Publish the token endpoint for authorization-code flows, or advertise only implicit response types.",
                    source=source,
                )
            )
    elif "token_endpoint" not in document:
        findings.append(
            _finding(
                "OIDC-008",
                "warning",
                "token_endpoint is absent and response types could not be evaluated",
                "$.token_endpoint",
                hint="Add token_endpoint when supporting authorization-code or hybrid flows.",
                source=source,
            )
        )

    subjects = document.get("subject_types_supported")
    if isinstance(subjects, list):
        invalid_subjects = [item for item in subjects if item not in {"public", "pairwise"}]
        if invalid_subjects:
            findings.append(
                _finding(
                    "OIDC-015",
                    "warning",
                    f"unknown subject type(s) advertised: {', '.join(map(repr, invalid_subjects))}",
                    "$.subject_types_supported",
                    hint="Use the standard public or pairwise subject type, or document an extension for clients.",
                    source=source,
                )
            )

    algorithms = document.get("id_token_signing_alg_values_supported")
    if isinstance(algorithms, list):
        if "RS256" not in algorithms:
            findings.append(
                _finding(
                    "OIDC-016",
                    "error",
                    "id_token_signing_alg_values_supported does not include required RS256",
                    "$.id_token_signing_alg_values_supported",
                    hint="Advertise RS256 for baseline OpenID Connect interoperability.",
                    source=source,
                )
            )
        if algorithms == ["none"] or (algorithms and set(algorithms) == {"none"}):
            findings.append(
                _finding(
                    "OIDC-017",
                    "error",
                    "the provider advertises no usable signed ID-token algorithm",
                    "$.id_token_signing_alg_values_supported",
                    hint="Publish at least one asymmetric signing algorithm; never rely on alg=none for signed ID tokens.",
                    source=source,
                )
            )

    scopes = document.get("scopes_supported")
    if isinstance(scopes, list) and "openid" not in scopes:
        findings.append(
            _finding(
                "OIDC-018",
                "warning",
                "scopes_supported omits the required openid scope",
                "$.scopes_supported",
                hint="Include openid when publishing the supported-scope list; clients use it to identify OIDC support.",
                source=source,
            )
        )

    auth_methods = document.get("token_endpoint_auth_methods_supported")
    auth_algs = document.get("token_endpoint_auth_signing_alg_values_supported")
    if isinstance(auth_methods, list) and "private_key_jwt" in auth_methods and isinstance(auth_algs, list):
        if not any(isinstance(value, str) and value != "none" for value in auth_algs):
            findings.append(
                _finding(
                    "OIDC-019",
                    "error",
                    "private_key_jwt is advertised without a usable signing algorithm",
                    "$.token_endpoint_auth_signing_alg_values_supported",
                    hint="Advertise at least one supported JWS algorithm other than none.",
                    source=source,
                )
            )
    if isinstance(auth_algs, list) and "none" in auth_algs:
        findings.append(
            _finding(
                "OIDC-020",
                "error",
                "token endpoint authentication algorithms must not include none",
                "$.token_endpoint_auth_signing_alg_values_supported",
                hint="Remove none; client authentication assertions must be signed.",
                source=source,
            )
        )

    return findings


def _decode_b64url(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or "=" in value or not _B64URL.fullmatch(value):
        return None
    if len(value) % 4 == 1:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return None
    return decoded or None


def _check_b64url_member(
    value: Any,
    path: str,
    *,
    source: str | None,
    label: str,
) -> list[Finding]:
    if _decode_b64url(value) is None:
        return [
            _finding(
                "JWK-004",
                "error",
                f"{label} must be non-empty unpadded base64url",
                path,
                hint="Encode key bytes with base64url without '=' padding.",
                source=source,
            )
        ]
    return []


def _alg_compatible(kty: str, alg: str) -> bool | None:
    """Return compatibility for known JOSE families; None for extensions."""

    if kty == "RSA":
        return alg.startswith(("RS", "PS", "RSA-OAEP", "RSA1_5"))
    if kty == "EC":
        return alg.startswith(("ES", "ECDH-ES"))
    if kty == "OKP":
        return alg == "EdDSA" or alg.startswith("ECDH-ES")
    if kty == "oct":
        return alg.startswith(("HS", "A", "dir", "PBES2"))
    return None


def _record_matches_alg(record: KeyRecord, alg: str) -> bool:
    """Check both a JWK's declared algorithm and its key-family compatibility."""

    if record.alg is not None and record.alg != alg:
        return False
    kty = record.value.get("kty")
    if not isinstance(kty, str):
        return False
    return _alg_compatible(kty, alg) is not False


def _key_fingerprint(value: Mapping[str, Any]) -> str | None:
    raw_kty = value.get("kty")
    kty = raw_kty if isinstance(raw_kty, str) else None
    fields: tuple[str, ...]
    if kty == "RSA":
        fields = ("n", "e")
    elif kty == "EC":
        fields = ("crv", "x", "y")
    elif kty == "OKP":
        fields = ("crv", "x")
    elif kty == "oct":
        fields = ("k",)
    else:
        fields = ()
    if not fields or any(not isinstance(value.get(field), str) for field in fields):
        return None
    canonical = "|".join([str(kty), *(str(value[field]) for field in fields)])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _inspect_jwks(
    document: Any,
    *,
    source: str | None = None,
) -> tuple[list[Finding], tuple[KeyRecord, ...]]:
    findings = _require_object(document, source=source, label="JWKS document")
    if findings:
        return findings, ()
    assert isinstance(document, dict)
    keys = document.get("keys")
    if not isinstance(keys, list):
        return [
            _finding(
                "JWK-001",
                "error",
                "JWKS must contain a keys array",
                "$.keys",
                hint='Wrap public JWK objects in {"keys": [...]}.',
                source=source,
            )
        ], ()
    if not keys:
        findings.append(
            _finding(
                "JWK-002",
                "error",
                "JWKS keys array is empty",
                "$.keys",
                hint="Publish at least one active public signing key during rotation.",
                source=source,
            )
        )

    records: list[KeyRecord] = []
    kids: dict[str, list[int]] = {}
    fingerprints: dict[str, list[int]] = {}
    for index, raw_key in enumerate(keys):
        path = path_index("$.keys", index)
        if not isinstance(raw_key, dict):
            findings.append(
                _finding(
                    "JWK-003",
                    "error",
                    f"JWK must be an object, got {_type_name(raw_key)}",
                    path,
                    hint="Each item in keys must be a JSON object.",
                    source=source,
                )
            )
            continue
        valid = True
        kty = raw_key.get("kty")
        if not isinstance(kty, str) or not kty:
            findings.append(
                _finding(
                    "JWK-005",
                    "error",
                    "required kty member is missing or not a string",
                    path_key(path, "kty"),
                    hint="Set kty to RSA, EC, OKP, or another documented JOSE key type.",
                    source=source,
                )
            )
            valid = False
        elif kty not in _KNOWN_KTY:
            findings.append(
                _finding(
                    "JWK-006",
                    "warning",
                    f"unrecognized JWK key type {kty!r}",
                    path_key(path, "kty"),
                    hint="Clients may not import extension key types; verify consumer support.",
                    source=source,
                )
            )
            valid = False

        kid = raw_key.get("kid")
        if kid is not None and (not isinstance(kid, str) or not kid):
            findings.append(
                _finding(
                    "JWK-008",
                    "error" if not isinstance(kid, str) else "warning",
                    "kid must be a non-empty string when present",
                    path_key(path, "kid"),
                    hint="Use a stable, unique string key identifier.",
                    source=source,
                )
            )
            valid = False
        elif isinstance(kid, str):
            kids.setdefault(kid, []).append(index)

        use = raw_key.get("use")
        if use is not None and use not in {"sig", "enc"}:
            findings.append(
                _finding(
                    "JWK-009",
                    "error",
                    f"use must be sig or enc, got {use!r}",
                    path_key(path, "use"),
                    hint="Use sig for verification keys or enc for encryption keys.",
                    source=source,
                )
            )
            valid = False

        operations = raw_key.get("key_ops")
        if operations is not None:
            if not isinstance(operations, list) or any(not isinstance(item, str) for item in operations):
                findings.append(
                    _finding(
                        "JWK-011",
                        "error",
                        "key_ops must be an array of strings",
                        path_key(path, "key_ops"),
                        hint="List the permitted operations such as verify or encrypt.",
                        source=source,
                    )
                )
                valid = False
            else:
                seen_ops: set[str] = set()
                for op_index, operation in enumerate(operations):
                    op_path = path_index(path_key(path, "key_ops"), op_index)
                    if operation not in _KEY_OPS:
                        findings.append(
                            _finding(
                                "JWK-012",
                                "warning",
                                f"unknown key operation {operation!r}",
                                op_path,
                                hint="Use a registered JOSE key operation or document the extension.",
                                source=source,
                            )
                        )
                    if operation in seen_ops:
                        findings.append(
                            _finding(
                                "JWK-013",
                                "warning",
                                f"duplicate key operation {operation!r}",
                                op_path,
                                hint="List each key operation once.",
                                source=source,
                            )
                        )
                    seen_ops.add(operation)
                if use == "sig" and any(op in {"encrypt", "decrypt", "wrapKey", "unwrapKey"} for op in operations):
                    findings.append(
                        _finding(
                            "JWK-014",
                            "warning",
                            "sig key declares encryption operations",
                            path_key(path, "key_ops"),
                            hint="Keep signing and encryption purposes separate, or omit conflicting metadata.",
                            source=source,
                        )
                    )
                if use == "enc" and any(op in {"sign", "verify"} for op in operations):
                    findings.append(
                        _finding(
                            "JWK-014",
                            "warning",
                            "enc key declares signing operations",
                            path_key(path, "key_ops"),
                            hint="Keep signing and encryption purposes separate, or omit conflicting metadata.",
                            source=source,
                        )
                    )

        alg = raw_key.get("alg")
        if alg is not None and not isinstance(alg, str):
            findings.append(
                _finding(
                    "JWK-015",
                    "error",
                    "alg must be a string when present",
                    path_key(path, "alg"),
                    hint="Set alg to a JOSE algorithm identifier or omit it.",
                    source=source,
                )
            )
            valid = False
        elif isinstance(alg, str) and isinstance(kty, str):
            compatible = _alg_compatible(kty, alg)
            if compatible is False:
                findings.append(
                    _finding(
                        "JWK-016",
                        "error",
                        f"alg {alg!r} is incompatible with kty {kty!r}",
                        path_key(path, "alg"),
                        hint="Use an algorithm family matching the key type (for example RS*/PS* for RSA).",
                        source=source,
                    )
                )
                valid = False

        private_present = sorted(name for name in _PRIVATE_MEMBERS if name in raw_key)
        if private_present:
            findings.append(
                _finding(
                    "JWK-010",
                    "error",
                    f"public JWKS contains private or symmetric member(s): {', '.join(private_present)}",
                    path,
                    hint="Publish only public RSA/EC/OKP material; never commit private key bytes to a provider JWKS.",
                    source=source,
                )
            )
            valid = False

        if kty == "RSA":
            for member in ("n", "e"):
                if member not in raw_key:
                    findings.append(
                        _finding(
                            "JWK-017",
                            "error",
                            f"RSA key is missing required {member!r} member",
                            path,
                            hint="Include the modulus n and exponent e as base64url values.",
                            source=source,
                        )
                    )
                    valid = False
                else:
                    member_findings = _check_b64url_member(
                        raw_key[member],
                        path_key(path, member),
                        source=source,
                        label=f"RSA {member}",
                    )
                    findings.extend(member_findings)
                    valid = valid and not member_findings
        elif kty == "EC":
            curve = raw_key.get("crv")
            if curve not in _KNOWN_CURVES["EC"]:
                findings.append(
                    _finding(
                        "JWK-018",
                        "error",
                        f"EC key has unsupported or missing curve {curve!r}",
                        path_key(path, "crv"),
                        hint="Use a curve supported by your consumers, such as P-256, P-384, or P-521.",
                        source=source,
                    )
                )
                valid = False
            for member in ("x", "y"):
                if member not in raw_key:
                    findings.append(
                        _finding(
                            "JWK-019",
                            "error",
                            f"EC key is missing required {member!r} member",
                            path,
                            hint="Include both public curve coordinates as base64url values.",
                            source=source,
                        )
                    )
                    valid = False
                else:
                    member_findings = _check_b64url_member(
                        raw_key[member],
                        path_key(path, member),
                        source=source,
                        label=f"EC {member}",
                    )
                    findings.extend(member_findings)
                    valid = valid and not member_findings
        elif kty == "OKP":
            curve = raw_key.get("crv")
            if curve not in _KNOWN_CURVES["OKP"]:
                findings.append(
                    _finding(
                        "JWK-020",
                        "error",
                        f"OKP key has unsupported or missing curve {curve!r}",
                        path_key(path, "crv"),
                        hint="Use an interoperable OKP curve such as Ed25519 or Ed448.",
                        source=source,
                    )
                )
                valid = False
            if "x" not in raw_key:
                findings.append(
                    _finding(
                        "JWK-021",
                        "error",
                        "OKP key is missing required x member",
                        path,
                        hint="Include the public key bytes as an unpadded base64url x value.",
                        source=source,
                    )
                )
                valid = False
            else:
                member_findings = _check_b64url_member(raw_key["x"], path_key(path, "x"), source=source, label="OKP x")
                findings.extend(member_findings)
                valid = valid and not member_findings
        elif kty == "oct":
            if "k" not in raw_key:
                findings.append(
                    _finding(
                        "JWK-022",
                        "error",
                        "symmetric oct key is missing k member",
                        path,
                        hint="Do not publish symmetric keys in an OpenID Provider JWKS; use an asymmetric public key.",
                        source=source,
                    )
                )
                valid = False
            else:
                member_findings = _check_b64url_member(raw_key["k"], path_key(path, "k"), source=source, label="oct k")
                findings.extend(member_findings)
                valid = False

        x5c = raw_key.get("x5c")
        if x5c is not None:
            if not isinstance(x5c, list):
                findings.append(
                    _finding(
                        "JWK-023",
                        "error",
                        "x5c must be an array of base64-encoded certificates",
                        path_key(path, "x5c"),
                        hint="Encode each DER certificate with standard base64 in an array.",
                        source=source,
                    )
                )
                valid = False
            else:
                for cert_index, certificate in enumerate(x5c):
                    cert_path = path_index(path_key(path, "x5c"), cert_index)
                    try:
                        decoded = base64.b64decode(certificate, validate=True) if isinstance(certificate, str) else b""
                    except (binascii.Error, ValueError):
                        decoded = b""
                    if not decoded:
                        findings.append(
                            _finding(
                                "JWK-024",
                                "error",
                                "x5c certificate must be non-empty standard base64",
                                cert_path,
                                hint="Use the DER certificate bytes, not PEM text or base64url.",
                                source=source,
                            )
                        )
                        valid = False

        for thumbprint_member in ("x5t", "x5t#S256"):
            if thumbprint_member in raw_key:
                thumbprint_findings = _check_b64url_member(
                    raw_key[thumbprint_member],
                    path_key(path, thumbprint_member),
                    source=source,
                    label=thumbprint_member,
                )
                findings.extend(thumbprint_findings)
                valid = valid and not thumbprint_findings

        fingerprint = _key_fingerprint(raw_key)
        if fingerprint:
            fingerprints.setdefault(fingerprint, []).append(index)
        records.append(KeyRecord(index, raw_key, valid))

    for kid, indexes in kids.items():
        if len(indexes) > 1:
            findings.append(
                _finding(
                    "JWK-007",
                    "warning",
                    f"kid {kid!r} is used by multiple keys ({', '.join(map(str, indexes))})",
                    "$.keys",
                    hint="Use unique key IDs during rotation so verifiers can select one key deterministically.",
                    source=source,
                )
            )
    for indexes in fingerprints.values():
        if len(indexes) > 1:
            findings.append(
                _finding(
                    "JWK-025",
                    "warning",
                    f"identical key material appears at indexes {', '.join(map(str, indexes))}",
                    "$.keys",
                    hint="Publish one canonical JWK per key material unless consumers explicitly need aliases.",
                    source=source,
                )
            )

    eligible_records = [record for record in records if record.is_signing_candidate()]
    if len(eligible_records) > 1 and any(record.kid is None for record in eligible_records):
        findings.append(
            _finding(
                "JWK-026",
                "warning",
                "multiple signing candidates have no usable kid",
                "$.keys",
                hint="Give each active signing key a stable kid so JWT verifiers can select it during rotation.",
                source=source,
            )
        )
    return findings, tuple(records)


def audit_jwks(document: Any, *, source: str | None = None) -> list[Finding]:
    """Audit one parsed JWKS document."""

    findings, _ = _inspect_jwks(document, source=source)
    return findings


def _decode_token_header(token: str, *, source: str | None = None) -> tuple[dict[str, Any] | None, list[Finding]]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, [
            _finding(
                "TOKEN-001",
                "error",
                "token is not a compact JWT with three segments",
                "$",
                hint="Pass a complete local compact JWT; oidc-audit only inspects its protected header.",
                source=source,
            )
        ]
    decoded = _decode_b64url(parts[0])
    if decoded is None:
        return None, [
            _finding(
                "TOKEN-002",
                "error",
                "JWT protected header is not valid unpadded base64url",
                "$.header",
                hint="Check that the first compact-JWT segment is base64url encoded.",
                source=source,
            )
        ]
    try:
        header_value = parse_json(decoded.decode("utf-8"), source="JWT protected header")
    except (UnicodeDecodeError, JsonInputError) as exc:
        return None, [
            _finding(
                "TOKEN-003",
                "error",
                f"JWT protected header is not a JSON object: {exc}",
                "$.header",
                hint="A compact JWT header must be UTF-8 JSON.",
                source=source,
            )
        ]
    if not isinstance(header_value, dict):
        return None, [
            _finding(
                "TOKEN-004",
                "error",
                "JWT protected header must be a JSON object",
                "$.header",
                hint="Encode alg, kid, and other JOSE header members in an object.",
                source=source,
            )
        ]
    return header_value, []


def audit_token(
    token: str,
    *,
    keys: Sequence[KeyRecord] = (),
    source: str | None = None,
) -> list[Finding]:
    """Inspect a compact JWT header and correlate it with JWK records."""

    header, findings = _decode_token_header(token, source=source)
    if header is None:
        return findings
    alg = header.get("alg")
    kid = header.get("kid")
    if not isinstance(alg, str) or not alg:
        findings.append(
            _finding(
                "TOKEN-005",
                "error",
                "JWT protected header requires a non-empty alg string",
                "$.header.alg",
                hint="Set alg to the signing algorithm used by the issuer.",
                source=source,
            )
        )
        return findings
    if alg == "none":
        findings.append(
            _finding(
                "TOKEN-006",
                "error",
                "JWT uses alg=none and has no cryptographic signature",
                "$.header.alg",
                hint="Use an asymmetric signing algorithm and verify the signature in the consuming library.",
                source=source,
            )
        )
    if kid is not None and not isinstance(kid, str):
        findings.append(
            _finding(
                "TOKEN-007",
                "error",
                "JWT kid must be a string when present",
                "$.header.kid",
                hint="Emit the JWK's string key identifier in the protected header.",
                source=source,
            )
        )
    critical = header.get("crit")
    if critical is not None:
        if not isinstance(critical, list) or any(not isinstance(item, str) for item in critical):
            findings.append(
                _finding(
                    "TOKEN-008",
                    "error",
                    "JWT crit must be an array of header-name strings",
                    "$.header.crit",
                    hint="Only list understood critical extensions; malformed crit headers must be rejected.",
                    source=source,
                )
            )
        elif critical:
            findings.append(
                _finding(
                    "TOKEN-009",
                    "warning",
                    f"JWT declares critical header(s) not evaluated by oidc-audit: {', '.join(critical)}",
                    "$.header.crit",
                    hint="Ensure the runtime verifier understands every critical extension before accepting the token.",
                    source=source,
                )
            )

    if not keys:
        return findings
    eligible = [record for record in keys if record.is_signing_candidate()]
    if isinstance(kid, str):
        kid_matches = [record for record in eligible if record.kid == kid]
        if not kid_matches:
            findings.append(
                _finding(
                    "TOKEN-010",
                    "error",
                    f"no eligible JWKS key matches token kid {kid!r}",
                    "$.header.kid",
                    hint="Refresh the JWKS snapshot or correct the issuer/token environment pairing.",
                    source=source,
                )
            )
        else:
            alg_matches = [record for record in kid_matches if _record_matches_alg(record, alg)]
            if not alg_matches:
                findings.append(
                    _finding(
                        "TOKEN-011",
                        "error",
                        f"JWKS key kid {kid!r} is incompatible with token alg {alg!r}",
                        "$.header.alg",
                        hint="Use the key and algorithm pair advertised by the provider.",
                        source=source,
                    )
                )
            elif len(alg_matches) > 1:
                findings.append(
                    _finding(
                        "TOKEN-012",
                        "error",
                        f"token kid {kid!r} selects multiple eligible JWKS keys",
                        "$.header.kid",
                        hint="Give each active key a unique kid or make the kty/use/alg tuple unambiguous.",
                        source=source,
                    )
                )
    elif len(eligible) > 1:
        findings.append(
            _finding(
                "TOKEN-013",
                "warning",
                "token has no kid while multiple signing keys are eligible",
                "$.header.kid",
                hint="Include the active JWK's kid in every signed token during key rotation.",
                source=source,
            )
        )
    return findings


def audit(
    discovery: Any,
    *,
    jwks: Any | None = None,
    token: str | None = None,
    expected_issuer: str | None = None,
    inputs: Iterable[str] = (),
    discovery_source: str | None = None,
    jwks_source: str | None = None,
    token_source: str | None = None,
) -> Report:
    """Audit parsed documents and return an immutable report."""

    findings = audit_discovery(
        discovery,
        expected_issuer=expected_issuer,
        source=discovery_source,
    )
    records: tuple[KeyRecord, ...] = ()
    if jwks is not None:
        jwks_findings, records = _inspect_jwks(jwks, source=jwks_source)
        findings.extend(jwks_findings)
        algorithms = discovery.get("id_token_signing_alg_values_supported") if isinstance(discovery, dict) else None
        if isinstance(algorithms, list) and records:
            signing = [record for record in records if record.is_signing_candidate()]
            declared = {value for value in algorithms if isinstance(value, str) and value != "none"}
            if declared and signing:
                compatible = [record for record in signing if any(_record_matches_alg(record, alg) for alg in declared)]
                if not compatible:
                    findings.append(
                        _finding(
                            "OIDC-021",
                            "error",
                            "JWKS has no signing key compatible with the provider's advertised ID-token algorithms",
                            "$.id_token_signing_alg_values_supported",
                            hint="Publish a matching public key or correct the metadata/JWKS environment pairing.",
                            source=discovery_source,
                        )
                    )
            elif declared and not signing:
                findings.append(
                    _finding(
                        "OIDC-021",
                        "error",
                        "JWKS contains no eligible signing key for the provider metadata",
                        "$.jwks_uri",
                        hint="Publish at least one non-private asymmetric verification key for ID-token signatures.",
                        source=discovery_source,
                    )
                )
    if token is not None:
        findings.extend(audit_token(token, keys=records, source=token_source))
    return Report(tuple(findings), tuple(inputs))


def _read_token_file(path: str | Path) -> str:
    path_obj = Path(path)
    try:
        return path_obj.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise JsonInputError(f"{path_obj}: file not found", kind="missing") from exc
    except UnicodeDecodeError as exc:
        raise JsonInputError(f"{path_obj}: not valid UTF-8", kind="encoding") from exc
    except OSError as exc:
        raise JsonInputError(f"{path_obj}: cannot read file: {exc}", kind="io") from exc


def audit_files(
    discovery_path: str | Path,
    *,
    jwks_path: str | Path | None = None,
    token_path: str | Path | None = None,
    token_header: str | None = None,
    expected_issuer: str | None = None,
) -> Report:
    """Load local files and audit them, marking unreadable input as exit code 2."""

    findings: list[Finding] = []
    input_error = False
    discovery: Any = None
    jwks: Any | None = None
    token: str | None = token_header
    inputs = [str(discovery_path)]
    try:
        discovery = load_json(discovery_path)
    except JsonInputError as exc:
        code = "INPUT-001" if exc.kind == "missing" else "INPUT-002" if exc.kind == "encoding" else "INPUT-003"
        findings.append(
            _finding(
                code,
                "error",
                str(exc),
                "$",
                hint="Fix or replace the local input file.",
                source=str(discovery_path),
            )
        )
        input_error = True
    if jwks_path is not None:
        inputs.append(str(jwks_path))
        try:
            jwks = load_json(jwks_path)
        except JsonInputError as exc:
            code = "INPUT-001" if exc.kind == "missing" else "INPUT-002" if exc.kind == "encoding" else "INPUT-003"
            findings.append(
                _finding(
                    code,
                    "error",
                    str(exc),
                    "$",
                    hint="Fix or replace the local input file.",
                    source=str(jwks_path),
                )
            )
            input_error = True
    if token_path is not None:
        inputs.append(str(token_path))
        try:
            token = _read_token_file(token_path)
        except JsonInputError as exc:
            code = "INPUT-001" if exc.kind == "missing" else "INPUT-002" if exc.kind == "encoding" else "INPUT-003"
            findings.append(
                _finding(
                    code,
                    "error",
                    str(exc),
                    "$",
                    hint="Fix or replace the local token file.",
                    source=str(token_path),
                )
            )
            input_error = True

    if discovery is None:
        return Report(tuple(findings), tuple(inputs), input_error=True)
    report = audit(
        discovery,
        jwks=jwks,
        token=token,
        expected_issuer=expected_issuer,
        inputs=inputs,
        discovery_source=str(discovery_path),
        jwks_source=str(jwks_path) if jwks_path is not None else None,
        token_source=str(token_path) if token_path is not None else "--token-header" if token_header else None,
    )
    return Report(tuple(findings) + report.findings, report.inputs, input_error or report.input_error)
