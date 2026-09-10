# oidc-audit

[![CI](https://github.com/thisbejim/oidc-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/thisbejim/oidc-audit/actions/workflows/ci.yml)

Offline diagnostics for OpenID Connect provider metadata, JWKS files, and JWT
protected headers.

`oidc-audit` catches the configuration failures that otherwise surface as vague
runtime errors: an issuer that does not match, an HTTP endpoint, a malformed JWK,
a private key accidentally published, a duplicate `kid`, or a token that cannot
select one key from a local rotation snapshot. It is intentionally a diagnostic,
not a token verifier.

## Why this exists

OIDC configuration is spread across a Discovery document, a JWKS endpoint, and the
headers emitted by a token issuer. Runtime libraries usually report only the last
symptom. The [OpenID Connect Discovery specification](https://openid.net/specs/openid-connect-discovery-1_0.html)
requires exact issuer semantics, HTTPS endpoints, a JWKS URI, and a set of
advertised signing algorithms. [RFC 7517](https://www.rfc-editor.org/info/rfc7517/)
defines the JWKS `keys` shape and public-key members. Those constraints are easy to
check before deployment, but a hosted checker is not a good fit for private
snapshots or reproducible pull requests.

This tool is file-first: no network request is made and no account is needed.
JWT payloads and key bytes are never copied into diagnostics (field names and
key IDs may be mentioned to make a finding actionable). Keep a provider snapshot
beside an application and make the audit part of CI.

## Install

With `pipx`:

```bash
pipx install oidc-audit
```

From a checkout:

```bash
uv sync
```

Python 3.10+ is supported on macOS, Linux, and Windows. Runtime dependencies are
the Python standard library only.

## 30-second example

```bash
oidc-audit examples/discovery.json \
  --jwks examples/jwks.json \
  --token examples/token.jwt
```

```text
OIDC AUDIT: PASS
0 error(s), 0 warning(s), 0 info
Inputs: examples/discovery.json, examples/jwks.json, examples/token.jwt
No findings.
```

The broken fixtures show the intended signal:

```bash
oidc-audit examples/broken-discovery.json --format text
```

```text
[ERROR] OIDC-010 examples/broken-discovery.json:$.issuer — invalid HTTPS URL (scheme is not https; issuer must not contain a query or fragment)
  hint: OIDC provider metadata uses absolute HTTPS URLs; remove query/fragment parts from issuer.
```

The token option reads a local compact JWT and decodes only its protected header.
It never verifies a signature, evaluates claims, or prints the payload. Use
`--token-header` when a short fixture is more convenient than a file.

## CI and output formats

The default exit code is non-zero only for errors. `--strict` also fails on
warnings, or use `--severity info` to fail on every finding:

```bash
oidc-audit config/oidc.json --jwks config/jwks.json --strict
```

Machine-readable reports are stable and versioned:

```bash
oidc-audit config/oidc.json --jwks config/jwks.json --format json > oidc-audit.json
oidc-audit config/oidc.json --jwks config/jwks.json --format sarif > oidc-audit.sarif
```

SARIF 2.1.0 can be uploaded as a code-scanning artifact. Suppress a reviewed,
documented exception with `--ignore RULE` (repeatable). Exit code `2` means an
input file could not be read or the invocation was invalid.

Minimal GitHub Actions step:

```yaml
- name: Audit OIDC fixtures
  run: oidc-audit config/oidc.json --jwks config/jwks.json --strict --format sarif > oidc-audit.sarif
- name: Upload OIDC audit
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: oidc-audit.sarif
```

## What is checked

Discovery metadata checks include required members (`issuer`, endpoints, response
types, subject types, signing algorithms), exact expected-issuer comparison,
HTTPS URL syntax, array types and duplicates, `RS256` baseline advertisement,
`openid` scope presence, and token-authentication algorithm safety.

JWKS checks include duplicate JSON member names, the `keys` array, JWK types,
required RSA/EC/OKP members, unpadded base64url key bytes, curves, algorithm and
key-use compatibility, duplicate `kid` values, duplicate key material, private or
symmetric members, and basic `x5c` encoding.

When both a JWKS and token are supplied, the audit correlates the token's `alg` and
`kid` with eligible verification keys and reports zero or multiple matches. This
is a useful explanation of key-rotation failures, not proof that a token is
authentic.

See [the rule catalogue](docs/rules.md) for severities and remediation guidance.

## Library API

```python
from oidc_audit import audit, audit_files

report = audit_files(
    "config/oidc.json",
    jwks_path="config/jwks.json",
    expected_issuer="https://id.example.test",
)
if report.exit_code("warning"):
    for finding in report.findings:
        print(finding.code, finding.path, finding.message)

# Parsed documents can be audited without touching disk.
report = audit(discovery_document, jwks=jwks_document)
```

`Finding` and `Report` are frozen dataclasses. `Report.as_dict()` is the same
schema emitted by the JSON renderer.

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
```

The project is MIT licensed. See [PRODUCT.md](PRODUCT.md) for the product
contract and [docs/research.md](docs/research.md) for the opportunity review.

## Boundaries

`oidc-audit` does not fetch URLs, perform an OAuth login, mint or verify tokens,
validate claims, or establish trust in an issuer. A clean report means that the
checked local documents are internally coherent according to the implemented
rules; it does not replace runtime verification, conformance testing, or an
operator's trust decision.
