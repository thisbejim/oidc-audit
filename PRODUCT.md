# Product specification: oidc-audit

## Problem

OIDC integrations join three independently supplied documents: provider metadata,
the provider's JSON Web Key Set (JWKS), and (during debugging) a token header.
Libraries normally report the final symptom—an issuer mismatch, missing `kid`, or
unusable key—after an application has already been wired up. Online checkers can
inspect a URL, but they are a poor fit for private environments, pull requests,
reproducible CI, and sensitive token fixtures. Teams need a deterministic,
editor-independent check that can run on files before deployment.

## Product promise

`oidc-audit` is a local-first command and Python API that audits OIDC Discovery
metadata, JWKS documents, and optional JWT headers. It explains what is wrong,
where it is wrong, and what to change, with text, JSON, and SARIF output. The
default command never makes a network request and never prints token contents.

## Target users

- Application and platform engineers integrating Auth0, Keycloak, Entra ID,
  Cognito, or another OIDC provider.
- Maintainers who commit provider metadata/JWKS snapshots or fixtures.
- CI authors who want a failing, reviewable check without credentials.

## Core workflow

```text
oidc-audit discovery.json --jwks jwks.json --token-header token.jwt \
  --format sarif > oidc-audit.sarif
```

The command exits `0` when no findings meet the selected threshold, `1` when
findings do, and `2` for invalid input or invocation. A finding has a stable rule
ID, severity, JSON path, concise explanation, and remediation hint.

## Scope for v0.1

### Discovery metadata

- Parse JSON while detecting duplicate member names.
- Check OIDC-required fields and their JSON types.
- Check issuer syntax (HTTPS, no query/fragment) and exact equality with an
  optional expected issuer.
- Check endpoint URI syntax and HTTPS requirements, including `jwks_uri`.
- Validate advertised arrays (strings, no duplicates, non-empty where required).
- Check algorithm advertisements against the key set when both documents are
  supplied; do not guess provider policy.

### JWKS/JWK

- Require a top-level object with a `keys` array of objects.
- Detect duplicate JSON members, duplicate `kid` values, and duplicate key
  material.
- Check required key members and base64url encoding for RSA, EC, and OKP keys.
- Check kty/curve/algorithm/use/key-ops compatibility.
- Flag private or symmetric material in a public provider JWKS.
- Check `x5c` values are non-empty base64 DER strings without exposing them.

### Optional JWT header correlation

- Read a compact JWT from a local file or a header-only value.
- Decode only the protected header; never verify signatures or claim trust.
- Match `kid` and `alg` to eligible JWKS keys and explain zero/multiple matches.
- Warn for `alg=none`, a missing `kid` with multiple signing keys, and unsupported
  critical headers.

### Output and integration

- Human text optimized for a terminal and pull-request logs.
- Stable JSON schema for scripts.
- SARIF 2.1.0 with locations mapped to input paths for code-scanning upload.
- `--severity`, `--strict`, and `--ignore` controls.
- Python API returning immutable report/finding objects.

## Non-goals

- No login flow, token minting, signature verification, or claim authorization.
- No network fetch by default. A future explicit fetch command is out of scope
  for v0.1 so offline behavior remains predictable.
- No provider-specific allowlist pretending to be a universal standard.
- No private-key generation, conversion, or secret storage.

## Success criteria

1. A new user can install with `pipx`/`uv`, run one command against the included
   fixture, and understand a concrete failure in under two minutes.
2. Every finding in the sample failure has a rule ID, path, severity, and fix.
3. The same report is available as text, JSON, and valid SARIF without network
   access.
4. Tests cover valid documents, malformed JSON, duplicate keys, key-type rules,
   issuer/endpoint checks, token correlation, exit codes, and output formats.
5. `uv run pytest`, `uv run ruff check .`, `uv run mypy src`, and `uv build` are
   clean on CI.

## Design principles

- Be conservative: distinguish an interoperability error from a provider-policy
  warning and from an informational observation.
- Prefer actionable diagnostics over a long standards checklist.
- Keep the runtime dependency-free; keep development dependencies isolated.
- Keep all input local and redact values in diagnostics by default.
