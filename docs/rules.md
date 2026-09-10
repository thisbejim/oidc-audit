# Rule catalogue

Severity is deliberately conservative. Errors indicate malformed input or a
document that violates a protocol requirement checked by oidc-audit. Warnings
highlight interoperability or operational risk that can be valid in a provider
extension. Informational findings are reserved for future non-failing notes.

Unreadable files and invalid JSON use `INPUT-001` through `INPUT-003` and return
exit code `2`; they are not protocol findings.

## Discovery metadata

| Rule | Level | Meaning |
| --- | --- | --- |
| OIDC-001..006 | error | Required OIDC metadata member is absent. |
| OIDC-007 | error | `issuer` is not an exact match for `--issuer`. |
| OIDC-008 | error/warning | A code flow has no `token_endpoint`, or flow data is unavailable. |
| OIDC-010 | error | A URL is not an absolute HTTPS URL, or an issuer has a query/fragment. |
| OIDC-011 | error | A multi-valued metadata member is not an array. |
| OIDC-012 | error | An advertised array contains a non-string or empty item. |
| OIDC-013 | warning | An advertised array repeats a value. |
| OIDC-014 | error | An advertised capability array is empty. |
| OIDC-015 | warning | A subject type is outside the standard public/pairwise values. |
| OIDC-016 | error | ID-token algorithms omit the OIDC baseline `RS256`. |
| OIDC-017 | error | The only advertised ID-token algorithm is `none`. |
| OIDC-018 | warning | A supplied scope list omits `openid`. |
| OIDC-019 | error | `private_key_jwt` has no usable signing algorithm. |
| OIDC-020 | error | Token-endpoint signing algorithms include forbidden `none`. |
| OIDC-021 | error | Supplied metadata and JWKS have no compatible signing key. |

## JWK/JWKS

| Rule | Level | Meaning |
| --- | --- | --- |
| JWK-001 | error | Top-level `keys` array is missing or has the wrong type. |
| JWK-002 | error | The JWKS is empty. |
| JWK-003 | error | An item in `keys` is not an object. |
| JWK-004 | error | Key bytes or thumbprints are not unpadded base64url. |
| JWK-005 | error | `kty` is missing or not a string. |
| JWK-006 | warning | `kty` is an extension not understood by the built-in checks. |
| JWK-007 | warning | Multiple keys share a `kid`. |
| JWK-008 | error/warning | `kid` is not a non-empty string. |
| JWK-009 | error | `use` is not `sig` or `enc`. |
| JWK-010 | error | Private or symmetric key material is present. |
| JWK-011..014 | error/warning | `key_ops` shape, values, duplicates, or purpose conflict. |
| JWK-015 | error | `alg` is not a string. |
| JWK-016 | error | A known `alg` family is incompatible with `kty`. |
| JWK-017..022 | error | Required RSA, EC, OKP, or oct members are missing/invalid. |
| JWK-023..024 | error | `x5c` is not a non-empty base64 certificate array. |
| JWK-025 | warning | Identical key material appears more than once. |
| JWK-026 | warning | Multiple signing candidates have no usable key ID. |

## JWT protected header

| Rule | Level | Meaning |
| --- | --- | --- |
| TOKEN-001..004 | error | The local token is not a three-part JWT with a JSON header. |
| TOKEN-005 | error | `alg` is absent or not a non-empty string. |
| TOKEN-006 | error | The token declares `alg=none`. |
| TOKEN-007 | error | `kid` is not a string. |
| TOKEN-008 | error | `crit` is not an array of strings. |
| TOKEN-009 | warning | Critical headers are not evaluated by this diagnostic tool. |
| TOKEN-010 | error | No eligible key matches the token `kid`. |
| TOKEN-011 | error | The matching key's type/algorithm is incompatible. |
| TOKEN-012 | error | A `kid` selects more than one eligible key. |
| TOKEN-013 | warning | A token has no `kid` while multiple signing keys are eligible. |

Rule IDs are stable API. New checks should add a new ID rather than changing the
meaning of an existing one.
