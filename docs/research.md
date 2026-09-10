# Opportunity research

## User problem

Teams integrating an OIDC provider routinely debug a chain of files and runtime
messages: the issuer in metadata must match the configured issuer, the discovery
document points at a JWKS, and a token's `kid`/`alg` must select exactly one public
key. A trailing slash can construct the wrong discovery URL; a private key or
duplicate `kid` can make a verifier reject every token; a stale snapshot can look
like a signature failure. These are deterministic checks, but application
libraries generally surface them only at runtime.

The evidence is repeated and concrete:

- The [OpenID Connect Discovery specification](https://openid.net/specs/openid-connect-discovery-1_0.html)
  requires exact issuer semantics, HTTPS endpoints, `jwks_uri`, response types,
  subject types, and `RS256` in the advertised ID-token algorithms.
- [RFC 7517](https://www.rfc-editor.org/info/rfc7517/) requires a JWKS `keys`
  array, unique object member names, and public JWK material. The OIDC Discovery
  text explicitly says an OP JWKS must not contain private or symmetric values.
- Microsoft's [signature-validation troubleshooting guide](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/troubleshooting-signature-validation-errors)
  describes selecting a signing key by the token `kid` and the effects of regular
  key rotation.
- Real integrations report the exact failure shapes this tool diagnoses:
  [Istio #45546](https://github.com/istio/istio/issues/45546) documents a trailing
  slash creating a double-slash discovery URL; [Vault #25024](https://github.com/hashicorp/vault/issues/25024)
  documents an issuer mismatch with split internal/public hosts; and
  [Backstage #31513](https://github.com/backstage/backstage/issues/31513) tracks
  a missing-`kid` cache/refresh failure.
- Duplicate IDs are not merely theoretical: the [OpenID working-group discussion](https://lists.openid.net/pipermail/openid-specs-ab/2019-November/007612.html)
  records different RP selection strategies, and [Broadcom's gateway guidance](https://knowledge.broadcom.com/external/article/138833)
  shows a duplicate `kid` causing key selection to fail.

## Existing alternatives and rejection notes

The search was intentionally aggressive. These projects and services are useful,
but none gives the same file-first, cross-document, CI-oriented workflow:

| Alternative | What it does well | Why it is not this project |
| --- | --- | --- |
| [Wythwool/oidc-lint](https://github.com/Wythwool/oidc-lint) | Early scanner for a live issuer, with broad heuristics. | Fetch-first MVP, no stable offline snapshot workflow, and currently no published release/usage signal. |
| [oauth2.dev endpoint validator](https://oauth2.dev/tools/jwks-endpoint-validator) | Convenient browser validation of a URL or pasted JWKS. | Hosted workflow; unsuitable for private fixtures and reproducible pull requests. |
| [Toolsmith JWKS validator](https://tools.netakecompany.com/tools/jwks-validator) | Local-in-browser duplicate/incomplete-key checks. | Browser-only and not a repository/CI CLI; no discovery-to-token correlation. |
| [frodejac/jwtool](https://github.com/frodejac/jwtool) | Key conversion and JWT/JWK utility commands. | Conversion/inspection utility, not a standards-oriented metadata and key-set audit. |
| Runtime JOSE libraries | Correct signature verification in an application. | They are not pre-deployment diagnostics and intentionally stop at runtime errors. |

The chosen gap is therefore not “another JWT decoder”. It is a small, dependency-
free audit that turns the three inputs developers already have into one local,
reviewable report. The v0.1 scope avoids network fetching, credentialed flows, and
claims verification so that a clean run is reproducible and safe to put in CI.

## Candidate ideas rejected

- Notebook execution-order linting: [nborder](https://github.com/moonrunnerkc/nborder)
  already targets the direct failure mode, alongside nbval and Jupyter tooling.
- Cross-platform Git path audit: [git-path-audit](https://github.com/bunta-expert/git-path-audit)
  is an exact existing project with index/tree/stdin and SARIF modes.
- GitHub Actions YAML/matrix validation: actionlint and the official syntax checks
  already cover the mature path, and the workspace also contains an earlier
  Actions-focused project.
- Compose/Helm/config drift: the workspace already contains `compose-envcheck`,
  `helm-values-audit`, and `compatlint`; another contract checker would overlap.
- Cargo unused features, JSON duplicate-key linting, YAML dialect checks, and
  GitLab/Azure pipeline validation all have active, established tools with the
  same core job.

## Product hypothesis

If a developer can run one offline command against committed Discovery/JWKS/token
fixtures and get a precise rule, path, severity, and remediation hint, then many
“invalid issuer”, “no valid key”, and rotation failures can be caught in review
without credentials or a live identity provider. The implementation and tests in
this repository validate that hypothesis for the documented v0.1 rule set; they do
not claim conformance or trust in an issuer.
