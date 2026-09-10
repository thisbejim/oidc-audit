# Security policy

`oidc-audit` is a local diagnostic. It does not fetch URLs, send telemetry, or
verify signatures. It should not be treated as an authentication boundary.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting flow for this repository when
available. If it is unavailable, open a minimal issue without including secrets
and ask for a private contact channel. Do not paste private keys, live JWTs, or
credentials into a public issue.

Security reports are especially valuable for parser crashes, accidental input
leakage, unsafe file handling, or a rule that could encourage accepting an
unverified token.
