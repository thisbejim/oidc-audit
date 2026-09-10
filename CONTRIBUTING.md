# Contributing

Thanks for helping make OIDC diagnostics clearer and safer.

## Development loop

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
```

Keep runtime dependencies in the standard library where practical. Add a focused
test and a rule-catalogue entry for every new diagnostic. Findings are part of the
public API: do not silently change an existing rule's meaning or severity.

Pull requests should explain the standards or observed failure that motivates a
rule and should include a safe, non-secret fixture. Never commit real provider
tokens, private keys, or client credentials.
