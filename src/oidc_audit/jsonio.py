"""Strict, local JSON loading helpers.

The standard library's JSON decoder otherwise keeps only the last value for a
duplicate object member.  That is a dangerous default for configuration and
JWK documents, so oidc-audit rejects duplicates before applying any rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonInputError(ValueError):
    """A user-facing JSON input error."""

    def __init__(self, message: str, *, kind: str = "invalid") -> None:
        super().__init__(message)
        self.kind = kind


class DuplicateMemberError(JsonInputError):
    """Raised when an object repeats a member name."""

    def __init__(self, key: str) -> None:
        super().__init__(f"duplicate JSON member {key!r}", kind="duplicate")
        self.key = key


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMemberError(key)
        result[key] = value
    return result


def parse_json(text: str, *, source: str = "input") -> Any:
    """Parse JSON with duplicate-member rejection and useful errors."""

    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_members)
    except DuplicateMemberError:
        raise
    except json.JSONDecodeError as exc:
        location = f"line {exc.lineno}, column {exc.colno}"
        raise JsonInputError(f"{source}: invalid JSON at {location}: {exc.msg}") from exc
    except (TypeError, ValueError) as exc:
        raise JsonInputError(f"{source}: invalid JSON: {exc}") from exc


def load_json(path: str | Path) -> Any:
    """Read and parse one UTF-8 JSON file without any network access."""

    path_obj = Path(path)
    try:
        text = path_obj.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise JsonInputError(f"{path_obj}: file not found", kind="missing") from exc
    except IsADirectoryError as exc:
        raise JsonInputError(f"{path_obj}: expected a file", kind="missing") from exc
    except UnicodeDecodeError as exc:
        raise JsonInputError(f"{path_obj}: not valid UTF-8", kind="encoding") from exc
    except OSError as exc:
        raise JsonInputError(f"{path_obj}: cannot read file: {exc}", kind="io") from exc
    return parse_json(text, source=str(path_obj))


def path_key(path: str, key: str) -> str:
    """Append a JSON object member to a human-readable path."""

    if key.replace("_", "").isalnum():
        return f"{path}.{key}"
    return f"{path}[{key!r}]"


def path_index(path: str, index: int) -> str:
    """Append an array index to a human-readable path."""

    return f"{path}[{index}]"
