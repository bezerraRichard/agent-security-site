"""Load ``KEY=value`` settings from a local ``.env`` file into the environment (no third-party dependency)."""

from __future__ import annotations

import os
import re
from collections.abc import MutableMapping
from pathlib import Path

_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def parse_env_file(text: str) -> dict[str, str]:
    """Parse ``.env`` content: comments, blank lines, ``export`` prefixes and quoted values are supported."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not _KEY.fullmatch(key):
            continue  # Never echo the line: it may hold a secret.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def load_env_file(path: Path | str = ".env", env: MutableMapping[str, str] | None = None) -> list[str]:
    """Copy the file's settings into ``env`` (``os.environ`` by default) without overriding variables that are
    already set, and skip empty values. Returns the names that were loaded; a missing file loads nothing."""
    target = os.environ if env is None else env
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError:
        return []
    loaded = []
    for key, value in parse_env_file(text).items():
        if value and not target.get(key):
            target[key] = value
            loaded.append(key)
    return loaded
