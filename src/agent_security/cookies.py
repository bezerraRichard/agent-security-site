"""Set-Cookie parsing helpers. Cookie values are never retained."""

from __future__ import annotations

import urllib.parse
from collections import Counter
from typing import Any


def parse_set_cookie(raw: str) -> tuple[str, list[str]]:
    """Return the cookie name and its attribute segments; the value is dropped."""
    segments = [part.strip() for part in raw.split(";")]
    name = segments[0].split("=", 1)[0].strip()
    return name, [part for part in segments[1:] if part]


def stable_attributes(attributes: list[str]) -> list[str]:
    """Mask ``Expires`` dates, which change on every response, so equal cookies compare equal across pages."""
    stable = []
    for attribute in attributes:
        key = attribute.split("=", 1)[0].strip()
        stable.append(f"{key}=<date>" if key.lower() == "expires" else attribute)
    return stable


def observe_cookies(pages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Summarise the cookies set across pages: where they appear and which attributes they carry."""
    seen: dict[str, dict[str, Any]] = {}
    for page in pages:
        headers = page.get("headers")
        if headers is None:
            continue
        url = page["final_url"] or page["requested_url"]
        host = urllib.parse.urlsplit(url).hostname or ""
        for raw in headers.get_all("Set-Cookie") or []:
            name, attributes = parse_set_cookie(raw)
            if not name:
                continue
            entry = seen.setdefault(name, {"hosts": set(), "pages": set(), "variants": Counter()})
            entry["hosts"].add(host)
            entry["pages"].add(url)
            entry["variants"]["; ".join(stable_attributes(attributes))] += 1
    return [
        {
            "name": name,
            "hosts": sorted(entry["hosts"]),
            "pages": len(entry["pages"]),
            "attributes": entry["variants"].most_common(1)[0][0],
            "variants": len(entry["variants"]),
        }
        for name, entry in sorted(seen.items())
    ]
