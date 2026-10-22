"""URL and hostname validation/normalization used to keep the crawl inside its authorized scope."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from pathlib import Path

_HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_NON_LINK_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:")


def validate_host(value: str) -> str:
    host = value.strip().lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError(f"IP addresses are not accepted: {value}")
    if not _HOST_PATTERN.fullmatch(host):
        raise ValueError(f"Invalid hostname: {value}")
    return host


def normalize_target(value: str) -> tuple[str, str]:
    """Validate a start URL or hostname and return ``(host, https_url)``."""
    target = value if "://" in value else f"https://{value}"
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target must be an HTTPS URL with a hostname and without embedded credentials")
    if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost targets are not supported")
    if parsed.port not in (None, 443):
        raise ValueError("Only the default HTTPS port is supported")
    host = validate_host(parsed.hostname)
    return host, urllib.parse.urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))


def normalize_url(base: str, href: str) -> str | None:
    """Resolve ``href`` against ``base`` into a canonical https URL, or None if it is not crawlable."""
    href = href.strip()
    if not href or href.startswith(_NON_LINK_PREFIXES):
        return None
    try:
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(base, href))
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return None
    if port not in (None, 80, 443):
        return None
    return urllib.parse.urlunsplit(("https", parts.hostname.lower(), parts.path or "/", parts.query, ""))


def hostname_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def load_url_file(path: str | Path, allowed_hosts: frozenset[str] | set[str]) -> list[str]:
    """Read approved URLs (one per line, ``#`` comments allowed); every URL must be on an allowed host."""
    urls = []
    with Path(path).open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                host, url = normalize_target(value)
            except ValueError as error:
                raise ValueError(f"Invalid URL on line {number}: {error}") from error
            if host not in allowed_hosts:
                raise ValueError(f"URL on line {number} is outside the authorized hosts: {host}")
            urls.append(url)
    return urls
