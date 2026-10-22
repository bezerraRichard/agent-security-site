"""Discovery helpers that read robots.txt and sitemaps."""

from __future__ import annotations

import html
import re
import urllib.parse
import urllib.robotparser
from collections import deque
from collections.abc import Iterable

from agent_security.network import Fetcher
from agent_security.urls import hostname_of, normalize_url

ROBOTS_TOKEN = "HTTP-Security-Report"
SITEMAP_MAX_BYTES = 10_000_000
MAX_SITEMAP_FILES = 20
MAX_CRAWL_DELAY_SECONDS = 10.0
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


class Robots:
    """robots.txt rules per host. A missing or unreadable file is treated as allow-all."""

    def __init__(self, fetch: Fetcher, hosts: Iterable[str], enabled: bool) -> None:
        self.parsers: dict[str, urllib.robotparser.RobotFileParser] = {}
        if not enabled:
            return
        for host in sorted(hosts):
            result = fetch(f"https://{host}/robots.txt", True)
            parser = urllib.robotparser.RobotFileParser()
            parser.parse((result.get("body") or "").splitlines() if result.get("status") == 200 else [])
            parser.modified()
            self.parsers[host] = parser

    def allowed(self, url: str) -> bool:
        parser = self.parsers.get(urllib.parse.urlsplit(url).hostname or "")
        return True if parser is None else parser.can_fetch(ROBOTS_TOKEN, url)

    def crawl_delay(self, host: str) -> float:
        parser = self.parsers.get(host)
        delay = parser.crawl_delay(ROBOTS_TOKEN) if parser else None
        return min(float(delay), MAX_CRAWL_DELAY_SECONDS) if delay else 0.0

    def sitemaps(self) -> list[str]:
        found: list[str] = []
        for parser in self.parsers.values():
            found.extend(parser.site_maps() or [])
        return found


def sitemap_urls(fetch: Fetcher, roots: Iterable[str], allowed_hosts: frozenset[str], limit: int) -> list[str]:
    """Collect up to ``limit`` in-scope page URLs from sitemaps, following sitemap indexes."""
    urls: list[str] = []
    pending = deque(roots)
    fetched: set[str] = set()
    while pending and len(fetched) < MAX_SITEMAP_FILES and len(urls) < limit:
        sitemap = pending.popleft()
        if sitemap in fetched:
            continue
        fetched.add(sitemap)
        result = fetch(sitemap, True, SITEMAP_MAX_BYTES)
        if result["error"] or result["status"] != 200 or not result.get("body"):
            continue
        for loc in _LOC.findall(result["body"]):
            url = normalize_url(sitemap, html.unescape(loc))
            if not url or hostname_of(url) not in allowed_hosts:
                continue
            if url.lower().endswith(".xml"):
                pending.append(url)
            elif len(urls) < limit:
                urls.append(url)
    return urls
