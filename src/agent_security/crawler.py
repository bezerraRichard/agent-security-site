"""Breadth-first, same-host crawler that only follows links found in static HTML."""

from __future__ import annotations

import posixpath
import re
import time
import urllib.parse
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from html.parser import HTMLParser

from agent_security.network import HTML_TYPES, Fetcher, FetchResult
from agent_security.urls import hostname_of, normalize_url

MAX_LINKS_PER_PAGE = 2000
MAX_QUERY_VARIANTS = 3
MAX_CONSECUTIVE_FAILURES = 15
DEPTH_SKIP = "unvisited links beyond the depth limit"
SKIP_EXTENSIONS = frozenset(
    {
        ".pdf",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".css",
        ".js",
        ".json",
        ".xml",
        ".zip",
        ".gz",
        ".tar",
        ".rar",
        ".7z",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".csv",
        ".txt",
    }
)
_UNSAFE_PATH = re.compile(r"log-?out|log-?off|sign-?out|delete|remove|unsubscribe", re.IGNORECASE)


@dataclass
class CrawlOutcome:
    pages: list[FetchResult]
    skipped: Counter[str]
    stop_reason: str | None
    remaining: int


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.base: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and values.get("href") and self.base is None:
            self.base = values["href"]
        elif tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"] or "")
        elif tag in {"frame", "iframe"} and values.get("src"):
            self.links.append(values["src"] or "")


def extract_links(body: str, base_url: str) -> list[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # Malformed markup must not abort the crawl.
        pass
    base = urllib.parse.urljoin(base_url, parser.base) if parser.base else base_url
    links = []
    for href in parser.links[:MAX_LINKS_PER_PAGE]:
        url = normalize_url(base, href)
        if url:
            links.append(url)
    return links


def crawl(
    seeds: Iterable[tuple[str, str]],
    fetch: Fetcher,
    allowed_hosts: frozenset[str] | set[str],
    robots_allowed: Callable[[str], bool],
    *,
    max_pages: int,
    max_depth: int,
    delay: float,
    deadline: float,
    progress: Callable[[int, FetchResult], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> CrawlOutcome:
    """Fetch pages starting from ``seeds`` (url, source) until the queue is empty or a limit is hit."""
    queue: deque[tuple[str, int, str]] = deque()
    seen: set[str] = set()
    final_seen: set[str] = set()
    query_counts: Counter[tuple[str | None, str]] = Counter()
    skipped: Counter[str] = Counter()
    pages: list[FetchResult] = []
    stop_reason: str | None = None
    failures_in_row = 0

    def in_scope(url: str) -> bool:
        return hostname_of(url) in allowed_hosts

    def enqueue(url: str, depth: int, source: str) -> None:
        parts = urllib.parse.urlsplit(url)
        if not in_scope(url):
            skipped["outside the authorized hosts"] += 1
            return
        if url in seen:
            return
        if posixpath.splitext(parts.path)[1].lower() in SKIP_EXTENSIONS:
            skipped["non-page file type"] += 1
            return
        if _UNSAFE_PATH.search(parts.path):
            skipped["path suggests a state-changing action"] += 1
            return
        if parts.query:
            key = (parts.hostname, parts.path)
            if query_counts[key] >= MAX_QUERY_VARIANTS:
                skipped["query-variant limit per path"] += 1
                return
            query_counts[key] += 1
        seen.add(url)
        queue.append((url, depth, source))

    for seed_url, seed_source in seeds:
        enqueue(seed_url, 0, seed_source)

    try:
        while queue:
            if len(pages) >= max_pages:
                stop_reason = f"page limit ({max_pages}) reached"
                break
            if clock() > deadline:
                stop_reason = "time limit reached"
                break
            if failures_in_row >= MAX_CONSECUTIVE_FAILURES:
                stop_reason = f"{MAX_CONSECUTIVE_FAILURES} consecutive request failures"
                break
            url, depth, source = queue.popleft()
            if not robots_allowed(url):
                skipped["blocked by robots.txt"] += 1
                continue
            result = fetch(url, True)
            result.update(depth=depth, source=source)
            if result.get("out_of_scope"):
                skipped["redirect outside the authorized hosts"] += 1
                continue
            failures_in_row = failures_in_row + 1 if result["error"] else 0
            if not result["error"]:
                final = (normalize_url(url, result["final_url"]) if result["final_url"] else None) or url
                if final in final_seen:
                    skipped["duplicate after redirect"] += 1
                    continue
                final_seen.add(final)
                seen.add(final)
            pages.append(result)
            body, result["body"] = result.get("body"), None
            if body and result["content_type"] in HTML_TYPES:
                links = extract_links(body, result["final_url"] or url)
                if depth < max_depth:
                    for link in links:
                        enqueue(link, depth + 1, "crawl")
                else:
                    skipped[DEPTH_SKIP] += len({link for link in links if in_scope(link) and link not in seen})
            if progress:
                progress(len(pages), result)
            if queue:
                sleep(delay)
    except KeyboardInterrupt:
        stop_reason = "interrupted by user"

    return CrawlOutcome(pages, skipped, stop_reason, len(queue))
