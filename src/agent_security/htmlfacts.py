"""Facts read from a page's static HTML: meta CSP, mixed content, Subresource Integrity and known technologies."""

from __future__ import annotations

import urllib.parse
from html.parser import HTMLParser
from typing import TypedDict

MAX_URLS_PER_FACT = 50
# Mixed content that can run code or restyle the page ("active") versus content that is only displayed ("passive").
_ACTIVE_SOURCES = {"script": "src", "iframe": "src", "frame": "src", "embed": "src", "object": "data"}
_PASSIVE_SOURCES = {"img": "src", "audio": "src", "video": "src", "source": "src", "track": "src"}
_STYLESHEET_RELS = {"stylesheet", "preload", "modulepreload"}
# technology -> URL fragments of the resources it loads
TECHNOLOGY_SIGNATURES = {
    "Adobe Experience Manager": ("/etc.clientlibs/", "/content/dam/"),
    "Adobe Experience Platform Tags": ("assets.adobedtm.com",),
    "OneTrust": ("cdn.cookielaw.org", "otsdkstub", "onetrust.com"),
    "Google Tag Manager": ("googletagmanager.com/gtm.js", "googletagmanager.com/gtag/js"),
}


class PageFacts(TypedDict):
    meta_csp: str | None
    mixed_active: list[str]
    mixed_passive: list[str]
    sri_missing: list[str]
    technologies: list[str]


class _FactsParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page_host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
        self.meta_csp: str | None = None
        self.active: list[str] = []
        self.passive: list[str] = []
        self.sri_missing: list[str] = []
        self.technologies: set[str] = set()

    def _resolve(self, value: str | None) -> urllib.parse.SplitResult | None:
        if not value or not value.strip():
            return None
        try:
            parts = urllib.parse.urlsplit(urllib.parse.urljoin(self.base_url, value.strip()))
        except ValueError:
            return None
        return parts if parts.scheme in {"http", "https"} and parts.hostname else None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs}
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "content-security-policy":
            if self.meta_csp is None and values.get("content"):
                self.meta_csp = values["content"]
            return
        rel = set((values.get("rel") or "").lower().split())
        if tag == "link" and rel & _STYLESHEET_RELS:
            self._subresource(values.get("href"), active=True, sri_candidate="stylesheet" in rel, values=values)
        elif tag in _ACTIVE_SOURCES:
            self._subresource(
                values.get(_ACTIVE_SOURCES[tag]), active=True, sri_candidate=tag == "script", values=values
            )
        elif tag in _PASSIVE_SOURCES:
            self._subresource(values.get(_PASSIVE_SOURCES[tag]), active=False, sri_candidate=False, values=values)

    def _subresource(self, value: str | None, *, active: bool, sri_candidate: bool, values: dict) -> None:
        parts = self._resolve(value)
        if parts is None:
            return
        url = urllib.parse.urlunsplit(parts)
        lowered = url.lower()
        self.technologies.update(
            name for name, fragments in TECHNOLOGY_SIGNATURES.items() if any(f in lowered for f in fragments)
        )
        if parts.scheme == "http":
            (self.active if active else self.passive).append(url)
        if sri_candidate and (parts.hostname or "").lower() != self.page_host and not values.get("integrity"):
            self.sri_missing.append(url)


def _unique(urls: list[str]) -> list[str]:
    return sorted(set(urls))[:MAX_URLS_PER_FACT]


def page_facts(body: str, base_url: str) -> PageFacts:
    parser = _FactsParser(base_url)
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # Malformed markup must not abort the crawl.
        pass
    return {
        "meta_csp": parser.meta_csp,
        "mixed_active": _unique(parser.active),
        "mixed_passive": _unique(parser.passive),
        "sri_missing": _unique(parser.sri_missing),
        "technologies": sorted(parser.technologies),
    }
