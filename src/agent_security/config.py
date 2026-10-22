"""Typed, validated scan configuration."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from agent_security.onetrust import OneTrustConfig

DEFAULT_MAX_PAGES = 500
HARD_MAX_PAGES = 5000
MIN_DELAY_SECONDS = 0.2


@dataclass(frozen=True)
class ScanConfig:
    start_url: str
    allowed_hosts: frozenset[str]
    seeds: tuple[tuple[str, str], ...]  # (url, source)
    max_pages: int = DEFAULT_MAX_PAGES
    max_depth: int = 10
    delay_seconds: float = 0.5
    timeout: float = 15.0
    retries: int = 2
    time_limit_minutes: float = 120.0
    respect_robots: bool = True
    sitemap: bool = False
    proxy: str | None = None
    no_proxy: bool = False
    fallback_direct: bool = False
    ca_bundle: str | None = None
    onetrust: OneTrustConfig | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.max_pages <= HARD_MAX_PAGES:
            raise ValueError(f"max_pages must be between 1 and {HARD_MAX_PAGES}")
        if not 0 <= self.max_depth <= 50:
            raise ValueError("max_depth must be between 0 and 50")
        if self.delay_seconds < MIN_DELAY_SECONDS:
            raise ValueError(f"delay_seconds must be at least {MIN_DELAY_SECONDS}")
        if not 0 <= self.retries <= 5:
            raise ValueError("retries must be between 0 and 5")
        if self.timeout <= 0 or self.time_limit_minutes <= 0:
            raise ValueError("timeout and time_limit_minutes must be positive")
        if self.start_url and urllib.parse.urlsplit(self.start_url).hostname not in self.allowed_hosts:
            raise ValueError("the start URL must be on an authorized host")

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.start_url).hostname or ""
