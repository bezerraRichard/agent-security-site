"""Turn the console's scan form into validated scan configurations."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from agent_security.config import ScanConfig
from agent_security.network import parse_proxy
from agent_security.onetrust import config_from_env
from agent_security.urls import normalize_target, validate_host

# name -> (max pages, max depth, delay seconds, time limit minutes)
PROFILES: dict[str, tuple[int, int, float, float]] = {
    "Rápido": (1, 0, 1.0, 5.0),
    "Conservador": (100, 3, 1.0, 20.0),
    "Padrão": (500, 10, 0.5, 120.0),
}


@dataclass(frozen=True)
class ScanOptions:
    max_pages: int = 100
    max_depth: int = 3
    delay_seconds: float = 1.0
    time_limit_minutes: float = 20.0
    respect_robots: bool = True
    sitemap: bool = False
    route: str = "auto"  # auto | proxy | direct
    proxy: str = ""
    fallback_direct: bool = False
    ca_bundle: str = ""
    classify_cookies: bool = True
    onetrust_language: str = ""
    onetrust_domain_ids: tuple[str, ...] = ()


def split_hosts(value: str | None) -> list[str]:
    return [part for part in re.split(r"[\s,;]+", value or "") if part]


def parse_domain_lines(text: str | None) -> list[tuple[str, str]]:
    """``"www.a.com shop.a.com, cdn.a.com"`` per line -> ``[("www.a.com", "shop.a.com,cdn.a.com")]``."""
    rows = []
    for line in (text or "").splitlines():
        tokens = split_hosts(line.split("#", 1)[0])
        if tokens:
            rows.append((tokens[0], ",".join(tokens[1:])))
    return rows


def build_configs(
    domains: Sequence[tuple[str, str | None]], options: ScanOptions, env: Mapping[str, str]
) -> list[ScanConfig]:
    """One config per (domain, extra hosts) row; blank rows are ignored. Raises ValueError with a readable message."""
    rows = [(domain.strip(), extra) for domain, extra in domains if domain and domain.strip()]
    if not rows:
        raise ValueError("Indique pelo menos um domínio.")
    if options.route == "proxy" and not options.proxy.strip():
        raise ValueError("Indique o URL do proxy.")
    if options.ca_bundle.strip() and not Path(options.ca_bundle.strip()).is_file():
        raise ValueError("O ficheiro de CA indicado não existe.")
    proxy = parse_proxy(options.proxy.strip()) if options.route == "proxy" else None
    onetrust = (
        config_from_env(env, None, options.onetrust_language or None, options.onetrust_domain_ids)
        if options.classify_cookies
        else None
    )
    configs, seen = [], set()
    for domain, extra in rows:
        try:
            host, start_url = normalize_target(domain)
            extra_hosts = {validate_host(value) for value in split_hosts(extra)}
        except ValueError as error:
            raise ValueError(f"{domain}: {error}") from None
        if host in seen:
            raise ValueError(f"O domínio {host} aparece mais de uma vez.")
        seen.add(host)
        configs.append(
            ScanConfig(
                start_url=start_url,
                allowed_hosts=frozenset({host, *extra_hosts}),
                seeds=((start_url, "seed"),),
                max_pages=options.max_pages,
                max_depth=options.max_depth,
                delay_seconds=options.delay_seconds,
                time_limit_minutes=options.time_limit_minutes,
                respect_robots=options.respect_robots,
                sitemap=options.sitemap,
                proxy=proxy,
                no_proxy=options.route == "direct",
                fallback_direct=options.route == "proxy" and options.fallback_direct,
                ca_bundle=options.ca_bundle.strip() or None,
                onetrust=onetrust,
            )
        )
    return configs
