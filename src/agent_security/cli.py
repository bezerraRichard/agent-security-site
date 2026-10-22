"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from agent_security.batch import run_batch
from agent_security.config import DEFAULT_MAX_PAGES, HARD_MAX_PAGES, MIN_DELAY_SECONDS, ScanConfig
from agent_security.network import FetchResult, parse_proxy
from agent_security.onetrust import config_from_env
from agent_security.report import write_reports
from agent_security.scan import run_scan
from agent_security.urls import hostname_of, load_url_file, normalize_target, validate_host

ONETRUST_ENV = ("ONETRUST_HOSTNAME", "ONETRUST_CLIENT_ID", "ONETRUST_CLIENT_SECRET")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-security", description="Passive same-host security crawler for authorized sites."
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="target",
        help="Start URL or hostname, e.g. https://www.example.com/ (several domains are scanned one after another)",
    )
    scope = parser.add_argument_group("scope")
    scope.add_argument("--allow-host", action="append", default=[], help="Additional authorized hostname (repeatable)")
    scope.add_argument("--urls-file", help="Extra approved HTTPS URLs, one per line")
    scope.add_argument("--sitemap", action="store_true", help="Also seed the crawl from sitemap.xml")
    scope.add_argument("--ignore-robots", action="store_true", help="Do not honor robots.txt")
    limits = parser.add_argument_group("limits")
    limits.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help=f"1-{HARD_MAX_PAGES}")
    limits.add_argument("--max-depth", type=int, default=10)
    limits.add_argument("--delay-seconds", type=float, default=0.5, help=f"minimum {MIN_DELAY_SECONDS}")
    limits.add_argument("--timeout", type=float, default=15.0)
    limits.add_argument("--retries", type=int, default=2)
    limits.add_argument("--time-limit-minutes", type=float, default=120.0)
    network = parser.add_argument_group("network")
    route = network.add_mutually_exclusive_group()
    route.add_argument("--proxy", help="Proxy URL, e.g. http://proxy.example:8080")
    route.add_argument("--no-proxy", action="store_true", help="Force a direct connection")
    network.add_argument("--fallback-direct", action="store_true", help="With --proxy, fall back to direct if it fails")
    network.add_argument("--ca-bundle", help="PEM file with extra CA certificates (e.g. a corporate TLS-inspection CA)")
    cookies = parser.add_argument_group("cookie classification (credentials come from ONETRUST_* variables)")
    cookies.add_argument("--onetrust-hostname", help="OneTrust host, e.g. app-eu.onetrust.com (or ONETRUST_HOSTNAME)")
    cookies.add_argument("--onetrust-language", help="Language code for the lookup (default: en)")
    cookies.add_argument(
        "--onetrust-domain-id", action="append", default=[], help="Restrict to a domain id (repeatable)"
    )
    cookies.add_argument("--no-cookie-classification", action="store_true", help="Never call OneTrust")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--quiet", action="store_true")
    return parser


def parent_domain(host: str) -> str:
    """``www.example.com`` -> ``example.com``; two-label hosts are their own parent."""
    return host.split(".", 1)[1] if host.count(".") >= 2 else host


def belongs_to(extra_host: str, target_host: str) -> bool:
    parent = parent_domain(target_host)
    return extra_host == parent or extra_host.endswith("." + parent)


def build_config(
    args: argparse.Namespace,
    env: Mapping[str, str],
    target: str | None = None,
    extra_hosts: Sequence[str] | None = None,
    approved_urls: Sequence[str] | None = None,
) -> ScanConfig:
    """Config for one target; by default the first target with every ``--allow-host`` and ``--urls-file`` URL."""
    host, start_url = normalize_target(target or args.targets[0])
    hosts = args.allow_host if extra_hosts is None else extra_hosts
    allowed_hosts = frozenset({host, *(validate_host(value) for value in hosts)})
    seeds = [(start_url, "seed")]
    if approved_urls is not None:
        seeds += [(url, "approved-list") for url in approved_urls]
    elif args.urls_file:
        seeds += [(url, "approved-list") for url in load_url_file(args.urls_file, allowed_hosts)]
    if args.ca_bundle and not Path(args.ca_bundle).is_file():
        raise ValueError("--ca-bundle file not found")
    onetrust = None
    if not args.no_cookie_classification:
        onetrust = config_from_env(env, args.onetrust_hostname, args.onetrust_language, args.onetrust_domain_id)
    return ScanConfig(
        start_url=start_url,
        allowed_hosts=allowed_hosts,
        seeds=tuple(seeds),
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        delay_seconds=args.delay_seconds,
        timeout=args.timeout,
        retries=args.retries,
        time_limit_minutes=args.time_limit_minutes,
        respect_robots=not args.ignore_robots,
        sitemap=args.sitemap,
        proxy=parse_proxy(args.proxy) if args.proxy else None,
        no_proxy=args.no_proxy,
        fallback_direct=args.fallback_direct,
        ca_bundle=args.ca_bundle,
        onetrust=onetrust,
    )


def build_configs(args: argparse.Namespace, env: Mapping[str, str]) -> list[ScanConfig]:
    """One config per target. With several targets, each ``--allow-host`` joins the targets of its parent domain
    and each ``--urls-file`` URL joins the target that authorizes its host."""
    if len(args.targets) == 1:
        return [build_config(args, env)]
    target_hosts = [normalize_target(target)[0] for target in args.targets]
    if len(set(target_hosts)) != len(target_hosts):
        raise ValueError("each target must be a different host")
    extras = [validate_host(value) for value in args.allow_host]
    for extra in extras:
        if not any(belongs_to(extra, host) for host in target_hosts):
            raise ValueError(f"--allow-host {extra} does not belong to any target domain")
    per_target = [[extra for extra in extras if belongs_to(extra, host)] for host in target_hosts]
    urls: list[list[str]] = [[] for _ in target_hosts]
    if args.urls_file:
        hosts_by_target = [{host, *hosts} for host, hosts in zip(target_hosts, per_target, strict=True)]
        for url in load_url_file(args.urls_file, set().union(*hosts_by_target)):
            index = next(i for i, hosts in enumerate(hosts_by_target) if hostname_of(url) in hosts)
            urls[index].append(url)
    return [
        build_config(args, env, target, extra_hosts, approved)
        for target, extra_hosts, approved in zip(args.targets, per_target, urls, strict=True)
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        configs = build_configs(args, os.environ)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    config = configs[0]
    if (
        config.onetrust is None
        and not args.quiet
        and not args.no_cookie_classification
        and any(os.environ.get(name) for name in ONETRUST_ENV)
    ):
        print("OneTrust settings are incomplete; cookies will not be classified.", file=sys.stderr)

    def progress(count: int, result: FetchResult) -> None:
        if not args.quiet and (count % 10 == 0 or result["error"]):
            label = result["status"] or "ERR"
            print(f"[{count}/{config.max_pages}] {label} {result['requested_url']}", file=sys.stderr)

    if len(configs) > 1:
        return run_many(configs, Path(args.output_dir), args.quiet)
    report = run_scan(config, progress)
    html_path, json_path = write_reports(report, Path(args.output_dir))
    print(
        json.dumps(
            {
                "status": report["status"],
                "route": report["route"]["selected"],
                "pages_assessed": report["scope"]["pages_assessed"],
                "pages_failed": report["scope"]["pages_failed"],
                "distinct_findings": len(report["groups"]),
                "html": str(html_path),
                "json": str(json_path),
            },
            indent=2,
        )
    )
    return 0 if report["status"].startswith("complete") else 2


def run_many(configs: list[ScanConfig], output_dir: Path, quiet: bool) -> int:
    def on_start(index: int, config: ScanConfig) -> None:
        if not quiet:
            print(f"== [{index + 1}/{len(configs)}] {config.start_url}", file=sys.stderr)

    def progress(index: int, count: int, result: FetchResult) -> None:
        if not quiet and (count % 10 == 0 or result["error"]):
            label = result["status"] or "ERR"
            print(f"[{count}/{configs[index].max_pages}] {label} {result['requested_url']}", file=sys.stderr)

    rows = run_batch(configs, output_dir, progress, on_start)
    print(json.dumps({"domains": rows}, indent=2))
    return 0 if all(row["status"].startswith("complete") for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
