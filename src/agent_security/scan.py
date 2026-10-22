"""Scan orchestration: route selection, crawl, analysis, cookie classification and report assembly."""

from __future__ import annotations

import ssl
import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from agent_security import onetrust
from agent_security.analysis import Finding, add_finding, analyze_response
from agent_security.config import ScanConfig
from agent_security.cookies import observe_cookies
from agent_security.crawler import DEPTH_SKIP, CrawlOutcome, crawl
from agent_security.discovery import Robots, sitemap_urls
from agent_security.findings import group_findings, summarize
from agent_security.network import FetchResult, Route, candidate_routes, select_route
from agent_security.onetrust import OneTrustClient, classify_cookies

METHODOLOGY = (
    "Sequential GET requests only. Links are discovered from static HTML (no JavaScript rendering, form "
    "submission or authentication), so pages reachable only that way are not covered. TLS protocol and cipher "
    "details were not tested."
)

Progress = Callable[[int, FetchResult], None]


def decide_status(outcome: CrawlOutcome, route: Route | None, assessed: int) -> str:
    if route is None:
        return "incomplete: the target could not be reached by any route"
    if not assessed:
        return "incomplete: no page could be assessed"
    reasons = []
    if outcome.stop_reason:
        reasons.append(outcome.stop_reason)
    if outcome.skipped.get(DEPTH_SKIP):
        reasons.append("links beyond the depth limit were not followed")
    failed = len(outcome.pages) - assessed
    if failed:
        reasons.append(f"{failed} page request(s) failed")
    if reasons:
        return "partial: " + "; ".join(reasons)
    return "complete: every in-scope page reachable through static HTML links was assessed"


def page_record(result: FetchResult) -> dict[str, Any]:
    return {
        "url": result["requested_url"],
        "final_url": result["final_url"],
        "status": result["status"],
        "depth": result.get("depth"),
        "source": result.get("source"),
        "content_type": result["content_type"],
        "error": result["error"],
    }


def collect_findings(pages: list[FetchResult], probe: FetchResult | None) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        analyze_response(page, findings)
    if probe and not probe["error"] and not probe["final_url"].startswith("https://"):
        add_finding(
            findings,
            severity="High",
            rule="TLS-HTTP-001",
            title="HTTP does not redirect to HTTPS",
            url=probe["final_url"],
            source="http-probe",
            evidence=f"HTTP request ended at {probe['final_url']} with status {probe['status']}.",
            expected="HTTP redirects to HTTPS",
            remediation="Configure HTTP to redirect to HTTPS.",
        )
    return findings


def classify_inventory(
    config: ScanConfig,
    inventory: list[dict[str, Any]],
    routes: list[Route],
    selected: Route | None,
    context: ssl.SSLContext,
) -> dict[str, Any]:
    """Classify cookie names with OneTrust (when configured) and annotate ``inventory`` in place."""
    if not inventory:
        return {"status": "no_cookies"}
    if config.onetrust is None:
        return {"status": "not_configured"}
    ordered = ([selected] if selected else []) + [route for route in routes if route is not selected]
    openers = [(route.name, onetrust.build_opener(route.proxies, context)) for route in ordered]
    client = OneTrustClient(config.onetrust, openers, config.timeout)
    summary, classes = classify_cookies(client, [{"name": c["name"], "hosts": c["hosts"]} for c in inventory])
    for cookie in inventory:
        cookie["classification"] = classes.get(cookie["name"])
    return summary


def run_scan(config: ScanConfig, progress: Progress | None = None) -> dict[str, Any]:
    """Run a full scan and return the report as a JSON-serialisable dict."""
    started_at = datetime.now(timezone.utc)
    context = ssl.create_default_context(cafile=config.ca_bundle)
    routes = candidate_routes(config.proxy, config.no_proxy, config.fallback_direct)
    route, fetch, attempts = select_route(
        routes, config.start_url, config.allowed_hosts, config.timeout, config.retries, context
    )

    outcome = CrawlOutcome([], Counter(), None, 0)
    probe: FetchResult | None = None
    delay = config.delay_seconds
    if route is not None and fetch is not None:
        robots = Robots(fetch, config.allowed_hosts, config.respect_robots)
        delay = max(delay, robots.crawl_delay(config.host))
        seeds = list(config.seeds)
        if config.sitemap:
            roots = [f"https://{host}/sitemap.xml" for host in sorted(config.allowed_hosts)] + robots.sitemaps()
            seeds += [(url, "sitemap") for url in sitemap_urls(fetch, roots, config.allowed_hosts, config.max_pages)]
        outcome = crawl(
            seeds,
            fetch,
            config.allowed_hosts,
            robots.allowed,
            max_pages=config.max_pages,
            max_depth=config.max_depth,
            delay=delay,
            deadline=time.monotonic() + config.time_limit_minutes * 60,
            progress=progress,
        )
        probe = fetch(f"http://{config.host}/")

    findings = collect_findings(outcome.pages, probe)
    groups = group_findings(findings)
    assessed = sum(1 for page in outcome.pages if not page["error"])
    inventory = observe_cookies(outcome.pages)
    classification = classify_inventory(config, inventory, routes, route, context)
    findings_per_url = Counter(finding["url"] for finding in findings)

    return {
        "target": config.start_url,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": decide_status(outcome, route, assessed),
        "methodology": METHODOLOGY,
        "route": {"selected": route.name if route else None, "attempts": attempts},
        "scope": {
            "allowed_hosts": sorted(config.allowed_hosts),
            "max_pages": config.max_pages,
            "max_depth": config.max_depth,
            "delay_seconds": delay,
            "respect_robots": config.respect_robots,
            "sitemap_used": config.sitemap,
            "pages_assessed": assessed,
            "pages_failed": len(outcome.pages) - assessed,
            "queue_remaining": outcome.remaining,
            "stop_reason": outcome.stop_reason,
            "status_counts": dict(Counter(str(page["status"]) for page in outcome.pages if page["status"])),
        },
        "skipped": dict(outcome.skipped),
        "http_probe": {k: v for k, v in probe.items() if k not in {"headers", "body"}} if probe else None,
        "summary": summarize(groups),
        "cookies": {"classification": classification, "inventory": inventory},
        "groups": groups,
        "pages": [
            {**page_record(page), "findings": findings_per_url[page["final_url"] or page["requested_url"]]}
            for page in outcome.pages
        ],
    }
