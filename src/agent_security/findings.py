"""Grouping of per-page findings into report entries and summary counts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from agent_security.taxonomy import BITSIGHT_CATEGORIES, SECTIONS, SEVERITIES, SEVERITY_ORDER, bitsight_of, section_of

_COOKIE_TITLE = re.compile(r"Cookie (\S+) missing")


def group_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings with the same rule and evidence, keeping every affected URL."""
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["severity"], finding["rule"], finding["title"], finding["evidence"])
        group = groups.setdefault(
            key,
            {
                "severity": finding["severity"],
                "rule": finding["rule"],
                "title": finding["title"],
                "evidence": finding["evidence"],
                "expected": finding["expected"],
                "remediation": finding["remediation"],
                "urls": set(),
                "sources": set(),
            },
        )
        group["urls"].add(finding["url"])
        group["sources"].add(finding.get("source", "seed"))
    result = []
    for group in groups.values():
        group["urls"] = sorted(group["urls"])
        group["sources"] = sorted(group["sources"])
        group["count"] = len(group["urls"])
        match = _COOKIE_TITLE.match(group["title"]) if group["rule"].startswith("COOKIE-") else None
        group["cookie"] = match.group(1) if match else None
        group["bitsight"] = bitsight_of(group["rule"])
        result.append(group)
    result.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 9), -g["count"], g["rule"], g["title"]))
    return result


def summarize(groups: Iterable[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    summary = {
        "severity": {name: {"distinct": 0, "instances": 0} for name in SEVERITIES},
        "sections": {name: {"distinct": 0, "instances": 0} for name in SECTIONS},
        "bitsight": {name: {"distinct": 0, "instances": 0} for name in BITSIGHT_CATEGORIES},
    }
    for group in groups:
        buckets = (
            summary["severity"][group["severity"]],
            summary["sections"][section_of(group["rule"])],
            summary["bitsight"][bitsight_of(group["rule"])["category"] or "Not assessed by Bitsight"],
        )
        for bucket in buckets:
            bucket["distinct"] += 1
            bucket["instances"] += group["count"]
    return summary
