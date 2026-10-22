"""Report loading and the tabular views the console renders. Pure Python, so it can be tested without Streamlit."""

from __future__ import annotations

import json
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_security.actions import LEGACY_STATUSES
from agent_security.taxonomy import (
    BITSIGHT,
    RULE_INFO,
    SECTIONS,
    SEVERITIES,
    SEVERITY_ORDER,
    WAH,
    WAS,
    bitsight_of,
    section_of,
)

SEVERITY_LABELS = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Info": "Info"}
SECTION_LABELS = {
    "Security Headers": "Security headers",
    "Content Security Policy": "Content Security Policy",
    "Cookies": "Cookies",
    "Page Content": "Page content",
    "TLS": "TLS",
}
STATUS_LABELS = {"complete": "Complete", "partial": "Partial", "incomplete": "Incomplete"}
# Rules that existed before the Bitsight alignment (v0.3); older reports never evaluated the others.
LEGACY_RULES = frozenset(
    {
        "HDR-HSTS-001",
        "HDR-HSTS-002",
        "CSP-000",
        "CSP-001",
        "CSP-002",
        "CSP-003",
        "HDR-XCTO-001",
        "HDR-XFO-001",
        "HDR-REF-001",
        "HDR-PP-001",
        "COOKIE-SECURE",
        "COOKIE-HTTPONLY",
        "COOKIE-SAMESITE",
        "TLS-HTTP-001",
    }
)


@dataclass
class ReportEntry:
    path: Path
    report: dict[str, Any]

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.report.get("target", "")).hostname or self.path.stem

    @property
    def batch_id(self) -> str:
        return (self.report.get("batch") or {}).get("id") or self.path.stem

    @property
    def batch_index(self) -> int:
        return int((self.report.get("batch") or {}).get("index") or 0)

    @property
    def started_at(self) -> str:
        return str(self.report.get("started_at") or "")


@dataclass
class Batch:
    id: str
    reports: list[ReportEntry] = field(default_factory=list)

    @property
    def started_at(self) -> str:
        return min((entry.started_at for entry in self.reports), default="")

    @property
    def label(self) -> str:
        stamp = self.started_at[:16].replace("T", " ")
        hosts = ", ".join(entry.host for entry in self.reports[:3])
        more = f" +{len(self.reports) - 3}" if len(self.reports) > 3 else ""
        return f"{stamp} UTC · {hosts}{more}"


def load_reports(directory: Path) -> list[ReportEntry]:
    """Every readable scan report in ``directory``, newest first. Unrelated or corrupt JSON files are skipped."""
    entries = []
    for path in sorted(directory.glob("site-security-report-*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(report, dict) and {"target", "groups", "scope", "summary"} <= report.keys():
            entries.append(ReportEntry(path, report))
    entries.sort(key=lambda entry: entry.started_at, reverse=True)
    return entries


def group_batches(entries: list[ReportEntry]) -> list[Batch]:
    batches: dict[str, Batch] = {}
    for entry in entries:
        batches.setdefault(entry.batch_id, Batch(entry.batch_id)).reports.append(entry)
    for batch in batches.values():
        batch.reports.sort(key=lambda entry: entry.batch_index)
    return sorted(batches.values(), key=lambda batch: batch.started_at, reverse=True)


def status_kind(status: str) -> str:
    kind = status.split(":", 1)[0].strip()
    return kind if kind in STATUS_LABELS else "incomplete"


def evaluated_rules(report: dict[str, Any]) -> frozenset[str]:
    """Rules this report actually checked: reports without Bitsight data predate the newer rules."""
    if not report["scope"].get("pages_assessed"):
        return frozenset()
    return frozenset(RULE_INFO) if "bitsight" in report["summary"] else LEGACY_RULES


def failed_rules(report: dict[str, Any]) -> set[str]:
    return {group["rule"] for group in report["groups"]}


def controls_passed(report: dict[str, Any]) -> tuple[int, int]:
    """(rules without findings, rules checked). Nothing passes when no page could be assessed."""
    evaluated = evaluated_rules(report)
    if not evaluated:
        return 0, len(RULE_INFO)
    return len(evaluated - failed_rules(report)), len(evaluated)


def severity_counts(report: dict[str, Any]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for group in report["groups"]:
        counts[group["severity"]] = counts.get(group["severity"], 0) + 1
    return counts


def domain_row(entry: ReportEntry) -> dict[str, Any]:
    report = entry.report
    passed, total = controls_passed(report)
    counts = severity_counts(report)
    return {
        "Domain": entry.host,
        "Status": STATUS_LABELS[status_kind(report["status"])],
        "Pages": report["scope"].get("pages_assessed", 0),
        "Failed pages": report["scope"].get("pages_failed", 0),
        **{SEVERITY_LABELS[severity]: counts[severity] for severity in SEVERITIES},
        "Controls passed": passed / total if total else 0.0,
        "Cookies": len(report.get("cookies", {}).get("inventory", [])),
        "Route": report.get("route", {}).get("selected") or "—",
        "path": str(entry.path),
    }


def finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for index, group in enumerate(report["groups"]):
        bitsight = group.get("bitsight") or bitsight_of(group["rule"])
        rows.append(
            {
                "index": index,
                "Severity": SEVERITY_LABELS.get(group["severity"], group["severity"]),
                "Rule": group["rule"],
                "Issue": group["title"],
                "Section": SECTION_LABELS.get(section_of(group["rule"]), section_of(group["rule"])),
                "BitSight": bitsight["assessment"] or "—",
                "Pages": group["count"],
                "order": SEVERITY_ORDER.get(group["severity"], 9),
            }
        )
    return rows


def severity_by_domain(entries: list[ReportEntry]) -> list[dict[str, Any]]:
    """Long-format rows (domain, severity, distinct issues) for a stacked bar chart."""
    rows = []
    for entry in entries:
        for severity, count in severity_counts(entry.report).items():
            if count:
                rows.append({"Domain": entry.host, "Severity": SEVERITY_LABELS[severity], "Findings": count})
    return rows


def rule_matrix(entries: list[ReportEntry]) -> list[dict[str, Any]]:
    """One row per (rule, domain): the severity when the rule failed there, or "Pass"."""
    rows = []
    for entry in entries:
        evaluated = evaluated_rules(entry.report)
        severity_by_rule = {group["rule"]: group["severity"] for group in entry.report["groups"]}
        pages_by_rule: dict[str, int] = defaultdict(int)
        for group in entry.report["groups"]:
            pages_by_rule[group["rule"]] += group["count"]
        for rule in RULE_INFO:
            if rule in severity_by_rule:
                result = SEVERITY_LABELS[severity_by_rule[rule]]
            else:
                result = "Pass" if rule in evaluated else "No data"
            rows.append({"Rule": rule, "Domain": entry.host, "Result": result, "Pages": pages_by_rule[rule]})
    return rows


def bitsight_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per Bitsight assessment the scanner approximates, with its outcome in this report."""
    evaluated = evaluated_rules(report)
    groups_by_rule = defaultdict(list)
    for group in report["groups"]:
        groups_by_rule[group["rule"]].append(group)
    assessments: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for rule, (vector, category, assessment) in BITSIGHT.items():
        if vector and assessment:
            assessments[(vector, category, assessment)].append(rule)
    rows = []
    for (vector, category, assessment), rules in assessments.items():
        failing = [rule for rule in rules if groups_by_rule.get(rule)]
        positive_only = "positive-only" in assessment
        if not evaluated & set(rules):
            outcome = "No data"
        elif positive_only:
            outcome = "Absent" if failing else "Present"
        else:
            outcome = "Fail" if failing else "Pass"
        rows.append(
            {
                "Vector": "WAS" if vector == WAS else "WAH (legacy)" if vector == WAH else vector,
                "Category": category,
                "BitSight assessment": assessment,
                "Result": outcome,
                "Rules": ", ".join(rules),
                "Affected pages": sum(group["count"] for rule in failing for group in groups_by_rule[rule]),
            }
        )
    order = {"Fail": 0, "Absent": 1, "Pass": 2, "Present": 3, "No data": 4}
    rows.sort(key=lambda row: (row["Vector"] != "WAS", order[row["Result"]], row["Category"]))
    return rows


def cookie_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for cookie in report.get("cookies", {}).get("inventory", []):
        info = cookie.get("classification") or {}
        status = info.get("status")
        category = {
            "classified": info.get("category"),
            "uncategorized": "Uncategorized in OneTrust",
            "not_found": "Not found in OneTrust",
            "lookup_failed": "Lookup failed",
        }.get(status or "", "Not classified")
        third = info.get("third_party")
        rows.append(
            {
                "Cookie": cookie["name"],
                "Category": category,
                "Party": "—" if third is None else ("Third-party" if third else "First-party"),
                "Duration": " ".join(p for p in (info.get("lifespan"), info.get("duration")) if p) or "—",
                "Pages": cookie["pages"],
                "Attributes": cookie["attributes"] or "—",
                "Hosts": ", ".join(cookie.get("hosts") or []),
                "Description": info.get("description") or "",
            }
        )
    return rows


PLAN_STATE_FILE = "action-plan-state.json"


def load_plan_state(directory: Path) -> dict[str, dict[str, Any]]:
    """Saved status, owner and note per action key; an unreadable file counts as empty."""
    try:
        state = json.loads((directory / PLAN_STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(state, dict):
        return {}
    entries = {k: v for k, v in state.items() if isinstance(v, dict)}
    for entry in entries.values():  # Files saved before the console was in English.
        if entry.get("status") in LEGACY_STATUSES:
            entry["status"] = LEGACY_STATUSES[entry["status"]]
    return entries


def save_action_state(directory: Path, key: str, **fields: str) -> dict[str, dict[str, Any]]:
    """Merge ``fields`` into one action's saved state and write the file atomically."""
    state = load_plan_state(directory)
    entry = state.setdefault(key, {})
    entry.update(fields)
    entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f".{PLAN_STATE_FILE}.tmp"
    temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(directory / PLAN_STATE_FILE)
    return state


def platform_rows(entries: list[ReportEntry]) -> list[dict[str, Any]]:
    rows = []
    for entry in entries:
        platform = entry.report.get("platform")
        rows.append(
            {
                "Domain": entry.host,
                "CMS": (platform or {}).get("cms") or ("—" if platform else "Not detected (older scan)"),
                "CDN": (platform or {}).get("cdn") or "—",
                "Other technologies": ", ".join((platform or {}).get("technologies") or []) or "—",
            }
        )
    return rows


def section_counts(report: dict[str, Any]) -> list[dict[str, Any]]:
    sections = report["summary"].get("sections", {})
    return [
        {"Section": SECTION_LABELS.get(name, name), "Findings": sections.get(name, {}).get("distinct", 0)}
        for name in SECTIONS
    ]
