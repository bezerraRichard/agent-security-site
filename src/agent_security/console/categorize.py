"""Support for recategorizing cookies in OneTrust from the console (always after explicit confirmation)."""

from __future__ import annotations

import json
import ssl
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agent_security import onetrust
from agent_security.network import candidate_routes
from agent_security.onetrust import CategoryChange, OneTrustClient, OneTrustConfig

AUDIT_FILE = "onetrust-changes.jsonl"
STATUS_LABELS = {
    "applied": "Aplicada",
    "partial": "Aplicada com avisos",
    "skipped": "Ignorada (já não existe no catálogo)",
    "failed": "Falhou",
    "not_run": "Não executada",
}


def categorizable_cookies(reports: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cookies observed in the reports that exist in the OneTrust catalogue (they carry a OneTrust cookie ID)."""
    found: dict[str, dict[str, Any]] = {}
    for report in reports:
        for cookie in report.get("cookies", {}).get("inventory", []):
            info = cookie.get("classification") or {}
            cookie_id = info.get("cookie_id")
            if not cookie_id:
                continue
            entry = found.setdefault(
                cookie_id,
                {
                    "cookie_id": cookie_id,
                    "name": cookie["name"],
                    "host": info.get("host"),
                    "category": info.get("category"),
                    "source": info.get("source"),
                    "domains": set(),
                },
            )
            entry["domains"].update(cookie.get("hosts") or [])
    rows = [{**entry, "domains": sorted(entry["domains"])} for entry in found.values()]
    # Uncategorized cookies first: they are the ones the action plan asks to fix.
    return sorted(rows, key=lambda row: (row["category"] is not None, row["name"].lower()))


def build_changes(cookies: Iterable[dict[str, Any]], category_id: str) -> list[CategoryChange]:
    return [
        CategoryChange(cookie["cookie_id"], cookie["name"], cookie.get("host"), cookie.get("category"), category_id)
        for cookie in cookies
    ]


def make_write_client(config: OneTrustConfig, timeout: float = 20.0) -> OneTrustClient:
    """Same routing as the scans: system proxy first when there is one, then a direct connection."""
    context = ssl.create_default_context()
    routes = candidate_routes(None, False, False)
    openers = [(route.name, onetrust.build_opener(route.proxies, context)) for route in routes]
    return OneTrustClient(config, openers, timeout)


def read_audit(path: Path, limit: int = 50) -> list[dict[str, Any]]:
    """The most recent audit records, newest first; unreadable lines are skipped."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records = []
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
        if len(records) >= limit:
            break
    return records
