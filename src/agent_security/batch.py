"""Scan several domains one after another, each with its own report, linked by a batch id."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_security.config import ScanConfig
from agent_security.network import FetchResult
from agent_security.report import write_reports
from agent_security.scan import run_scan

BatchProgress = Callable[[int, int, FetchResult], None]  # domain index, pages fetched, last result


class ScanCancelled(KeyboardInterrupt):
    """Raised from a progress callback to stop the current crawl; the crawler records it as an interruption."""


def new_batch_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def summary_row(report: dict[str, Any], html_path: Path | None, json_path: Path | None) -> dict[str, Any]:
    return {
        "target": report["target"],
        "status": report["status"],
        "route": report["route"]["selected"],
        "pages_assessed": report["scope"]["pages_assessed"],
        "pages_failed": report["scope"]["pages_failed"],
        "distinct_findings": len(report["groups"]),
        "html": str(html_path) if html_path else None,
        "json": str(json_path) if json_path else None,
    }


def run_batch(
    configs: Sequence[ScanConfig],
    output_dir: Path,
    progress: BatchProgress | None = None,
    on_start: Callable[[int, ScanConfig], None] | None = None,
    stop: Callable[[], bool] | None = None,
    on_done: Callable[[int, dict[str, Any]], None] | None = None,
    batch_id: str | None = None,
) -> list[dict[str, Any]]:
    """Scan each config in order and write its reports; returns one summary row per domain."""
    batch_id = batch_id or new_batch_id()
    targets = [config.start_url for config in configs]
    rows: list[dict[str, Any]] = []

    def finish(index: int, row: dict[str, Any]) -> None:
        rows.append(row)
        if on_done:
            on_done(index, row)

    for index, config in enumerate(configs):
        if stop and stop():
            finish(index, {"target": config.start_url, "status": "not run: cancelled", "error": None})
            continue
        if on_start:
            on_start(index, config)

        def domain_progress(count: int, result: FetchResult, index: int = index) -> None:
            if progress:
                progress(index, count, result)

        try:
            report = run_scan(config, domain_progress)
        except Exception as error:  # One failing domain must not abort the rest of the batch.
            finish(index, {"target": config.start_url, "status": "failed", "error": f"{type(error).__name__}: {error}"})
            continue
        report["batch"] = {"id": batch_id, "index": index, "total": len(configs), "targets": targets}
        html_path, json_path = write_reports(report, output_dir)
        finish(index, summary_row(report, html_path, json_path))
    return rows
