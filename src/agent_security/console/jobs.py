"""Background scan jobs, so the console stays responsive and can show live progress."""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_security.batch import ScanCancelled, new_batch_id, run_batch
from agent_security.config import ScanConfig
from agent_security.network import FetchResult

Runner = Callable[..., list[dict[str, Any]]]


@dataclass
class DomainProgress:
    target: str
    max_pages: int
    state: str = "queued"  # queued | running | done | failed | cancelled
    pages: int = 0
    last_url: str = ""
    status: str = ""
    findings: int = 0
    json_path: str | None = None
    error: str | None = None


@dataclass
class ScanJob:
    id: str
    output_dir: Path
    domains: list[DomainProgress]
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    error: str | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    @property
    def running(self) -> bool:
        return self.finished_at is None

    @property
    def cancel_requested(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self, configs: Sequence[ScanConfig], runner: Runner = run_batch) -> None:
        def on_start(index: int, config: ScanConfig) -> None:
            self.domains[index].state = "running"

        def progress(index: int, count: int, result: FetchResult) -> None:
            domain = self.domains[index]
            domain.pages, domain.last_url = count, result["requested_url"]
            if self._cancel.is_set():
                raise ScanCancelled

        def on_done(index: int, row: dict[str, Any]) -> None:
            domain = self.domains[index]
            domain.status = row["status"]
            domain.error = row.get("error")
            domain.findings = row.get("distinct_findings", 0)
            domain.json_path = row.get("json")
            if row["status"] == "failed":
                domain.state = "failed"
            elif row["status"].startswith("not run") or "interrupted" in row["status"]:
                domain.state = "cancelled"
            else:
                domain.state = "done"

        try:
            runner(
                configs,
                self.output_dir,
                progress=progress,
                on_start=on_start,
                stop=self._cancel.is_set,
                on_done=on_done,
                batch_id=self.id,
            )
        except Exception as error:  # Keep the console alive and show what went wrong.
            self.error = f"{type(error).__name__}: {error}"
        finally:
            self.finished_at = datetime.now(timezone.utc).isoformat()


class JobRegistry:
    """Jobs of this console process. Only one scan runs at a time to keep the load on targets predictable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.jobs: list[ScanJob] = []

    @property
    def current(self) -> ScanJob | None:
        return self.jobs[-1] if self.jobs else None

    def start(self, configs: Sequence[ScanConfig], output_dir: Path, runner: Runner = run_batch) -> ScanJob:
        with self._lock:
            if self.current and self.current.running:
                raise RuntimeError("A scan is already running.")
            job = ScanJob(
                id=new_batch_id(),
                output_dir=output_dir,
                domains=[DomainProgress(config.start_url, config.max_pages) for config in configs],
            )
            job._thread = threading.Thread(target=job.run, args=(configs, runner), name=f"scan-{job.id}", daemon=True)
            self.jobs.append(job)
            job._thread.start()
            return job
