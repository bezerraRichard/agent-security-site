"""Process-wide console state: where reports live, the job registry and cached report loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import streamlit as st

from agent_security.console.data import Batch, ReportEntry, group_batches, load_reports
from agent_security.console.jobs import JobRegistry
from agent_security.onetrust import config_from_env

REPORTS_ENV = "AGENT_SECURITY_REPORTS_DIR"
SELECTED_BATCH = "selected_batch"
SELECTED_REPORT = "selected_report"


def reports_dir() -> Path:
    return Path(os.environ.get(REPORTS_ENV) or "reports").resolve()


@st.cache_resource
def registry() -> JobRegistry:
    return JobRegistry()


def _signature(directory: Path) -> tuple[tuple[str, int], ...]:
    if not directory.is_dir():
        return ()
    return tuple(sorted((p.name, p.stat().st_mtime_ns) for p in directory.glob("site-security-report-*.json")))


@st.cache_data(show_spinner=False, max_entries=4)
def _load(directory: str, signature: tuple[tuple[str, int], ...]) -> list[ReportEntry]:
    return load_reports(Path(directory))


def entries() -> list[ReportEntry]:
    directory = reports_dir()
    return _load(str(directory), _signature(directory))


def batches() -> list[Batch]:
    return group_batches(entries())


def onetrust_status() -> dict[str, Any]:
    """What the console may show about OneTrust: never the client id or secret."""
    try:
        config = config_from_env(os.environ)
    except ValueError as error:
        return {"configured": False, "detail": str(error)}
    if config is None:
        partial = any(os.environ.get(n) for n in ("ONETRUST_HOSTNAME", "ONETRUST_CLIENT_ID", "ONETRUST_CLIENT_SECRET"))
        return {"configured": False, "detail": "Configuração incompleta." if partial else "Não configurada."}
    return {"configured": True, "hostname": config.hostname, "language": config.language}


def select_batch(batch_id: str) -> None:
    st.session_state[SELECTED_BATCH] = batch_id


def select_report(path: str) -> None:
    st.session_state[SELECTED_REPORT] = path


def current_batch(all_batches: list[Batch]) -> Batch | None:
    wanted = st.session_state.get(SELECTED_BATCH)
    return next((b for b in all_batches if b.id == wanted), all_batches[0] if all_batches else None)
