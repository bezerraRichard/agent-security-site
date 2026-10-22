"""History of every report in the reports folder."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agent_security.console import state, theme
from agent_security.console.data import STATUS_LABELS, severity_counts, status_kind


def render() -> None:
    theme.page_header("History", f"Reports in {state.reports_dir()}", eyebrow="Archive")
    entries = state.entries()
    if not entries:
        theme.note("There are no reports in this folder yet.")
        return
    rows = []
    for entry in entries:
        counts = severity_counts(entry.report)
        rows.append(
            {
                "Date (UTC)": entry.started_at[:16].replace("T", " "),
                "Domain": entry.host,
                "Status": STATUS_LABELS[status_kind(entry.report["status"])],
                "Pages": entry.report["scope"].get("pages_assessed", 0),
                "Critical+high": counts["Critical"] + counts["High"],
                "Issues": len(entry.report["groups"]),
                "Batch": entry.batch_id,
            }
        )
    hosts = sorted({row["Domain"] for row in rows})
    chosen = st.multiselect("Filter by domain", hosts, placeholder="All domains")
    visible = [i for i, row in enumerate(rows) if not chosen or row["Domain"] in chosen]
    selection = st.dataframe(
        pd.DataFrame([rows[i] for i in visible]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
    )
    picked = selection.selection.rows if selection else []
    if not picked:
        st.caption("Select a report to open it.")
        return
    entry = entries[visible[picked[0]]]
    left, right = st.columns(2)
    if left.button(f"Open {entry.host}", type="primary", width="stretch"):
        state.select_batch(entry.batch_id)
        state.select_report(str(entry.path))
        st.switch_page(st.session_state["pages"]["domain"])
    if right.button("Open the batch in the dashboard", width="stretch"):
        state.select_batch(entry.batch_id)
        st.switch_page(st.session_state["pages"]["dashboard"])
