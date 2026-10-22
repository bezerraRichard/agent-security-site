"""Portfolio dashboard: every domain of a batch side by side."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agent_security.console import state, theme
from agent_security.console.data import (
    SEVERITY_LABELS,
    bitsight_rows,
    domain_row,
    rule_matrix,
    severity_by_domain,
)


def batch_picker() -> None:
    all_batches = state.batches()
    if not all_batches:
        return
    current = state.current_batch(all_batches)
    ids = [b.id for b in all_batches]
    labels = {b.id: b.label for b in all_batches}
    chosen = st.selectbox(
        "Scan batch",
        ids,
        index=ids.index(current.id) if current else 0,
        format_func=lambda batch_id: labels[batch_id],
        label_visibility="collapsed",
    )
    if chosen:
        state.select_batch(chosen)


def render() -> None:
    all_batches = state.batches()
    head, picker = st.columns([3, 2], vertical_alignment="bottom")
    with head:
        theme.page_header("Dashboard", "Consolidated view of every domain in a batch.", eyebrow="Portfolio")
    if not all_batches:
        theme.note("There are no reports yet. Start a scan on the New scan page.")
        return
    with picker:
        batch_picker()
    batch = state.current_batch(all_batches)
    assert batch is not None
    rows = [domain_row(entry) for entry in batch.reports]

    pages = sum(row["Pages"] for row in rows)
    severe = sum(row["Critical"] + row["High"] for row in rows)
    distinct = sum(sum(row[label] for label in SEVERITY_LABELS.values()) for row in rows)
    complete = sum(row["Status"] == "Complete" for row in rows)
    was_fail = sum(
        sum(1 for b in bitsight_rows(entry.report) if b["Vector"] == "WAS" and b["Result"] == "Fail")
        for entry in batch.reports
    )
    theme.kpi_row(
        [
            theme.kpi("Domains", len(rows), f"{complete} with complete coverage", "info"),
            theme.kpi("Pages assessed", f"{pages:,}".replace(",", " "), "across all domains", "info"),
            theme.kpi("Distinct issues", distinct, "summed per domain", "warn" if distinct else "ok"),
            theme.kpi("Critical and high", severe, "fix first", "bad" if severe else "ok"),
            theme.kpi("BitSight WAS failures", was_fail, "failing assessments", "bad" if was_fail else "ok"),
        ]
    )
    st.markdown("&nbsp;")

    st.markdown("##### Domains")
    table = pd.DataFrame(rows)
    selection = st.dataframe(
        table.drop(columns=["path"]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Controls passed": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
            "Pages": st.column_config.NumberColumn(format="%d"),
        },
    )
    picked = selection.selection.rows if selection else []
    if picked:
        row = rows[picked[0]]
        if st.button(f"Open details for {row['Domain']}", type="primary"):
            state.select_report(row["path"])
            st.switch_page(st.session_state["pages"]["domain"])
    else:
        st.caption("Select a row to open the domain details.")

    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Issues by severity")
        severity_rows = severity_by_domain(batch.reports)
        if severity_rows:
            st.altair_chart(theme.stacked_severity_chart(severity_rows), width="stretch")
        else:
            st.success("No issues found in the domains of this batch.")
    with right, st.container(border=True):
        st.markdown("##### BitSight Web Application Security")
        was_rows = []
        for entry in batch.reports:
            for row in bitsight_rows(entry.report):
                if row["Vector"] == "WAS":
                    was_rows.append({"Domain": entry.host, "Assessment": row["BitSight assessment"], **row})
        if was_rows:
            colors = theme.BITSIGHT_COLORS
            tooltip = ["Domain", "Assessment", "Result", "Affected pages"]
            st.altair_chart(theme.heatmap(pd.DataFrame(was_rows), "Assessment", colors, tooltip), width="content")

    with st.container(border=True):
        st.markdown("##### Control matrix")
        st.caption("Each cell shows the severity of the issue on that domain, or Pass when the rule did not fail.")
        matrix = pd.DataFrame(rule_matrix(batch.reports))
        st.altair_chart(
            theme.heatmap(matrix, "Rule", theme.RESULT_COLORS, ["Rule", "Domain", "Result", "Pages"]),
            width="content",
        )
