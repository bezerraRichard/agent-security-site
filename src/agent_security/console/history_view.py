"""History of every report in the reports folder."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agent_security.console import state, theme
from agent_security.console.data import STATUS_LABELS, severity_counts, status_kind


def render() -> None:
    theme.page_header("Histórico", f"Relatórios em {state.reports_dir()}", eyebrow="Arquivo")
    entries = state.entries()
    if not entries:
        theme.note("Ainda não há relatórios nesta pasta.")
        return
    rows = []
    for entry in entries:
        counts = severity_counts(entry.report)
        rows.append(
            {
                "Data (UTC)": entry.started_at[:16].replace("T", " "),
                "Domínio": entry.host,
                "Estado": STATUS_LABELS[status_kind(entry.report["status"])],
                "Páginas": entry.report["scope"].get("pages_assessed", 0),
                "Críticos+altos": counts["Critical"] + counts["High"],
                "Problemas": len(entry.report["groups"]),
                "Lote": entry.batch_id,
            }
        )
    hosts = sorted({row["Domínio"] for row in rows})
    chosen = st.multiselect("Filtrar por domínio", hosts, placeholder="Todos os domínios")
    visible = [i for i, row in enumerate(rows) if not chosen or row["Domínio"] in chosen]
    selection = st.dataframe(
        pd.DataFrame([rows[i] for i in visible]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
    )
    picked = selection.selection.rows if selection else []
    if not picked:
        st.caption("Selecione um relatório para o abrir.")
        return
    entry = entries[visible[picked[0]]]
    left, right = st.columns(2)
    if left.button(f"Abrir {entry.host}", type="primary", width="stretch"):
        state.select_batch(entry.batch_id)
        state.select_report(str(entry.path))
        st.switch_page(st.session_state["pages"]["domain"])
    if right.button("Abrir o lote no painel", width="stretch"):
        state.select_batch(entry.batch_id)
        st.switch_page(st.session_state["pages"]["dashboard"])
