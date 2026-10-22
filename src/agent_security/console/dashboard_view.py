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
        "Lote de análise",
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
        theme.page_header("Painel", "Visão consolidada de todos os domínios de um lote.", eyebrow="Portefólio")
    if not all_batches:
        theme.note("Ainda não há relatórios. Inicie uma análise na página Nova análise.")
        return
    with picker:
        batch_picker()
    batch = state.current_batch(all_batches)
    assert batch is not None
    rows = [domain_row(entry) for entry in batch.reports]

    pages = sum(row["Páginas"] for row in rows)
    severe = sum(row["Crítico"] + row["Alto"] for row in rows)
    distinct = sum(sum(row[label] for label in SEVERITY_LABELS.values()) for row in rows)
    complete = sum(row["Estado"] == "Completa" for row in rows)
    was_fail = sum(
        sum(1 for b in bitsight_rows(entry.report) if b["Vetor"] == "WAS" and b["Resultado"] == "Falha")
        for entry in batch.reports
    )
    theme.kpi_row(
        [
            theme.kpi("Domínios", len(rows), f"{complete} com cobertura completa", "info"),
            theme.kpi("Páginas avaliadas", f"{pages:,}".replace(",", " "), "em todos os domínios", "info"),
            theme.kpi("Problemas distintos", distinct, "somados por domínio", "warn" if distinct else "ok"),
            theme.kpi("Críticos e altos", severe, "a tratar primeiro", "bad" if severe else "ok"),
            theme.kpi("Falhas BitSight WAS", was_fail, "avaliações em falha", "bad" if was_fail else "ok"),
        ]
    )
    st.markdown("&nbsp;")

    st.markdown("##### Domínios")
    table = pd.DataFrame(rows)
    selection = st.dataframe(
        table.drop(columns=["path"]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Controlos aprovados": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
            "Páginas": st.column_config.NumberColumn(format="%d"),
        },
    )
    picked = selection.selection.rows if selection else []
    if picked:
        row = rows[picked[0]]
        if st.button(f"Abrir detalhe de {row['Domínio']}", type="primary"):
            state.select_report(row["path"])
            st.switch_page(st.session_state["pages"]["domain"])
    else:
        st.caption("Selecione uma linha para abrir o detalhe do domínio.")

    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Problemas por severidade")
        severity_rows = severity_by_domain(batch.reports)
        if severity_rows:
            st.altair_chart(theme.stacked_severity_chart(severity_rows), width="stretch")
        else:
            st.success("Nenhum problema encontrado nos domínios deste lote.")
    with right, st.container(border=True):
        st.markdown("##### BitSight Web Application Security")
        was_rows = []
        for entry in batch.reports:
            for row in bitsight_rows(entry.report):
                if row["Vetor"] == "WAS":
                    was_rows.append({"Domínio": entry.host, "Avaliação": row["Avaliação BitSight"], **row})
        if was_rows:
            colors = theme.BITSIGHT_COLORS
            tooltip = ["Domínio", "Avaliação", "Resultado", "Páginas afetadas"]
            st.altair_chart(theme.heatmap(pd.DataFrame(was_rows), "Avaliação", colors, tooltip), width="content")

    with st.container(border=True):
        st.markdown("##### Matriz de controlos")
        st.caption("Cada célula mostra a severidade do problema nesse domínio, ou Aprovado quando a regra não falhou.")
        matrix = pd.DataFrame(rule_matrix(batch.reports))
        st.altair_chart(
            theme.heatmap(matrix, "Regra", theme.RESULT_COLORS, ["Regra", "Domínio", "Resultado", "Páginas"]),
            width="content",
        )
