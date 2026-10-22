"""Domain detail: findings, Bitsight alignment, cookies, coverage and exports for one report."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from agent_security.console import state, theme
from agent_security.console.data import (
    SEVERITY_LABELS,
    STATUS_LABELS,
    ReportEntry,
    bitsight_rows,
    controls_passed,
    cookie_rows,
    finding_rows,
    section_counts,
    severity_counts,
    status_kind,
)
from agent_security.report import render_html
from agent_security.taxonomy import RULE_INFO, bitsight_of

RESULT_TONES = {"Falha": "bad", "Ausente": "warn", "Aprovado": "ok", "Presente": "ok", "Sem dados": "neutral"}


def _pick_report() -> ReportEntry | None:
    entries = state.entries()
    if not entries:
        return None
    wanted = st.session_state.get(state.SELECTED_REPORT)
    batch = state.current_batch(state.batches())
    options = batch.reports if batch else entries
    if wanted and not any(str(e.path) == wanted for e in options):
        options = entries
    paths = [str(e.path) for e in options]
    labels = {str(e.path): f"{e.host} · {e.started_at[:16].replace('T', ' ')} UTC" for e in options}
    index = paths.index(wanted) if wanted in paths else 0
    chosen = st.selectbox(
        "Relatório", paths, index=index, format_func=lambda path: labels[path], label_visibility="collapsed"
    )
    chosen = chosen or paths[0]
    state.select_report(chosen)
    return next(e for e in options if str(e.path) == chosen)


def _overview(report: dict[str, Any]) -> None:
    left, right = st.columns(2, gap="large")
    counts = severity_counts(report)
    with left, st.container(border=True):
        st.markdown("##### Problemas por severidade")
        rows = [{"Severidade": SEVERITY_LABELS[s], "Achados": n} for s, n in counts.items()]
        if any(row["Achados"] for row in rows):
            st.altair_chart(theme.donut(rows, "Severidade", "Achados", theme.SEVERITY_COLORS), width="stretch")
        else:
            st.success("Nenhum problema encontrado nas páginas avaliadas.")
    with right, st.container(border=True):
        st.markdown("##### Problemas por secção")
        st.altair_chart(theme.horizontal_bars(section_counts(report), "Secção", "Achados"), width="stretch")
    with st.container(border=True):
        st.markdown("##### Prioridades")
        top = [g for g in report["groups"] if g["severity"] in {"Critical", "High"}][:6]
        if not top:
            st.caption("Sem problemas críticos ou altos.")
        for group in top:
            st.markdown(
                f"{theme.severity_badge(SEVERITY_LABELS[group['severity']])} &nbsp;**{theme.esc(group['title'])}** "
                f"<span class='domain-progress'>· {theme.esc(group['rule'])} · {group['count']} páginas</span>",
                unsafe_allow_html=True,
            )


def _finding_detail(group: dict[str, Any]) -> None:
    description, references = RULE_INFO.get(group["rule"], ("", []))
    bitsight = group.get("bitsight") or bitsight_of(group["rule"])
    with st.container(border=True):
        st.markdown(
            f"{theme.severity_badge(SEVERITY_LABELS[group['severity']])} &nbsp;<b>{theme.esc(group['title'])}</b>"
            f" <span class='domain-progress'>· {theme.esc(group['rule'])}</span>",
            unsafe_allow_html=True,
        )
        if description:
            st.caption(description)
        bitsight_text = (
            f"{bitsight['vector']} · {bitsight['category']} · {bitsight['assessment']}"
            if bitsight["vector"]
            else "Não avaliado pela BitSight"
        )
        st.markdown(
            "<dl class='kv'>"
            f"<dt>Páginas afetadas</dt><dd>{group['count']}</dd>"
            f"<dt>Origem</dt><dd>{theme.esc(', '.join(group.get('sources') or []))}</dd>"
            f"<dt>BitSight</dt><dd>{theme.esc(bitsight_text)}</dd></dl>",
            unsafe_allow_html=True,
        )
        left, right = st.columns(2)
        left.markdown("**Valor observado**")
        left.markdown(f"<div class='evidence'>{theme.esc(group['evidence'])}</div>", unsafe_allow_html=True)
        right.markdown("**Esperado**")
        right.markdown(f"<div class='evidence'>{theme.esc(group['expected'])}</div>", unsafe_allow_html=True)
        st.markdown("**Remediação**")
        st.markdown(f"<div class='evidence'>{theme.esc(group['remediation'])}</div>", unsafe_allow_html=True)
        if references:
            st.markdown("**Referências**  \n" + "  \n".join(f"- [{ref}]({ref})" for ref in references))
        with st.expander(f"URLs afetados ({len(group['urls'])})"):
            st.dataframe(
                pd.DataFrame({"URL": group["urls"]}),
                hide_index=True,
                width="stretch",
                column_config={"URL": st.column_config.LinkColumn()},
            )


def _findings(report: dict[str, Any]) -> None:
    rows = finding_rows(report)
    if not rows:
        st.success("Nenhum problema encontrado nas páginas avaliadas.")
        return
    data = pd.DataFrame(rows)
    filters = st.columns([2, 2, 3])
    severities = filters[0].multiselect("Severidade", list(SEVERITY_LABELS.values()), placeholder="Todas")
    sections = filters[1].multiselect("Secção", sorted(data["Secção"].unique()), placeholder="Todas")
    query = filters[2].text_input("Pesquisar", placeholder="Regra, problema ou avaliação BitSight")
    if severities:
        data = data[data["Severidade"].isin(severities)]
    if sections:
        data = data[data["Secção"].isin(sections)]
    if query:
        text = (
            data[["Regra", "Problema", "BitSight"]].agg(" ".join, axis=1).str.contains(query, case=False, regex=False)
        )
        data = data[text]
    data = data.sort_values(["order", "Páginas"], ascending=[True, False])
    selection = st.dataframe(
        data.drop(columns=["index", "order"]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key=f"findings-{report['started_at']}",
    )
    picked = selection.selection.rows if selection else []
    if picked:
        _finding_detail(report["groups"][int(data.iloc[picked[0]]["index"])])
    else:
        st.caption("Selecione um problema para ver a evidência, a remediação e os URLs afetados.")


def _bitsight(report: dict[str, Any]) -> None:
    theme.note(
        "Mapeamento aproximado, com base na documentação pública da BitSight. Desde 10/07/2025 o rating usa o vetor "
        "Web Application Security (WAS); o antigo Web Application Headers (WAH) deixou de ter nota. A BitSight avalia "
        "apenas a página inicial de cada domínio num browser; esta análise cobre todas as páginas percorridas."
    )
    rows = bitsight_rows(report)
    was = [r for r in rows if r["Vetor"] == "WAS"]
    failing = sum(r["Resultado"] == "Falha" for r in was)
    passing = sum(r["Resultado"] in {"Aprovado", "Presente"} for r in was)
    st.markdown("&nbsp;")
    theme.kpi_row(
        [
            theme.kpi("Avaliações WAS em falha", failing, f"de {len(was)} aproximadas", "bad" if failing else "ok"),
            theme.kpi("Avaliações WAS aprovadas", passing, "sem problemas observados", "ok"),
            theme.kpi(
                "Fora do âmbito BitSight",
                report["summary"].get("bitsight", {}).get("Not assessed by Bitsight", {}).get("distinct", 0),
                "problemas sem equivalente",
                "info",
            ),
        ]
    )
    st.markdown("&nbsp;")
    for vector, title in (("WAS", "Web Application Security"), ("WAH (legado)", "Web Application Headers (legado)")):
        subset = [r for r in rows if r["Vetor"] == vector]
        if not subset:
            continue
        st.markdown(f"##### {title}")
        table = pd.DataFrame(subset).drop(columns=["Vetor"])
        st.dataframe(
            table.style.map(
                lambda value: theme.BITSIGHT_CELL_STYLES.get(value, ""),
                subset=["Resultado"],
            ),
            hide_index=True,
            width="stretch",
        )


def _cookies(report: dict[str, Any]) -> None:
    meta = report.get("cookies", {}).get("classification", {})
    status = meta.get("status")
    messages = {
        "not_configured": ("A classificação OneTrust não estava configurada nesta análise.", True),
        "no_cookies": ("As páginas avaliadas não definiram cookies.", False),
        "unavailable": (f"A OneTrust não esteve disponível: {meta.get('detail') or 'erro desconhecido'}.", True),
        "partial": (
            f"Classificação parcial ({meta.get('cookies_checked')} de {meta.get('cookies_total')} cookies). "
            f"{meta.get('detail') or ''}",
            True,
        ),
        "ok": (f"Cookies classificados pela OneTrust ({meta.get('hostname')}, idioma {meta.get('language')}).", False),
    }
    text, warn = messages.get(status or "", ("Estado da classificação desconhecido.", True))
    theme.note(text, warn=warn)
    rows = cookie_rows(report)
    if not rows:
        return
    st.markdown("&nbsp;")
    left, right = st.columns([2, 3], gap="large")
    with left, st.container(border=True):
        st.markdown("##### Por categoria")
        counts = Counter(row["Categoria"] for row in rows)
        st.altair_chart(
            theme.donut([{"Categoria": k, "Cookies": v} for k, v in counts.items()], "Categoria", "Cookies"),
            width="stretch",
        )
    with right, st.container(border=True):
        st.markdown("##### Por origem")
        origin = Counter(row["Origem"] for row in rows)
        st.altair_chart(
            theme.horizontal_bars([{"Origem": k, "Cookies": v} for k, v in origin.items()], "Origem", "Cookies"),
            width="stretch",
        )
    st.markdown("##### Inventário")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Os valores dos cookies nunca são guardados.")


def _coverage(report: dict[str, Any]) -> None:
    scope = report["scope"]
    probe = report.get("http_probe")
    probe_text = (
        f"{probe['requested_url']} → {probe['final_url']} (HTTP {probe['status']})"
        if probe and not probe.get("error")
        else f"não concluída ({(probe or {}).get('error') or 'não executada'})"
    )
    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Âmbito")
        items = {
            "Hosts autorizados": ", ".join(scope["allowed_hosts"]),
            "Rota": report["route"].get("selected") or "nenhuma",
            "Limite de páginas / profundidade": f"{scope['max_pages']} / {scope['max_depth']}",
            "Pausa entre pedidos": f"{scope['delay_seconds']} s",
            "robots.txt respeitado": "sim" if scope["respect_robots"] else "não",
            "Sitemap": "sim" if scope["sitemap_used"] else "não",
            "Fila por visitar": scope["queue_remaining"],
            "Motivo de paragem": scope.get("stop_reason") or "—",
            "HTTP → HTTPS": probe_text,
        }
        st.markdown(
            "<dl class='kv'>"
            + "".join(f"<dt>{theme.esc(k)}</dt><dd>{theme.esc(v)}</dd>" for k, v in items.items())
            + "</dl>",
            unsafe_allow_html=True,
        )
    with right, st.container(border=True):
        st.markdown("##### Excluído da varredura")
        skipped = [{"Motivo": k, "URLs": v} for k, v in report.get("skipped", {}).items()]
        if skipped:
            st.altair_chart(theme.horizontal_bars(skipped, "Motivo", "URLs", theme.SUBTLE), width="stretch")
        else:
            st.caption("Nada excluído.")
        st.markdown("##### Tentativas de rota")
        for attempt in report["route"].get("attempts", []):
            tone = "ok" if attempt["ok"] else "bad"
            st.markdown(
                f"{theme.pill('ok' if attempt['ok'] else 'falhou', tone)} &nbsp;{theme.esc(attempt['route'])} "
                f"<span class='domain-progress'>· {theme.esc(attempt['detail'])}</span>",
                unsafe_allow_html=True,
            )
    st.markdown("##### Páginas avaliadas")
    pages = pd.DataFrame(report.get("pages", []))
    if not pages.empty:
        columns = [c for c in ("url", "status", "depth", "source", "findings", "error") if c in pages]
        st.dataframe(
            pages[columns].rename(
                columns={
                    "url": "URL",
                    "status": "HTTP",
                    "depth": "Profundidade",
                    "source": "Origem",
                    "findings": "Problemas",
                    "error": "Erro",
                }
            ),
            hide_index=True,
            width="stretch",
            column_config={"URL": st.column_config.LinkColumn()},
        )


def _exports(entry: ReportEntry) -> None:
    report = entry.report
    html_path = Path(str(entry.path)[: -len(".json")] + ".html")
    # Rendered from the JSON, so reports saved before the current layout also download with it.
    html = render_html(report)
    left, right = st.columns(2)
    left.download_button(
        "Descarregar relatório HTML", html, file_name=html_path.name, mime="text/html", type="primary", width="stretch"
    )
    right.download_button(
        "Descarregar dados JSON",
        json.dumps(report, indent=2, ensure_ascii=True),
        file_name=entry.path.name,
        mime="application/json",
        width="stretch",
    )
    st.caption(f"Ficheiros em {entry.path.parent}")


def render() -> None:
    head, picker = st.columns([3, 2], vertical_alignment="bottom")
    with picker:
        entry = _pick_report()
    if entry is None:
        with head:
            theme.page_header("Domínio", "Detalhe de um relatório.", eyebrow="Domínio")
        theme.note("Ainda não há relatórios. Inicie uma análise na página Nova análise.")
        return
    report = entry.report
    status = STATUS_LABELS[status_kind(report["status"])]
    with head:
        theme.page_header(
            entry.host,
            f"{report['started_at'][:19].replace('T', ' ')} UTC · rota {report['route'].get('selected') or 'nenhuma'}",
            eyebrow="Domínio",
            right=theme.status_pill(status),
        )
    theme.note(report["status"], warn=status != "Completa")
    st.markdown("&nbsp;")
    passed, total = controls_passed(report)
    counts = severity_counts(report)
    severe = counts["Critical"] + counts["High"]
    theme.kpi_row(
        [
            theme.kpi(
                "Páginas avaliadas",
                report["scope"]["pages_assessed"],
                f"{report['scope']['pages_failed']} falhadas",
                "info",
            ),
            theme.kpi(
                "Controlos aprovados", f"{passed}/{total}", "regras sem problemas", "ok" if passed == total else "warn"
            ),
            theme.kpi(
                "Problemas distintos",
                len(report["groups"]),
                "agrupados por evidência",
                "warn" if report["groups"] else "ok",
            ),
            theme.kpi("Críticos e altos", severe, "a tratar primeiro", "bad" if severe else "ok"),
            theme.kpi("Cookies", len(report.get("cookies", {}).get("inventory", [])), "observados", "info"),
        ]
    )
    st.markdown("&nbsp;")
    tabs = st.tabs(["Visão geral", "Problemas", "BitSight", "Cookies", "Cobertura", "Exportar"])
    with tabs[0]:
        _overview(report)
    with tabs[1]:
        _findings(report)
    with tabs[2]:
        _bitsight(report)
    with tabs[3]:
        _cookies(report)
    with tabs[4]:
        _coverage(report)
    with tabs[5]:
        _exports(entry)
