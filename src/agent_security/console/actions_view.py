"""Action plan page: what to fix, who fixes it, how, and how to verify — with Adobe AEM and OneTrust guidance."""

from __future__ import annotations

import json
import os
from collections import Counter

import pandas as pd
import streamlit as st

from agent_security.actions import STATUSES, Action, action_rows, aem_cdn_config, build_actions, markdown_plan
from agent_security.console import state, theme
from agent_security.console.categorize import (
    AUDIT_FILE,
    STATUS_LABELS,
    build_changes,
    categorizable_cookies,
    make_write_client,
    read_audit,
)
from agent_security.console.dashboard_view import batch_picker
from agent_security.console.data import load_plan_state, platform_rows, save_action_state
from agent_security.fingerprint import AEM_CLOUD
from agent_security.onetrust import (
    MAX_CHANGES_PER_RUN,
    STANDARD_CATEGORIES,
    UPDATE_COOKIE_PATH,
    CategoryChange,
    apply_category_changes,
    validate_changes,
    write_config_from_env,
)

PRIORITY_COLORS = {"P1": "#D64545", "P2": "#F2A93B", "P3": "#3E7CB1", "P4": "#808B94"}
PRIORITY_HELP = "P1 corrigir já · P2 próximo ciclo · P3 planear · P4 melhoria"


def _priority_badge(priority: str) -> str:
    return f"<span class='sev' style='background:{PRIORITY_COLORS[priority]}'>{priority}</span>"


def _save(key: str, field: str) -> None:
    widget = f"{field}-{key}"
    save_action_state(state.reports_dir(), key, **{field: st.session_state[widget]})


def _action_card(action: Action, saved: dict) -> None:
    status = saved.get("status") or STATUSES[0]
    with st.container(border=True):
        warning = (
            " &nbsp;" + theme.pill("Ainda detetado na última análise", "bad")
            if status == "Feito"  # Every action in the plan was found in the batch shown.
            else ""
        )
        title = theme.esc(action.title.replace("`", ""))
        st.html(
            f"{_priority_badge(action.priority)} &nbsp;<b style='font-size:1.02rem'>{title}</b>"
            f"{warning}<div class='domain-progress' style='margin-top:.35rem'>"
            f"{theme.esc(saved.get('owner') or action.owner)} · esforço {theme.esc(action.effort.lower())} · "
            f"{theme.esc(', '.join(action.domains))} · {action.pages} páginas"
            + (f" · BitSight: {theme.esc(action.bitsight)}" if action.bitsight else "")
            + "</div>"
        )
        with st.expander("Como corrigir"):
            st.caption(action.why)
            st.markdown("\n".join(f"{n}. {step}" for n, step in enumerate(action.steps, start=1)))
            if action.snippet:
                st.code(action.snippet, language=action.snippet_language)
            st.markdown("**Verificação**")
            st.code(action.verify, language="bash")
        columns = st.columns([1.2, 1.6, 2.2])
        columns[0].selectbox(
            "Estado",
            STATUSES,
            index=STATUSES.index(status) if status in STATUSES else 0,
            key=f"status-{action.key}",
            on_change=_save,
            args=(action.key, "status"),
        )
        columns[1].text_input(
            "Responsável",
            value=saved.get("owner") or "",
            placeholder=action.owner,
            key=f"owner-{action.key}",
            on_change=_save,
            args=(action.key, "owner"),
        )
        columns[2].text_input(
            "Nota",
            value=saved.get("note") or "",
            placeholder="Ticket, prazo, decisão…",
            key=f"note-{action.key}",
            on_change=_save,
            args=(action.key, "note"),
        )


def _actions_tab(plan: list[Action], saved: dict) -> None:
    filters = st.columns([2, 3, 2])
    priorities = filters[0].multiselect("Prioridade", list(PRIORITY_COLORS), placeholder="Todas", help=PRIORITY_HELP)
    owners = filters[1].multiselect("Responsável", sorted({a.owner for a in plan}), placeholder="Todos")
    statuses = filters[2].multiselect("Estado", list(STATUSES), placeholder="Todos")
    visible = [
        action
        for action in plan
        if (not priorities or action.priority in priorities)
        and (not owners or action.owner in owners)
        and (not statuses or (saved.get(action.key, {}).get("status") or STATUSES[0]) in statuses)
    ]
    if not visible:
        st.caption("Nenhuma ação corresponde aos filtros.")
    for action in visible:
        _action_card(action, saved.get(action.key, {}))


def _integrations_tab(plan: list[Action], batch_reports: list[dict]) -> None:
    aem_cloud = any((r.get("platform") or {}).get("cms") == AEM_CLOUD for r in batch_reports)
    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Adobe Experience Manager")
        if aem_cloud:
            st.html(theme.pill("AEM as a Cloud Service detetado", "ok"))
            st.markdown(
                "Os cabeçalhos de segurança corrigem-se na CDN da Adobe, com um ficheiro `cdn.yaml` no repositório "
                "AEM, publicado pelo **Config Pipeline** do Cloud Manager:\n"
                "1. Rever o ficheiro sugerido abaixo e juntá-lo a `config/cdn.yaml`.\n"
                "2. Fazer deploy em dev e stage, validar e promover para produção.\n"
                "3. Voltar a analisar os domínios para confirmar.\n\n"
                "Os cabeçalhos CSP atuais podem vir de outra camada (Dispatcher ou aplicação): ao alterar a CSP, "
                "confirme a origem e retire os cabeçalhos antigos, porque o browser aplica todas as políticas em "
                "conjunto."
            )
            config = aem_cdn_config(plan)
            if config:
                st.code(config, language="yaml")
                st.download_button("Descarregar cdn.yaml sugerido", config, file_name="cdn.yaml", mime="text/yaml")
            else:
                st.caption("Não há cabeçalhos a acrescentar pela CDN neste lote.")
        else:
            st.html(theme.pill("AEM as a Cloud Service não detetado neste lote", "neutral"))
            st.caption("As ações indicam a configuração para Dispatcher/Apache ou para a CDN detetada.")
    with right, st.container(border=True):
        st.markdown("##### OneTrust")
        statuses = Counter(r.get("cookies", {}).get("classification", {}).get("status") for r in batch_reports)
        if statuses.get("not_configured"):
            st.html(theme.pill("Classificação OneTrust não configurada nas análises", "warn"))
        else:
            st.html(theme.pill("Classificação OneTrust usada nas análises", "ok"))
        onetrust = [a for a in plan if a.key.startswith("ONETRUST-") or a.owner.startswith("OneTrust")]
        st.markdown(
            "A consola **lê** o catálogo de cookies (API *Get List of Cookies by Criteria*, scope `COOKIE_READ`). "
            "A **categorização** pode ser feita abaixo, com confirmação, pela API *Update Cookie* "
            "(`PUT /api/cookiemanager/v1/cookies`, scope `COOKIE`, credenciais próprias). Registar cookies em falta "
            "e novos scans do domínio continuam a ser feitos no OneTrust. Os atributos Secure/HttpOnly/SameSite "
            "não se corrigem no OneTrust: dependem de quem envia o cookie."
        )
        if onetrust:
            for action in onetrust:
                st.html(f"{_priority_badge(action.priority)} &nbsp;{theme.esc(action.title.replace('`', ''))}")
        else:
            st.caption("Sem ações OneTrust neste lote.")
    _categorize_section(batch_reports)


@st.dialog("Confirmar alterações na OneTrust", width="large")
def _confirm_changes(changes: list[CategoryChange], tenant: str) -> None:
    st.warning(
        f"Vai alterar a categoria de {len(changes)} cookie(s) no tenant **{tenant}**. A alteração fica no catálogo "
        "da OneTrust e chega ao banner de consentimento quando o script do domínio for publicado."
    )
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Cookie": c.cookie_name,
                    "Host": c.host or "—",
                    "Categoria atual": c.current_category or "sem categoria",
                    "Nova categoria": c.new_category_id,
                }
                for c in changes
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    with st.expander("Pedidos que serão enviados"):
        st.code(
            "\n\n".join(f"PUT {UPDATE_COOKIE_PATH}\n{json.dumps(c.payload(), indent=2)}" for c in changes),
            language="http",
        )
    st.caption(
        "Antes de cada alteração o cookie é relido no catálogo; a categoria anterior fica no registo de alterações."
    )
    confirmed = st.checkbox("Confirmo que estas alterações foram aprovadas e quero aplicá-las na OneTrust.")
    left, right = st.columns(2)
    if left.button("Cancelar", width="stretch"):
        st.rerun()
    if right.button(f"Aplicar {len(changes)} alteração(ões)", type="primary", disabled=not confirmed, width="stretch"):
        config = write_config_from_env(os.environ)  # Credentials come from the environment, never from the page.
        if config is None:
            st.error("As credenciais de escrita da OneTrust deixaram de estar definidas.")
            return
        with st.spinner("A aplicar na OneTrust…"):
            results = apply_category_changes(make_write_client(config), changes, state.reports_dir() / AUDIT_FILE)
        st.session_state["onetrust_results"] = results
        st.rerun()


def _categorize_section(batch_reports: list[dict]) -> None:
    st.markdown("&nbsp;")
    with st.container(border=True):
        st.markdown("##### Categorizar cookies na OneTrust")
        try:
            config = write_config_from_env(os.environ)
        except ValueError as error:
            st.error(str(error))
            return
        cookies = categorizable_cookies(batch_reports)
        if not cookies:
            theme.note(
                "Nenhum cookie deste lote tem ID da OneTrust. Repita a análise com a classificação OneTrust ligada "
                "(as análises anteriores não guardavam o ID)."
            )
            return
        if config is None:
            theme.note(
                "A escrita na OneTrust está desligada. Para a ligar, crie na OneTrust um cliente de API com o scope "
                "COOKIE (leitura e escrita), defina ONETRUST_WRITE_CLIENT_ID e ONETRUST_WRITE_CLIENT_SECRET e "
                "reinicie a consola. As credenciais de leitura (COOKIE_READ) continuam a ser usadas nas análises.",
                warn=True,
            )
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Cookie": c["name"], "Host": c["host"] or "—", "Categoria": c["category"] or "sem categoria"}
                        for c in cookies
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            return
        st.html(theme.pill(f"Escrita ativa · {config.hostname}", "warn"))
        labels = {
            c["cookie_id"]: f"{c['name']} · {c['host'] or '—'} · {c['category'] or 'sem categoria'}" for c in cookies
        }
        selected = st.multiselect(
            "Cookies a alterar",
            list(labels),
            format_func=lambda cookie_id: labels[cookie_id],
            max_selections=MAX_CHANGES_PER_RUN,
            placeholder="Escolha os cookies (os sem categoria aparecem primeiro)",
        )
        left, right = st.columns([2, 1])
        choice = left.selectbox(
            "Nova categoria",
            [*STANDARD_CATEGORIES, "custom"],
            format_func=lambda c: f"{c} · {STANDARD_CATEGORIES[c]}" if c in STANDARD_CATEGORIES else "Outro ID…",
            help="IDs por omissão da OneTrust. Se o tenant usar categorias próprias, escolha Outro ID.",
        )
        category_id = (
            right.text_input("ID da categoria", placeholder="ex.: C0007") if choice == "custom" else (choice or "")
        ).strip()
        if st.button("Rever alterações", type="primary", disabled=not selected or not category_id):
            changes = build_changes([c for c in cookies if c["cookie_id"] in selected], category_id)
            try:
                validate_changes(changes)
            except ValueError as error:
                st.error(str(error))
            else:
                _confirm_changes(changes, config.hostname)
        results = st.session_state.get("onetrust_results")
        if results:
            st.markdown("**Resultado da última alteração**")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Cookie": r["cookie_name"],
                            "Antes": r.get("before") or "sem categoria",
                            "Nova categoria": r["new_category_id"],
                            "Resultado": STATUS_LABELS.get(r["status"], r["status"]),
                            "Detalhe": r.get("detail") or "",
                        }
                        for r in results
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            st.caption("Publique o script do domínio na OneTrust e volte a analisar para confirmar.")
    audit = read_audit(state.reports_dir() / AUDIT_FILE)
    if audit:
        with st.expander(f"Registo de alterações na OneTrust ({len(audit)} mais recentes)"):
            st.dataframe(pd.DataFrame(audit), hide_index=True, width="stretch")


def render() -> None:
    all_batches = state.batches()
    head, picker = st.columns([3, 2], vertical_alignment="bottom")
    with head:
        theme.page_header("Plano de ação", "O que corrigir, quem corrige, como e como verificar.", eyebrow="Remediação")
    if not all_batches:
        theme.note("Ainda não há relatórios. Inicie uma análise na página Nova análise.")
        return
    with picker:
        batch_picker()
    batch = state.current_batch(all_batches)
    assert batch is not None
    reports = [entry.report for entry in batch.reports]
    plan = build_actions(reports)
    saved = load_plan_state(state.reports_dir())

    counts = Counter(action.priority for action in plan)
    statuses = Counter(saved.get(a.key, {}).get("status") or STATUSES[0] for a in plan)
    theme.kpi_row(
        [
            theme.kpi("Ações", len(plan), f"{len(batch.reports)} domínios", "info"),
            theme.kpi(
                "P1 · corrigir já", counts["P1"], "críticas ou de grande alcance", "bad" if counts["P1"] else "ok"
            ),
            theme.kpi("P2 · próximo ciclo", counts["P2"], "alta prioridade", "warn" if counts["P2"] else "ok"),
            theme.kpi("Em curso", statuses["Em curso"], "com responsável", "info"),
            theme.kpi(
                "Feitas ou aceites",
                statuses["Feito"] + statuses["Risco aceite"],
                "a confirmar na próxima análise",
                "ok",
            ),
        ]
    )
    st.markdown("&nbsp;")
    with st.expander("Plataforma detetada", expanded=False):
        st.dataframe(pd.DataFrame(platform_rows(batch.reports)), hide_index=True, width="stretch")
    if not plan:
        st.success("Nada a corrigir neste lote.")
        return
    tabs = st.tabs(["Ações", "Integrações Adobe e OneTrust", "Exportar"])
    with tabs[0]:
        _actions_tab(plan, saved)
    with tabs[1]:
        _integrations_tab(plan, reports)
    with tabs[2]:
        rows = action_rows(plan, saved)
        st.dataframe(pd.DataFrame(rows).drop(columns=["Chave"]), hide_index=True, width="stretch")
        left, right = st.columns(2)
        left.download_button(
            "Descarregar CSV",
            pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig"),
            file_name=f"plano-de-acao-{batch.id}.csv",
            mime="text/csv",
            type="primary",
            width="stretch",
        )
        right.download_button(
            "Descarregar Markdown",
            markdown_plan(plan, saved, f"Plano de ação · {batch.label}"),
            file_name=f"plano-de-acao-{batch.id}.md",
            mime="text/markdown",
            width="stretch",
        )
