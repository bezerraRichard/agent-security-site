"""Streamlit entry point of the HTTP Security console (run with ``agent-security-console``)."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from agent_security.console import dashboard_view, domain_view, history_view, rules_view, scan_view, state, theme

HERE = Path(__file__).parent
st.set_page_config(
    page_title="novobanco · Segurança HTTP",
    page_icon=str(HERE / "novobanco-icon.svg"),
    layout="wide",
    initial_sidebar_state="expanded",
)
st.logo(str(HERE / "novobanco.svg"), size="large", icon_image=str(HERE / "novobanco-icon.svg"))
theme.inject_css()

pages = {
    "scan": st.Page(scan_view.render, title="Nova análise", icon=":material/radar:", default=True),
    "dashboard": st.Page(dashboard_view.render, title="Painel", icon=":material/dashboard:", url_path="painel"),
    "domain": st.Page(domain_view.render, title="Domínio", icon=":material/language:", url_path="dominio"),
    "history": st.Page(history_view.render, title="Histórico", icon=":material/history:", url_path="historico"),
    "rules": st.Page(rules_view.render, title="Regras e BitSight", icon=":material/rule:", url_path="regras"),
}
st.session_state["pages"] = pages

navigation = st.navigation(
    {
        "Análise": [pages["scan"], pages["dashboard"], pages["domain"]],
        "Arquivo": [pages["history"], pages["rules"]],
    }
)

with st.sidebar:
    onetrust = state.onetrust_status()
    job = state.registry().current
    activity = "análise em curso" if job and job.running else "inativa"
    onetrust_text = f"ligada ({theme.esc(onetrust['hostname'])})" if onetrust["configured"] else "não configurada"
    st.markdown(
        "<div class='side-meta'><div class='product'>Consola de Segurança HTTP</div>"
        f"<b>OneTrust</b> · {onetrust_text}<br>"
        f"<b>Estado</b> · {activity}<br>"
        f"<b>Relatórios</b> · {theme.esc(state.reports_dir().name)}/<br><br>"
        "Só pedidos GET · valores de cookies nunca guardados</div>",
        unsafe_allow_html=True,
    )

navigation.run()
