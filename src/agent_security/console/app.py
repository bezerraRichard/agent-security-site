"""Streamlit entry point of the HTTP Security console (run with ``agent-security-console``)."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from agent_security.console import (
    actions_view,
    dashboard_view,
    domain_view,
    history_view,
    rules_view,
    scan_view,
    state,
    theme,
)

HERE = Path(__file__).parent
st.set_page_config(
    page_title="novobanco · HTTP Security",
    page_icon=str(HERE / "novobanco-icon.svg"),
    layout="wide",
    initial_sidebar_state="expanded",
)
st.logo(str(HERE / "novobanco.svg"), size="large", icon_image=str(HERE / "novobanco-icon.svg"))
theme.inject_css()

pages = {
    "scan": st.Page(scan_view.render, title="New scan", icon=":material/radar:", default=True),
    "dashboard": st.Page(dashboard_view.render, title="Dashboard", icon=":material/dashboard:", url_path="dashboard"),
    "actions": st.Page(actions_view.render, title="Action plan", icon=":material/task_alt:", url_path="actions"),
    "domain": st.Page(domain_view.render, title="Domain", icon=":material/language:", url_path="domain"),
    "history": st.Page(history_view.render, title="History", icon=":material/history:", url_path="history"),
    "rules": st.Page(rules_view.render, title="Rules and BitSight", icon=":material/rule:", url_path="rules"),
}
st.session_state["pages"] = pages

navigation = st.navigation(
    {
        "Scan": [pages["scan"], pages["dashboard"], pages["actions"], pages["domain"]],
        "Archive": [pages["history"], pages["rules"]],
    }
)

with st.sidebar:
    onetrust = state.onetrust_status()
    job = state.registry().current
    activity = "scan running" if job and job.running else "idle"
    onetrust_text = f"connected ({theme.esc(onetrust['hostname'])})" if onetrust["configured"] else "not configured"
    st.markdown(
        "<div class='side-meta'><div class='product'>HTTP Security Console</div>"
        f"<b>OneTrust</b> · {onetrust_text}<br>"
        f"<b>Status</b> · {activity}<br>"
        f"<b>Reports</b> · {theme.esc(state.reports_dir().name)}/<br>"
        "<b>Theme</b> · System, Light or Dark in the ⋮ menu<br><br>"
        "GET requests only · cookie values never stored</div>",
        unsafe_allow_html=True,
    )

navigation.run()
