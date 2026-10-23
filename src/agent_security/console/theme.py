"""Visual identity of the console (novobanco palette, from www.novobanco.pt), for both the light and the dark theme:
colours, CSS and HTML components."""

from __future__ import annotations

import html
from collections.abc import Sequence

import altair as alt
import pandas as pd
import streamlit as st

PRIMARY = "#009F98"  # novobanco teal
PRIMARY_LIGHT = "#00B9B2"
SUBTLE = "#808B94"  # mid grey, readable on light and dark backgrounds
ACCENT = "#F7D54E"
# The console runs with a light and a dark theme (see console/__init__.py), so the colours below are mid tones or
# translucent tints that read well on both, and text inherits the active theme's colour.
TINT = "rgba(128, 150, 160, 0.10)"
LINE = "rgba(128, 150, 160, 0.30)"
SEVERITY_COLORS = {
    "Critical": "#9E2A38",
    "High": "#D64545",
    "Medium": "#F2A93B",
    "Low": "#3E7CB1",
    "Info": SUBTLE,
}
PASS_COLOR = "rgba(0, 159, 152, 0.40)"
NO_DATA_COLOR = "rgba(128, 150, 160, 0.22)"
RESULT_COLORS = {**SEVERITY_COLORS, "Pass": PASS_COLOR, "No data": NO_DATA_COLOR}
# Bitsight outcomes: chart colours and table cell styles.
BITSIGHT_COLORS = {
    "Fail": SEVERITY_COLORS["High"],
    "Absent": SEVERITY_COLORS["Medium"],
    "Pass": PRIMARY,
    "Present": PRIMARY_LIGHT,
    "No data": NO_DATA_COLOR,
}
BITSIGHT_CELL_STYLES = {
    "Fail": "background-color:rgba(214,69,69,.18);color:#D64545;font-weight:600",
    "Absent": "background-color:rgba(242,169,59,.20);color:#C9861A;font-weight:600",
    "Pass": f"background-color:rgba(0,159,152,.18);color:{PRIMARY};font-weight:600",
    "Present": f"background-color:rgba(0,159,152,.18);color:{PRIMARY};font-weight:600",
}
STATUS_TONES = {"Complete": "ok", "Partial": "warn", "Incomplete": "bad"}
RAIL = 'section[data-testid="stSidebar"][data-collapsed="true"]'

CSS = f"""
<style>
:root {{ --primary:{PRIMARY}; --border:{LINE}; --surface:{TINT}; }}
footer, [data-testid="stDeployButton"] {{ visibility: hidden; }}
.block-container {{ padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1680px; }}
h1, h2, h3 {{ letter-spacing: -0.01em; }}
[data-testid="stSidebar"] {{ border-right:1px solid var(--border); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] span {{ font-weight:500; }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover {{ background:var(--surface); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] {{
  background:var(--surface); box-shadow:inset 3px 0 0 var(--primary); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] span {{
  color:var(--primary); font-weight:700; }}
[data-testid="stSidebar"] [data-testid="stNavSectionHeader"] {{ color:{SUBTLE}; text-transform:uppercase;
  letter-spacing:.08em; font-size:.7rem; font-weight:700; }}
[data-testid="stSidebarHeader"] img {{ height:1.9rem; max-width:100%; }}
/* Collapsed sidebar: keep a rail with the page icons instead of hiding the navigation (wide screens only). */
@media (min-width: 640px) {{
  {RAIL} {{ transform:none !important; min-width:4rem !important; max-width:4rem !important; width:4rem !important;
    visibility:visible !important; }}
  {RAIL} [data-testid="stSidebarHeader"], {RAIL} [data-testid="stSidebarUserContent"] {{ display:none !important; }}
  {RAIL} [data-testid="stSidebarContent"] {{ padding-left:.4rem !important; padding-right:.4rem !important;
    overflow-x:hidden; }}
  /* Full-width links: otherwise they shrink to a few pixels and their highlight draws a line over the icon. */
  {RAIL} [data-testid="stSidebarNav"], {RAIL} [data-testid="stSidebarNavItems"] {{ width:100% !important;
    padding-left:0 !important; padding-right:0 !important; margin-left:0 !important; margin-right:0 !important; }}
  {RAIL} [data-testid="stSidebarNav"] {{ padding-top:3.75rem; }}
  {RAIL} [data-testid="stNavSectionHeader"] {{ font-size:0 !important; height:1px; padding:0 !important;
    margin:.6rem .3rem !important; background:var(--border); }}
  {RAIL} [data-testid="stSidebarNavItems"] > :first-child[data-testid="stNavSectionHeader"] {{ display:none; }}
  {RAIL} [data-testid="stSidebarNavLink"] {{ justify-content:center; padding:.55rem 0 !important; min-height:2.5rem;
    width:100%; border-radius:8px; }}
  /* The links are as narrow as the icon here, so the active page is a tint instead of the left bar over the icon. */
  {RAIL} [data-testid="stSidebarNavLink"][aria-current="page"] {{ box-shadow:none; background:rgba(0,159,152,.16); }}
  {RAIL} [data-testid="stSidebarNavLink"] [data-testid="stIconMaterial"] {{ font-size:1.35rem; }}
  /* Page names stay readable by screen readers, just not shown. */
  {RAIL} [data-testid="stSidebarNavLink"] > span:last-child {{ position:absolute !important; width:1px; height:1px;
    overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }}
}}
.product {{ font-size:.78rem; font-weight:700; letter-spacing:.02em; margin:0 0 .5rem; }}
.side-meta {{ font-size:.76rem; color:{SUBTLE}; line-height:1.7; }}
.side-meta b {{ color:inherit; font-weight:600; }}
.stButton button[kind="primary"], .stDownloadButton button[kind="primary"] {{ border-radius:999px; font-weight:700; }}
.stButton button, .stDownloadButton button {{ border-radius:999px; }}
.page-head {{ display:flex; justify-content:space-between; align-items:flex-end; gap:1rem;
  border-bottom:1px solid var(--border); padding-bottom:.9rem; margin-bottom:1.2rem; }}
.page-title {{ font-size:1.65rem; font-weight:750; margin:0; }}
.page-sub {{ opacity:.75; font-size:.92rem; margin-top:.15rem; }}
.eyebrow {{ text-transform:uppercase; letter-spacing:.08em; font-size:.7rem; font-weight:700; color:var(--primary); }}
.kpi {{ background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1rem 1.1rem;
  height:100%; }}
.kpi-label {{ font-size:.76rem; font-weight:600; opacity:.75; text-transform:uppercase; letter-spacing:.05em; }}
.kpi-value {{ font-size:1.9rem; font-weight:750; line-height:1.2; margin-top:.2rem; }}
.kpi-sub {{ font-size:.8rem; opacity:.75; }}
.kpi.tone-bad {{ border-top:3px solid #D64545; }} .kpi.tone-warn {{ border-top:3px solid #F2A93B; }}
.kpi.tone-ok {{ border-top:3px solid var(--primary); }} .kpi.tone-info {{ border-top:3px solid {SUBTLE}; }}
.pill {{ display:inline-block; padding:.12rem .6rem; border-radius:999px; font-size:.75rem; font-weight:650; }}
.pill.ok {{ background:rgba(0,159,152,.16); color:var(--primary); }}
.pill.warn {{ background:rgba(242,169,59,.20); color:#C9861A; }}
.pill.bad {{ background:rgba(214,69,69,.16); color:#D64545; }}
.pill.neutral {{ background:var(--surface); color:inherit; }}
.sev {{ display:inline-block; padding:.1rem .55rem; border-radius:6px; font-size:.74rem; font-weight:700; color:#fff; }}
.panel {{ background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.1rem 1.2rem; }}
.note {{ background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--primary);
  border-radius:10px; padding:.75rem 1rem; font-size:.88rem; }}
.note.warn {{ border-left-color:{ACCENT}; background:rgba(247,213,78,.14); }}
.kv {{ display:grid; grid-template-columns:max-content 1fr; gap:.35rem 1.2rem; font-size:.88rem; }}
.kv dt {{ opacity:.7; }} .kv dd {{ margin:0; overflow-wrap:anywhere; }}
.evidence {{ font-family:Consolas,'SFMono-Regular',monospace; font-size:.8rem; background:var(--surface);
  border:1px solid var(--border); border-radius:8px; padding:.55rem .7rem; overflow-wrap:anywhere;
  white-space:pre-wrap; max-height:16rem; overflow-y:auto; }}
.domain-progress {{ font-size:.82rem; opacity:.75; overflow-wrap:anywhere; }}
div[data-testid="stTabs"] button p {{ font-weight:600; }}
div[data-testid="stTabs"] button[aria-selected="true"] p {{ color:var(--primary); }}
</style>
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "", eyebrow: str = "", right: str = "") -> None:
    st.markdown(
        f"<div class='page-head'><div><div class='eyebrow'>{esc(eyebrow)}</div>"
        f"<div class='page-title'>{esc(title)}</div><div class='page-sub'>{esc(subtitle)}</div></div>"
        f"<div>{right}</div></div>",
        unsafe_allow_html=True,
    )


def kpi(label: str, value: object, sub: str = "", tone: str = "info") -> str:
    return (
        f"<div class='kpi tone-{esc(tone)}'><div class='kpi-label'>{esc(label)}</div>"
        f"<div class='kpi-value'>{esc(value)}</div><div class='kpi-sub'>{esc(sub)}</div></div>"
    )


def kpi_row(cards: Sequence[str]) -> None:
    for column, card in zip(st.columns(len(cards)), cards, strict=True):
        column.markdown(card, unsafe_allow_html=True)


def pill(text: str, tone: str = "neutral") -> str:
    return f"<span class='pill {esc(tone)}'>{esc(text)}</span>"


def status_pill(label: str) -> str:
    return pill(label, STATUS_TONES.get(label, "neutral"))


def severity_badge(label: str) -> str:
    return f"<span class='sev' style='background:{SEVERITY_COLORS.get(label, SUBTLE)}'>{esc(label)}</span>"


def note(text: str, warn: bool = False) -> None:
    st.markdown(f"<div class='note{' warn' if warn else ''}'>{esc(text)}</div>", unsafe_allow_html=True)


def severity_scale() -> alt.Scale:
    return alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values()))


def stacked_severity_chart(rows: list[dict]) -> alt.Chart:
    data = pd.DataFrame(rows)
    height = 44 * data["Domain"].nunique() + 30
    order = {name: index for index, name in enumerate(SEVERITY_COLORS)}
    data["order"] = data["Severity"].map(order)
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusEnd=3, size=24)
        .encode(
            y=alt.Y("Domain:N", title=None, sort="-x", axis=alt.Axis(labelLimit=220)),
            x=alt.X("sum(Findings):Q", title="Distinct issues", axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("Severity:N", scale=severity_scale(), legend=alt.Legend(orient="bottom", title=None)),
            order=alt.Order("order:Q"),
            tooltip=["Domain", "Severity", "Findings"],
        )
        .properties(height=height)
    )


def donut(rows: list[dict], category: str, value: str, colors: dict[str, str] | None = None) -> alt.Chart:
    data = pd.DataFrame(rows)
    data = data[data[value] > 0]
    color = alt.Color(f"{category}:N", legend=alt.Legend(orient="right", title=None))
    if colors:
        present = [name for name in colors if name in set(data[category])]
        color = alt.Color(
            f"{category}:N",
            scale=alt.Scale(domain=present, range=[colors[name] for name in present]),
            legend=alt.Legend(orient="right", title=None),
        )
    return (
        alt.Chart(data)
        .mark_arc(innerRadius=58, outerRadius=95, cornerRadius=3)
        .encode(theta=f"{value}:Q", color=color, tooltip=[category, value])
        .properties(height=220)
    )


def heatmap(data: pd.DataFrame, y: str, colors: dict[str, str], tooltip: list[str]) -> alt.Chart:
    """Domains as columns of fixed width, so one domain does not stretch across the page."""
    return (
        alt.Chart(data)
        .mark_rect(stroke=None, cornerRadius=4, width=alt.RelativeBandSize(0.94), height=alt.RelativeBandSize(0.86))
        .encode(
            x=alt.X("Domain:N", title=None, axis=alt.Axis(orient="top", labelAngle=0, labelLimit=150)),
            y=alt.Y(f"{y}:N", title=None, sort=None, axis=alt.Axis(labelLimit=320)),
            color=alt.Color(
                "Result:N",
                scale=alt.Scale(domain=list(colors), range=list(colors.values())),
                legend=alt.Legend(orient="bottom", title=None),
            ),
            tooltip=tooltip,
        )
        .properties(width=alt.Step(150), height=alt.Step(26))
    )


def horizontal_bars(rows: list[dict], category: str, value: str, color: str = PRIMARY) -> alt.Chart:
    data = pd.DataFrame(rows)
    return (
        alt.Chart(data)
        .mark_bar(color=color, cornerRadiusEnd=3, size=20)
        .encode(
            y=alt.Y(f"{category}:N", title=None, sort="-x", axis=alt.Axis(labelLimit=260)),
            x=alt.X(f"{value}:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
            tooltip=[category, value],
        )
        .properties(height=max(120, 34 * len(data)))
    )
