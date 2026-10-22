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

RESULT_TONES = {"Fail": "bad", "Absent": "warn", "Pass": "ok", "Present": "ok", "No data": "neutral"}


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
        "Report", paths, index=index, format_func=lambda path: labels[path], label_visibility="collapsed"
    )
    chosen = chosen or paths[0]
    state.select_report(chosen)
    return next(e for e in options if str(e.path) == chosen)


def _overview(report: dict[str, Any]) -> None:
    left, right = st.columns(2, gap="large")
    counts = severity_counts(report)
    with left, st.container(border=True):
        st.markdown("##### Issues by severity")
        rows = [{"Severity": SEVERITY_LABELS[s], "Findings": n} for s, n in counts.items()]
        if any(row["Findings"] for row in rows):
            st.altair_chart(theme.donut(rows, "Severity", "Findings", theme.SEVERITY_COLORS), width="stretch")
        else:
            st.success("No issues found on the assessed pages.")
    with right, st.container(border=True):
        st.markdown("##### Issues by section")
        st.altair_chart(theme.horizontal_bars(section_counts(report), "Section", "Findings"), width="stretch")
    with st.container(border=True):
        st.markdown("##### Priorities")
        top = [g for g in report["groups"] if g["severity"] in {"Critical", "High"}][:6]
        if not top:
            st.caption("No critical or high issues.")
        for group in top:
            st.markdown(
                f"{theme.severity_badge(SEVERITY_LABELS[group['severity']])} &nbsp;**{theme.esc(group['title'])}** "
                f"<span class='domain-progress'>· {theme.esc(group['rule'])} · {group['count']} pages</span>",
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
            else "Not assessed by BitSight"
        )
        st.markdown(
            "<dl class='kv'>"
            f"<dt>Affected pages</dt><dd>{group['count']}</dd>"
            f"<dt>Sources</dt><dd>{theme.esc(', '.join(group.get('sources') or []))}</dd>"
            f"<dt>BitSight</dt><dd>{theme.esc(bitsight_text)}</dd></dl>",
            unsafe_allow_html=True,
        )
        left, right = st.columns(2)
        left.markdown("**Observed value**")
        left.markdown(f"<div class='evidence'>{theme.esc(group['evidence'])}</div>", unsafe_allow_html=True)
        right.markdown("**Expected**")
        right.markdown(f"<div class='evidence'>{theme.esc(group['expected'])}</div>", unsafe_allow_html=True)
        st.markdown("**Remediation**")
        st.markdown(f"<div class='evidence'>{theme.esc(group['remediation'])}</div>", unsafe_allow_html=True)
        if references:
            st.markdown("**References**  \n" + "  \n".join(f"- [{ref}]({ref})" for ref in references))
        with st.expander(f"Affected URLs ({len(group['urls'])})"):
            st.dataframe(
                pd.DataFrame({"URL": group["urls"]}),
                hide_index=True,
                width="stretch",
                column_config={"URL": st.column_config.LinkColumn()},
            )


def _findings(report: dict[str, Any]) -> None:
    rows = finding_rows(report)
    if not rows:
        st.success("No issues found on the assessed pages.")
        return
    data = pd.DataFrame(rows)
    filters = st.columns([2, 2, 3])
    severities = filters[0].multiselect("Severity", list(SEVERITY_LABELS.values()), placeholder="All")
    sections = filters[1].multiselect("Section", sorted(data["Section"].unique()), placeholder="All")
    query = filters[2].text_input("Search", placeholder="Rule, issue or BitSight assessment")
    if severities:
        data = data[data["Severity"].isin(severities)]
    if sections:
        data = data[data["Section"].isin(sections)]
    if query:
        text = data[["Rule", "Issue", "BitSight"]].agg(" ".join, axis=1).str.contains(query, case=False, regex=False)
        data = data[text]
    data = data.sort_values(["order", "Pages"], ascending=[True, False])
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
        st.caption("Select an issue to see the evidence, the remediation and the affected URLs.")


def _bitsight(report: dict[str, Any]) -> None:
    theme.note(
        "Approximate mapping, based on public BitSight documentation. Since 10 July 2025 the rating uses the Web "
        "Application Security (WAS) vector; the former Web Application Headers (WAH) vector is no longer graded. "
        "BitSight only assesses the home page of each domain in a browser; this scan covers every crawled page."
    )
    rows = bitsight_rows(report)
    was = [r for r in rows if r["Vector"] == "WAS"]
    failing = sum(r["Result"] == "Fail" for r in was)
    passing = sum(r["Result"] in {"Pass", "Present"} for r in was)
    st.markdown("&nbsp;")
    theme.kpi_row(
        [
            theme.kpi("Failing WAS assessments", failing, f"of {len(was)} approximated", "bad" if failing else "ok"),
            theme.kpi("Passing WAS assessments", passing, "no issues observed", "ok"),
            theme.kpi(
                "Outside BitSight scope",
                report["summary"].get("bitsight", {}).get("Not assessed by Bitsight", {}).get("distinct", 0),
                "issues with no equivalent",
                "info",
            ),
        ]
    )
    st.markdown("&nbsp;")
    for vector, title in (("WAS", "Web Application Security"), ("WAH (legacy)", "Web Application Headers (legacy)")):
        subset = [r for r in rows if r["Vector"] == vector]
        if not subset:
            continue
        st.markdown(f"##### {title}")
        table = pd.DataFrame(subset).drop(columns=["Vector"])
        st.dataframe(
            table.style.map(
                lambda value: theme.BITSIGHT_CELL_STYLES.get(value, ""),
                subset=["Result"],
            ),
            hide_index=True,
            width="stretch",
        )


def _cookies(report: dict[str, Any]) -> None:
    meta = report.get("cookies", {}).get("classification", {})
    status = meta.get("status")
    messages = {
        "not_configured": ("OneTrust classification was not configured for this scan.", True),
        "no_cookies": ("The assessed pages did not set any cookies.", False),
        "unavailable": (f"OneTrust was unavailable: {meta.get('detail') or 'unknown error'}.", True),
        "partial": (
            f"Partial classification ({meta.get('cookies_checked')} of {meta.get('cookies_total')} cookies). "
            f"{meta.get('detail') or ''}",
            True,
        ),
        "ok": (f"Cookies classified by OneTrust ({meta.get('hostname')}, language {meta.get('language')}).", False),
    }
    text, warn = messages.get(status or "", ("Unknown classification status.", True))
    theme.note(text, warn=warn)
    rows = cookie_rows(report)
    if not rows:
        return
    st.markdown("&nbsp;")
    left, right = st.columns([2, 3], gap="large")
    with left, st.container(border=True):
        st.markdown("##### By category")
        counts = Counter(row["Category"] for row in rows)
        st.altair_chart(
            theme.donut([{"Category": k, "Cookies": v} for k, v in counts.items()], "Category", "Cookies"),
            width="stretch",
        )
    with right, st.container(border=True):
        st.markdown("##### By party")
        origin = Counter(row["Party"] for row in rows)
        st.altair_chart(
            theme.horizontal_bars([{"Party": k, "Cookies": v} for k, v in origin.items()], "Party", "Cookies"),
            width="stretch",
        )
    st.markdown("##### Inventory")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Cookie values are never stored.")


def _coverage(report: dict[str, Any]) -> None:
    scope = report["scope"]
    probe = report.get("http_probe")
    probe_text = (
        f"{probe['requested_url']} → {probe['final_url']} (HTTP {probe['status']})"
        if probe and not probe.get("error")
        else f"not completed ({(probe or {}).get('error') or 'not run'})"
    )
    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Scope")
        items = {
            "Authorized hosts": ", ".join(scope["allowed_hosts"]),
            "Route": report["route"].get("selected") or "none",
            "Page limit / depth": f"{scope['max_pages']} / {scope['max_depth']}",
            "Delay between requests": f"{scope['delay_seconds']} s",
            "robots.txt respected": "yes" if scope["respect_robots"] else "no",
            "Sitemap": "yes" if scope["sitemap_used"] else "no",
            "Queue remaining": scope["queue_remaining"],
            "Stop reason": scope.get("stop_reason") or "—",
            "HTTP → HTTPS": probe_text,
        }
        st.markdown(
            "<dl class='kv'>"
            + "".join(f"<dt>{theme.esc(k)}</dt><dd>{theme.esc(v)}</dd>" for k, v in items.items())
            + "</dl>",
            unsafe_allow_html=True,
        )
    with right, st.container(border=True):
        st.markdown("##### Excluded from the crawl")
        skipped = [{"Reason": k, "URLs": v} for k, v in report.get("skipped", {}).items()]
        if skipped:
            st.altair_chart(theme.horizontal_bars(skipped, "Reason", "URLs", theme.SUBTLE), width="stretch")
        else:
            st.caption("Nothing excluded.")
        st.markdown("##### Route attempts")
        for attempt in report["route"].get("attempts", []):
            tone = "ok" if attempt["ok"] else "bad"
            st.markdown(
                f"{theme.pill('ok' if attempt['ok'] else 'failed', tone)} &nbsp;{theme.esc(attempt['route'])} "
                f"<span class='domain-progress'>· {theme.esc(attempt['detail'])}</span>",
                unsafe_allow_html=True,
            )
    st.markdown("##### Pages assessed")
    pages = pd.DataFrame(report.get("pages", []))
    if not pages.empty:
        columns = [c for c in ("url", "status", "depth", "source", "findings", "error") if c in pages]
        st.dataframe(
            pages[columns].rename(
                columns={
                    "url": "URL",
                    "status": "HTTP",
                    "depth": "Depth",
                    "source": "Source",
                    "findings": "Issues",
                    "error": "Error",
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
        "Download HTML report", html, file_name=html_path.name, mime="text/html", type="primary", width="stretch"
    )
    right.download_button(
        "Download JSON data",
        json.dumps(report, indent=2, ensure_ascii=True),
        file_name=entry.path.name,
        mime="application/json",
        width="stretch",
    )
    st.caption(f"Files in {entry.path.parent}")


def render() -> None:
    head, picker = st.columns([3, 2], vertical_alignment="bottom")
    with picker:
        entry = _pick_report()
    if entry is None:
        with head:
            theme.page_header("Domain", "Details of one report.", eyebrow="Domain")
        theme.note("There are no reports yet. Start a scan on the New scan page.")
        return
    report = entry.report
    status = STATUS_LABELS[status_kind(report["status"])]
    with head:
        theme.page_header(
            entry.host,
            f"{report['started_at'][:19].replace('T', ' ')} UTC · route {report['route'].get('selected') or 'none'}",
            eyebrow="Domain",
            right=theme.status_pill(status),
        )
    theme.note(report["status"], warn=status != "Complete")
    st.markdown("&nbsp;")
    passed, total = controls_passed(report)
    counts = severity_counts(report)
    severe = counts["Critical"] + counts["High"]
    theme.kpi_row(
        [
            theme.kpi(
                "Pages assessed",
                report["scope"]["pages_assessed"],
                f"{report['scope']['pages_failed']} failed",
                "info",
            ),
            theme.kpi(
                "Controls passed", f"{passed}/{total}", "rules without issues", "ok" if passed == total else "warn"
            ),
            theme.kpi(
                "Distinct issues",
                len(report["groups"]),
                "grouped by evidence",
                "warn" if report["groups"] else "ok",
            ),
            theme.kpi("Critical and high", severe, "fix first", "bad" if severe else "ok"),
            theme.kpi("Cookies", len(report.get("cookies", {}).get("inventory", [])), "observed", "info"),
        ]
    )
    st.markdown("&nbsp;")
    tabs = st.tabs(["Overview", "Issues", "BitSight", "Cookies", "Coverage", "Export"])
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
