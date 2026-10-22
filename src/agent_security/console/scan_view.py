"""New scan page: domains, limits, network, OneTrust and live progress."""

from __future__ import annotations

import os

import streamlit as st

from agent_security.config import HARD_MAX_PAGES, MIN_DELAY_SECONDS
from agent_security.console import state, theme
from agent_security.console.forms import PROFILES, ScanOptions, build_configs, parse_domain_lines, split_hosts
from agent_security.console.jobs import ScanJob

STATE_LABELS = {
    "queued": ("Queued", "neutral"),
    "running": ("Scanning", "warn"),
    "done": ("Done", "ok"),
    "failed": ("Failed", "bad"),
    "cancelled": ("Cancelled", "neutral"),
}
ROUTES = {
    "auto": "Automatic (system proxy, then direct)",
    "proxy": "Explicit proxy",
    "direct": "Direct connection",
}


def _limits() -> tuple[int, int, float, float]:
    profile = st.segmented_control("Scan profile", [*PROFILES, "Custom"], default="Conservative", key="profile")
    if profile in PROFILES:
        pages, depth, delay, minutes = PROFILES[profile]
        st.caption(f"Up to {pages} pages per domain · depth {depth} · {delay:g} s between requests · {minutes:g} min")
        return pages, depth, delay, minutes
    columns = st.columns(4)
    pages = columns[0].number_input("Max pages", 1, HARD_MAX_PAGES, 100, step=50)
    depth = columns[1].number_input("Depth", 0, 50, 3)
    delay = columns[2].number_input("Delay (s)", MIN_DELAY_SECONDS, 30.0, 1.0, step=0.1, format="%.1f")
    minutes = columns[3].number_input("Time limit (min)", 1.0, 600.0, 20.0, step=5.0)
    return int(pages), int(depth), float(delay), float(minutes)


def _form() -> None:
    with st.container(border=True):
        st.markdown("##### Domains")
        text = st.text_area(
            "Domains",
            key="domains",
            height=130,
            placeholder="www.example.com\nwww.example.org  shop.example.org  cdn.example.org",
            label_visibility="collapsed",
        )
        st.caption(
            "One domain per line; other authorized hostnames for that domain can follow on the same line. "
            "Each domain is scanned separately and gets its own report."
        )
        rows = parse_domain_lines(text)
        if rows:
            # st.html, not st.markdown: markdown would turn the hostnames into links.
            st.html(
                " ".join(
                    theme.pill(domain + (f" + {len(split_hosts(extra))} hosts" if extra else ""), "neutral")
                    for domain, extra in rows
                )
            )

    with st.container(border=True):
        st.markdown("##### Limits")
        pages, depth, delay, minutes = _limits()
        left, right = st.columns(2)
        sitemap = left.toggle("Use sitemap.xml as a starting point", value=False)
        robots = right.toggle("Respect robots.txt", value=True)
        if not robots:
            theme.note("Only ignore robots.txt when the site owner has explicitly asked you to.", warn=True)

    with st.expander("Network"):
        route = st.radio("Route", list(ROUTES), format_func=lambda route: ROUTES[route], horizontal=True)
        proxy, fallback = "", False
        if route == "proxy":
            proxy = st.text_input("Proxy URL", placeholder="http://proxy.example:8080")
            fallback = st.checkbox("If the proxy fails, try a direct connection")
        ca_bundle = st.text_input("PEM file with extra CAs (optional)", help="E.g. a corporate TLS-inspection CA")

    onetrust = state.onetrust_status()
    with st.container(border=True):
        st.markdown("##### Cookie classification (OneTrust)")
        if onetrust["configured"]:
            st.markdown(
                theme.pill("Configured", "ok")
                + f"&nbsp; <span class='domain-progress'>{theme.esc(onetrust['hostname'])}"
                f" · language {theme.esc(onetrust['language'])}</span>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(theme.pill(onetrust["detail"], "neutral"), unsafe_allow_html=True)
            st.caption(
                "Set ONETRUST_HOSTNAME, ONETRUST_CLIENT_ID and ONETRUST_CLIENT_SECRET (e.g. in .env) before "
                "starting the console."
            )
        classify = st.toggle("Classify cookies", value=onetrust["configured"], disabled=not onetrust["configured"])
        language, domain_ids = "", ""
        if onetrust["configured"] and classify:
            left, right = st.columns([1, 3])
            language = left.text_input("Language", placeholder=onetrust["language"])
            domain_ids = right.text_input("OneTrust domain IDs (optional)", help="Comma-separated UUIDs")
        st.caption("Only cookie names are sent to your OneTrust tenant; values are never stored.")

    authorized = st.checkbox(
        "I confirm I have written authorization to assess every domain and host listed.", key="authorized"
    )
    registry = state.registry()
    busy = bool(registry.current and registry.current.running)
    has_domains = bool(rows)
    if st.button(
        "Start scan",
        type="primary",
        width="stretch",
        disabled=busy or not authorized or not has_domains,
        help="A scan is already running." if busy else None,
    ):
        options = ScanOptions(
            max_pages=pages,
            max_depth=depth,
            delay_seconds=delay,
            time_limit_minutes=minutes,
            respect_robots=robots,
            sitemap=sitemap,
            route=route or "auto",
            proxy=proxy,
            fallback_direct=fallback,
            ca_bundle=ca_bundle,
            classify_cookies=classify,
            onetrust_language=language.strip(),
            onetrust_domain_ids=tuple(split_hosts(domain_ids)),
        )
        try:
            configs = build_configs(rows, options, os.environ)
            job = registry.start(configs, state.reports_dir())
        except (ValueError, RuntimeError) as error:
            st.error(str(error))
        else:
            state.select_batch(job.id)
            st.rerun()


def _job_body(job: ScanJob) -> None:
    done = sum(d.state in {"done", "failed", "cancelled"} for d in job.domains)
    headline = "Running" if job.running else ("Cancelled" if job.cancel_requested else "Finished")
    tone = "warn" if job.running else ("neutral" if job.cancel_requested else "ok")
    st.markdown(
        f"{theme.pill(headline, tone)} &nbsp;<span class='domain-progress'>Batch {theme.esc(job.id)} · "
        f"{done}/{len(job.domains)} domains</span>",
        unsafe_allow_html=True,
    )
    for domain in job.domains:
        label, tone = STATE_LABELS[domain.state]
        with st.container(border=True):
            st.html(f"<b>{theme.esc(domain.target)}</b> &nbsp; {theme.pill(label, tone)}")
            if domain.state == "running":
                st.progress(
                    min(domain.pages / max(domain.max_pages, 1), 1.0), text=f"{domain.pages}/{domain.max_pages} pages"
                )
                st.markdown(f"<div class='domain-progress'>{theme.esc(domain.last_url)}</div>", unsafe_allow_html=True)
            elif domain.state in {"done", "cancelled"} and domain.status:
                st.markdown(
                    f"<div class='domain-progress'>{domain.pages} pages · {domain.findings} distinct issues · "
                    f"{theme.esc(domain.status)}</div>",
                    unsafe_allow_html=True,
                )
            elif domain.state == "failed":
                st.error(domain.error or "Unknown error")
    if job.error:
        st.error(job.error)
    if job.running:
        if st.button("Cancel scan", disabled=job.cancel_requested, width="stretch"):
            job.cancel()
    elif st.button("Open batch dashboard", type="primary", width="stretch"):
        state.select_batch(job.id)
        st.switch_page(st.session_state["pages"]["dashboard"])


@st.fragment(run_every=1.0)
def _live_job(job: ScanJob) -> None:
    if not job.running:
        st.rerun()  # Re-render the whole page so the finished batch shows up everywhere.
    _job_body(job)


def render() -> None:
    theme.page_header(
        "New scan",
        "Passive scan of headers, CSP, cookies and content, with BitSight alignment and OneTrust classification.",
        eyebrow="Scan",
    )
    form, progress = st.columns([3, 2], gap="large")
    with form:
        _form()
    with progress:
        st.markdown("##### Progress")
        job = state.registry().current
        if job is None:
            theme.note("No scan started in this console session.")
        elif job.running:
            _live_job(job)
        else:
            _job_body(job)
        st.markdown("&nbsp;")
        theme.note(
            "GET requests only, one at a time, with a delay between requests. No authentication, forms or attack "
            "payloads, and redirects outside the authorized hosts are not followed."
        )
