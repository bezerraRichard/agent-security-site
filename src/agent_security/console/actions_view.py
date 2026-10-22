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
PRIORITY_HELP = "P1 fix now · P2 next cycle · P3 plan · P4 improvement"


def _priority_badge(priority: str) -> str:
    return f"<span class='sev' style='background:{PRIORITY_COLORS[priority]}'>{priority}</span>"


def _save(key: str, field: str) -> None:
    widget = f"{field}-{key}"
    save_action_state(state.reports_dir(), key, **{field: st.session_state[widget]})


def _action_card(action: Action, saved: dict) -> None:
    status = saved.get("status") or STATUSES[0]
    with st.container(border=True):
        warning = (
            " &nbsp;" + theme.pill("Still detected in the latest scan", "bad")
            if status == "Done"  # Every action in the plan was found in the batch shown.
            else ""
        )
        title = theme.esc(action.title.replace("`", ""))
        st.html(
            f"{_priority_badge(action.priority)} &nbsp;<b style='font-size:1.02rem'>{title}</b>"
            f"{warning}<div class='domain-progress' style='margin-top:.35rem'>"
            f"{theme.esc(saved.get('owner') or action.owner)} · effort {theme.esc(action.effort.lower())} · "
            f"{theme.esc(', '.join(action.domains))} · {action.pages} pages"
            + (f" · BitSight: {theme.esc(action.bitsight)}" if action.bitsight else "")
            + "</div>"
        )
        with st.expander("How to fix"):
            st.caption(action.why)
            st.markdown("\n".join(f"{n}. {step}" for n, step in enumerate(action.steps, start=1)))
            if action.snippet:
                st.code(action.snippet, language=action.snippet_language)
            st.markdown("**Verification**")
            st.code(action.verify, language="bash")
        columns = st.columns([1.2, 1.6, 2.2])
        columns[0].selectbox(
            "Status",
            STATUSES,
            index=STATUSES.index(status) if status in STATUSES else 0,
            key=f"status-{action.key}",
            on_change=_save,
            args=(action.key, "status"),
        )
        columns[1].text_input(
            "Owner",
            value=saved.get("owner") or "",
            placeholder=action.owner,
            key=f"owner-{action.key}",
            on_change=_save,
            args=(action.key, "owner"),
        )
        columns[2].text_input(
            "Note",
            value=saved.get("note") or "",
            placeholder="Ticket, deadline, decision…",
            key=f"note-{action.key}",
            on_change=_save,
            args=(action.key, "note"),
        )


def _actions_tab(plan: list[Action], saved: dict) -> None:
    filters = st.columns([2, 3, 2])
    priorities = filters[0].multiselect("Priority", list(PRIORITY_COLORS), placeholder="All", help=PRIORITY_HELP)
    owners = filters[1].multiselect("Owner", sorted({a.owner for a in plan}), placeholder="All")
    statuses = filters[2].multiselect("Status", list(STATUSES), placeholder="All")
    visible = [
        action
        for action in plan
        if (not priorities or action.priority in priorities)
        and (not owners or action.owner in owners)
        and (not statuses or (saved.get(action.key, {}).get("status") or STATUSES[0]) in statuses)
    ]
    if not visible:
        st.caption("No action matches the filters.")
    for action in visible:
        _action_card(action, saved.get(action.key, {}))


def _integrations_tab(plan: list[Action], batch_reports: list[dict]) -> None:
    aem_cloud = any((r.get("platform") or {}).get("cms") == AEM_CLOUD for r in batch_reports)
    left, right = st.columns(2, gap="large")
    with left, st.container(border=True):
        st.markdown("##### Adobe Experience Manager")
        if aem_cloud:
            st.html(theme.pill("AEM as a Cloud Service detected", "ok"))
            st.markdown(
                "Security headers are fixed in the Adobe CDN, with a `cdn.yaml` file in the AEM repository, deployed "
                "by the Cloud Manager **Config Pipeline**:\n"
                "1. Review the suggested file below and merge it into `config/cdn.yaml`.\n"
                "2. Deploy to dev and stage, validate, then promote to production.\n"
                "3. Scan the domains again to confirm.\n\n"
                "The current CSP headers may come from another layer (Dispatcher or application): when changing "
                "the CSP, confirm where it comes from and remove the old headers, because the browser enforces "
                "every policy together."
            )
            config = aem_cdn_config(plan)
            if config:
                st.code(config, language="yaml")
                st.download_button("Download suggested cdn.yaml", config, file_name="cdn.yaml", mime="text/yaml")
            else:
                st.caption("No headers to add through the CDN in this batch.")
        else:
            st.html(theme.pill("AEM as a Cloud Service not detected in this batch", "neutral"))
            st.caption("The actions show the configuration for Dispatcher/Apache or for the detected CDN.")
    with right, st.container(border=True):
        st.markdown("##### OneTrust")
        statuses = Counter(r.get("cookies", {}).get("classification", {}).get("status") for r in batch_reports)
        if statuses.get("not_configured"):
            st.html(theme.pill("OneTrust classification not configured in the scans", "warn"))
        else:
            st.html(theme.pill("OneTrust classification used in the scans", "ok"))
        onetrust = [a for a in plan if a.key.startswith("ONETRUST-") or a.owner.startswith("OneTrust")]
        st.markdown(
            "The console **reads** the cookie catalogue (*Get List of Cookies by Criteria* API, `COOKIE_READ` scope). "
            "**Categorization** can be done below, with confirmation, through the *Update Cookie* API "
            "(`PUT /api/cookiemanager/v1/cookies`, `COOKIE` scope, separate credentials). Registering missing "
            "cookies and new domain scans are still done in OneTrust. The Secure/HttpOnly/SameSite attributes "
            "cannot be fixed in OneTrust: they depend on whoever sends the cookie."
        )
        if onetrust:
            for action in onetrust:
                st.html(f"{_priority_badge(action.priority)} &nbsp;{theme.esc(action.title.replace('`', ''))}")
        else:
            st.caption("No OneTrust actions in this batch.")
    _categorize_section(batch_reports)


@st.dialog("Confirm OneTrust changes", width="large")
def _confirm_changes(changes: list[CategoryChange], tenant: str) -> None:
    st.warning(
        f"You are about to change the category of {len(changes)} cookie(s) in tenant **{tenant}**. The change is "
        "saved in the OneTrust catalogue and reaches the consent banner once the domain script is published."
    )
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Cookie": c.cookie_name,
                    "Host": c.host or "—",
                    "Current category": c.current_category or "uncategorized",
                    "New category": c.new_category_id,
                }
                for c in changes
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    with st.expander("Requests that will be sent"):
        st.code(
            "\n\n".join(f"PUT {UPDATE_COOKIE_PATH}\n{json.dumps(c.payload(), indent=2)}" for c in changes),
            language="http",
        )
    st.caption(
        "Each cookie is read again from the catalogue before it is changed; the previous category is kept in the "
        "change log."
    )
    confirmed = st.checkbox("I confirm these changes have been approved and I want to apply them in OneTrust.")
    left, right = st.columns(2)
    if left.button("Cancel", width="stretch"):
        st.rerun()
    if right.button(f"Apply {len(changes)} change(s)", type="primary", disabled=not confirmed, width="stretch"):
        config = write_config_from_env(os.environ)  # Credentials come from the environment, never from the page.
        if config is None:
            st.error("The OneTrust write credentials are no longer set.")
            return
        with st.spinner("Applying in OneTrust…"):
            results = apply_category_changes(make_write_client(config), changes, state.reports_dir() / AUDIT_FILE)
        st.session_state["onetrust_results"] = results
        st.rerun()


def _categorize_section(batch_reports: list[dict]) -> None:
    st.markdown("&nbsp;")
    with st.container(border=True):
        st.markdown("##### Categorize cookies in OneTrust")
        try:
            config = write_config_from_env(os.environ)
        except ValueError as error:
            st.error(str(error))
            return
        cookies = categorizable_cookies(batch_reports)
        if not cookies:
            theme.note(
                "No cookie in this batch has a OneTrust ID. Run the scan again with OneTrust classification on "
                "(older scans did not store the ID)."
            )
            return
        if config is None:
            theme.note(
                "Writing to OneTrust is off. To turn it on, create a OneTrust API client with the COOKIE scope (read "
                "and write), set ONETRUST_WRITE_CLIENT_ID and ONETRUST_WRITE_CLIENT_SECRET (e.g. in .env) and restart "
                "the console. The read credentials (COOKIE_READ) are still used by the scans.",
                warn=True,
            )
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Cookie": c["name"], "Host": c["host"] or "—", "Category": c["category"] or "uncategorized"}
                        for c in cookies
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            return
        st.html(theme.pill(f"Writing enabled · {config.hostname}", "warn"))
        labels = {
            c["cookie_id"]: f"{c['name']} · {c['host'] or '—'} · {c['category'] or 'uncategorized'}" for c in cookies
        }
        selected = st.multiselect(
            "Cookies to change",
            list(labels),
            format_func=lambda cookie_id: labels[cookie_id],
            max_selections=MAX_CHANGES_PER_RUN,
            placeholder="Choose the cookies (uncategorized ones come first)",
        )
        left, right = st.columns([2, 1])
        choice = left.selectbox(
            "New category",
            [*STANDARD_CATEGORIES, "custom"],
            format_func=lambda c: f"{c} · {STANDARD_CATEGORIES[c]}" if c in STANDARD_CATEGORIES else "Other ID…",
            help="OneTrust default IDs. If the tenant uses its own categories, choose Other ID.",
        )
        category_id = (
            right.text_input("Category ID", placeholder="e.g. C0007") if choice == "custom" else (choice or "")
        ).strip()
        if st.button("Review changes", type="primary", disabled=not selected or not category_id):
            changes = build_changes([c for c in cookies if c["cookie_id"] in selected], category_id)
            try:
                validate_changes(changes)
            except ValueError as error:
                st.error(str(error))
            else:
                _confirm_changes(changes, config.hostname)
        results = st.session_state.get("onetrust_results")
        if results:
            st.markdown("**Result of the last change**")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Cookie": r["cookie_name"],
                            "Before": r.get("before") or "uncategorized",
                            "New category": r["new_category_id"],
                            "Result": STATUS_LABELS.get(r["status"], r["status"]),
                            "Detail": r.get("detail") or "",
                        }
                        for r in results
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            st.caption("Publish the domain script in OneTrust and scan again to confirm.")
    audit = read_audit(state.reports_dir() / AUDIT_FILE)
    if audit:
        with st.expander(f"OneTrust change log ({len(audit)} most recent)"):
            st.dataframe(pd.DataFrame(audit), hide_index=True, width="stretch")


def render() -> None:
    all_batches = state.batches()
    head, picker = st.columns([3, 2], vertical_alignment="bottom")
    with head:
        theme.page_header("Action plan", "What to fix, who fixes it, how, and how to verify.", eyebrow="Remediation")
    if not all_batches:
        theme.note("There are no reports yet. Start a scan on the New scan page.")
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
            theme.kpi("Actions", len(plan), f"{len(batch.reports)} domains", "info"),
            theme.kpi("P1 · fix now", counts["P1"], "critical or wide-reaching", "bad" if counts["P1"] else "ok"),
            theme.kpi("P2 · next cycle", counts["P2"], "high priority", "warn" if counts["P2"] else "ok"),
            theme.kpi("In progress", statuses["In progress"], "with an owner", "info"),
            theme.kpi(
                "Done or accepted",
                statuses["Done"] + statuses["Risk accepted"],
                "to confirm in the next scan",
                "ok",
            ),
        ]
    )
    st.markdown("&nbsp;")
    with st.expander("Detected platform", expanded=False):
        st.dataframe(pd.DataFrame(platform_rows(batch.reports)), hide_index=True, width="stretch")
    if not plan:
        st.success("Nothing to fix in this batch.")
        return
    tabs = st.tabs(["Actions", "Adobe and OneTrust integrations", "Export"])
    with tabs[0]:
        _actions_tab(plan, saved)
    with tabs[1]:
        _integrations_tab(plan, reports)
    with tabs[2]:
        rows = action_rows(plan, saved)
        st.dataframe(pd.DataFrame(rows).drop(columns=["Key"]), hide_index=True, width="stretch")
        left, right = st.columns(2)
        left.download_button(
            "Download CSV",
            pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig"),
            file_name=f"action-plan-{batch.id}.csv",
            mime="text/csv",
            type="primary",
            width="stretch",
        )
        right.download_button(
            "Download Markdown",
            markdown_plan(plan, saved, f"Action plan · {batch.label}"),
            file_name=f"action-plan-{batch.id}.md",
            mime="text/markdown",
            width="stretch",
        )
