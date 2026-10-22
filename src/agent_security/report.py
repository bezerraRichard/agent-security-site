"""HTML/JSON report rendering, laid out like the earlier PDF report."""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_security.taxonomy import RULE_INFO, SECTIONS, SEVERITIES, section_of

URL_LIST_LIMIT = 200
PAGES_TABLE_LIMIT = 1000

CSS = """
body{font:15px/1.5 -apple-system,'Segoe UI',system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#212529}
h1{border-bottom:1px solid #dee2e6;padding-bottom:.4rem}
h2.section{background:#f1f3f5;border-left:4px solid #0d6efd;padding:.5rem .8rem;margin:2rem 0 .8rem;font-size:1.15rem}
.count{background:#0d6efd;color:#fff;border-radius:1rem;padding:0 .5rem;font-size:.8rem;margin-left:.4rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0 1.2rem;font-size:.9rem}
th,td{border:1px solid #dee2e6;padding:.45rem .6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f8f9fa}td.detail{background:#fff;padding:.8rem 1rem}
code,pre{font:.8rem/1.4 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
pre{background:#f8f9fa;padding:.6rem;margin:.3rem 0}
.badge{display:inline-block;color:#fff;border-radius:.3rem;padding:.05rem .5rem;font-size:.8rem}
.sev-critical{background:#8b0000}.sev-high{background:#dc3545}.sev-medium{background:#d39e00}
.sev-low{background:#0d6efd}.sev-info{background:#6c757d}
.cards{display:flex;gap:.8rem;flex-wrap:wrap}.card{flex:1;min-width:130px;border:1px solid #dee2e6;border-radius:.5rem;padding:.7rem;text-align:center}
.num{font-size:1.9rem;font-weight:700}.sub,.muted{color:#6c757d;font-size:.8rem}
.cat-ok{background:#198754}.cat-warn{background:#d39e00}.cat-muted{background:#6c757d}
.notice{padding:.8rem 1rem;border-left:4px solid #d39e00;background:#fff8e8;margin:1rem 0}
h5{margin:.8rem 0 .2rem}ul{margin:.3rem 0}
@media print{tr,.card{break-inside:avoid}}
"""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def link(url: str) -> str:
    if url.startswith(("https://", "http://")):
        return f'<a href="{esc(url)}">{esc(url)}</a>'
    return esc(url)


def badge(severity: str) -> str:
    return f'<span class="badge sev-{esc(severity.lower())}">{esc(severity)}</span>'


def category_label(classification: dict | None) -> tuple[str, str]:
    if not classification:
        return "Not classified", "cat-muted"
    status = classification["status"]
    if status == "classified":
        return str(classification["category"]), "cat-ok"
    if status == "uncategorized":
        return "Uncategorized in OneTrust", "cat-warn"
    if status == "not_found":
        return "Not found in OneTrust", "cat-warn"
    return "Lookup failed", "cat-muted"


def category_chip(classification: dict | None) -> str:
    text, css = category_label(classification)
    return f'<span class="badge {css}">{esc(text)}</span>'


def classification_notice(meta: dict) -> str:
    status = meta.get("status")
    if status == "not_configured":
        return (
            "Cookie classification is not configured. Set ONETRUST_HOSTNAME, ONETRUST_CLIENT_ID and "
            "ONETRUST_CLIENT_SECRET to classify cookies with the OneTrust Cookie Consent API."
        )
    if status == "no_cookies":
        return "No cookies were set by the pages assessed."
    if status == "unavailable":
        return f"OneTrust classification was unavailable: {meta.get('detail') or 'unknown error'}."
    where = f"{meta.get('hostname')}, language {meta.get('language')}, via {meta.get('route')}"
    scope = " (filtered to the configured domains)" if meta.get("domain_filter") else ""
    if status == "partial":
        return (
            f"Partial OneTrust classification ({where}){scope}: {meta.get('cookies_checked')} of "
            f"{meta.get('cookies_total')} cookies checked. {meta.get('detail') or ''}"
        )
    return f"Cookies classified with the OneTrust Cookie Consent API ({where}){scope}."


def cookie_inventory_html(cookies: dict) -> str:
    inventory = cookies["inventory"]
    notice = f'<div class="notice">{esc(classification_notice(cookies["classification"]))}</div>'
    if not inventory:
        return notice
    labels = {}
    for cookie in inventory:
        text, css = category_label(cookie.get("classification"))
        labels[text] = css
    totals = Counter(category_label(c.get("classification"))[0] for c in inventory)
    summary = "".join(
        f"<tr><td><span class='badge {labels[name]}'>{esc(name)}</span></td><td>{count}</td></tr>"
        for name, count in sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    )
    rows = []
    for cookie in inventory:
        info = cookie.get("classification") or {}
        third = info.get("third_party")
        party = "—" if third is None else ("Third party" if third else "First party")
        lifespan = " ".join(
            part for part in (info.get("lifespan"), f"({info['duration']})" if info.get("duration") else "") if part
        )
        extra = (
            f"<br><span class='muted'>{cookie['variants']} attribute variants</span>" if cookie["variants"] > 1 else ""
        )
        rows.append(
            f"<tr><td><code>{esc(cookie['name'])}</code></td><td>{category_chip(cookie.get('classification'))}</td>"
            f"<td>{esc(party)}</td><td>{esc(lifespan or '—')}</td><td>{cookie['pages']}</td>"
            f"<td><code>{esc(cookie['attributes'] or '—')}</code>{extra}</td>"
            f"<td>{esc(info.get('description') or '—')}</td></tr>"
        )
    return (
        f"{notice}<h4>Cookies by category</h4><table><thead><tr><th>Category</th><th>Cookies</th></tr></thead>"
        f"<tbody>{summary}</tbody></table><h4>Cookie inventory</h4>"
        "<table><thead><tr><th>Cookie</th><th>Category</th><th>Party</th><th>Lifespan</th><th>Pages</th>"
        f"<th>Attributes observed</th><th>Description</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def finding_rows(group: dict, inventory: dict) -> str:
    description, references = RULE_INFO.get(group["rule"], ("", []))
    urls = group["urls"]
    more = f' <span class="muted">+{len(urls) - 1} more</span>' if len(urls) > 1 else ""
    items = "".join(f"<li>{link(u)}</li>" for u in urls[:URL_LIST_LIMIT])
    if len(urls) > URL_LIST_LIMIT:
        items += f"<li>… {len(urls) - URL_LIST_LIMIT} more in the JSON report</li>"
    cookie = group.get("cookie")
    classification = (
        f"<p><b>Cookie classification:</b> {category_chip(inventory.get(cookie, {}).get('classification'))}</p>"
        if cookie
        else ""
    )
    refs = "".join(f'<li><a href="{esc(r)}">{esc(r)}</a></li>' for r in references)
    return (
        f"<tr><td>{badge(group['severity'])}</td><td><code>{esc(group['rule'])}</code></td>"
        f"<td>{esc(group['title'])}</td><td>{link(urls[0])}{more}</td><td>{esc(', '.join(group.get('sources') or []))}</td></tr>"
        f"<tr><td class='detail' colspan='5'><p>{esc(description)}</p><p><b>Affected pages:</b> {group['count']}</p>"
        f"{classification}<p><b>Current value:</b> <code>{esc(group['evidence'])}</code></p>"
        f"<p><b>Expected:</b> <code>{esc(group['expected'])}</code></p>"
        f"<h5>Remediation</h5><pre>{esc(group['remediation'])}</pre>"
        f"{f'<h5>References:</h5><ul>{refs}</ul>' if refs else ''}"
        f"<details><summary>Affected URLs ({len(urls)})</summary><ul>{items}</ul></details></td></tr>"
    )


def render_html(report: dict) -> str:
    summary = report["summary"]
    cards = "".join(
        f"<div class='card'>{badge(s)}<div class='num'>{summary['severity'][s]['distinct']}</div>"
        f"<div class='sub'>{summary['severity'][s]['instances']} page instances</div></div>"
        for s in SEVERITIES
    )
    section_rows = "".join(
        f"<tr><td>{esc(s)}</td><td>{summary['sections'][s]['distinct']}</td><td>{summary['sections'][s]['instances']}</td></tr>"
        for s in SECTIONS
    )
    by_section: dict[str, list] = defaultdict(list)
    for group in report["groups"]:
        by_section[section_of(group["rule"])].append(group)
    inventory = {c["name"]: c for c in report["cookies"]["inventory"]}

    toc, blocks = [], []
    for section in SECTIONS:
        groups = by_section.get(section)
        slug = section.lower().replace(" ", "-")
        if section == "Cookies":
            toc.append("<li><a href='#cookie-inventory'>Cookie classification</a></li>")
        if not groups:
            continue
        toc.append(f"<li><a href='#{slug}'>{esc(section)}</a> <span class='count'>{len(groups)}</span></li>")
        rows = "".join(finding_rows(g, inventory) for g in groups)
        blocks.append(
            f"<h2 class='section' id='{slug}'>{esc(section)} <span class='count'>{len(groups)}</span></h2>"
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>URL</th><th>Source</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    scope = report["scope"]
    scope_rows = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>"
        for label, value in (
            ("Route", report["route"]["selected"] or "none"),
            ("Authorized hosts", ", ".join(scope["allowed_hosts"])),
            ("Pages assessed", scope["pages_assessed"]),
            ("Page requests failed", scope["pages_failed"]),
            ("Page limit / depth limit", f"{scope['max_pages']} / {scope['max_depth']}"),
            ("Request delay (s)", scope["delay_seconds"]),
            ("robots.txt honored", scope["respect_robots"]),
            ("Sitemap used", scope["sitemap_used"]),
            ("Queue left unvisited", scope["queue_remaining"]),
            ("HTTP status counts", json.dumps(scope["status_counts"])),
        )
    )
    attempts = "".join(
        f"<li>{esc(a['route'])}: {'selected' if a['ok'] else 'failed'} — {esc(a['detail'])}</li>"
        for a in report["route"]["attempts"]
    )
    skipped = "".join(f"<li>{esc(reason)}: {count}</li>" for reason, count in report["skipped"].items())
    failed = "".join(f"<li>{esc(p['url'])}: {esc(p['error'])}</li>" for p in report["pages"] if p["error"])
    probe = report["http_probe"]
    probe_text = (
        f"{probe['requested_url']} ended at {probe['final_url']} (HTTP {probe['status']})"
        if probe and not probe["error"]
        else f"not completed ({probe['error'] if probe else 'not run'})"
    )
    pages = report["pages"][:PAGES_TABLE_LIMIT]
    page_rows = "".join(
        f"<tr><td>{link(p['url'])}</td><td>{esc(p['status'] or 'ERR')}</td><td>{esc(p['depth'])}</td>"
        f"<td>{esc(p['source'])}</td><td>{p['findings']}</td></tr>"
        for p in pages
    )
    page_note = (
        f"<p class='muted'>Showing {len(pages)} of {len(report['pages'])} pages; the rest are in the JSON report.</p>"
        if len(report["pages"]) > len(pages)
        else ""
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>HTTP Security Report - {esc(report['target'])}</title><style>{CSS}</style></head><body>"
        f"<h1>HTTP Security Report</h1><p>Started at <code>{esc(report['started_at'])}</code> — finished at "
        f"<code>{esc(report['finished_at'])}</code></p>"
        f"<div class='notice'><b>Status:</b> {esc(report['status'])}<br>{esc(report['methodology'])}</div>"
        f"<h2 class='section'>Summary by severity</h2><div class='cards'>{cards}</div>"
        "<h2 class='section'>Summary by section</h2><table><thead><tr><th>Section</th><th>Distinct issues</th>"
        f"<th>Page instances</th></tr></thead><tbody>{section_rows}</tbody></table>"
        f"<h2 class='section'>{esc(report['target'])}</h2><ul>{''.join(toc)}</ul>"
        f"<h2 class='section' id='cookie-inventory'>Cookie classification</h2>{cookie_inventory_html(report['cookies'])}"
        f"{''.join(blocks) or '<p>No confirmed findings in the pages assessed.</p>'}"
        f"<h2 class='section'>Scope and coverage</h2><table><tbody>{scope_rows}</tbody></table>"
        f"<h4>Route attempts</h4><ul>{attempts}</ul><p><b>HTTP→HTTPS probe:</b> {esc(probe_text)}</p>"
        f"<h4>Excluded from the crawl</h4><ul>{skipped or '<li>none</li>'}</ul>"
        f"{f'<h4>Failed requests</h4><ul>{failed}</ul>' if failed else ''}"
        "<h2 class='section'>Pages assessed</h2><table><thead><tr><th>URL</th><th>Status</th><th>Depth</th>"
        f"<th>Source</th><th>Issues</th></tr></thead><tbody>{page_rows}</tbody></table>{page_note}"
        "<p class='muted'>Cookie values are redacted. Only GET requests were sent. Cookie names are sent to the "
        "configured OneTrust tenant for classification.</p></body></html>"
    )


def write_reports(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write ``<name>.html`` and ``<name>.json``; an existing report is never overwritten."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for attempt in range(100):
        base = output_dir / f"site-security-report-{stamp}{f'-{attempt}' if attempt else ''}"
        html_path, json_path = base.with_suffix(".html"), base.with_suffix(".json")
        if html_path.exists() or json_path.exists():
            continue
        with html_path.open("x", encoding="utf-8") as html_file, json_path.open("x", encoding="utf-8") as json_file:
            html_file.write(render_html(report))
            json_file.write(json.dumps(report, indent=2, ensure_ascii=True))
        return html_path, json_path
    raise FileExistsError(f"could not find a free report name in {output_dir}")
