"""HTML/JSON report rendering, laid out like the earlier PDF report, with the novobanco visual identity."""

from __future__ import annotations

import base64
import html
import json
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_security.taxonomy import BITSIGHT_CATEGORIES, RULE_INFO, SECTIONS, SEVERITIES, bitsight_of, section_of

URL_LIST_LIMIT = 200
PAGES_TABLE_LIMIT = 1000

LOGO_PATH = Path(__file__).parent / "console" / "novobanco.svg"

# novobanco palette (from www.novobanco.pt), shared with the console theme.
CSS = """
:root{--primary:#009f98;--primary-dark:#007179;--ink:#273c4e;--muted:#54616c;--border:#d6e4e6;--surface:#edf4f5}
body{font:15px/1.5 -apple-system,'Segoe UI',system-ui,sans-serif;max-width:1100px;margin:0 auto 2rem;padding:0 1rem;color:var(--ink)}
a{color:var(--primary-dark)}
.brand{display:flex;justify-content:space-between;align-items:center;gap:1rem;border-bottom:3px solid var(--primary);padding:1.4rem 0 1rem;margin-bottom:1.2rem}
.brand img{height:28px;display:block}.brand .product{color:var(--muted);font-size:.85rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
h1{font-size:1.8rem;margin:.2rem 0 .3rem;color:var(--ink)}
h2.section{background:var(--surface);border-left:4px solid var(--primary);border-radius:0 .4rem .4rem 0;padding:.5rem .8rem;margin:2rem 0 .8rem;font-size:1.15rem;color:var(--ink)}
.count{background:var(--primary);color:#fff;border-radius:1rem;padding:0 .5rem;font-size:.8rem;margin-left:.4rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0 1.2rem;font-size:.9rem}
th,td{border:1px solid var(--border);padding:.45rem .6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:var(--surface);color:var(--ink)}td.detail{background:#fff;padding:.8rem 1rem}
code,pre{font:.8rem/1.4 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
pre{background:var(--surface);padding:.6rem;margin:.3rem 0;border-radius:.3rem}
.badge{display:inline-block;color:#fff;border-radius:.3rem;padding:.05rem .5rem;font-size:.8rem}
.sev-critical{background:#7a1f2b}.sev-high{background:#d64545}.sev-medium{background:#f2a93b}
.sev-low{background:#3e7cb1}.sev-info{background:#808b94}
.cards{display:flex;gap:.8rem;flex-wrap:wrap}.card{flex:1;min-width:130px;border:1px solid var(--border);border-radius:.6rem;padding:.7rem;text-align:center}
.num{font-size:1.9rem;font-weight:700}.sub,.muted{color:var(--muted);font-size:.8rem}
.cat-ok{background:var(--primary)}.cat-warn{background:#f2a93b}.cat-muted{background:#808b94}
.notice{padding:.8rem 1rem;border-left:4px solid #f7d54e;background:#fffbea;margin:1rem 0;border-radius:0 .4rem .4rem 0}
h5{margin:.8rem 0 .2rem}ul{margin:.3rem 0}
footer{margin-top:2.5rem;border-top:1px solid var(--border);padding-top:.8rem}
@media print{tr,.card{break-inside:avoid}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def logo_img() -> str:
    """The logo as an inline data URI, so the report stays a single self-contained file."""
    try:
        data = base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")
    except OSError:
        return ""
    return f"<img src='data:image/svg+xml;base64,{data}' alt='novobanco'>"


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
    bitsight = group.get("bitsight") or bitsight_of(group["rule"])
    bitsight_text = (
        f"{bitsight['vector']} — {bitsight['category']} — {bitsight['assessment']}"
        if bitsight["vector"]
        else "Not assessed by Bitsight"
    )
    return (
        f"<tr><td>{badge(group['severity'])}</td><td><code>{esc(group['rule'])}</code></td>"
        f"<td>{esc(group['title'])}</td><td>{link(urls[0])}{more}</td><td>{esc(', '.join(group.get('sources') or []))}</td></tr>"
        f"<tr><td class='detail' colspan='5'><p>{esc(description)}</p><p><b>Affected pages:</b> {group['count']}</p>"
        f"{classification}<p><b>Bitsight:</b> {esc(bitsight_text)}</p><p><b>Current value:</b> <code>{esc(group['evidence'])}</code></p>"
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
    bitsight_summary = summary.get("bitsight") or {}
    bitsight_rows = "".join(
        f"<tr><td>{esc(c)}</td><td>{bitsight_summary.get(c, {}).get('distinct', 0)}</td>"
        f"<td>{bitsight_summary.get(c, {}).get('instances', 0)}</td></tr>"
        for c in BITSIGHT_CATEGORIES
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
        f"<header class='brand'>{logo_img()}<span class='product'>HTTP Security Report</span></header>"
        f"<h1>{esc(report['target'])}</h1><p>Started at <code>{esc(report['started_at'])}</code> — finished at "
        f"<code>{esc(report['finished_at'])}</code></p>"
        f"<div class='notice'><b>Status:</b> {esc(report['status'])}<br>{esc(report['methodology'])}</div>"
        f"<h2 class='section'>Summary by severity</h2><div class='cards'>{cards}</div>"
        "<h2 class='section'>Summary by section</h2><table><thead><tr><th>Section</th><th>Distinct issues</th>"
        f"<th>Page instances</th></tr></thead><tbody>{section_rows}</tbody></table>"
        "<h2 class='section'>Bitsight alignment</h2><p class='muted'>Approximate mapping to the Bitsight Web "
        "Application Security risk vector, based on Bitsight's public documentation. Bitsight assesses only each "
        "domain's landing page; this scan covers every page crawled.</p><table><thead><tr><th>Bitsight category</th>"
        f"<th>Distinct issues</th><th>Page instances</th></tr></thead><tbody>{bitsight_rows}</tbody></table>"
        f"<h2 class='section'>{esc(report['target'])}</h2><ul>{''.join(toc)}</ul>"
        f"<h2 class='section' id='cookie-inventory'>Cookie classification</h2>{cookie_inventory_html(report['cookies'])}"
        f"{''.join(blocks) or '<p>No confirmed findings in the pages assessed.</p>'}"
        f"<h2 class='section'>Scope and coverage</h2><table><tbody>{scope_rows}</tbody></table>"
        f"<h4>Route attempts</h4><ul>{attempts}</ul><p><b>HTTP→HTTPS probe:</b> {esc(probe_text)}</p>"
        f"<h4>Excluded from the crawl</h4><ul>{skipped or '<li>none</li>'}</ul>"
        f"{f'<h4>Failed requests</h4><ul>{failed}</ul>' if failed else ''}"
        "<h2 class='section'>Pages assessed</h2><table><thead><tr><th>URL</th><th>Status</th><th>Depth</th>"
        f"<th>Source</th><th>Issues</th></tr></thead><tbody>{page_rows}</tbody></table>{page_note}"
        "<footer class='muted'>Cookie values are redacted. Only GET requests were sent. Cookie names are sent to the "
        "configured OneTrust tenant for classification.</footer></body></html>"
    )


def write_reports(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write ``<name>.html`` and ``<name>.json``; an existing report is never overwritten."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = urllib.parse.urlsplit(report["target"]).hostname or "site"
    for attempt in range(100):
        # Built by concatenation: with_suffix() would treat the ".com-..." of the host as an extension.
        base = f"site-security-report-{host}-{stamp}{f'-{attempt}' if attempt else ''}"
        html_path, json_path = output_dir / f"{base}.html", output_dir / f"{base}.json"
        if html_path.exists() or json_path.exists():
            continue
        with html_path.open("x", encoding="utf-8") as html_file, json_path.open("x", encoding="utf-8") as json_file:
            html_file.write(render_html(report))
            json_file.write(json.dumps(report, indent=2, ensure_ascii=True))
        return html_path, json_path
    raise FileExistsError(f"could not find a free report name in {output_dir}")
