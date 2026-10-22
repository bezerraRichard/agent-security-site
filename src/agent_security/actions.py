"""Action plan: turn the findings of one or more reports into prioritised, owner-specific remediation steps."""

from __future__ import annotations

import json
import math
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_security.fingerprint import AEM, AEM_CLOUD
from agent_security.taxonomy import SEVERITY_ORDER, bitsight_of

SEVERITY_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Info": 5}
PRIORITY_THRESHOLDS = (("P1", 90), ("P2", 60), ("P3", 30))
STATUSES = ("To do", "In progress", "Done", "Risk accepted")
# Status values saved by the console before it was translated to English.
LEGACY_STATUSES = dict(zip(("Por fazer", "Em curso", "Feito", "Risco aceite"), STATUSES, strict=True))
# Cookies written by the OneTrust banner script: they must stay readable by JavaScript.
ONETRUST_COOKIES = ("OptanonConsent", "OptanonAlertBoxClosed", "eupubconsent", "OTAdditionalConsentString")
NECESSARY_HINTS = ("necess", "essential", "essencia", "strictly", "estritamente")
ONETRUST_UPDATE_COOKIE = "PUT /api/cookiemanager/v1/cookies"


@dataclass
class Action:
    key: str
    title: str
    severity: str
    owner: str
    effort: str
    why: str
    steps: list[str]
    verify: str
    snippet: str = ""
    snippet_language: str = "text"
    bitsight: str | None = None
    rules: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    pages: int = 0

    @property
    def score(self) -> float:
        score: float = SEVERITY_WEIGHT.get(self.severity, 0) + (15 if self.bitsight else 0)
        score += min(15.0, 5 * math.log10(self.pages + 1)) + 5 * max(len(self.domains) - 1, 0)
        return round(score, 1)

    @property
    def priority(self) -> str:
        return next((name for name, minimum in PRIORITY_THRESHOLDS if self.score >= minimum), "P4")


@dataclass(frozen=True)
class Platform:
    cdn: str | None = None
    cms: str | None = None
    technologies: tuple[str, ...] = ()

    @property
    def aem_cloud(self) -> bool:
        return self.cms == AEM_CLOUD

    @property
    def aem(self) -> bool:
        return self.cms in {AEM, AEM_CLOUD}

    def header_owner(self) -> str:
        if self.aem_cloud:
            return "Adobe AEM · CDN (cdn.yaml, Config Pipeline)"
        if self.aem:
            return "Adobe AEM · Dispatcher (vhost)"
        return f"CDN {self.cdn}" if self.cdn else "Web server / reverse proxy"


def platform_of(report: dict[str, Any]) -> Platform:
    info = report.get("platform") or {}
    return Platform(info.get("cdn"), info.get("cms"), tuple(info.get("technologies") or ()))


def _yaml(value: str) -> str:
    """A JSON string is a valid double-quoted YAML scalar, which keeps CSP quotes and backslashes intact."""
    return json.dumps(value)


def header_snippet(platform: Platform, header: str, value: str) -> tuple[str, str]:
    """(snippet, language) that sets a response header on the detected platform."""
    if platform.aem_cloud:
        return (
            "# config/cdn.yaml — deploy through a Cloud Manager Config Pipeline\n"
            'kind: "CDN"\nversion: "1"\ndata:\n  responseTransformations:\n    rules:\n'
            f"      - name: set-{header.lower()}\n        when:\n          reqProperty: path\n          like: '*'\n"
            f"        actions:\n          - type: set\n            respHeader: {header}\n"
            f"            value: {_yaml(value)}\n",
            "yaml",
        )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'# Apache / AEM Dispatcher vhost (mod_headers)\nHeader always set {header} "{escaped}"\n', "apacheconf"


def _curl(domain: str, header: str) -> str:
    return f'curl -sI https://{domain}/ | grep -i "^{header.lower()}"'


@dataclass(frozen=True)
class Playbook:
    title: str
    effort: str
    why: str
    steps: Callable[[Platform, dict[str, Any]], list[str]]
    header: str | None = None
    value: str | None = None
    owner: Callable[[Platform, dict[str, Any]], str] | None = None
    snippet: Callable[[Platform, dict[str, Any]], tuple[str, str]] | None = None
    verify: Callable[[str, dict[str, Any]], str] | None = None


def _header_steps(header: str, value: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    def steps(platform: Platform, group: dict[str, Any]) -> list[str]:
        if platform.aem_cloud:
            return [
                f"Add the rule that sets `{header}: {value}` to the `cdn.yaml` of the AEM repository "
                "(`config/` folder).",
                "Deploy to dev and stage with the Cloud Manager Config Pipeline and validate the site.",
                "Promote to production and confirm the header with the verification command.",
            ]
        if platform.aem:
            return [
                f"Add `Header always set {header}` to the Dispatcher vhost.",
                "Validate on stage, publish and invalidate the cache.",
            ]
        return [f"Set `{header}: {value}` on the outermost layer (CDN or reverse proxy)."]

    return steps


def _code_steps(*lines: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    return lambda platform, group: list(lines)


def _frontend_owner(platform: Platform, group: dict[str, Any]) -> str:
    return "AEM front-end and tag management" if platform.aem else "Front-end team and tag management"


def _content_owner(platform: Platform, group: dict[str, Any]) -> str:
    return "AEM authors and front-end" if platform.aem else "Front-end team"


def _cookie_owner(platform: Platform, group: dict[str, Any]) -> str:
    name = group.get("cookie") or ""
    if name.startswith(ONETRUST_COOKIES):
        return "OneTrust · consent script"
    if name == "affinity" and platform.aem_cloud:
        return "Adobe AEM · platform affinity cookie"
    return "Application that sets the cookie"


def _cookie_steps(attribute: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    def steps(platform: Platform, group: dict[str, Any]) -> list[str]:
        name = group.get("cookie") or "the cookie"
        if name.startswith(ONETRUST_COOKIES):
            return [
                f"The `{name}` cookie is written by the OneTrust script in the browser.",
                "HttpOnly does not apply to cookies that JavaScript must read; document it as an accepted risk.",
                "Confirm in OneTrust (Cookie Consent > domain settings) that Secure and SameSite are enabled.",
            ]
        steps = [f"Identify the component that sends `Set-Cookie: {name}` (application, dispatcher or platform)."]
        if name == "affinity" and platform.aem_cloud:
            steps.append(
                "On AEM as a Cloud Service this cookie usually comes from the Adobe affinity layer; if your code does "
                "not set it, open an Adobe support ticket to add the attribute."
            )
        steps.append(f"Add `{attribute}` to the cookie at its source and scan again.")
        return steps

    return steps


def _cookie_snippet(attribute: str) -> Callable[[Platform, dict[str, Any]], tuple[str, str]]:
    def snippet(platform: Platform, group: dict[str, Any]) -> tuple[str, str]:
        name = group.get("cookie") or "cookie"
        return (
            "# Apache / AEM Dispatcher vhost (mod_headers): adds the attribute to the cookie\n"
            f'Header always edit Set-Cookie "^({name}=(?!.*{attribute.split("=")[0]}).*)$" "$1; {attribute}"\n',
            "apacheconf",
        )

    return snippet


def _cookie_verify(domain: str, group: dict[str, Any]) -> str:
    return f'curl -sI https://{domain}/ | grep -i "^set-cookie: {group.get("cookie") or ""}"'


def _header(rule_header: str, value: str, title: str, effort: str, why: str) -> Playbook:
    return Playbook(title, effort, why, _header_steps(rule_header, value), header=rule_header, value=value)


HSTS = "max-age=31536000; includeSubDomains"
PLAYBOOKS: dict[str, Playbook] = {
    "HDR-HSTS-001": _header(
        "Strict-Transport-Security", HSTS, "Enable HSTS", "Low", "Prevents downgrade attacks to HTTP."
    ),
    "HDR-HSTS-002": _header(
        "Strict-Transport-Security", HSTS, "Increase the HSTS max-age", "Low", "A short HSTS gives little protection."
    ),
    "HDR-HSTS-003": Playbook(
        "Prepare for the HSTS preload list",
        "Medium",
        "Protects the first visit; it is a positive control in BitSight (WAS).",
        _code_steps(
            "Confirm every subdomain serves HTTPS (preloading applies to all of them and is hard to undo).",
            "Add `preload` to Strict-Transport-Security.",
            "Submit the domain at https://hstspreload.org/.",
        ),
        header="Strict-Transport-Security",
        value=HSTS + "; preload",
    ),
    "HDR-XCTO-001": _header(
        "X-Content-Type-Options", "nosniff", "Enable X-Content-Type-Options", "Low", "Prevents MIME sniffing."
    ),
    "HDR-XFO-001": _header(
        "X-Frame-Options", "SAMEORIGIN", "Protect against clickjacking", "Low", "Stops the site from being framed."
    ),
    "HDR-REF-001": _header(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Set a Referrer-Policy",
        "Low",
        "Avoids sending full URLs to third parties.",
    ),
    "HDR-REF-002": _header(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Fix the unsafe Referrer-Policy",
        "Low",
        "The current policy sends full URLs to other sites.",
    ),
    "HDR-PP-001": _header(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
        "Set a Permissions-Policy",
        "Low",
        "Restricts browser features the site does not use.",
    ),
    "CSP-000": Playbook(
        "Create a Content-Security-Policy",
        "High",
        "Without a CSP the browser does not block injected scripts.",
        _code_steps(
            "Inventory the script, style, image and frame origins the site uses.",
            "Publish the policy as Content-Security-Policy-Report-Only and collect violations.",
            "Once the violations are resolved, publish it as Content-Security-Policy.",
        ),
        header="Content-Security-Policy-Report-Only",
        value="default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; report-uri /csp-report",
    ),
    "CSP-001": Playbook(
        "Add default-src to the CSP",
        "Medium",
        "Without default-src, resource types that are not listed are unrestricted.",
        _code_steps(
            "Confirm which Content-Security-Policy headers are sent (the browser enforces all of them together).",
            "Add `default-src 'self'` to the policy and the required origins to the specific directives.",
        ),
    ),
    "CSP-002": Playbook(
        "Remove 'unsafe-eval' from the CSP",
        "High",
        "'unsafe-eval' allows dynamically generated code to run and makes XSS easier.",
        _code_steps(
            "Identify the code that uses eval/new Function/setTimeout with strings (libraries and third-party tags).",
            "Replace or update that code; remove `'unsafe-eval'` in a Report-Only policy first.",
            "Publish the policy without `'unsafe-eval'` once there are no violations.",
        ),
        owner=_frontend_owner,
    ),
    "CSP-003": Playbook(
        "Replace 'unsafe-inline' with nonces or hashes",
        "High",
        "Inline scripts are the main XSS vector.",
        _code_steps(
            "Move inline scripts to files, or generate a nonce per response and apply it to the <script> tags.",
            "Add `'nonce-…'` (or hashes) and `'strict-dynamic'` to script-src.",
            "Remove `'unsafe-inline'` after validating in Report-Only.",
        ),
        owner=_frontend_owner,
    ),
    "CSP-004": Playbook(
        "Enforce the Report-Only CSP",
        "Medium",
        "A stricter policy is already being tested but does not protect users yet.",
        _code_steps(
            "Review the violations collected by the report-uri of the Report-Only policy.",
            "Fix the missing origins and publish the policy as Content-Security-Policy.",
            "Remove the old CSP headers, so the new policy is not combined with them.",
        ),
    ),
    "COOKIE-SECURE": Playbook(
        "Add Secure to the cookie",
        "Low",
        "Without Secure the cookie can be sent over HTTP.",
        _cookie_steps("Secure"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("Secure"),
        verify=_cookie_verify,
    ),
    "COOKIE-HTTPONLY": Playbook(
        "Add HttpOnly to the cookie",
        "Low",
        "Without HttpOnly the cookie is readable by scripts (XSS risk).",
        _cookie_steps("HttpOnly"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("HttpOnly"),
        verify=_cookie_verify,
    ),
    "COOKIE-SAMESITE": Playbook(
        "Add SameSite to the cookie",
        "Low",
        "SameSite=Lax or Strict mitigates CSRF; it is assessed by BitSight (WAS).",
        _cookie_steps("SameSite=Lax"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("SameSite=Lax"),
        verify=_cookie_verify,
    ),
    "COOKIE-SAMESITE-NONE": Playbook(
        "Fix SameSite=None without Secure",
        "Low",
        "Browsers reject these cookies; it is assessed by BitSight (WAS).",
        _cookie_steps("Secure"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("Secure"),
        verify=_cookie_verify,
    ),
    "MIXED-001": Playbook(
        "Remove active mixed content",
        "Medium",
        "Scripts or frames loaded over HTTP can be modified in transit.",
        _code_steps(
            "Replace http:// references with their https:// equivalents (AEM components, templates and content).",
            "As a safety net, add `upgrade-insecure-requests` to the CSP.",
        ),
        owner=_content_owner,
    ),
    "MIXED-002": Playbook(
        "Remove passive mixed content",
        "Low",
        "Images loaded over HTTP can be replaced in transit.",
        _code_steps("Update the http:// references in images and media to https://."),
        owner=_content_owner,
    ),
    "SRI-001": Playbook(
        "Protect third-party scripts",
        "Medium",
        "Without integrity checks, a compromised third party serves malicious code to the site.",
        lambda platform, group: [
            "Add `integrity` and `crossorigin` to versioned third-party files (pinned libraries).",
            "For resources that change on every release (tag managers"
            + (
                ", such as Adobe Experience Platform Tags"
                if "Adobe Experience Platform Tags" in platform.technologies
                else ""
            )
            + "), SRI does not work: restrict them with the CSP instead.",
        ],
        owner=_frontend_owner,
    ),
    "URL-SESSION-001": Playbook(
        "Remove session identifiers from URLs",
        "Medium",
        "Sessions in URLs leak through logs, the Referer header and shared links.",
        _code_steps(
            "Track sessions by cookie only (turn off URL rewriting).",
            "Redirect URLs carrying the parameter to the version without it.",
        ),
        owner=lambda platform, group: "Application team",
    ),
    "TLS-HTTP-001": Playbook(
        "Redirect HTTP to HTTPS",
        "Low",
        "Visitors who arrive over HTTP are left unprotected.",
        lambda platform, group: [f"Set up a 301 redirect from http:// to https:// on {platform.header_owner()}."],
        verify=lambda domain, group: f"curl -sI http://{domain}/ | grep -iE '^(HTTP|location)'",
    ),
}


def _build(rule: str, key: str, group: dict[str, Any], platform: Platform, domain: str) -> Action:
    playbook = PLAYBOOKS.get(rule)
    bitsight = bitsight_of(rule)
    was = bitsight["assessment"] if bitsight["vector"] and "Security" in bitsight["vector"] else None
    if playbook is None:
        return Action(
            key, group["title"], group["severity"], platform.header_owner(), "Medium", group["title"],
            [group["remediation"]], f"curl -sI https://{domain}/", bitsight=was, rules=[rule],
        )  # fmt: skip
    snippet, language = ("", "text")
    if playbook.snippet:
        snippet, language = playbook.snippet(platform, group)
    elif playbook.header and playbook.value:
        snippet, language = header_snippet(platform, playbook.header, playbook.value)
    verify = (
        playbook.verify(domain, group)
        if playbook.verify
        else _curl(domain, playbook.header or ("content-security-policy" if rule.startswith("CSP") else ""))
    )
    title = playbook.title + (f" `{group['cookie']}`" if group.get("cookie") else "")
    return Action(
        key=key,
        title=title,
        severity=group["severity"],
        owner=playbook.owner(platform, group) if playbook.owner else platform.header_owner(),
        effort=playbook.effort,
        why=playbook.why,
        steps=playbook.steps(platform, group),
        verify=verify,
        snippet=snippet,
        snippet_language=language,
        bitsight=was,
        rules=[rule],
    )


def _merge(actions: dict[str, Action], action: Action, domain: str, pages: int) -> None:
    current = actions.setdefault(action.key, action)
    if domain not in current.domains:
        current.domains.append(domain)
    current.pages += pages
    if SEVERITY_ORDER.get(action.severity, 9) < SEVERITY_ORDER.get(current.severity, 9):
        current.severity = action.severity


def _is_necessary(category: str) -> bool:
    return any(hint in category.lower() for hint in NECESSARY_HINTS)


def _onetrust_actions(reports: list[tuple[str, dict[str, Any]]]) -> list[Action]:
    missing: dict[str, set[str]] = {}
    uncategorized: dict[str, set[str]] = {}
    before_consent: dict[str, set[str]] = {}
    not_configured: list[str] = []
    for domain, report in reports:
        cookies = report.get("cookies", {})
        if cookies.get("classification", {}).get("status") == "not_configured":
            not_configured.append(domain)
        for cookie in cookies.get("inventory", []):
            info = cookie.get("classification") or {}
            status = info.get("status")
            if status == "not_found":
                missing.setdefault(cookie["name"], set()).add(domain)
            elif status == "uncategorized":
                uncategorized.setdefault(cookie["name"], set()).add(domain)
            elif status == "classified" and not _is_necessary(str(info.get("category") or "")):
                before_consent.setdefault(f"{cookie['name']} ({info.get('category')})", set()).add(domain)
    owner = "OneTrust · Cookie Consent"
    actions = []
    if before_consent:
        actions.append(
            Action(
                "ONETRUST-BEFORE-CONSENT",
                "Non-essential cookies set before consent",
                "High",
                f"{owner} + application team",
                "Medium",
                "The scan never accepts cookies, so these Set-Cookie headers arrived before any consent "
                "(GDPR/ePrivacy risk).",
                [
                    "Cookies: " + ", ".join(sorted(before_consent)) + ".",
                    "Confirm the category in OneTrust; if it is right, stop the server from setting them before "
                    "consent (or turn on OneTrust auto-blocking for the scripts that create them).",
                    "If the category is wrong, fix it in OneTrust.",
                ],
                "Scan again: the cookies must not appear without consent.",
                domains=sorted(set().union(*before_consent.values())),
                pages=len(before_consent),
            )
        )
    if uncategorized:
        actions.append(
            Action(
                "ONETRUST-UNCATEGORIZED",
                "Categorize cookies in OneTrust",
                "Medium",
                owner,
                "Low",
                "Uncategorized cookies are not controlled by the consent banner.",
                [
                    "Cookies: " + ", ".join(sorted(uncategorized)) + ".",
                    "Assign the category in Cookie Consent > Cookies (or through the Update Cookie API, "
                    f"`{ONETRUST_UPDATE_COOKIE}`, with the category ID).",
                    "Publish the consent script of the domain.",
                ],
                "Scan again with OneTrust classification on.",
                domains=sorted(set().union(*uncategorized.values())),
                pages=len(uncategorized),
            )
        )
    if missing:
        actions.append(
            Action(
                "ONETRUST-NOT-FOUND",
                "Register the missing cookies in OneTrust",
                "Medium",
                owner,
                "Low",
                "Cookies OneTrust does not know about are left out of the banner and the cookie list.",
                [
                    "Cookies: " + ", ".join(sorted(missing)) + ".",
                    "Run a new domain scan in OneTrust or add the cookies by hand.",
                    "Categorize them and publish the consent script.",
                ],
                "Scan again with OneTrust classification on.",
                domains=sorted(set().union(*missing.values())),
                pages=len(missing),
            )
        )
    if not_configured:
        actions.append(
            Action(
                "ONETRUST-NOT-CONFIGURED",
                "Connect OneTrust classification to the scans",
                "Info",
                "Security team",
                "Low",
                "Without OneTrust there is no way to know whether cookies are registered and categorized.",
                [
                    "Create a OneTrust API client with the COOKIE_READ scope.",
                    "Set ONETRUST_HOSTNAME, ONETRUST_CLIENT_ID and ONETRUST_CLIENT_SECRET and run the scan again.",
                ],
                "The Cookies tab of the domain shows the categories.",
                domains=sorted(not_configured),
            )
        )
    return actions


def _link_report_only_policy(actions: dict[str, Action]) -> None:
    """A report-only policy being tested is usually the way out of unsafe-eval/unsafe-inline: rank it with them."""
    report_only = actions.get("CSP-004")
    unsafe = [actions[key] for key in ("CSP-002", "CSP-003") if key in actions]
    if not report_only or not unsafe:
        return
    report_only.severity = "High"
    report_only.why += " Enforcing it is the way to resolve: " + "; ".join(a.title for a in unsafe) + "."
    for action in unsafe:
        action.steps.insert(
            0, 'A Report-Only CSP is already being tested: see the action "Enforce the Report-Only CSP".'
        )


def build_actions(reports: Iterable[dict[str, Any]]) -> list[Action]:
    """One action per rule (per cookie for cookie rules) across all reports, highest priority first."""
    entries = [(urllib.parse.urlsplit(r["target"]).hostname or r["target"], r) for r in reports]
    actions: dict[str, Action] = {}
    for domain, report in entries:
        platform = platform_of(report)
        for group in report["groups"]:
            rule = group["rule"]
            key = f"{rule}:{group['cookie']}" if group.get("cookie") else rule
            _merge(actions, _build(rule, key, group, platform, domain), domain, group["count"])
    _link_report_only_policy(actions)
    result = list(actions.values()) + _onetrust_actions(entries)
    result.sort(key=lambda a: (-a.score, SEVERITY_ORDER.get(a.severity, 9), a.title))
    return result


def aem_cdn_config(actions: Iterable[Action]) -> str:
    """A cdn.yaml combining every header the plan asks to set, for AEM as a Cloud Service."""
    headers: dict[str, str] = {}
    for action in actions:
        playbook = PLAYBOOKS.get(action.rules[0]) if action.rules else None
        if not (playbook and playbook.header and playbook.value) or playbook.header.endswith("Report-Only"):
            continue
        # preload is never written to a deployable file: it binds every subdomain and is hard to undo.
        headers[playbook.header] = HSTS if playbook.header == "Strict-Transport-Security" else playbook.value
    lines = [
        "# Suggested by agent-security. Review, then deploy with a Cloud Manager Config Pipeline (dev, stage, prod).",
        "# CSP changes are not included: promote or adjust the policy by hand after reviewing violation reports.",
        "# HSTS preload is left out on purpose: add '; preload' only once every subdomain serves HTTPS.",
        'kind: "CDN"',
        'version: "1"',
        "data:",
        "  responseTransformations:",
        "    rules:",
        "      - name: security-headers",
        "        when:",
        "          reqProperty: path",
        "          like: '*'",
        "        actions:",
    ]
    for header, value in sorted(headers.items()):
        lines += ["          - type: set", f"            respHeader: {header}", f"            value: {_yaml(value)}"]
    return "\n".join(lines) + "\n" if headers else ""


def action_rows(actions: Iterable[Action], state: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Flat rows for tables and CSV export."""
    return [
        {
            "Priority": action.priority,
            "Action": action.title.replace("`", ""),
            "Owner": state.get(action.key, {}).get("owner") or action.owner,
            "Effort": action.effort,
            "Severity": action.severity,
            "BitSight": action.bitsight or "—",
            "Domains": ", ".join(action.domains),
            "Pages": action.pages,
            "Status": state.get(action.key, {}).get("status") or STATUSES[0],
            "Note": state.get(action.key, {}).get("note") or "",
            "Key": action.key,
        }
        for action in actions
    ]


def markdown_plan(actions: Iterable[Action], state: dict[str, dict[str, Any]], title: str) -> str:
    lines = [f"# {title}", ""]
    for action in actions:
        status = state.get(action.key, {}).get("status") or STATUSES[0]
        lines += [
            f"## [{action.priority}] {action.title}",
            "",
            f"- **Owner:** {state.get(action.key, {}).get('owner') or action.owner}",
            f"- **Status:** {status} · **Effort:** {action.effort} · **Severity:** {action.severity}",
            f"- **Domains:** {', '.join(action.domains)} ({action.pages} pages)",
        ]
        if action.bitsight:
            lines.append(f"- **BitSight (WAS):** {action.bitsight}")
        lines += ["", action.why, ""]
        lines += [f"{n}. {step}" for n, step in enumerate(action.steps, start=1)]
        if action.snippet:
            lines += ["", f"```{action.snippet_language}", action.snippet.rstrip(), "```"]
        lines += ["", f"**Verification:** `{action.verify}`", ""]
    return "\n".join(lines)
