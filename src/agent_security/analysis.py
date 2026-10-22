"""Security checks applied to a single HTTP response."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable
from typing import Any, TypedDict

from agent_security.cookies import parse_set_cookie, stable_attributes

HSTS_MIN_AGE = 31_536_000
MAX_EVIDENCE_ITEMS = 10
_MAX_AGE = re.compile(r"(?:^|;)\s*max-age\s*=\s*(\d+)", re.IGNORECASE)
_PRELOAD = re.compile(r"(?:^|;)\s*preload\s*(?:;|$)", re.IGNORECASE)
# A nonce, a hash or 'strict-dynamic' makes CSP Level 3 browsers ignore 'unsafe-inline' in scripts.
_INLINE_OVERRIDE = re.compile(r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+|strict-dynamic)'")
_SESSION_PARAM = re.compile(
    r"jsessionid|phpsessid|aspsessionid\w*|asp\.net_sessionid|sessionid|session_id|sessid|sid|cfid|cftoken",
    re.IGNORECASE,
)
_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
_UNSAFE_REFERRER_POLICIES = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


class Finding(TypedDict):
    severity: str
    rule: str
    title: str
    url: str
    source: str
    evidence: str
    expected: str
    remediation: str


Emit = Callable[[str, str, str, str, str, str], None]  # severity, rule, title, evidence, expected, remediation


def add_finding(
    findings: list[Finding],
    *,
    severity: str,
    rule: str,
    title: str,
    url: str,
    evidence: str,
    expected: str,
    remediation: str,
    source: str = "seed",
) -> None:
    findings.append(
        {
            "severity": severity,
            "rule": rule,
            "title": title,
            "url": url,
            "source": source,
            "evidence": evidence,
            "expected": expected,
            "remediation": remediation,
        }
    )


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return directives


def _check_hsts(headers: Any, emit: Emit) -> None:
    value = headers.get("Strict-Transport-Security")
    if not value:
        emit(
            "High",
            "HDR-HSTS-001",
            "Strict-Transport-Security missing",
            "Header not present in the HTTPS response.",
            "max-age=31536000; includeSubDomains; preload",
            "Configure HSTS after confirming all covered hosts support HTTPS.",
        )
        return
    match = _MAX_AGE.search(value)
    if not match or int(match.group(1)) < HSTS_MIN_AGE:
        emit(
            "Medium",
            "HDR-HSTS-002",
            "Strict-Transport-Security max-age is short or invalid",
            value,
            "max-age=31536000 or greater",
            "Review the HSTS lifetime and deployment requirements.",
        )
    elif not _PRELOAD.search(value):
        emit(
            "Info",
            "HDR-HSTS-003",
            "Strict-Transport-Security without preload",
            value,
            "max-age=31536000; includeSubDomains; preload",
            "Once every subdomain serves HTTPS, add includeSubDomains and preload and submit the domain to "
            "hstspreload.org.",
        )


def _script_sources(directives: dict[str, list[str]]) -> list[str] | None:
    """Sources a policy allows for scripts, or None when it does not restrict scripts at all."""
    return directives.get("script-src", directives.get("default-src"))


def _allows_inline(sources: list[str]) -> bool:
    return "'unsafe-inline'" in sources and not any(_INLINE_OVERRIDE.fullmatch(s) for s in sources)


def _check_csp(policies: list[str], emit: Emit) -> None:
    """Evaluate every enforced policy together: browsers apply all of them, so a script runs only if each allows it."""
    if not policies:
        emit(
            "High",
            "CSP-000",
            "Content-Security-Policy missing",
            "Neither a Content-Security-Policy header nor a CSP meta tag was present.",
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            "Define and test a restrictive CSP appropriate to the site before enforcement.",
        )
        return
    evidence = " | ".join(policies)
    parsed = [parse_csp(policy) for policy in policies]
    if not any("default-src" in directives for directives in parsed):
        emit(
            "Medium",
            "CSP-001",
            "CSP missing default-src",
            evidence,
            "default-src 'self'",
            "Add an appropriate default-src directive after validating application dependencies.",
        )
    restricting = [sources for sources in map(_script_sources, parsed) if sources is not None]
    if restricting and all("'unsafe-eval'" in sources for sources in restricting):
        emit(
            "Critical",
            "CSP-002",
            "CSP allows unsafe-eval",
            evidence,
            "script-src without 'unsafe-eval'",
            "Remove unsafe-eval and refactor code that requires dynamic evaluation.",
        )
    if restricting and all(_allows_inline(sources) for sources in restricting):
        emit(
            "High",
            "CSP-003",
            "CSP allows unsafe-inline in scripts",
            evidence,
            "script-src with nonce or hash and without 'unsafe-inline'",
            "Use nonces or hashes and remove unsafe inline scripts where practical.",
        )


def _check_csp_report_only(policies: list[str], emit: Emit) -> None:
    if policies:
        emit(
            "Info",
            "CSP-004",
            "Content-Security-Policy-Report-Only present (not enforced)",
            " | ".join(policies),
            "The tested policy enforced as Content-Security-Policy",
            "Review the violation reports and, once they are clean, promote the report-only policy to "
            "Content-Security-Policy.",
        )


_SIMPLE_HEADERS = (
    (
        "X-Content-Type-Options",
        "Medium",
        "HDR-XCTO-001",
        "X-Content-Type-Options missing",
        "nosniff",
        'Header always set X-Content-Type-Options "nosniff"',
    ),
    (
        "Referrer-Policy",
        "Low",
        "HDR-REF-001",
        "Referrer-Policy missing",
        "strict-origin-when-cross-origin",
        'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    ),
    (
        "Permissions-Policy",
        "Low",
        "HDR-PP-001",
        "Permissions-Policy missing",
        "camera=(), microphone=(), geolocation=()",
        "Set a Permissions-Policy appropriate to required browser features.",
    ),
)


def _check_cookies(headers: Any, emit: Emit) -> None:
    for raw in headers.get_all("Set-Cookie") or []:
        name, attributes = parse_set_cookie(raw)
        flags = {attribute.split("=", 1)[0].strip().lower() for attribute in attributes}
        evidence = f"{name}=<redacted>; " + "; ".join(stable_attributes(attributes))
        if "secure" not in flags:
            emit(
                "High",
                "COOKIE-SECURE",
                f"Cookie {name} missing Secure flag",
                evidence,
                "...; Secure",
                "Add Secure to cookies that should only be sent over HTTPS.",
            )
        if "httponly" not in flags:
            emit(
                "Medium",
                "COOKIE-HTTPONLY",
                f"Cookie {name} missing HttpOnly flag",
                evidence,
                "...; HttpOnly",
                "Add HttpOnly when client-side JavaScript does not need to read the cookie.",
            )
        samesite = next(
            (a.split("=", 1)[-1].strip().lower() for a in attributes if a.lower().startswith("samesite")), None
        )
        if samesite is None:
            emit(
                "Medium",
                "COOKIE-SAMESITE",
                f"Cookie {name} missing SameSite",
                evidence,
                "...; SameSite=Lax or Strict",
                "Set an appropriate SameSite attribute; use None only when cross-site use is required "
                "and Secure is set.",
            )
        elif samesite == "none" and "secure" not in flags:
            emit(
                "High",
                "COOKIE-SAMESITE-NONE",
                f"Cookie {name} uses SameSite=None without Secure",
                evidence,
                "...; SameSite=None; Secure",
                "Browsers reject SameSite=None cookies that are not Secure: add Secure or use SameSite=Lax.",
            )


def _check_referrer_policy(value: str | None, emit: Emit) -> None:
    # Browsers apply the last policy token they recognise in a comma-separated list.
    tokens = [token.strip().lower() for token in (value or "").split(",")]
    effective = next((token for token in reversed(tokens) if token in _REFERRER_POLICIES), None)
    if effective in _UNSAFE_REFERRER_POLICIES:
        emit(
            "Medium",
            "HDR-REF-002",
            "Unsafe Referrer-Policy",
            value or "",
            "strict-origin-when-cross-origin (or stricter)",
            "Use strict-origin-when-cross-origin, same-origin or no-referrer so full URLs are not sent to other sites.",
        )


def _summarize_urls(urls: list[str], hosts_only: bool = False) -> str:
    """Stable evidence for a URL list, so the same third parties group together across pages."""
    if hosts_only:
        urls = sorted({urllib.parse.urlsplit(url).hostname or url for url in urls})
    shown = ", ".join(urls[:MAX_EVIDENCE_ITEMS])
    return shown + (f" (+{len(urls) - MAX_EVIDENCE_ITEMS} more)" if len(urls) > MAX_EVIDENCE_ITEMS else "")


def _check_page_content(url: str, facts: dict[str, Any], emit: Emit) -> None:
    if url.startswith("https://"):
        if facts.get("mixed_active"):
            emit(
                "High",
                "MIXED-001",
                "Active mixed content (scripts, styles or frames over HTTP)",
                "Loaded over HTTP from: " + _summarize_urls(facts["mixed_active"], hosts_only=True),
                "Every script, stylesheet and frame loaded over HTTPS",
                "Serve these resources over HTTPS (or add CSP upgrade-insecure-requests after testing).",
            )
        if facts.get("mixed_passive"):
            emit(
                "Medium",
                "MIXED-002",
                "Passive mixed content (images or media over HTTP)",
                "Loaded over HTTP from: " + _summarize_urls(facts["mixed_passive"], hosts_only=True),
                "Every image and media file loaded over HTTPS",
                "Serve these resources over HTTPS.",
            )
    if facts.get("sri_missing"):
        emit(
            "Low",
            "SRI-001",
            "Cross-origin scripts or stylesheets without Subresource Integrity",
            "No integrity attribute on resources from: " + _summarize_urls(facts["sri_missing"], hosts_only=True),
            '<script src="..." integrity="sha384-..." crossorigin="anonymous">',
            "Add integrity hashes to versioned third-party files; for resources that change (tag managers), "
            "restrict them with CSP instead.",
        )


def _check_session_in_url(urls: list[str], emit: Emit) -> None:
    names: set[str] = set()
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        names.update(name for name, _ in urllib.parse.parse_qsl(parts.query) if _SESSION_PARAM.fullmatch(name))
        names.update(
            segment.split("=", 1)[0]
            for segment in parts.path.split(";")[1:]
            if _SESSION_PARAM.fullmatch(segment.split("=", 1)[0])
        )
    if names:
        emit(
            "High",
            "URL-SESSION-001",
            "Session token in URL",
            "Session parameter(s) in the URL (values not recorded): " + ", ".join(sorted(names)),
            "Session identifiers only in Secure, HttpOnly cookies",
            "Disable URL-based session tracking (e.g. cookie-only session tracking mode).",
        )


def analyze_response(result: dict[str, Any], findings: list[Finding]) -> None:
    """Append the findings for one fetched page; responses without headers (failed requests) are skipped."""
    headers = result["headers"]
    if headers is None:
        return
    url = result["final_url"] or result["requested_url"]
    source = result.get("source", "seed")
    facts = result.get("facts") or {}

    def emit(severity: str, rule: str, title: str, evidence: str, expected: str, remediation: str) -> None:
        add_finding(
            findings,
            severity=severity,
            rule=rule,
            title=title,
            url=url,
            evidence=evidence,
            expected=expected,
            remediation=remediation,
            source=source,
        )

    _check_hsts(headers, emit)
    header_policies = [value for value in headers.get_all("Content-Security-Policy") or [] if value.strip()]
    _check_csp(header_policies + ([facts["meta_csp"]] if facts.get("meta_csp") else []), emit)
    _check_csp_report_only(
        [value for value in headers.get_all("Content-Security-Policy-Report-Only") or [] if value.strip()], emit
    )
    for header, severity, rule, title, expected, remediation in _SIMPLE_HEADERS:
        if not headers.get(header):
            emit(severity, rule, title, f"{header} header not present.", expected, remediation)
    _check_referrer_policy(headers.get("Referrer-Policy"), emit)
    # frame-ancestors is ignored when the policy comes from a meta tag.
    framed = any("frame-ancestors" in parse_csp(policy) for policy in header_policies)
    if not headers.get("X-Frame-Options") and not framed:
        emit(
            "Medium",
            "HDR-XFO-001",
            "Clickjacking protection missing",
            "Neither X-Frame-Options nor CSP frame-ancestors was present.",
            "X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'",
            "Configure X-Frame-Options or a suitable CSP frame-ancestors directive.",
        )
    _check_cookies(headers, emit)
    _check_page_content(url, facts, emit)
    _check_session_in_url([result["requested_url"], url], emit)
