"""Security checks applied to a single HTTP response."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, TypedDict

from agent_security.cookies import parse_set_cookie, stable_attributes

HSTS_MIN_AGE = 31_536_000
_MAX_AGE = re.compile(r"(?:^|;)\s*max-age\s*=\s*(\d+)", re.IGNORECASE)
# A nonce, a hash or 'strict-dynamic' makes CSP Level 3 browsers ignore 'unsafe-inline' in scripts.
_INLINE_OVERRIDE = re.compile(r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+|strict-dynamic)'")


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


def _check_csp(policy: str | None, emit: Emit) -> dict[str, list[str]]:
    if not policy:
        emit(
            "High",
            "CSP-000",
            "Content-Security-Policy missing",
            "Header not present in the HTTPS response.",
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            "Define and test a restrictive CSP appropriate to the site before enforcement.",
        )
        return {}
    directives = parse_csp(policy)
    if "default-src" not in directives:
        emit(
            "Medium",
            "CSP-001",
            "CSP missing default-src",
            policy,
            "default-src 'self'",
            "Add an appropriate default-src directive after validating application dependencies.",
        )
    script_sources = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-eval'" in script_sources:
        emit(
            "Critical",
            "CSP-002",
            "CSP allows unsafe-eval",
            policy,
            "script-src without 'unsafe-eval'",
            "Remove unsafe-eval and refactor code that requires dynamic evaluation.",
        )
    if "'unsafe-inline'" in script_sources and not any(_INLINE_OVERRIDE.fullmatch(s) for s in script_sources):
        emit(
            "High",
            "CSP-003",
            "CSP allows unsafe-inline in scripts",
            policy,
            "script-src with nonce or hash and without 'unsafe-inline'",
            "Use nonces or hashes and remove unsafe inline scripts where practical.",
        )
    return directives


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
        if not any(flag.startswith("samesite") for flag in flags):
            emit(
                "Medium",
                "COOKIE-SAMESITE",
                f"Cookie {name} missing SameSite",
                evidence,
                "...; SameSite=Lax or Strict",
                "Set an appropriate SameSite attribute; use None only when cross-site use is required "
                "and Secure is set.",
            )


def analyze_response(result: dict[str, Any], findings: list[Finding]) -> None:
    """Append the findings for one fetched page; responses without headers (failed requests) are skipped."""
    headers = result["headers"]
    if headers is None:
        return
    url = result["final_url"] or result["requested_url"]
    source = result.get("source", "seed")

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
    directives = _check_csp(headers.get("Content-Security-Policy"), emit)
    for header, severity, rule, title, expected, remediation in _SIMPLE_HEADERS:
        if not headers.get(header):
            emit(severity, rule, title, f"{header} header not present.", expected, remediation)
    if not headers.get("X-Frame-Options") and "frame-ancestors" not in directives:
        emit(
            "Medium",
            "HDR-XFO-001",
            "Clickjacking protection missing",
            "Neither X-Frame-Options nor CSP frame-ancestors was present.",
            "X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'",
            "Configure X-Frame-Options or a suitable CSP frame-ancestors directive.",
        )
    _check_cookies(headers, emit)
