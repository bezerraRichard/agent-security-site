"""Severity levels, report sections and per-rule guidance shared across the package."""

from __future__ import annotations

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
SECTIONS = ("Security Headers", "Content Security Policy", "Cookies", "TLS")

_SECTION_BY_PREFIX = (
    ("CSP-", "Content Security Policy"),
    ("COOKIE-", "Cookies"),
    ("TLS-", "TLS"),
)

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_OWASP = "https://owasp.org/www-project-secure-headers/"
_STRICT_CSP = "https://csp.withgoogle.com/docs/strict-csp.html"

# rule id -> (explanation shown in the report, reference links)
RULE_INFO: dict[str, tuple[str, list[str]]] = {
    "HDR-HSTS-001": (
        "The HSTS header prevents downgrade attacks to HTTP.",
        [_OWASP, _MDN + "Strict-Transport-Security"],
    ),
    "HDR-HSTS-002": (
        "A short HSTS lifetime weakens protection against downgrade attacks.",
        [_MDN + "Strict-Transport-Security"],
    ),
    "HDR-XCTO-001": ("Prevents MIME-sniffing by the browser.", [_OWASP]),
    "HDR-XFO-001": ("Set X-Frame-Options or CSP frame-ancestors.", [_OWASP]),
    "HDR-REF-001": ("Controls information sent in the Referer header.", [_OWASP]),
    "HDR-PP-001": ("Restricts browser features (camera, microphone, geolocation).", [_OWASP]),
    "CSP-000": (
        "Without a CSP the browser does not block injection of untrusted scripts/resources.",
        [_MDN + "Content-Security-Policy", _OWASP + "#content-security-policy"],
    ),
    "CSP-001": ("default-src is the fallback for unspecified directives.", [_MDN + "Content-Security-Policy"]),
    "CSP-002": ("'unsafe-eval' allows dynamic code execution — enables XSS.", [_MDN + "Content-Security-Policy"]),
    "CSP-003": ("Inline scripts are the main XSS vector.", [_MDN + "Content-Security-Policy", _STRICT_CSP]),
    "COOKIE-SECURE": ("Cookies without Secure may be sent over HTTP connections.", [_MDN + "Set-Cookie"]),
    "COOKIE-HTTPONLY": ("Without HttpOnly the cookie is accessible to JavaScript (XSS risk).", [_MDN + "Set-Cookie"]),
    "COOKIE-SAMESITE": ("SameSite=Lax/Strict mitigates CSRF; None requires Secure.", [_MDN + "Set-Cookie"]),
    "TLS-HTTP-001": ("Plain HTTP should redirect to HTTPS.", ["https://wiki.mozilla.org/Security/Server_Side_TLS"]),
}


def section_of(rule: str) -> str:
    for prefix, section in _SECTION_BY_PREFIX:
        if rule.startswith(prefix):
            return section
    return "Security Headers"
