"""Severity levels, report sections, per-rule guidance and the Bitsight alignment shared across the package."""

from __future__ import annotations

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
SECTIONS = ("Security Headers", "Content Security Policy", "Cookies", "Page Content", "TLS")

_SECTION_BY_PREFIX = (
    ("CSP-", "Content Security Policy"),
    ("COOKIE-", "Cookies"),
    ("MIXED-", "Page Content"),
    ("SRI-", "Page Content"),
    ("URL-", "Page Content"),
    ("TLS-", "TLS"),
)

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_OWASP = "https://owasp.org/www-project-secure-headers/"
_STRICT_CSP = "https://csp.withgoogle.com/docs/strict-csp.html"
_MIXED = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
_SRI = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"

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
    "HDR-HSTS-003": (
        "Preloading puts the domain in the browsers' built-in HTTPS-only list, protecting even the first visit.",
        ["https://hstspreload.org/", _MDN + "Strict-Transport-Security"],
    ),
    "HDR-XCTO-001": ("Prevents MIME-sniffing by the browser.", [_OWASP]),
    "HDR-XFO-001": ("Set X-Frame-Options or CSP frame-ancestors.", [_OWASP]),
    "HDR-REF-001": ("Controls information sent in the Referer header.", [_OWASP]),
    "HDR-REF-002": (
        "unsafe-url and no-referrer-when-downgrade send full URLs, including paths and queries, to other sites.",
        [_MDN + "Referrer-Policy"],
    ),
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
    "COOKIE-SAMESITE-NONE": ("Browsers block SameSite=None cookies that lack Secure.", [_MDN + "Set-Cookie"]),
    "MIXED-001": (
        "Scripts, styles or frames loaded over HTTP can be modified in transit to take over the page.",
        [_MIXED],
    ),
    "MIXED-002": ("Images or media loaded over HTTP can be observed or replaced in transit.", [_MIXED]),
    "SRI-001": (
        "Without integrity hashes, a compromised third-party host can serve malicious code to the site.",
        [_SRI],
    ),
    "URL-SESSION-001": (
        "Session identifiers in URLs leak through logs, the Referer header and shared links.",
        ["https://owasp.org/www-community/vulnerabilities/Session_Management_Cheat_Sheet"],
    ),
    "TLS-HTTP-001": ("Plain HTTP should redirect to HTTPS.", ["https://wiki.mozilla.org/Security/Server_Side_TLS"]),
}


def section_of(rule: str) -> str:
    for prefix, section in _SECTION_BY_PREFIX:
        if rule.startswith(prefix):
            return section
    return "Security Headers"


# Alignment with the Bitsight "Web Application Security" (WAS) risk vector, based on Bitsight's public help-center
# documentation. WAS replaced "Web Application Headers" (WAH) in the headline rating on 10 July 2025; WAH is now
# non-graded. Bitsight loads a domain's landing page in a browser and does not crawl, so this is an approximation.
WAS = "Web Application Security"
WAH = "Web Application Headers (legacy, non-graded since July 2025)"
BITSIGHT_CATEGORIES = ("Cross-Site Scripting", "Sensitive Data Exposure", "Legacy headers", "Not assessed by Bitsight")

# rule id -> (risk vector, WAS category, assessment)
BITSIGHT: dict[str, tuple[str | None, str, str | None]] = {
    "CSP-000": (WAS, "Cross-Site Scripting", "Content Security Policy Configurations"),
    "CSP-001": (WAS, "Cross-Site Scripting", "Content Security Policy Configurations"),
    "CSP-002": (WAS, "Cross-Site Scripting", "Content Security Policy Configurations"),
    "CSP-003": (WAS, "Cross-Site Scripting", "Content Security Policy Configurations"),
    "HDR-XFO-001": (WAS, "Cross-Site Scripting", "Content Security Policy Configurations"),
    "SRI-001": (WAS, "Cross-Site Scripting", "Cross-Domain Subresource Integrity Check"),
    "COOKIE-SAMESITE": (WAS, "Sensitive Data Exposure", "Cookie SameSite Attribute"),
    "COOKIE-SAMESITE-NONE": (WAS, "Sensitive Data Exposure", "Cookie SameSite Blocked"),
    "MIXED-001": (WAS, "Sensitive Data Exposure", "Mixed Content"),
    "MIXED-002": (WAS, "Sensitive Data Exposure", "Mixed Content"),
    "URL-SESSION-001": (WAS, "Sensitive Data Exposure", "Session Token in URL"),
    "HDR-REF-002": (WAS, "Sensitive Data Exposure", "Unsafe Referrer Policy"),
    "HDR-HSTS-003": (WAS, "Sensitive Data Exposure", "HSTS Preload Directive Present (positive-only)"),
    "HDR-HSTS-001": (WAH, "Legacy headers", "Strict-Transport-Security"),
    "HDR-HSTS-002": (WAH, "Legacy headers", "Strict-Transport-Security"),
    "HDR-XCTO-001": (WAH, "Legacy headers", "X-Content-Type-Options"),
    "COOKIE-SECURE": (WAH, "Legacy headers", "Set-Cookie"),
    "COOKIE-HTTPONLY": (WAH, "Legacy headers", "Set-Cookie"),
    "HDR-REF-001": (None, "Not assessed by Bitsight", None),
    "HDR-PP-001": (None, "Not assessed by Bitsight", None),
    "TLS-HTTP-001": (None, "Not assessed by Bitsight", None),
}


def bitsight_of(rule: str) -> dict[str, str | None]:
    vector, category, assessment = BITSIGHT.get(rule, (None, "Not assessed by Bitsight", None))
    return {"vector": vector, "category": category, "assessment": assessment}
