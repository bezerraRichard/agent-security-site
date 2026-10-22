import unittest
from email.message import Message

from agent_security import analysis

GOOD = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
)


def headers(*pairs):
    message = Message()
    for key, value in pairs:
        message[key] = value
    return message


def analyze(pairs, source="crawl"):
    findings = []
    analysis.analyze_response(
        {
            "headers": headers(*pairs),
            "final_url": "https://a.example.com/x",
            "requested_url": "https://a.example.com/",
            "source": source,
        },
        findings,
    )
    return findings


def rules(findings):
    return sorted(finding["rule"] for finding in findings)


def without(name):
    return tuple(pair for pair in GOOD if pair[0] != name)


class AnalyzeResponseTests(unittest.TestCase):
    def test_hardened_response_has_no_findings(self):
        self.assertEqual(analyze(GOOD), [])

    def test_failed_request_is_skipped(self):
        findings = []
        analysis.analyze_response(
            {"headers": None, "final_url": None, "requested_url": "https://a.example.com/"}, findings
        )
        self.assertEqual(findings, [])

    def test_bare_response_reports_every_missing_header(self):
        self.assertEqual(
            rules(analyze(())),
            ["CSP-000", "HDR-HSTS-001", "HDR-PP-001", "HDR-REF-001", "HDR-XCTO-001", "HDR-XFO-001"],
        )

    def test_findings_use_final_url_and_source(self):
        finding = analyze(())[0]
        self.assertEqual(finding["url"], "https://a.example.com/x")
        self.assertEqual(finding["source"], "crawl")
        self.assertEqual(analyze((), source="seed")[0]["source"], "seed")

    def test_hsts_lifetime(self):
        self.assertEqual(
            rules(analyze(without("Strict-Transport-Security") + (("Strict-Transport-Security", "max-age=600"),))),
            ["HDR-HSTS-002"],
        )
        self.assertEqual(
            rules(
                analyze(without("Strict-Transport-Security") + (("Strict-Transport-Security", "includeSubDomains"),))
            ),
            ["HDR-HSTS-002"],
        )
        self.assertEqual(
            analyze(without("Strict-Transport-Security") + (("Strict-Transport-Security", "MAX-AGE=63072000"),)), []
        )

    def test_csp_without_default_src_does_not_mask_other_directives(self):
        csp = ("Content-Security-Policy", "object-src 'none'; base-uri 'self'")
        self.assertEqual(rules(analyze(without("Content-Security-Policy") + (csp,))), ["CSP-001", "HDR-XFO-001"])

    def test_csp_with_default_src_is_not_reported_missing(self):
        csp = ("Content-Security-Policy", "OBJECT-SRC 'none'; DEFAULT-SRC 'self'; frame-ancestors 'self'")
        self.assertEqual(analyze(without("Content-Security-Policy") + (csp,)), [])

    def test_unsafe_script_sources(self):
        csp = (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'",
        )
        self.assertEqual(rules(analyze(without("Content-Security-Policy") + (csp,))), ["CSP-002", "CSP-003"])

    def test_default_src_is_the_script_fallback_but_script_src_overrides_it(self):
        fallback = ("Content-Security-Policy", "default-src 'unsafe-inline'; frame-ancestors 'self'")
        override = ("Content-Security-Policy", "default-src 'unsafe-inline'; script-src 'self'; frame-ancestors 'self'")
        self.assertEqual(rules(analyze(without("Content-Security-Policy") + (fallback,))), ["CSP-003"])
        self.assertEqual(analyze(without("Content-Security-Policy") + (override,)), [])

    def test_x_frame_options_or_frame_ancestors_prevent_clickjacking_finding(self):
        csp = ("Content-Security-Policy", "default-src 'self'")
        self.assertEqual(rules(analyze(without("Content-Security-Policy") + (csp,))), ["HDR-XFO-001"])
        self.assertEqual(analyze(without("Content-Security-Policy") + (csp, ("X-Frame-Options", "SAMEORIGIN"))), [])

    def test_cookie_flags_are_checked_and_values_redacted(self):
        findings = analyze(GOOD + (("Set-Cookie", "sid=TOPSECRET; Path=/"),))
        self.assertEqual(rules(findings), ["COOKIE-HTTPONLY", "COOKIE-SAMESITE", "COOKIE-SECURE"])
        for finding in findings:
            self.assertNotIn("TOPSECRET", str(finding))
            self.assertIn("sid=<redacted>; Path=/", finding["evidence"])
            self.assertIn("Cookie sid missing", finding["title"])

    def test_hardened_cookies_and_multiple_set_cookie_headers(self):
        good = ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(analyze(GOOD + (good, ("Set-Cookie", "b=2; secure; httponly; samesite=Strict"))), [])
        self.assertEqual(rules(analyze(GOOD + (good, ("Set-Cookie", "b=2; Secure; HttpOnly")))), ["COOKIE-SAMESITE"])


class AddFindingTests(unittest.TestCase):
    def test_appends_a_complete_finding(self):
        findings = []
        analysis.add_finding(
            findings, severity="High", rule="R", title="T", url="u", evidence="e", expected="x", remediation="r"
        )
        self.assertEqual(
            findings,
            [
                {
                    "severity": "High",
                    "rule": "R",
                    "title": "T",
                    "url": "u",
                    "source": "seed",
                    "evidence": "e",
                    "expected": "x",
                    "remediation": "r",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
