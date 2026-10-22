import unittest
from email.message import Message

from agent_security import analysis

GOOD = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
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
            rules(analyze(without("Strict-Transport-Security") + (("Strict-Transport-Security", "MAX-AGE=63072000"),))),
            ["HDR-HSTS-003"],
        )
        self.assertEqual(
            analyze(
                without("Strict-Transport-Security") + (("Strict-Transport-Security", "MAX-AGE=63072000; Preload"),)
            ),
            [],
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

    def test_nonce_hash_or_strict_dynamic_neutralize_unsafe_inline(self):
        for source in ("'nonce-R4nd0m'", "'sha256-abc='", "'strict-dynamic'"):
            csp = (
                "Content-Security-Policy",
                f"default-src 'self'; script-src {source} 'unsafe-inline'; frame-ancestors 'self'",
            )
            self.assertEqual(analyze(without("Content-Security-Policy") + (csp,)), [], source)
        bogus = (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'nonce-' 'unsafe-inline'; frame-ancestors 'self'",
        )
        self.assertEqual(rules(analyze(without("Content-Security-Policy") + (bogus,))), ["CSP-003"])

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

    def test_cookie_expiry_dates_are_masked_in_evidence(self):
        first = analyze(GOOD + (("Set-Cookie", "sid=1; Expires=Thu, 22 Oct 2027 10:00:01 GMT; Secure; HttpOnly"),))
        second = analyze(GOOD + (("Set-Cookie", "sid=1; expires=Thu, 22 Oct 2027 10:00:02 GMT; Secure; HttpOnly"),))
        self.assertEqual(first[0]["evidence"], "sid=<redacted>; Expires=<date>; Secure; HttpOnly")
        self.assertEqual(second[0]["evidence"], "sid=<redacted>; expires=<date>; Secure; HttpOnly")

    def test_hardened_cookies_and_multiple_set_cookie_headers(self):
        good = ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(analyze(GOOD + (good, ("Set-Cookie", "b=2; secure; httponly; samesite=Strict"))), [])
        self.assertEqual(rules(analyze(GOOD + (good, ("Set-Cookie", "b=2; Secure; HttpOnly")))), ["COOKIE-SAMESITE"])


def analyze_page(pairs=GOOD, facts=None, url="https://a.example.com/x"):
    findings = []
    analysis.analyze_response(
        {"headers": headers(*pairs), "final_url": url, "requested_url": url, "facts": facts}, findings
    )
    return findings


def facts(**values):
    return {"meta_csp": None, "mixed_active": [], "mixed_passive": [], "sri_missing": [], **values}


class BitsightAlignedRuleTests(unittest.TestCase):
    def test_samesite_none_without_secure_is_blocked_by_browsers(self):
        found = rules(analyze(GOOD + (("Set-Cookie", "a=1; HttpOnly; SameSite=None"),)))
        self.assertEqual(found, ["COOKIE-SAMESITE-NONE", "COOKIE-SECURE"])
        self.assertEqual(analyze(GOOD + (("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=None"),)), [])

    def test_unsafe_referrer_policy_uses_the_last_recognised_token(self):
        for value, expected in (
            ("unsafe-url", ["HDR-REF-002"]),
            ("no-referrer-when-downgrade", ["HDR-REF-002"]),
            ("unsafe-url, strict-origin-when-cross-origin", []),
            ("no-referrer, unsafe-url, bogus", ["HDR-REF-002"]),
        ):
            pairs = without("Referrer-Policy") + (("Referrer-Policy", value),)
            self.assertEqual(rules(analyze(pairs)), expected, value)

    def test_meta_csp_is_evaluated_when_the_header_is_missing(self):
        meta = facts(meta_csp="default-src 'self'; script-src 'unsafe-eval'; frame-ancestors 'self'")
        pairs = without("Content-Security-Policy") + (("X-Frame-Options", "DENY"),)
        self.assertEqual(rules(analyze_page(pairs, meta)), ["CSP-002"])
        # frame-ancestors in a meta tag is ignored by browsers.
        self.assertEqual(rules(analyze_page(without("Content-Security-Policy"), meta)), ["CSP-002", "HDR-XFO-001"])

    def test_mixed_content_and_sri_group_by_host(self):
        page_facts = facts(
            mixed_active=["http://cdn.example.net/a.js", "http://cdn.example.net/b.js"],
            mixed_passive=["http://img.example.net/x.png"],
            sri_missing=["https://cdn.example.net/lib.js"],
        )
        found = {f["rule"]: f["evidence"] for f in analyze_page(facts=page_facts)}
        self.assertEqual(sorted(found), ["MIXED-001", "MIXED-002", "SRI-001"])
        self.assertEqual(found["MIXED-001"], "Loaded over HTTP from: cdn.example.net")
        # Mixed content only exists on HTTPS pages.
        self.assertEqual(rules(analyze_page(facts=page_facts, url="http://a.example.com/x")), ["SRI-001"])

    def test_session_token_in_url_is_reported_without_its_value(self):
        found = analyze_page(url="https://a.example.com/x;jsessionid=SECRET1?PHPSESSID=SECRET2&page=1")
        self.assertEqual(rules(found), ["URL-SESSION-001"])
        self.assertIn("PHPSESSID, jsessionid", found[0]["evidence"])
        self.assertNotIn("SECRET", found[0]["evidence"])
        self.assertEqual(analyze_page(url="https://a.example.com/x?page=1&sort=asc"), [])


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
