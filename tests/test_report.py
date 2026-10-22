import json
import tempfile
import unittest
from pathlib import Path

from agent_security import report as rp
from agent_security.findings import group_findings, summarize

SECRET = "s3cr3t-value-that-must-not-leak"


def sample_report(classification_status="ok"):
    groups = group_findings(
        [
            {
                "severity": "Medium",
                "rule": "COOKIE-SAMESITE",
                "title": "Cookie affinity missing SameSite",
                "evidence": "affinity=<redacted>; Path=/",
                "expected": "...; SameSite=Lax",
                "remediation": "Set SameSite.",
                "url": "https://www.example.com/a",
                "source": "crawl",
            },
            {
                "severity": "Critical",
                "rule": "CSP-002",
                "title": "CSP allows unsafe-eval",
                "evidence": "script-src 'unsafe-eval' <script>alert(1)</script>",
                "expected": "none",
                "remediation": "Remove.",
                "url": "https://www.example.com/b",
                "source": "seed",
            },
        ]
    )
    inventory = [
        {
            "name": "affinity",
            "hosts": ["www.example.com"],
            "pages": 1,
            "attributes": "Path=/",
            "variants": 1,
            "classification": {
                "status": "classified",
                "category": "Strictly <b>Necessary</b>",
                "third_party": False,
                "lifespan": "SESSION",
                "duration": None,
                "description": "Load <i>balancer</i>",
            },
        },
        {
            "name": "unknown",
            "hosts": [],
            "pages": 1,
            "attributes": "",
            "variants": 1,
            "classification": {"status": "not_found", "category": None},
        },
    ]
    return {
        "target": "https://www.example.com/",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "status": "complete: ok",
        "methodology": "m",
        "route": {
            "selected": "direct (no proxy)",
            "attempts": [{"route": "direct (no proxy)", "ok": True, "detail": "HTTP 200"}],
        },
        "scope": {
            "allowed_hosts": ["www.example.com"],
            "max_pages": 5,
            "max_depth": 2,
            "delay_seconds": 0.5,
            "respect_robots": True,
            "sitemap_used": False,
            "pages_assessed": 2,
            "pages_failed": 0,
            "queue_remaining": 0,
            "stop_reason": None,
            "status_counts": {"200": 2},
        },
        "skipped": {"non-page file type": 3},
        "http_probe": {
            "requested_url": "http://www.example.com/",
            "final_url": "https://www.example.com/",
            "status": 200,
            "error": None,
        },
        "summary": summarize(groups),
        "cookies": {
            "classification": {
                "status": classification_status,
                "hostname": "app.onetrust.com",
                "language": "en",
                "route": "direct",
                "domain_filter": False,
                "cookies_checked": 2,
                "cookies_total": 2,
                "detail": "",
            },
            "inventory": inventory,
        },
        "groups": groups,
        "pages": [
            {
                "url": "https://www.example.com/a",
                "final_url": None,
                "status": 200,
                "depth": 0,
                "source": "seed",
                "content_type": "text/html",
                "error": None,
                "findings": 1,
            }
        ],
    }


class RenderTests(unittest.TestCase):
    def test_layout_sections_and_classification(self):
        page = rp.render_html(sample_report())
        for expected in (
            "Summary by severity",
            "Summary by section",
            "Content Security Policy",
            "Cookie classification",
            "Not found in OneTrust",
            "Cookie classification:",
            "References:",
            "Current value:",
            "Remediation",
            "Pages assessed",
        ):
            self.assertIn(expected, page)
        self.assertLess(page.index("id='content-security-policy'"), page.index("id='cookies'"))

    def test_untrusted_content_is_escaped(self):
        page = rp.render_html(sample_report())
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("Strictly <b>Necessary</b>", page)
        self.assertNotIn("Load <i>balancer</i>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_only_http_links_become_anchors(self):
        self.assertEqual(rp.link("javascript:alert(1)"), "javascript:alert(1)")
        self.assertEqual(
            rp.link('https://a.example.com/"x'),
            '<a href="https://a.example.com/&quot;x">https://a.example.com/&quot;x</a>',
        )

    def test_notices_for_every_classification_state(self):
        base = {
            "hostname": "h",
            "language": "en",
            "route": "r",
            "domain_filter": False,
            "cookies_checked": 1,
            "cookies_total": 2,
            "detail": "why",
        }
        self.assertIn("not configured", rp.classification_notice({"status": "not_configured"}))
        self.assertIn("No cookies", rp.classification_notice({"status": "no_cookies"}))
        self.assertIn("unavailable: why", rp.classification_notice(dict(base, status="unavailable")))
        self.assertIn("1 of 2", rp.classification_notice(dict(base, status="partial")))
        self.assertIn("classified with the OneTrust", rp.classification_notice(dict(base, status="ok")))

    def test_report_without_cookies_or_findings_renders(self):
        report = sample_report()
        report.update(groups=[], pages=[])
        report["summary"] = summarize([])
        report["cookies"] = {"classification": {"status": "no_cookies"}, "inventory": []}
        page = rp.render_html(report)
        self.assertIn("No confirmed findings", page)
        self.assertIn("No cookies were set", page)

    def test_long_url_lists_are_truncated_in_html_only(self):
        report = sample_report()
        report["groups"][0]["urls"] = [f"https://www.example.com/{n}" for n in range(rp.URL_LIST_LIMIT + 5)]
        self.assertIn("5 more in the JSON report", rp.render_html(report))

    def test_report_has_no_secret(self):
        self.assertNotIn(SECRET, json.dumps(sample_report()))


class WriteReportsTests(unittest.TestCase):
    def test_writes_both_files_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "nested" / "reports"
            paths = [rp.write_reports(sample_report(), out) for _ in range(3)]
            names = {path.name for pair in paths for path in pair}
            self.assertEqual(len(names), 6)
            html_path, json_path = paths[0]
            self.assertEqual(html_path.suffix, ".html")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["target"], "https://www.example.com/")
            self.assertIn("<!doctype html>", html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
