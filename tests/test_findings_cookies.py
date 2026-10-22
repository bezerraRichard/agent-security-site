import json
import unittest
from email.message import Message

from agent_security.cookies import observe_cookies, parse_set_cookie
from agent_security.findings import group_findings, summarize
from agent_security.taxonomy import RULE_INFO, SECTIONS, SEVERITIES, section_of

SECRET_VALUE = "SESSIONVALUE-must-not-leak"


def headers(*cookies):
    message = Message()
    for cookie in cookies:
        message["Set-Cookie"] = cookie
    return message


def finding(rule="CSP-002", severity="Critical", url="https://a.example.com/1", title="t", evidence="e", source="seed"):
    return {
        "severity": severity,
        "rule": rule,
        "title": title,
        "evidence": evidence,
        "expected": "x",
        "remediation": "r",
        "url": url,
        "source": source,
    }


class CookieTests(unittest.TestCase):
    def test_parse_set_cookie_drops_the_value(self):
        self.assertEqual(
            parse_set_cookie("sid=abc=def; Path=/; Secure;; HttpOnly"), ("sid", ["Path=/", "Secure", "HttpOnly"])
        )
        self.assertEqual(parse_set_cookie("=nameless"), ("", []))

    def test_observation_merges_pages_and_never_keeps_values(self):
        pages = [
            {
                "requested_url": "https://www.example.com/a",
                "final_url": "https://www.example.com/a",
                "headers": headers(f"affinity={SECRET_VALUE}; Path=/; HttpOnly; secure", "other=1; Path=/"),
            },
            {
                "requested_url": "https://www.example.com/b",
                "final_url": None,
                "headers": headers(f"affinity={SECRET_VALUE}; Path=/; HttpOnly; secure"),
            },
            {
                "requested_url": "https://shop.example.com/",
                "final_url": "https://shop.example.com/",
                "headers": headers(f"affinity={SECRET_VALUE}; Path=/; Secure"),
            },
            {"requested_url": "https://www.example.com/c", "final_url": None, "headers": None},
        ]
        inventory = observe_cookies(pages)
        self.assertEqual([c["name"] for c in inventory], ["affinity", "other"])
        affinity = inventory[0]
        self.assertEqual((affinity["pages"], affinity["variants"]), (3, 2))
        self.assertEqual(affinity["hosts"], ["shop.example.com", "www.example.com"])
        self.assertEqual(affinity["attributes"], "Path=/; HttpOnly; secure")
        self.assertNotIn(SECRET_VALUE, json.dumps(inventory))

    def test_expiry_dates_do_not_create_attribute_variants(self):
        pages = [
            {
                "requested_url": f"https://www.example.com/{second}",
                "final_url": None,
                "headers": headers(f"sid=1; Path=/; Expires=Thu, 22 Oct 2027 10:00:0{second} GMT; Secure"),
            }
            for second in range(3)
        ]
        [sid] = observe_cookies(pages)
        self.assertEqual((sid["pages"], sid["variants"]), (3, 1))
        self.assertEqual(sid["attributes"], "Path=/; Expires=<date>; Secure")


class FindingsTests(unittest.TestCase):
    def test_groups_merge_identical_evidence_across_pages(self):
        base = finding(rule="CSP-001", severity="Medium", evidence="same")
        findings = [dict(base, url=f"https://a.example.com/{n}") for n in ("b", "a", "a")]
        findings.append(dict(base, url="https://a.example.com/c", evidence="different"))
        groups = group_findings(findings)
        self.assertEqual([g["count"] for g in groups], [2, 1])
        self.assertEqual(groups[0]["urls"], ["https://a.example.com/a", "https://a.example.com/b"])

    def test_groups_are_sorted_by_severity_then_reach(self):
        findings = [
            finding("CSP-001", "Medium", "https://a.example.com/1"),
            finding("HDR-HSTS-001", "High", "https://a.example.com/1"),
            finding("CSP-002", "Critical", "https://a.example.com/1"),
            finding("CSP-002", "Critical", "https://a.example.com/2", title="other"),
            finding("CSP-002", "Critical", "https://a.example.com/3", title="other"),
        ]
        self.assertEqual(
            [(g["severity"], g["title"]) for g in group_findings(findings)],
            [("Critical", "other"), ("Critical", "t"), ("High", "t"), ("Medium", "t")],
        )

    def test_sources_are_merged_and_cookie_names_extracted(self):
        findings = [
            finding(
                "COOKIE-SAMESITE",
                "Medium",
                "https://a.example.com/1",
                "Cookie affinity missing SameSite",
                source="seed",
            ),
            finding(
                "COOKIE-SAMESITE",
                "Medium",
                "https://a.example.com/2",
                "Cookie affinity missing SameSite",
                source="crawl",
            ),
            finding("CSP-001", "Medium", title="Cookie lookalike missing"),
        ]
        by_rule = {g["rule"]: g for g in group_findings(findings)}
        self.assertEqual(by_rule["COOKIE-SAMESITE"]["cookie"], "affinity")
        self.assertEqual(by_rule["COOKIE-SAMESITE"]["sources"], ["crawl", "seed"])
        self.assertIsNone(by_rule["CSP-001"]["cookie"])

    def test_summary_counts_by_severity_and_section(self):
        findings = [
            finding("CSP-002", "Critical", "https://a.example.com/1"),
            finding("CSP-002", "Critical", "https://a.example.com/2"),
            finding("HDR-HSTS-001", "High", "https://a.example.com/1"),
        ]
        summary = summarize(group_findings(findings))
        self.assertEqual(summary["severity"]["Critical"], {"distinct": 1, "instances": 2})
        self.assertEqual(summary["sections"]["Content Security Policy"], {"distinct": 1, "instances": 2})
        self.assertEqual(summary["sections"]["Security Headers"], {"distinct": 1, "instances": 1})
        self.assertEqual(summary["sections"]["TLS"], {"distinct": 0, "instances": 0})
        self.assertEqual(tuple(summary["severity"]), SEVERITIES)
        self.assertEqual(tuple(summary["sections"]), SECTIONS)

    def test_every_rule_has_guidance_and_a_known_section(self):
        for rule, (description, references) in RULE_INFO.items():
            self.assertTrue(description and references, rule)
            self.assertTrue(all(ref.startswith("https://") for ref in references), rule)
            self.assertIn(section_of(rule), SECTIONS)


if __name__ == "__main__":
    unittest.main()
