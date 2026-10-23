import unittest

from agent_security import actions
from agent_security.findings import group_findings

AEM_CLOUD_PLATFORM = {"cdn": "Fastly", "cms": "Adobe Experience Manager as a Cloud Service", "technologies": []}


def report(host, findings=(), platform=None, inventory=(), classification="ok"):
    groups = group_findings(
        [
            {
                "severity": severity,
                "rule": rule,
                "title": title,
                "evidence": "e",
                "expected": "x",
                "remediation": "r",
                "url": f"https://{host}/{n}",
            }
            for rule, severity, title, n in findings
        ]
    )
    return {
        "target": f"https://{host}/",
        "groups": groups,
        "platform": platform,
        "cookies": {"classification": {"status": classification}, "inventory": list(inventory)},
    }


class BuildActionsTests(unittest.TestCase):
    def test_findings_merge_across_domains_and_are_prioritised(self):
        plan = actions.build_actions(
            [
                report("a.example.com", [("CSP-002", "Critical", "CSP allows unsafe-eval", 1)]),
                report(
                    "b.example.com",
                    [
                        ("CSP-002", "Critical", "CSP allows unsafe-eval", 1),
                        ("HDR-PP-001", "Low", "Permissions-Policy missing", 1),
                    ],
                ),
            ]
        )
        self.assertEqual([a.key for a in plan], ["CSP-002", "HDR-PP-001"])
        self.assertEqual(plan[0].domains, ["a.example.com", "b.example.com"])
        self.assertEqual((plan[0].priority, plan[0].pages), ("P1", 2))
        self.assertEqual(plan[0].bitsight, "Content Security Policy Configurations")
        self.assertEqual(plan[1].priority, "P4")

    def test_header_fixes_target_the_detected_platform(self):
        finding = [("HDR-XCTO-001", "Medium", "X-Content-Type-Options missing", 1)]
        [aem] = actions.build_actions([report("a.example.com", finding, AEM_CLOUD_PLATFORM)])
        self.assertEqual(aem.owner, "Adobe AEM · CDN (cdn.yaml, Config Pipeline)")
        self.assertEqual(aem.snippet_language, "yaml")
        self.assertIn("respHeader: X-Content-Type-Options", aem.snippet)
        self.assertIn('value: "nosniff"', aem.snippet)
        [generic] = actions.build_actions([report("b.example.com", finding)])
        self.assertEqual(generic.owner, "Web server / reverse proxy")
        self.assertIn('Header always set X-Content-Type-Options "nosniff"', generic.snippet)
        self.assertIn("curl -sI https://b.example.com/", generic.verify)

    def test_cookie_actions_are_per_cookie_and_name_the_owner(self):
        findings = [
            ("COOKIE-SAMESITE", "Medium", "Cookie affinity missing SameSite", 1),
            ("COOKIE-HTTPONLY", "Medium", "Cookie OptanonConsent missing HttpOnly flag", 1),
        ]
        plan = {a.key: a for a in actions.build_actions([report("a.example.com", findings, AEM_CLOUD_PLATFORM)])}
        self.assertEqual(plan["COOKIE-SAMESITE:affinity"].owner, "Adobe AEM · platform affinity cookie")
        self.assertIn("Adobe support", " ".join(plan["COOKIE-SAMESITE:affinity"].steps))
        self.assertEqual(plan["COOKIE-HTTPONLY:OptanonConsent"].owner, "OneTrust · consent script")
        self.assertIn("accepted risk", " ".join(plan["COOKIE-HTTPONLY:OptanonConsent"].steps))

    def test_onetrust_actions_from_cookie_classification(self):
        inventory = [
            {"name": "_ga", "classification": {"status": "classified", "category": "Performance Cookies"}},
            {"name": "sid", "classification": {"status": "classified", "category": "Strictly Necessary Cookies"}},
            {"name": "mystery", "classification": {"status": "not_found"}},
            {"name": "blank", "classification": {"status": "uncategorized"}},
        ]
        plan = {a.key: a for a in actions.build_actions([report("a.example.com", inventory=inventory)])}
        self.assertEqual(set(plan), {"ONETRUST-BEFORE-CONSENT", "ONETRUST-UNCATEGORIZED", "ONETRUST-NOT-FOUND"})
        self.assertIn("_ga (Performance Cookies)", plan["ONETRUST-BEFORE-CONSENT"].steps[0])
        self.assertNotIn("sid", plan["ONETRUST-BEFORE-CONSENT"].steps[0])
        self.assertIn(actions.ONETRUST_UPDATE_COOKIE, " ".join(plan["ONETRUST-UNCATEGORIZED"].steps))
        unconfigured = actions.build_actions([report("a.example.com", classification="not_configured")])
        self.assertEqual([a.key for a in unconfigured], ["ONETRUST-NOT-CONFIGURED"])

    def test_code_fixes_go_to_front_end_and_report_only_policy_is_linked(self):
        findings = [
            ("CSP-002", "Critical", "CSP allows unsafe-eval", 1),
            ("CSP-004", "Info", "Content-Security-Policy-Report-Only present (not enforced)", 1),
        ]
        plan = {a.key: a for a in actions.build_actions([report("a.example.com", findings, AEM_CLOUD_PLATFORM)])}
        self.assertEqual(plan["CSP-002"].owner, "AEM front-end and tag management")
        self.assertIn("Report-Only", plan["CSP-002"].steps[0])
        self.assertEqual(plan["CSP-004"].severity, "High")
        self.assertIn(plan["CSP-004"].priority, {"P1", "P2"})
        alone = actions.build_actions([report("b.example.com", findings[1:])])
        self.assertEqual((alone[0].severity, alone[0].priority), ("Info", "P4"))

    def test_every_rule_has_a_playbook(self):
        from agent_security.taxonomy import RULE_INFO

        self.assertEqual(set(actions.PLAYBOOKS), set(RULE_INFO))


class OutputTests(unittest.TestCase):
    def plan(self):
        findings = [
            ("HDR-XCTO-001", "Medium", "X-Content-Type-Options missing", 1),
            ("HDR-HSTS-001", "High", "Strict-Transport-Security missing", 1),
            ("HDR-HSTS-003", "Info", "Strict-Transport-Security without preload", 2),
            ("CSP-000", "High", "Content-Security-Policy missing", 1),
        ]
        return actions.build_actions([report("a.example.com", findings, AEM_CLOUD_PLATFORM)])

    def test_cdn_config_combines_headers_and_leaves_csp_out(self):
        config = actions.aem_cdn_config(self.plan())
        self.assertIn('kind: "CDN"', config)
        self.assertIn('value: "max-age=31536000; includeSubDomains"', config)
        self.assertNotIn("includeSubDomains; preload", config)
        self.assertEqual(config.count("respHeader: Strict-Transport-Security"), 1)
        self.assertIn("respHeader: X-Content-Type-Options", config)
        self.assertNotIn("respHeader: Content-Security-Policy", config)
        self.assertEqual(actions.aem_cdn_config([]), "")

    def test_yaml_values_keep_csp_quotes(self):
        snippet, _ = actions.header_snippet(actions.Platform(cms=actions.AEM_CLOUD), "X", "default-src 'self' \"a\"")
        self.assertIn('value: "default-src \'self\' \\"a\\""', snippet)

    def test_rows_and_markdown_use_saved_state(self):
        plan = self.plan()
        state = {plan[0].key: {"status": "In progress", "owner": "AEM team", "note": "sprint 12"}}
        row = actions.action_rows(plan, state)[0]
        self.assertEqual((row["Status"], row["Owner"], row["Note"]), ("In progress", "AEM team", "sprint 12"))
        self.assertEqual(actions.action_rows(plan, {})[0]["Status"], "To do")
        markdown = actions.markdown_plan(plan, state, "Plano")
        self.assertTrue(markdown.startswith("# Plano"))
        self.assertIn("**Status:** In progress", markdown)
        self.assertIn("```yaml", markdown)


class CriticalActionTests(unittest.TestCase):
    POLICIES = "object-src 'none' | default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' cdn.example"

    def csp_report(self, host="a.example.com", platform=None):
        data = report(host, [("CSP-002", "Critical", "CSP allows unsafe-eval", n) for n in range(3)], platform)
        for group in data["groups"]:
            group["evidence"] = self.POLICIES
        return data

    def test_fix_csp_only_touches_script_directives(self):
        policy = "default-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; script-src 'unsafe-inline' a.example"
        fixed = actions.fix_csp(policy, "'unsafe-inline'", (actions.NONCE, "'strict-dynamic'"))
        self.assertEqual(
            fixed,
            "default-src 'self' 'nonce-{RANDOM_PER_RESPONSE}' 'strict-dynamic'; style-src 'unsafe-inline'; "
            "script-src a.example 'nonce-{RANDOM_PER_RESPONSE}' 'strict-dynamic'",
        )

    def test_critical_action_carries_evidence_urls_and_the_corrected_policy(self):
        action = actions.build_actions([self.csp_report(platform=AEM_CLOUD_PLATFORM)])[0]
        self.assertEqual((action.key, action.severity, action.priority), ("CSP-002", "Critical", "P1"))
        self.assertEqual(action.evidence, self.POLICIES)
        self.assertEqual(action.urls, [f"https://a.example.com/{n}" for n in range(3)])
        self.assertIn("respHeader: Content-Security-Policy-Report-Only", action.snippet)
        self.assertIn("script-src 'self' 'unsafe-inline' cdn.example", action.snippet)
        self.assertNotIn("object-src", action.snippet)  # Policies that allow no unsafe-eval stay as they are.
        self.assertIn("grep -c \"'unsafe-eval'\"", action.verify)
        markdown = actions.markdown_plan([action], {}, "Plan")
        self.assertIn("**Observed:**", markdown)

    def test_page_level_rules_get_a_real_verification_command(self):
        plan = {a.key: a for a in actions.build_actions([report("a.example.com", [("SRI-001", "Low", "SRI", 1)])])}
        self.assertIn("grep -vi integrity", plan["SRI-001"].verify)
        self.assertNotIn('grep -i "^"', plan["SRI-001"].verify)


if __name__ == "__main__":
    unittest.main()
