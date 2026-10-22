import unittest

from agent_security.htmlfacts import page_facts

BASE = "https://www.example.com/page"


class PageFactsTests(unittest.TestCase):
    def test_meta_csp_mixed_content_and_sri(self):
        body = """
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        <script src="http://cdn.example.net/a.js"></script>
        <script src="https://cdn.example.net/b.js" integrity="sha384-x"></script>
        <script src="https://cdn.example.net/c.js"></script>
        <script src="/local.js"></script>
        <link rel="stylesheet" href="https://fonts.example.net/f.css">
        <link rel="icon" href="http://www.example.com/favicon.ico">
        <img src="http://img.example.net/x.png"><iframe src="http://w.example.net/"></iframe>
        """
        facts = page_facts(body, BASE)
        self.assertEqual(facts["meta_csp"], "default-src 'self'")
        self.assertEqual(facts["mixed_active"], ["http://cdn.example.net/a.js", "http://w.example.net/"])
        self.assertEqual(facts["mixed_passive"], ["http://img.example.net/x.png"])
        self.assertEqual(
            facts["sri_missing"],
            ["http://cdn.example.net/a.js", "https://cdn.example.net/c.js", "https://fonts.example.net/f.css"],
        )

    def test_known_technologies_are_recognised_from_their_resources(self):
        body = """
        <link rel="stylesheet" href="/etc.clientlibs/site/clientlibs/base.css">
        <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
        <script src="https://assets.adobedtm.com/launch-123.min.js"></script>
        """
        self.assertEqual(
            page_facts(body, BASE)["technologies"],
            ["Adobe Experience Manager", "Adobe Experience Platform Tags", "OneTrust"],
        )

    def test_empty_and_malformed_markup(self):
        empty = {"meta_csp": None, "mixed_active": [], "mixed_passive": [], "sri_missing": [], "technologies": []}
        self.assertEqual(page_facts("<script src=", BASE), empty)
        self.assertEqual(page_facts("", BASE), empty)


if __name__ == "__main__":
    unittest.main()
