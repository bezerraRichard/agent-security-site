import json
import tempfile
import unittest
from pathlib import Path

from agent_security.console import categorize
from agent_security.onetrust import OneTrustConfig

ID_A = "5dd32a8b-de66-42d1-a4d8-0000b6a10b1a"
ID_B = "6ee43b9c-ef77-43e2-b5e9-1111c7b21c2b"


def report(*cookies):
    return {"cookies": {"inventory": list(cookies)}}


def cookie(name, cookie_id=None, category=None, hosts=("www.example.com",)):
    classification = {"status": "classified" if category else "uncategorized", "category": category, "host": "x.com"}
    if cookie_id:
        classification["cookie_id"] = cookie_id
    return {"name": name, "hosts": list(hosts), "classification": classification}


class CategorizeTests(unittest.TestCase):
    def test_only_catalogued_cookies_are_offered_uncategorized_first(self):
        rows = categorize.categorizable_cookies(
            [
                report(cookie("zeta", ID_A, "Performance"), cookie("legacy")),
                report(cookie("zeta", ID_A, "Performance", hosts=("shop.example.com",)), cookie("alpha", ID_B)),
            ]
        )
        self.assertEqual([r["name"] for r in rows], ["alpha", "zeta"])
        self.assertEqual(rows[1]["domains"], ["shop.example.com", "www.example.com"])

    def test_changes_carry_the_current_category(self):
        [change] = categorize.build_changes([{"cookie_id": ID_A, "name": "a", "host": "h", "category": "X"}], "C0002")
        self.assertEqual(
            (change.current_category, change.payload()), ("X", {"cookieId": ID_A, "customCategoryName": "C0002"})
        )

    def test_audit_is_read_newest_first_and_tolerates_bad_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / categorize.AUDIT_FILE
            self.assertEqual(categorize.read_audit(path), [])
            path.write_text(
                "\n".join([json.dumps({"n": 1}), "not json", json.dumps({"n": 2}), json.dumps({"n": 3})]),
                encoding="utf-8",
            )
            self.assertEqual([r["n"] for r in categorize.read_audit(path, limit=2)], [3, 2])

    def test_write_client_uses_the_given_config(self):
        config = OneTrustConfig("app-eu.onetrust.com", "w", "secret", scope="COOKIE")
        client = categorize.make_write_client(config)
        self.assertEqual((client.config.scope, client.base_url), ("COOKIE", "https://app-eu.onetrust.com"))
        self.assertTrue(client.openers)


if __name__ == "__main__":
    unittest.main()
