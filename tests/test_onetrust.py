import http.server
import json
import threading
import unittest
import urllib.parse
import urllib.request
from unittest import mock

from agent_security import onetrust as ot

SECRET = "s3cr3t-value-that-must-not-leak"


class FakeOneTrust(http.server.BaseHTTPRequestHandler):
    state: dict = {}

    def _json(self, status, payload, extra=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        state = FakeOneTrust.state
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path == "/api/access/v1/oauth/token":
            form = urllib.parse.parse_qs(body)
            state["token_calls"] = state.get("token_calls", 0) + 1
            if form.get("client_secret") != [SECRET] or form.get("grant_type") != ["client_credentials"]:
                return self._json(401, {"error": "invalid_client"})
            return self._json(200, {"access_token": f"tok{state['token_calls']}", "expires_in": 3600})
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            self.end_headers()
            return
        if "/cookies/filter" in self.path:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            state.setdefault("requests", []).append(
                {
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                    "body": json.loads(body or "{}"),
                }
            )
            name = query["cookieName"][0]
            if state.get("expire_first_token") and state["token_calls"] == 1:
                return self._json(401, {})
            if name == "limited" and not state.get("limited_done"):
                state["limited_done"] = True
                return self._json(429, {}, {"Retry-After": "0"})
            if name == "denied":
                return self._json(403, {})
            page = int(query["page"][0])
            if name == "paged":
                pages = [[{"cookieName": "other"}] * 2, [{"cookieName": "paged", "displayGroupName": "Performance"}]]
                return self._json(200, {"content": pages[page], "last": page == 1})
            catalog = {
                "affinity": [
                    {
                        "cookieName": "affinity",
                        "displayGroupName": "Strictly Necessary Cookies",
                        "host": "novobanco.pt",
                        "thirdParty": False,
                        "lifespan": "SESSION",
                        "description": "Load balancer",
                        "cookieSource": "SCAN",
                    }
                ],
                "multi": [
                    {"cookieName": "multi", "displayGroupName": "Marketing", "host": "ads.example.com"},
                    {
                        "cookieName": "multi",
                        "displayGroupName": "Functional",
                        "host": "novobanco.pt",
                        "length": 5,
                        "durationType": "DAY",
                        "lifespan": "PERSISTENT",
                    },
                ],
                "nocat": [{"cookieName": "nocat", "host": "x.com"}],
                "partial": [{"cookieName": "partial-extra", "displayGroupName": "Other"}],
            }
            return self._json(200, {"content": catalog.get(name, []), "last": True})
        self._json(404, {})

    def log_message(self, *args):
        pass


def make_client(base, sleep=lambda seconds: None, domain_ids=()):
    config = ot.OneTrustConfig("app.onetrust.com", "client-id", SECRET, "en", tuple(domain_ids))
    return ot.OneTrustClient(config, [("direct", ot.build_opener({}, None))], 5, sleep=sleep, base_url=base)


class OneTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOneTrust)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeOneTrust.state = {}

    def test_config_validation_and_secret_not_in_repr(self):
        env = {"ONETRUST_HOSTNAME": "app-eu.onetrust.com", "ONETRUST_CLIENT_ID": "id", "ONETRUST_CLIENT_SECRET": SECRET}
        config = ot.config_from_env(env)
        self.assertEqual(config.hostname, "app-eu.onetrust.com")
        self.assertNotIn(SECRET, repr(config))
        self.assertIsNone(ot.config_from_env({}))
        for host in ("evil.example.com", "app.onetrust.com.evil.com", "http://app.onetrust.com"):
            with self.assertRaises(ValueError):
                ot.config_from_env(env, hostname=host)
        with self.assertRaises(ValueError):
            ot.config_from_env(env, language="../etc")
        with self.assertRaises(ValueError):
            ot.config_from_env(env, domain_ids=["not-a-uuid"])

    def test_lookup_sends_bearer_filter_and_domain_restriction(self):
        domain = "f2229953-b4b5-4042-8cb9-b78038cc4c46"
        entries = make_client(self.base, domain_ids=[domain]).find_cookies("affinity")
        request = FakeOneTrust.state["requests"][0]
        self.assertEqual(request["auth"], "Bearer tok1")
        self.assertEqual(request["body"], {"domains": [domain]})
        self.assertIn("/api/cmp/v1/webscans/languages/en/cookies/filter", request["path"])
        self.assertIn("cookieName=affinity", request["path"])
        self.assertEqual(entries[0]["displayGroupName"], "Strictly Necessary Cookies")

    def test_pagination_is_followed(self):
        self.assertEqual(len(make_client(self.base).find_cookies("paged")), 3)

    def test_expired_token_is_refreshed_once(self):
        FakeOneTrust.state["expire_first_token"] = True
        entries = make_client(self.base).find_cookies("affinity")
        self.assertEqual(FakeOneTrust.state["token_calls"], 2)
        self.assertEqual(len(entries), 1)

    def test_rate_limit_is_retried(self):
        slept = []
        self.assertEqual(make_client(self.base, sleep=slept.append).find_cookies("limited"), [])
        self.assertEqual(slept, [0.0])

    def test_bad_credentials_are_fatal_and_do_not_leak(self):
        config = ot.OneTrustConfig("app.onetrust.com", "id", "wrong", "en")
        client = ot.OneTrustClient(config, [("direct", ot.build_opener({}, None))], 5, base_url=self.base)
        with self.assertRaises(ot.OneTrustError) as caught:
            client.find_cookies("affinity")
        self.assertTrue(caught.exception.fatal)
        self.assertNotIn("wrong", str(caught.exception))

    def test_forbidden_is_fatal(self):
        with self.assertRaises(ot.OneTrustError) as caught:
            make_client(self.base).find_cookies("denied")
        self.assertTrue(caught.exception.fatal)
        self.assertIn("COOKIE_READ", str(caught.exception))

    def test_redirects_are_not_followed(self):
        client = make_client(self.base)
        client._token, client._token_expiry = "tok", 1e12
        with self.assertRaises(ot.OneTrustError):
            client._post("/redirect", {})

    def test_connection_failure_is_fatal(self):
        config = ot.OneTrustConfig("app.onetrust.com", "id", SECRET, "en")
        client = ot.OneTrustClient(config, [("direct", ot.build_opener({}, None))], 2, base_url="http://127.0.0.1:1")
        with self.assertRaises(ot.OneTrustError) as caught:
            client.find_cookies("x")
        self.assertTrue(caught.exception.fatal)

    def test_classify_cookies_end_to_end(self):
        cookies = [
            {"name": "affinity", "hosts": ["www.novobanco.pt"]},
            {"name": "multi", "hosts": ["www.novobanco.pt"]},
            {"name": "nocat", "hosts": []},
            {"name": "partial", "hosts": []},
            {"name": "unknown", "hosts": []},
        ]
        meta, results = ot.classify_cookies(make_client(self.base), cookies)
        self.assertEqual(meta["status"], "ok")
        self.assertEqual(results["affinity"]["category"], "Strictly Necessary Cookies")
        self.assertIs(results["affinity"]["third_party"], False)
        self.assertEqual(results["multi"]["category"], "Functional")
        self.assertEqual(results["multi"]["other_categories"], ["Marketing"])
        self.assertEqual(results["multi"]["duration"], "5 DAY")
        self.assertEqual(results["nocat"]["status"], "uncategorized")
        self.assertEqual(results["partial"]["status"], "not_found")
        self.assertEqual(results["unknown"]["status"], "not_found")

    def test_classify_unavailable_when_credentials_rejected(self):
        config = ot.OneTrustConfig("app.onetrust.com", "id", "wrong", "en")
        client = ot.OneTrustClient(config, [("direct", ot.build_opener({}, None))], 5, base_url=self.base)
        meta, results = ot.classify_cookies(client, [{"name": "a", "hosts": []}, {"name": "b", "hosts": []}])
        self.assertEqual(meta["status"], "unavailable")
        self.assertEqual(results, {})

    def test_partial_when_lookup_limit_is_exceeded(self):
        names = [{"name": f"c{i}", "hosts": []} for i in range(ot.MAX_COOKIES_PER_RUN + 2)]
        meta, results = ot.classify_cookies(make_client(self.base), names)
        self.assertEqual(meta["status"], "partial")
        self.assertEqual(len(results), ot.MAX_COOKIES_PER_RUN)

    @mock.patch.object(urllib.request, "proxy_bypass", lambda host: False)
    def test_route_fallback_when_first_route_is_unusable(self):
        config = ot.OneTrustConfig("app.onetrust.com", "id", SECRET, "en")
        dead = ("dead proxy", ot.build_opener({"http": "http://127.0.0.1:1"}, None))
        direct = ("direct", ot.build_opener({}, None))
        client = ot.OneTrustClient(config, [dead, direct], 3, base_url=self.base)
        self.assertEqual(len(client.find_cookies("affinity")), 1)
        self.assertEqual(client.route, "direct")


if __name__ == "__main__":
    unittest.main()
