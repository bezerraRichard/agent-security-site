import http.server
import ssl
import threading
import unittest
from collections import Counter
from unittest import mock

from agent_security import network as net
from agent_security.discovery import Robots, sitemap_urls

HOST = "www.example.com"


class LocalHandler(http.server.BaseHTTPRequestHandler):
    hits: Counter = Counter()

    def do_GET(self):
        LocalHandler.hits[self.path] += 1
        if self.path == "/flaky" and LocalHandler.hits[self.path] <= 2:
            self.send_response(503)
            self.send_header("Retry-After", "0")
            self.end_headers()
        elif self.path == "/always-503":
            self.send_response(503)
            self.end_headers()
        elif self.path == "/leave":
            self.send_response(302)
            self.send_header("Location", "http://other.example.com/")
            self.end_headers()
        elif self.path == "/image":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"abc")
        else:
            body = '<a href="/next">n</a>'.encode("latin-1")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=latin-1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


class FetcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        opener = net.build_opener(net.Route("direct (no proxy)", {}), {"127.0.0.1"}, ssl.create_default_context())
        cls.fetch = staticmethod(net.make_fetcher(opener, 5, 2, sleep=lambda seconds: None))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        LocalHandler.hits.clear()

    def test_retries_transient_503_then_reads_body(self):
        result = self.fetch(f"{self.base}/flaky", True)
        self.assertEqual(result["status"], 200)
        self.assertEqual(LocalHandler.hits["/flaky"], 3)
        self.assertIn('href="/next"', result["body"])
        self.assertEqual(result["content_type"], "text/html")

    def test_gives_up_after_the_retry_budget_and_returns_the_status(self):
        result = self.fetch(f"{self.base}/always-503")
        self.assertEqual(result["status"], 503)
        self.assertIsNone(result["error"])
        self.assertEqual(LocalHandler.hits["/always-503"], 3)

    def test_body_is_only_read_when_requested_and_for_text_types(self):
        self.assertIsNone(self.fetch(f"{self.base}/page")["body"])
        self.assertIsNone(self.fetch(f"{self.base}/image", True)["body"])

    def test_redirect_outside_scope_is_not_followed(self):
        result = self.fetch(f"{self.base}/leave", True)
        self.assertTrue(result["out_of_scope"])
        self.assertIn("outside the authorized hosts", result["error"])

    def test_connection_refused_is_reported_not_raised(self):
        result = self.fetch("http://127.0.0.1:1/")
        self.assertIsNotNone(result["error"])
        self.assertFalse(result["out_of_scope"])


class RouteTests(unittest.TestCase):
    def test_proxy_parsing_and_label(self):
        self.assertEqual(net.parse_proxy("proxy.example:8080"), "http://proxy.example:8080")
        self.assertEqual(net.proxy_label("http://user:pw@proxy.example:3128"), "proxy.example:3128")
        for value in ("ftp://proxy.example", "http://"):
            with self.assertRaises(ValueError):
                net.parse_proxy(value)

    def test_explicit_routes(self):
        self.assertEqual([r.name for r in net.candidate_routes(None, True, False)], ["direct (no proxy)"])
        explicit = net.candidate_routes("http://p.example:8080", False, True)
        self.assertEqual(
            [r.proxies for r in explicit], [{"http": "http://p.example:8080", "https": "http://p.example:8080"}, {}]
        )
        self.assertEqual(len(net.candidate_routes("http://p.example:8080", False, False)), 1)

    def test_system_proxy_is_tried_before_direct(self):
        with mock.patch.object(net.urllib.request, "getproxies", return_value={"https": "http://sys.example:3128"}):
            routes = net.candidate_routes(None, False, False)
        self.assertEqual([r.name for r in routes], ["system proxy sys.example:3128", "direct (no proxy)"])
        self.assertIsNone(routes[0].proxies)
        with mock.patch.object(net.urllib.request, "getproxies", return_value={}):
            self.assertEqual([r.name for r in net.candidate_routes(None, False, False)], ["direct (no proxy)"])

    def test_retry_delay_honors_retry_after_with_a_cap(self):
        self.assertEqual(net.retry_delay(0, None), 1.0)
        self.assertEqual(net.retry_delay(5, None), 8.0)
        self.assertEqual(net.retry_delay(0, "7"), 7.0)
        self.assertEqual(net.retry_delay(0, "9999"), 30.0)
        self.assertEqual(net.retry_delay(1, "Wed, 21 Oct 2026 07:28:00 GMT"), 2.0)

    def test_decode_body_survives_unknown_charsets(self):
        self.assertEqual(net.decode_body("é".encode(), "not-a-charset"), "é")
        self.assertEqual(net.decode_body("é".encode("latin-1"), "latin-1"), "é")


class SelectRouteTests(unittest.TestCase):
    routes = [net.Route("proxy p.example:8080", {"https": "http://p.example:8080"}), net.Route("direct (no proxy)", {})]

    def select(self, outcomes):
        def fake_make_fetcher(opener, timeout, retries, sleep=None):
            return lambda url, *a, **k: outcomes.pop(0)

        with (
            mock.patch.object(net, "make_fetcher", fake_make_fetcher),
            mock.patch.object(net, "build_opener", lambda *a: None),
        ):
            return net.select_route(self.routes, f"https://{HOST}/", {HOST}, 1, 0, None)

    def test_falls_back_to_direct_when_proxy_fails(self):
        route, _, attempts = self.select([net.failure("u", "proxy down"), {"error": None, "status": 200}])
        self.assertEqual(route.name, "direct (no proxy)")
        self.assertEqual([a["ok"] for a in attempts], [False, True])

    def test_proxy_auth_required_counts_as_failure(self):
        route, _, attempts = self.select([{"error": None, "status": 407}, {"error": None, "status": 200}])
        self.assertEqual(route.name, "direct (no proxy)")
        self.assertIn("407", attempts[0]["detail"])

    def test_first_working_route_wins(self):
        route, _, attempts = self.select([{"error": None, "status": 404}])
        self.assertEqual(route.name, "proxy p.example:8080")
        self.assertEqual(len(attempts), 1)

    def test_no_route_when_everything_fails(self):
        route, fetch, attempts = self.select([net.failure("u", "a"), net.failure("u", "b")])
        self.assertIsNone(route)
        self.assertIsNone(fetch)
        self.assertEqual(len(attempts), 2)


def fake_fetch(files):
    def fetch(url, want_body=False, max_bytes=0):
        status, body = files.get(url, (404, ""))
        return {
            "requested_url": url,
            "final_url": url,
            "status": status,
            "headers": None,
            "error": None,
            "content_type": "text/plain",
            "body": body,
            "out_of_scope": False,
        }

    return fetch


class DiscoveryTests(unittest.TestCase):
    def test_robots_rules_delay_and_sitemaps(self):
        robots_txt = "User-agent: *\nDisallow: /private\nCrawl-delay: 99\nSitemap: https://www.example.com/map.xml\n"
        robots = Robots(fake_fetch({f"https://{HOST}/robots.txt": (200, robots_txt)}), {HOST}, True)
        self.assertFalse(robots.allowed(f"https://{HOST}/private/x"))
        self.assertTrue(robots.allowed(f"https://{HOST}/public"))
        self.assertTrue(robots.allowed("https://unknown.example.org/private"))
        self.assertEqual(robots.crawl_delay(HOST), 10.0)
        self.assertEqual(robots.sitemaps(), [f"https://{HOST}/map.xml"])

    def test_missing_or_disabled_robots_allows_everything(self):
        missing = Robots(fake_fetch({}), {HOST}, True)
        disabled = Robots(
            fake_fetch({f"https://{HOST}/robots.txt": (200, "User-agent: *\nDisallow: /")}), {HOST}, False
        )
        for robots in (missing, disabled):
            self.assertTrue(robots.allowed(f"https://{HOST}/anything"))
            self.assertEqual(robots.crawl_delay(HOST), 0.0)

    def test_sitemap_index_is_followed_and_scoped(self):
        files = {
            f"https://{HOST}/sitemap.xml": (
                200,
                f"<sitemapindex><sitemap><loc>https://{HOST}/part1.xml</loc></sitemap></sitemapindex>",
            ),
            f"https://{HOST}/part1.xml": (
                200,
                f"<urlset><url><loc>https://{HOST}/a</loc></url><url><loc>https://evil.example.org/b</loc></url>"
                f"<url><loc> http://{HOST}/c?x=1&amp;y=2 </loc></url></urlset>",
            ),
        }
        found = sitemap_urls(fake_fetch(files), [f"https://{HOST}/sitemap.xml"], frozenset({HOST}), 10)
        self.assertEqual(found, [f"https://{HOST}/a", f"https://{HOST}/c?x=1&y=2"])

    def test_sitemap_limit_and_failures(self):
        urls = "".join(f"<url><loc>https://{HOST}/p{i}</loc></url>" for i in range(20))
        files = {f"https://{HOST}/sitemap.xml": (200, f"<urlset>{urls}</urlset>")}
        self.assertEqual(len(sitemap_urls(fake_fetch(files), [f"https://{HOST}/sitemap.xml"], frozenset({HOST}), 5)), 5)
        self.assertEqual(sitemap_urls(fake_fetch({}), [f"https://{HOST}/sitemap.xml"], frozenset({HOST}), 5), [])


if __name__ == "__main__":
    unittest.main()
