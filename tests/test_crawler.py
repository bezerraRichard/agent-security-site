import unittest

from agent_security import crawler
from agent_security.network import failure

HOST = "www.example.com"


def page(links=(), final=None, status=200):
    body = "<html>" + "".join(f'<a href="{href}">x</a>' for href in links) + "</html>"
    return {"status": status, "body": body, "final": final}


def make_fetch(site, fail=()):
    calls = []

    def fetch(url, want_body=False, max_bytes=0):
        calls.append(url)
        if url in fail:
            return failure(url, "boom")
        entry = site.get(url, {"status": 404, "body": "", "final": None})
        return {
            "requested_url": url,
            "final_url": entry["final"] or url,
            "status": entry["status"],
            "headers": None,
            "error": None,
            "content_type": "text/html",
            "body": entry["body"],
            "out_of_scope": False,
        }

    fetch.calls = calls
    return fetch


def run(site, fail=(), **overrides):
    options = dict(
        seeds=[(f"https://{HOST}/", "seed")],
        allowed_hosts={HOST},
        robots_allowed=lambda url: True,
        max_pages=100,
        max_depth=10,
        delay=0,
        deadline=float("inf"),
        sleep=lambda seconds: None,
    )
    options.update(overrides)
    fetch = make_fetch(site, fail)
    return crawler.crawl(fetch=fetch, **options), fetch


class ExtractLinksTests(unittest.TestCase):
    def test_base_href_is_honored(self):
        links = crawler.extract_links('<base href="/docs/"><a href="page">p</a>', f"https://{HOST}/")
        self.assertEqual(links, [f"https://{HOST}/docs/page"])

    def test_collects_anchors_areas_and_frames_only(self):
        body = '<a href="/a">a</a><area href="/b"><iframe src="/c"></iframe><img src="/d.png"><script src="/e.js"></script>'
        self.assertEqual(
            crawler.extract_links(body, f"https://{HOST}/"),
            [f"https://{HOST}/a", f"https://{HOST}/b", f"https://{HOST}/c"],
        )

    def test_malformed_markup_does_not_raise(self):
        self.assertIsInstance(crawler.extract_links("<a href=<<>>\x00<a href='/ok'", f"https://{HOST}/"), list)

    def test_link_count_is_capped(self):
        body = "".join(f'<a href="/p{i}">x</a>' for i in range(crawler.MAX_LINKS_PER_PAGE + 50))
        self.assertEqual(len(crawler.extract_links(body, f"https://{HOST}/")), crawler.MAX_LINKS_PER_PAGE)


class CrawlTests(unittest.TestCase):
    def test_follows_same_host_links_once_and_ignores_others(self):
        site = {
            f"https://{HOST}/": page(["/x", "/y", "https://evil.example.org/", "#frag", "/x"]),
            f"https://{HOST}/x": page(["/", "/y"]),
            f"https://{HOST}/y": page(["/z"]),
            f"https://{HOST}/z": page(),
        }
        outcome, fetch = run(site)
        self.assertEqual(sorted(fetch.calls), sorted(site))
        self.assertIsNone(outcome.stop_reason)
        self.assertEqual(outcome.skipped["outside the authorized hosts"], 1)

    def test_records_depth_and_source(self):
        site = {f"https://{HOST}/": page(["/x"]), f"https://{HOST}/x": page()}
        outcome, _ = run(site)
        self.assertEqual([(p["depth"], p["source"]) for p in outcome.pages], [(0, "seed"), (1, "crawl")])
        self.assertTrue(all(p["body"] is None for p in outcome.pages))

    def test_depth_limit_is_reported(self):
        site = {f"https://{HOST}/": page(["/x"]), f"https://{HOST}/x": page(["/deep"])}
        outcome, fetch = run(site, max_depth=1)
        self.assertNotIn(f"https://{HOST}/deep", fetch.calls)
        self.assertEqual(outcome.skipped[crawler.DEPTH_SKIP], 1)

    def test_page_limit_stops_with_remaining_queue(self):
        outcome, _ = run({f"https://{HOST}/": page(["/a", "/b", "/c"])}, max_pages=2)
        self.assertEqual(len(outcome.pages), 2)
        self.assertIn("page limit", outcome.stop_reason)
        self.assertGreater(outcome.remaining, 0)

    def test_skips_risky_binary_and_query_traps(self):
        links = ["/logout", "/Sign-Out", "/manual.pdf", "/c?d=1", "/c?d=2", "/c?d=3", "/c?d=4"]
        outcome, fetch = run({f"https://{HOST}/": page(links)})
        for skipped in ("/logout", "/Sign-Out", "/manual.pdf"):
            self.assertNotIn(f"https://{HOST}{skipped}", fetch.calls)
        self.assertEqual(sum(1 for url in fetch.calls if "/c?" in url), crawler.MAX_QUERY_VARIANTS)
        self.assertEqual(outcome.skipped["query-variant limit per path"], 1)
        self.assertEqual(outcome.skipped["path suggests a state-changing action"], 2)

    def test_redirect_duplicates_are_not_counted_twice(self):
        site = {
            f"https://{HOST}/": page(["/old", "/new"]),
            f"https://{HOST}/old": page(final=f"https://{HOST}/new"),
            f"https://{HOST}/new": page(),
        }
        outcome, _ = run(site)
        self.assertEqual(len(outcome.pages), 2)
        self.assertEqual(outcome.skipped["duplicate after redirect"], 1)

    def test_robots_exclusions_are_counted(self):
        site = {f"https://{HOST}/": page(["/private", "/public"]), f"https://{HOST}/public": page()}
        outcome, fetch = run(site, robots_allowed=lambda url: "/private" not in url)
        self.assertNotIn(f"https://{HOST}/private", fetch.calls)
        self.assertEqual(outcome.skipped["blocked by robots.txt"], 1)

    def test_extra_seeds_keep_their_source(self):
        site = {f"https://{HOST}/": page(), f"https://{HOST}/s": page()}
        seeds = [
            (f"https://{HOST}/", "seed"),
            (f"https://{HOST}/s", "sitemap"),
            ("https://other.example.org/", "sitemap"),
        ]
        outcome, _ = run(site, seeds=seeds)
        self.assertEqual([p["source"] for p in outcome.pages], ["seed", "sitemap"])

    def test_consecutive_failures_abort_the_crawl(self):
        links = [f"/p{i}" for i in range(40)]
        fail = {f"https://{HOST}/p{i}" for i in range(40)}
        outcome, _ = run({f"https://{HOST}/": page(links)}, fail=fail)
        self.assertIn("consecutive request failures", outcome.stop_reason)

    def test_time_limit(self):
        outcome, _ = run({f"https://{HOST}/": page(["/a"])}, deadline=-1.0)
        self.assertEqual(outcome.stop_reason, "time limit reached")

    def test_progress_callback_and_delay_between_pages(self):
        slept, seen = [], []
        site = {f"https://{HOST}/": page(["/a"]), f"https://{HOST}/a": page()}
        run(site, delay=0.7, sleep=slept.append, progress=lambda count, result: seen.append(count))
        self.assertEqual(seen, [1, 2])
        self.assertEqual(slept, [0.7])


if __name__ == "__main__":
    unittest.main()
