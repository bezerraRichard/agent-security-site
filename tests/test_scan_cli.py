import argparse
import json
import tempfile
import unittest
from collections import Counter
from email.message import Message
from pathlib import Path
from unittest import mock

from agent_security import cli, scan
from agent_security.config import HARD_MAX_PAGES, ScanConfig
from agent_security.crawler import DEPTH_SKIP, CrawlOutcome
from agent_security.network import Route

HOST = "www.example.com"
START = f"https://{HOST}/"
DIRECT = Route("direct (no proxy)", {})


def config(**overrides):
    values = dict(start_url=START, allowed_hosts=frozenset({HOST}), seeds=((START, "seed"),), delay_seconds=0.2)
    values.update(overrides)
    return ScanConfig(**values)


class ScanConfigTests(unittest.TestCase):
    def test_defaults_are_valid_and_host_is_derived(self):
        cfg = config()
        self.assertEqual(cfg.host, HOST)
        self.assertEqual(cfg.max_pages, 500)

    def test_limits_are_validated(self):
        for bad in (
            dict(max_pages=0),
            dict(max_pages=HARD_MAX_PAGES + 1),
            dict(max_depth=-1),
            dict(max_depth=51),
            dict(delay_seconds=0.1),
            dict(retries=6),
            dict(timeout=0),
            dict(time_limit_minutes=0),
        ):
            with self.assertRaises(ValueError, msg=bad):
                config(**bad)

    def test_start_url_must_be_on_an_allowed_host(self):
        with self.assertRaises(ValueError):
            config(allowed_hosts=frozenset({"other.example.com"}))

    def test_config_is_immutable(self):
        with self.assertRaises(AttributeError):
            config().max_pages = 1


def parse(*argv):
    return cli.build_parser().parse_args(list(argv))


class BuildConfigTests(unittest.TestCase):
    ENV = {"ONETRUST_HOSTNAME": "app-eu.onetrust.com", "ONETRUST_CLIENT_ID": "id", "ONETRUST_CLIENT_SECRET": "secret"}

    def test_minimal_arguments(self):
        cfg = cli.build_config(parse("www.example.com"), {})
        self.assertEqual((cfg.start_url, cfg.allowed_hosts, cfg.seeds), (START, frozenset({HOST}), ((START, "seed"),)))
        self.assertIsNone(cfg.onetrust)
        self.assertTrue(cfg.respect_robots)

    def test_options_are_mapped(self):
        args = parse(
            START,
            "--allow-host",
            "Shop.Example.com",
            "--max-pages",
            "7",
            "--max-depth",
            "2",
            "--ignore-robots",
            "--sitemap",
            "--proxy",
            "proxy.example:8080",
            "--fallback-direct",
            "--delay-seconds",
            "1.5",
        )
        cfg = cli.build_config(args, {})
        self.assertEqual(cfg.allowed_hosts, frozenset({HOST, "shop.example.com"}))
        self.assertEqual((cfg.max_pages, cfg.max_depth, cfg.delay_seconds), (7, 2, 1.5))
        self.assertEqual((cfg.respect_robots, cfg.sitemap, cfg.fallback_direct), (False, True, True))
        self.assertEqual(cfg.proxy, "http://proxy.example:8080")

    def test_onetrust_comes_from_the_environment_only(self):
        self.assertEqual(cli.build_config(parse(START), self.ENV).onetrust.hostname, "app-eu.onetrust.com")
        self.assertIsNone(cli.build_config(parse(START, "--no-cookie-classification"), self.ENV).onetrust)
        cfg = cli.build_config(parse(START, "--onetrust-language", "pt-pt"), self.ENV)
        self.assertEqual(cfg.onetrust.language, "pt-pt")
        self.assertNotIn("secret", repr(cfg))

    def test_invalid_input_raises_value_error(self):
        for argv in (
            [START, "--allow-host", "10.0.0.1"],
            ["http://www.example.com/"],
            [START, "--proxy", "ftp://p"],
            [START, "--ca-bundle", "missing.pem"],
            [START, "--max-pages", "0"],
            [START, "--urls-file", "missing.txt"],
        ):
            with self.assertRaises((ValueError, OSError), msg=argv):
                cli.build_config(parse(*argv), {})

    def test_proxy_and_no_proxy_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            parse(START, "--proxy", "p.example:1", "--no-proxy")


def headers(*pairs):
    message = Message()
    for key, value in pairs:
        message[key] = value
    return message


HARDENED = (
    ("Strict-Transport-Security", "max-age=31536000; preload"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
)


def response(url, body="", final=None, status=200, pairs=(), content_type="text/html"):
    return {
        "requested_url": url,
        "final_url": final or url,
        "status": status,
        "headers": headers(*pairs),
        "error": None,
        "content_type": content_type,
        "body": body,
        "out_of_scope": False,
    }


def site_fetch(pages, probe_final=f"https://{HOST}/"):
    def fetch(url, want_body=False, max_bytes=0):
        if url == f"http://{HOST}/":
            return response(url, final=probe_final)
        if url == f"https://{HOST}/robots.txt":
            return response(url, status=404)
        return pages.get(url) or response(url, status=404)

    return fetch


class RunScanTests(unittest.TestCase):
    def run_scan(self, pages, cfg=None, probe_final=f"https://{HOST}/", route=DIRECT):
        fetch = site_fetch(pages, probe_final)
        attempts = [{"route": DIRECT.name, "ok": route is not None, "detail": "HTTP 200"}]
        with mock.patch.object(scan, "select_route", return_value=(route, fetch if route else None, attempts)):
            return scan.run_scan(cfg or config())

    def test_end_to_end_report(self):
        pages = {
            START: response(
                START,
                '<a href="/a">a</a><a href="/b">b</a>',
                pairs=HARDENED + (("Set-Cookie", "sid=TOPSECRET; Path=/"),),
            ),
            f"https://{HOST}/a": response(f"https://{HOST}/a", pairs=HARDENED[1:]),
            f"https://{HOST}/b": response(
                f"https://{HOST}/b", pairs=HARDENED + (("Set-Cookie", "sid=TOPSECRET; Path=/"),)
            ),
        }
        report = self.run_scan(pages)
        self.assertTrue(report["status"].startswith("complete"))
        self.assertEqual(report["scope"]["pages_assessed"], 3)
        self.assertEqual(report["route"]["selected"], DIRECT.name)
        rules = {g["rule"] for g in report["groups"]}
        self.assertEqual(rules, {"HDR-HSTS-001", "COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"})
        hsts = next(g for g in report["groups"] if g["rule"] == "HDR-HSTS-001")
        self.assertEqual(hsts["urls"], [f"https://{HOST}/a"])
        self.assertEqual(report["cookies"]["classification"], {"status": "not_configured"})
        self.assertEqual(report["cookies"]["inventory"][0]["pages"], 2)
        self.assertEqual({p["url"]: p["findings"] for p in report["pages"]}[f"https://{HOST}/a"], 1)
        self.assertEqual(report["summary"]["severity"]["High"]["distinct"], 2)
        self.assertNotIn("TOPSECRET", json.dumps(report))

    def test_http_that_does_not_redirect_is_a_finding(self):
        report = self.run_scan({START: response(START, pairs=HARDENED)}, probe_final=f"http://{HOST}/")
        self.assertEqual([g["rule"] for g in report["groups"]], ["TLS-HTTP-001"])
        self.assertEqual(report["groups"][0]["sources"], ["http-probe"])

    def test_unreachable_target_is_incomplete_without_findings(self):
        report = self.run_scan({}, route=None)
        self.assertTrue(report["status"].startswith("incomplete"))
        self.assertEqual((report["groups"], report["pages"], report["http_probe"]), ([], [], None))
        self.assertEqual(report["cookies"]["classification"], {"status": "no_cookies"})

    def test_limits_make_the_scan_partial(self):
        pages = {
            START: response(START, '<a href="/a">a</a><a href="/b">b</a>', pairs=HARDENED),
            f"https://{HOST}/a": response(f"https://{HOST}/a", pairs=HARDENED),
        }
        report = self.run_scan(pages, config(max_pages=1))
        self.assertTrue(report["status"].startswith("partial: page limit"))
        self.assertGreater(report["scope"]["queue_remaining"], 0)

    def test_report_is_json_serialisable(self):
        report = self.run_scan({START: response(START, '<a href="/a">a</a>', pairs=HARDENED)})
        self.assertEqual(json.loads(json.dumps(report))["target"], START)


class DecideStatusTests(unittest.TestCase):
    def test_status_decisions(self):
        empty = CrawlOutcome([], Counter(), None, 0)
        ok = [{"error": None}] * 3
        self.assertTrue(scan.decide_status(empty, None, 0).startswith("incomplete"))
        self.assertTrue(scan.decide_status(empty, DIRECT, 0).startswith("incomplete"))
        self.assertTrue(scan.decide_status(CrawlOutcome(ok, Counter(), None, 0), DIRECT, 3).startswith("complete"))
        self.assertTrue(
            scan.decide_status(CrawlOutcome(ok[:2], Counter(), "page limit (2) reached", 4), DIRECT, 2).startswith(
                "partial"
            )
        )
        self.assertTrue(
            scan.decide_status(CrawlOutcome(ok[:2] + [{"error": "x"}], Counter(), None, 0), DIRECT, 2).startswith(
                "partial"
            )
        )
        self.assertIn("depth", scan.decide_status(CrawlOutcome(ok, Counter({DEPTH_SKIP: 2}), None, 0), DIRECT, 3))


class CollectFindingsTests(unittest.TestCase):
    def test_probe_findings(self):
        https_probe = {"error": None, "final_url": f"https://{HOST}/", "status": 200}
        http_probe = {"error": None, "final_url": f"http://{HOST}/", "status": 200}
        self.assertEqual(scan.collect_findings([], https_probe), [])
        self.assertEqual(scan.collect_findings([], {"error": "refused", "final_url": None, "status": None}), [])
        self.assertEqual(scan.collect_findings([], None), [])
        self.assertEqual(scan.collect_findings([], http_probe)[0]["rule"], "TLS-HTTP-001")


class BuildConfigsTests(unittest.TestCase):
    def test_single_target_keeps_every_extra_host(self):
        [cfg] = cli.build_configs(parse(START, "--allow-host", "other.example.org"), {})
        self.assertEqual(cfg.allowed_hosts, frozenset({HOST, "other.example.org"}))

    def test_several_targets_get_their_own_hosts_and_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            urls = Path(directory) / "urls.txt"
            urls.write_text("https://shop.example.com/a\nhttps://example.org/b\n", encoding="utf-8")
            configs = cli.build_configs(
                parse(START, "example.org", "--allow-host", "shop.example.com", "--urls-file", str(urls)), {}
            )
        self.assertEqual([c.host for c in configs], [HOST, "example.org"])
        self.assertEqual(configs[0].allowed_hosts, frozenset({HOST, "shop.example.com"}))
        self.assertEqual(configs[0].seeds[1], ("https://shop.example.com/a", "approved-list"))
        self.assertEqual(configs[1].allowed_hosts, frozenset({"example.org"}))
        self.assertEqual(configs[1].seeds[1], ("https://example.org/b", "approved-list"))

    def test_several_targets_reject_unattached_hosts_and_duplicates(self):
        with self.assertRaises(ValueError):
            cli.build_configs(parse(START, "example.org", "--allow-host", "elsewhere.net"), {})
        with self.assertRaises(ValueError):
            cli.build_configs(parse(START, START), {})

    def test_main_with_several_targets_runs_a_batch(self):
        rows = [{"target": START, "status": "complete: ok"}, {"target": "https://example.org/", "status": "partial: x"}]
        with mock.patch.object(cli, "run_batch", return_value=rows) as run, mock.patch("builtins.print") as printed:
            self.assertEqual(cli.main([START, "example.org", "--quiet"]), 2)
        self.assertEqual(len(run.call_args[0][0]), 2)
        self.assertEqual(json.loads(printed.call_args[0][0])["domains"], rows)


class MainTests(unittest.TestCase):
    def test_exit_code_reflects_status_and_summary_is_printed(self):
        with (
            mock.patch.object(cli, "run_scan") as run,
            mock.patch.object(cli, "write_reports") as write,
            mock.patch("builtins.print") as printed,
        ):
            run.return_value = {
                "status": "complete: ok",
                "route": {"selected": "direct"},
                "groups": [],
                "scope": {"pages_assessed": 1, "pages_failed": 0},
            }
            write.return_value = ("r.html", "r.json")
            self.assertEqual(cli.main([START, "--quiet"]), 0)
            run.return_value["status"] = "partial: x"
            self.assertEqual(cli.main([START, "--quiet"]), 2)
        self.assertEqual(json.loads(printed.call_args[0][0])["html"], "r.html")

    def test_invalid_arguments_exit_with_usage_error(self):
        with self.assertRaises(SystemExit) as caught, mock.patch("sys.stderr"):
            cli.main(["http://insecure.example.com/"])
        self.assertEqual(caught.exception.code, 2)


class ParserTests(unittest.TestCase):
    def test_parser_defaults(self):
        args = parse(START)
        self.assertIsInstance(args, argparse.Namespace)
        self.assertEqual((args.max_pages, args.max_depth, args.output_dir), (500, 10, "reports"))


if __name__ == "__main__":
    unittest.main()
