import tempfile
import unittest
from pathlib import Path

from agent_security import urls

HOST = "www.example.com"


class NormalizeUrlTests(unittest.TestCase):
    def test_resolves_relative_links_and_forces_https(self):
        base = f"https://{HOST}/a/"
        self.assertEqual(urls.normalize_url(base, "../b#frag"), f"https://{HOST}/b")
        self.assertEqual(urls.normalize_url(base, f"http://{HOST}/x?y=1"), f"https://{HOST}/x?y=1")
        self.assertEqual(urls.normalize_url(base, f"HTTPS://{HOST.upper()}"), f"https://{HOST}/")

    def test_rejects_non_crawlable_links(self):
        base = f"https://{HOST}/a/"
        for href in (
            "mailto:a@b.c",
            "javascript:void(0)",
            "#top",
            "",
            "tel:123",
            "data:text/html,x",
            f"https://user:pw@{HOST}/",
            f"https://{HOST}:8443/",
            f"https://{HOST}:notaport/",
            "ftp://x.example.com/",
        ):
            self.assertIsNone(urls.normalize_url(base, href), href)


class ValidateHostTests(unittest.TestCase):
    def test_accepts_and_lowercases_hostnames(self):
        self.assertEqual(urls.validate_host(" WWW.Example.com "), HOST)

    def test_rejects_ips_localhost_and_malformed_names(self):
        for value in ("10.0.0.1", "::1", "localhost", "bad host.com", "-x.com", "x..com", "", "a_b.example.com"):
            with self.assertRaises(ValueError, msg=value):
                urls.validate_host(value)


class NormalizeTargetTests(unittest.TestCase):
    def test_adds_scheme_and_default_path(self):
        self.assertEqual(urls.normalize_target("Example.com"), ("example.com", "https://example.com/"))
        self.assertEqual(
            urls.normalize_target("https://example.com/a?b=1#c"), ("example.com", "https://example.com/a?b=1")
        )

    def test_rejects_unsafe_targets(self):
        for value in (
            "http://example.com/",
            "https://user:pw@example.com/",
            "https://localhost/",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "ftp://example.com/",
        ):
            with self.assertRaises(ValueError, msg=value):
                urls.normalize_target(value)


class LoadUrlFileTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "urls.txt"
        path.write_text(text, encoding="utf-8-sig")
        return path

    def test_reads_urls_ignoring_comments_and_blanks(self):
        path = self.write(f"# approved\n\nhttps://{HOST}/a\n  https://{HOST}/b  \n")
        self.assertEqual(urls.load_url_file(path, {HOST}), [f"https://{HOST}/a", f"https://{HOST}/b"])

    def test_rejects_other_hosts_and_reports_the_line(self):
        path = self.write(f"https://{HOST}/a\nhttps://evil.example.org/\n")
        with self.assertRaisesRegex(ValueError, "line 2"):
            urls.load_url_file(path, {HOST})

    def test_rejects_invalid_urls_and_reports_the_line(self):
        path = self.write("http://www.example.com/\n")
        with self.assertRaisesRegex(ValueError, "line 1"):
            urls.load_url_file(path, {HOST})


if __name__ == "__main__":
    unittest.main()
