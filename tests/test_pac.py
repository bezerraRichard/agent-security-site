import builtins
import http.server
import sys
import threading
import unittest
from unittest import mock

from agent_security import network as net
from agent_security import pac

PAC = b"""function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.example.test")) return "PROXY pac-proxy.example:3128; DIRECT";
  return "DIRECT";
}"""
SCUTIL = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://pac.corp.example/proxy.pac
  ProxyAutoDiscoveryEnable : 0
}
"""
KIOSLAVERC = """[Proxy Settings]
Proxy Config Script=http://pac.corp.example/kde.pac
ProxyType=2
"""


class PacServer:
    """Serves the test PAC script on localhost."""

    def __enter__(self) -> str:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                self.send_header("Content-Length", str(len(PAC)))
                self.end_headers()
                self.wfile.write(PAC)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_port}/proxy.pac"

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class ParseProxyListTests(unittest.TestCase):
    def test_first_usable_proxy_becomes_a_url(self):
        cases = {
            "p.example:8080": "http://p.example:8080",
            "p1.example:8080 p2.example:8080": "http://p1.example:8080",
            "PROXY p.example:3128; DIRECT": "http://p.example:3128",
            "SOCKS s.example:1080; PROXY p.example:3128": "http://p.example:3128",
            "HTTPS tls.example:443": "https://tls.example:443",
            "http=h.example:80;https=s.example:443": "http://s.example:443",
        }
        for value, expected in cases.items():
            self.assertEqual(pac.parse_proxy_list(value), expected, value)

    def test_direct_or_empty_means_no_proxy(self):
        for value in (None, "", "DIRECT", "DIRECT; PROXY p.example:3128", "SOCKS s.example:1080", "http=h.example:80"):
            self.assertIsNone(pac.parse_proxy_list(value), value)

    def test_scheme_specific_entry_is_chosen(self):
        self.assertEqual(pac.parse_proxy_list("http=h.example:80;https=s.example:443", "http"), "http://h.example:80")


class DiscoveryTests(unittest.TestCase):
    def test_macos_scutil_output(self):
        self.assertEqual(pac.parse_scutil(SCUTIL), "http://pac.corp.example/proxy.pac")
        self.assertIsNone(pac.parse_scutil(SCUTIL.replace("ProxyAutoConfigEnable : 1", "ProxyAutoConfigEnable : 0")))
        self.assertIsNone(pac.parse_scutil(""))

    def test_kde_kioslaverc(self):
        self.assertEqual(pac.parse_kioslaverc(KIOSLAVERC), "http://pac.corp.example/kde.pac")
        self.assertIsNone(pac.parse_kioslaverc(KIOSLAVERC.replace("ProxyType=2", "ProxyType=1")))
        self.assertIsNone(pac.parse_kioslaverc("not an ini file"))

    def test_explicit_setting_wins_on_every_system(self):
        env = {pac.PAC_URL_ENV: " http://pac.example/x.pac "}
        for platform in ("darwin", "linux", "win32"):
            with mock.patch.object(pac.sys, "platform", platform):
                self.assertEqual(pac.discover_pac_url(env), "http://pac.example/x.pac")

    def test_macos_and_gnome_settings_are_read(self):
        with mock.patch.object(pac.sys, "platform", "darwin"), mock.patch.object(pac, "_run", return_value=SCUTIL):
            self.assertEqual(pac.discover_pac_url({}), "http://pac.corp.example/proxy.pac")
        answers = {"mode": "'auto'\n", "autoconfig-url": "'http://pac.corp.example/gnome.pac'\n"}
        with (
            mock.patch.object(pac.sys, "platform", "linux"),
            mock.patch.object(pac, "_run", side_effect=lambda *command: answers[command[-1]]),
        ):
            self.assertEqual(
                pac.discover_pac_url({"XDG_CONFIG_HOME": "/nonexistent"}), "http://pac.corp.example/gnome.pac"
            )


class LookupTests(unittest.TestCase):
    def test_script_is_downloaded_and_evaluated_on_macos_and_linux(self):
        with PacServer() as pac_url:
            env = {pac.PAC_URL_ENV: pac_url}
            with mock.patch.object(pac.sys, "platform", "linux"):
                self.assertEqual(pac.lookup("https://wwwq.example.test/", env).proxy, "http://pac-proxy.example:3128")
                self.assertEqual(pac.lookup("https://other.example.org/", env), pac.PacLookup())

    def test_missing_engine_and_broken_script_are_reported_not_raised(self):
        real_import = builtins.__import__

        def no_pypac(name, *args, **kwargs):
            if name.startswith("pypac"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        with PacServer() as pac_url, mock.patch.object(pac.sys, "platform", "darwin"):
            with mock.patch.object(builtins, "__import__", no_pypac):
                found = pac.lookup("https://wwwq.example.test/", {pac.PAC_URL_ENV: pac_url})
            self.assertIsNone(found.proxy)
            self.assertIn("pip install", found.note or "")
            broken = pac.lookup("https://wwwq.example.test/", {pac.PAC_URL_ENV: "http://127.0.0.1:9/none.pac"})
            self.assertEqual((broken.proxy, (broken.note or "").startswith("PAC script unavailable")), (None, True))

    def test_nothing_configured_means_direct(self):
        with mock.patch.object(pac.sys, "platform", "linux"), mock.patch.object(pac, "_run", return_value=""):
            self.assertEqual(
                pac.lookup("https://www.example.com/", {"XDG_CONFIG_HOME": "/nonexistent"}), pac.PacLookup()
            )


class PacRouteTests(unittest.TestCase):
    def test_pac_proxy_is_used_when_there_is_no_fixed_system_proxy(self):
        with (
            mock.patch.object(net.urllib.request, "getproxies", return_value={}),
            mock.patch.object(pac, "lookup", return_value=pac.PacLookup("http://pac.example:3128")) as lookup,
        ):
            routes = net.candidate_routes(None, False, False, "https://www.example.com/")
        lookup.assert_called_once_with("https://www.example.com/")
        self.assertEqual([r.name for r in routes], ["system proxy (PAC) pac.example:3128", "direct (no proxy)"])
        self.assertEqual(routes[0].proxies, {"http": "http://pac.example:3128", "https": "http://pac.example:3128"})

    def test_an_unusable_pac_script_is_named_in_the_direct_route(self):
        with (
            mock.patch.object(net.urllib.request, "getproxies", return_value={}),
            mock.patch.object(pac, "lookup", return_value=pac.PacLookup(note="PAC script unavailable: URLError")),
        ):
            routes = net.candidate_routes(None, False, False, "https://www.example.com/")
        self.assertEqual([r.name for r in routes], ["direct (no proxy; PAC script unavailable: URLError)"])
        self.assertEqual(routes[0].proxies, {})

    def test_fixed_proxy_and_explicit_choices_skip_the_pac_lookup(self):
        with mock.patch.object(pac, "lookup") as lookup:
            with mock.patch.object(net.urllib.request, "getproxies", return_value={"https": "http://sys.example:1"}):
                net.candidate_routes(None, False, False, "https://www.example.com/")
            net.candidate_routes(None, True, False, "https://www.example.com/")
            net.candidate_routes("http://p.example:8080", False, False, "https://www.example.com/")
        lookup.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "WinHTTP is only available on Windows")
class WinHttpTests(unittest.TestCase):
    def test_pac_script_is_evaluated_by_windows(self):
        with PacServer() as pac_url:
            self.assertEqual(
                pac.windows_proxy_for("https://wwwq.example.test/", pac_url, False), "http://pac-proxy.example:3128"
            )
            self.assertIsNone(pac.windows_proxy_for("https://other.example.org/", pac_url, False))
            self.assertEqual(
                pac.lookup("https://wwwq.example.test/", {pac.PAC_URL_ENV: pac_url}).proxy,
                "http://pac-proxy.example:3128",
            )

    def test_unreachable_pac_script_falls_back_to_no_proxy(self):
        self.assertIsNone(pac.windows_proxy_for("https://www.example.com/", "http://127.0.0.1:9/none.pac", False))


if __name__ == "__main__":
    unittest.main()
