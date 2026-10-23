"""Proxy auto-configuration (PAC), so scans use the same proxy as the browser on Windows, macOS and Linux.

Python's ``urllib`` only reads fixed proxies (environment variables, the Windows registry, macOS network settings);
corporate VPNs often publish a PAC script instead. On Windows, WinHTTP finds and evaluates the script (or WPAD)
exactly as the system does. On macOS and Linux the script URL is read from the system settings (``scutil --proxy``,
GNOME or KDE) and the script is evaluated with the optional ``pypac`` package (``pip install -e ".[pac]"``).
``AGENT_SECURITY_PAC_URL`` sets the script URL explicitly on any system.
"""

from __future__ import annotations

import configparser
import ctypes
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from collections.abc import Mapping
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

PAC_URL_ENV = "AGENT_SECURITY_PAC_URL"
PROXY_TIMEOUT_MS = 5000  # Bound for resolving, connecting to and downloading the PAC script.
MAX_PAC_BYTES = 1_000_000

_AUTOPROXY_AUTO_DETECT = 0x1
_AUTOPROXY_CONFIG_URL = 0x2
_AUTO_DETECT_TYPE_DHCP = 0x1
_AUTO_DETECT_TYPE_DNS_A = 0x2
_ACCESS_TYPE_NO_PROXY = 1
_ACCESS_TYPE_NAMED_PROXY = 3


class _IEProxyConfig(ctypes.Structure):
    _fields_ = [
        ("fAutoDetect", wintypes.BOOL),
        ("lpszAutoConfigUrl", ctypes.c_void_p),  # Raw pointers: WinHTTP allocates them and they must be freed.
        ("lpszProxy", ctypes.c_void_p),
        ("lpszProxyBypass", ctypes.c_void_p),
    ]


class _AutoProxyOptions(ctypes.Structure):
    _fields_ = [
        ("dwFlags", wintypes.DWORD),
        ("dwAutoDetectFlags", wintypes.DWORD),
        ("lpszAutoConfigUrl", wintypes.LPCWSTR),
        ("lpvReserved", wintypes.LPVOID),
        ("dwReserved", wintypes.DWORD),
        ("fAutoLogonIfChallenged", wintypes.BOOL),
    ]


class _ProxyInfo(ctypes.Structure):
    _fields_ = [
        ("dwAccessType", wintypes.DWORD),
        ("lpszProxy", ctypes.c_void_p),
        ("lpszProxyBypass", ctypes.c_void_p),
    ]


def parse_proxy_list(value: str | None, scheme: str = "https") -> str | None:
    """First usable proxy of a WinHTTP/PAC list as an ``http://host:port`` URL.

    Accepts ``"p:8080"``, ``"p1:8080 p2:8080"``, ``"PROXY p:8080; DIRECT"`` and per-scheme lists such as
    ``"http=p:80;https=s:443"``. Returns None when the list is empty or prefers a direct connection. SOCKS entries
    are skipped: urllib cannot use them.
    """
    tokens = re.split(r"[;\s]+", value or "")
    skip_next, proxy_scheme = False, "http"
    for token in filter(None, tokens):
        keyword = token.upper()
        if skip_next:
            skip_next = False
        elif keyword == "DIRECT":
            return None
        elif keyword in {"SOCKS", "SOCKS4", "SOCKS5"}:
            skip_next = True
        elif keyword in {"PROXY", "HTTP", "HTTPS"}:
            proxy_scheme = "https" if keyword == "HTTPS" else "http"  # PAC "HTTPS host:port" is a TLS proxy.
        else:
            target = token
            if "=" in token:
                entry_scheme, target = token.split("=", 1)
                if entry_scheme.lower() != scheme:
                    continue
            return target if "://" in target else f"{proxy_scheme}://{target}"
    return None


def _text(pointer: int | None) -> str | None:
    return ctypes.wstring_at(pointer) if pointer else None


def _free(pointer: int | None, kernel32: ctypes.WinDLL) -> None:
    if pointer:
        kernel32.GlobalFree(pointer)


def windows_proxy_for(url: str, config_url: str | None = None, auto_detect: bool | None = None) -> str | None:
    """The proxy Windows would use for ``url`` according to the PAC script or WPAD, or None for a direct connection.

    Without ``config_url`` the PAC URL and auto-detection setting come from the current user's Internet settings.
    Never raises: on any failure, or outside Windows, it returns None.
    """
    if sys.platform != "win32":
        return None
    try:
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:
        return None
    winhttp.WinHttpOpen.restype = wintypes.LPVOID
    winhttp.WinHttpOpen.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    winhttp.WinHttpSetTimeouts.argtypes = [wintypes.LPVOID, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    winhttp.WinHttpGetProxyForUrl.argtypes = [
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_AutoProxyOptions),
        ctypes.POINTER(_ProxyInfo),
    ]
    winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [ctypes.POINTER(_IEProxyConfig)]
    winhttp.WinHttpCloseHandle.argtypes = [wintypes.LPVOID]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    if config_url is None and auto_detect is None:
        settings = _IEProxyConfig()
        if not winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(settings)):
            return None
        config_url = _text(settings.lpszAutoConfigUrl)
        auto_detect = bool(settings.fAutoDetect)
        for value in (settings.lpszAutoConfigUrl, settings.lpszProxy, settings.lpszProxyBypass):
            _free(value, kernel32)
    if not config_url and not auto_detect:
        return None

    options = _AutoProxyOptions()
    options.fAutoLogonIfChallenged = True
    if config_url:
        options.dwFlags |= _AUTOPROXY_CONFIG_URL
        options.lpszAutoConfigUrl = config_url
    if auto_detect:
        options.dwFlags |= _AUTOPROXY_AUTO_DETECT
        options.dwAutoDetectFlags = _AUTO_DETECT_TYPE_DHCP | _AUTO_DETECT_TYPE_DNS_A

    session = winhttp.WinHttpOpen("agent-security", _ACCESS_TYPE_NO_PROXY, None, None, 0)
    if not session:
        return None
    try:
        winhttp.WinHttpSetTimeouts(session, PROXY_TIMEOUT_MS, PROXY_TIMEOUT_MS, PROXY_TIMEOUT_MS, PROXY_TIMEOUT_MS)
        info = _ProxyInfo()
        if not winhttp.WinHttpGetProxyForUrl(session, url, ctypes.byref(options), ctypes.byref(info)):
            return None
        try:
            if info.dwAccessType != _ACCESS_TYPE_NAMED_PROXY:
                return None
            scheme = "https" if url.lower().startswith("https:") else "http"
            return parse_proxy_list(_text(info.lpszProxy), scheme)
        finally:
            _free(info.lpszProxy, kernel32)
            _free(info.lpszProxyBypass, kernel32)
    finally:
        winhttp.WinHttpCloseHandle(session)


def parse_scutil(text: str) -> str | None:
    """PAC URL from ``scutil --proxy`` output (macOS), when automatic proxy configuration is enabled."""
    values = dict(re.findall(r"^\s*(\w+)\s*:\s*(.+?)\s*$", text, re.MULTILINE))
    if values.get("ProxyAutoConfigEnable") == "1":
        return values.get("ProxyAutoConfigURLString") or None
    return None


def parse_kioslaverc(text: str) -> str | None:
    """PAC URL from KDE's ``kioslaverc``, when the proxy type is "automatic configuration URL" (2)."""
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.optionxform = str  # type: ignore[assignment,method-assign]  # Keys such as "Proxy Config Script".
    try:
        config.read_string(text)
    except configparser.Error:
        return None
    section = config["Proxy Settings"] if config.has_section("Proxy Settings") else None
    if section is None or section.get("ProxyType", "").strip() != "2":
        return None
    return section.get("Proxy Config Script", "").strip() or None


def _run(*command: str) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _gnome_pac_url() -> str | None:
    if _run("gsettings", "get", "org.gnome.system.proxy", "mode").strip().strip("'") != "auto":
        return None
    return _run("gsettings", "get", "org.gnome.system.proxy", "autoconfig-url").strip().strip("'") or None


def discover_pac_url(env: Mapping[str, str] | None = None) -> str | None:
    """The PAC script URL: ``AGENT_SECURITY_PAC_URL`` first, then the macOS or Linux (GNOME, KDE) settings."""
    env = os.environ if env is None else env
    explicit = (env.get(PAC_URL_ENV) or "").strip()
    if explicit:
        return explicit
    if sys.platform == "darwin":
        return parse_scutil(_run("scutil", "--proxy"))
    if sys.platform.startswith("linux"):
        kde = Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "kioslaverc"
        try:
            kde_url = parse_kioslaverc(kde.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            kde_url = None
        return _gnome_pac_url() or kde_url
    return None


class PacEngineMissing(RuntimeError):
    """A PAC script is configured but ``pypac`` is not installed to evaluate it."""


def fetch_script(pac_url: str, timeout: float = PROXY_TIMEOUT_MS / 1000) -> str:
    """Download the PAC script directly (it is normally served inside the network); ``file://`` URLs work too."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(pac_url, timeout=timeout) as response:
        return response.read(MAX_PAC_BYTES).decode("utf-8", errors="replace")


def evaluate(script: str, url: str) -> str | None:
    """Run ``FindProxyForURL`` from ``script`` for ``url`` and return the proxy URL, or None for direct."""
    try:
        from pypac.parser import PACFile
    except ImportError as error:
        raise PacEngineMissing('install the PAC extra: pip install -e ".[pac]"') from error
    host = urllib.parse.urlsplit(url).hostname or ""
    scheme = "https" if url.lower().startswith("https:") else "http"
    return parse_proxy_list(PACFile(script).find_proxy_for_url(url, host), scheme)


@dataclass(frozen=True)
class PacLookup:
    proxy: str | None = None  # http(s)://host:port, or None for a direct connection
    note: str | None = None  # Why a configured PAC script could not be used.


def lookup(url: str, env: Mapping[str, str] | None = None) -> PacLookup:
    """The proxy the system's PAC configuration gives for ``url``. Never raises."""
    env = os.environ if env is None else env
    if sys.platform == "win32":
        explicit = (env.get(PAC_URL_ENV) or "").strip() or None
        return PacLookup(windows_proxy_for(url, explicit, False if explicit else None))
    pac_url = discover_pac_url(env)
    if not pac_url:
        return PacLookup()
    try:
        return PacLookup(evaluate(fetch_script(pac_url), url))
    except PacEngineMissing as error:
        return PacLookup(note=f"PAC script found but not evaluated: {error}")
    except Exception as error:  # A broken or unreachable script must never stop the scan.
        return PacLookup(note=f"PAC script unavailable: {type(error).__name__}")
