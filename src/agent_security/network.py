"""HTTP transport: proxy routes, scoped redirects, retrying fetches and route selection."""

from __future__ import annotations

import http.client
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

USER_AGENT = "HTTP-Security-Report/2.0 (passive; authorized assessment)"
MAX_BODY_BYTES = 2_000_000
RETRY_STATUSES = frozenset({429, 502, 503, 504})
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
BODY_TYPES = HTML_TYPES | {"text/xml", "application/xml", "text/plain"}

FetchResult = dict[str, Any]


class Fetcher(Protocol):
    def __call__(self, url: str, want_body: bool = False, max_bytes: int = MAX_BODY_BYTES) -> FetchResult: ...


class OutOfScopeRedirect(urllib.error.URLError):
    """Raised when a redirect would leave the authorized hosts."""


class ScopedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        super().__init__()
        self.allowed_hosts = frozenset(allowed_hosts)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme not in {"http", "https"} or parts.username or parts.password or host not in self.allowed_hosts:
            raise OutOfScopeRedirect(f"redirect to {host or newurl[:80]} is outside the authorized hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class Route:
    name: str
    proxies: dict[str, str] | None  # None = urllib system/environment proxies, {} = direct


def proxy_label(value: str) -> str:
    parts = urllib.parse.urlsplit(value if "://" in value else f"http://{value}")
    return f"{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 8080)}"


def parse_proxy(value: str) -> str:
    candidate = value if "://" in value else f"http://{value}"
    parts = urllib.parse.urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Proxy must be an http(s) URL such as http://proxy.example:8080")
    return candidate


def candidate_routes(proxy: str | None, no_proxy: bool, fallback_direct: bool) -> list[Route]:
    """Routes to try in order: an explicit proxy, else the system proxy, always ending with a direct route."""
    direct = Route("direct (no proxy)", {})
    if no_proxy:
        return [direct]
    if proxy:
        explicit = Route(f"proxy {proxy_label(proxy)}", {"http": proxy, "https": proxy})
        return [explicit, direct] if fallback_direct else [explicit]
    system = urllib.request.getproxies()
    endpoint = system.get("https") or system.get("http")
    if endpoint:
        return [Route(f"system proxy {proxy_label(endpoint)}", None), direct]
    return [direct]


def build_opener(route: Route, allowed_hosts: Iterable[str], context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [ScopedRedirects(allowed_hosts), urllib.request.HTTPSHandler(context=context)]
    if route.proxies is not None:
        handlers.append(urllib.request.ProxyHandler(route.proxies))
    return urllib.request.build_opener(*handlers)


def retry_delay(attempt: int, retry_after: str | None) -> float:
    delay = float(min(2**attempt, 8))
    if retry_after and retry_after.strip().isdigit():
        delay = max(delay, float(min(int(retry_after), 30)))
    return delay


def decode_body(raw: bytes, charset: str | None) -> str:
    try:
        return raw.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def failure(url: str, message: str, out_of_scope: bool = False) -> FetchResult:
    return {
        "requested_url": url,
        "final_url": None,
        "status": None,
        "headers": None,
        "error": message[:300],
        "content_type": None,
        "body": None,
        "out_of_scope": out_of_scope,
    }


def read_result(url: str, response: Any, status: int, want_body: bool, max_bytes: int) -> FetchResult:
    headers = response.headers
    content_type = headers.get_content_type() if headers else None
    body = None
    if want_body and 200 <= status < 300 and content_type in BODY_TYPES:
        body = decode_body(response.read(max_bytes), headers.get_content_charset())
    return {
        "requested_url": url,
        "final_url": response.geturl(),
        "status": status,
        "headers": headers,
        "error": None,
        "content_type": content_type,
        "body": body,
        "out_of_scope": False,
    }


def make_fetcher(
    opener: urllib.request.OpenerDirector,
    timeout: float,
    retries: int,
    sleep: Callable[[float], None] = time.sleep,
) -> Fetcher:
    def fetch(url: str, want_body: bool = False, max_bytes: int = MAX_BODY_BYTES) -> FetchResult:
        attempt = 0
        while True:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
            )
            try:
                with opener.open(request, timeout=timeout) as response:
                    return read_result(url, response, response.status, want_body, max_bytes)
            except OutOfScopeRedirect as error:
                return failure(url, str(error), out_of_scope=True)
            except urllib.error.HTTPError as error:
                if error.code in RETRY_STATUSES and attempt < retries:
                    wait = retry_delay(attempt, error.headers.get("Retry-After"))
                    error.close()
                    attempt += 1
                    sleep(wait)
                    continue
                result = read_result(url, error, error.code, False, max_bytes)
                error.close()
                return result
            except (OSError, ValueError, http.client.HTTPException) as error:
                if attempt < retries:
                    sleep(retry_delay(attempt, None))
                    attempt += 1
                    continue
                return failure(url, f"{type(error).__name__}: {error}")

    return fetch


def select_route(
    routes: Iterable[Route],
    start_url: str,
    allowed_hosts: Iterable[str],
    timeout: float,
    retries: int,
    context: ssl.SSLContext,
) -> tuple[Route | None, Fetcher | None, list[dict[str, Any]]]:
    """Return the first route that can reach ``start_url`` (a proxy answering 407 counts as a failure)."""
    hosts = frozenset(allowed_hosts)
    attempts: list[dict[str, Any]] = []
    for route in routes:
        fetch = make_fetcher(build_opener(route, hosts, context), timeout, retries)
        probe = fetch(start_url)
        failed = bool(probe["error"]) or probe["status"] == 407
        attempts.append({"route": route.name, "ok": not failed, "detail": probe["error"] or f"HTTP {probe['status']}"})
        if not failed:
            return route, fetch, attempts
    return None, None, attempts
