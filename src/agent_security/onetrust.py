"""Classify observed cookies with the OneTrust Cookie Consent API (read-only)."""

from __future__ import annotations

import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

HOSTNAME_PATTERN = re.compile(r"(?:[a-z0-9-]+\.)+onetrust\.com")
LANGUAGE_PATTERN = re.compile(r"[A-Za-z]{2}(?:[-_][A-Za-z]{2})?")
MAX_RESPONSE_BYTES = 5_000_000
PAGE_SIZE = 100
MAX_PAGES = 5
MAX_RATE_LIMIT_RETRIES = 3
MAX_SERVER_ERROR_RETRIES = 2
MAX_CONSECUTIVE_LOOKUP_FAILURES = 5
LOOKUP_PAUSE_SECONDS = 0.2
MAX_COOKIES_PER_RUN = 300


class OneTrustError(Exception):
    def __init__(self, message: str, fatal: bool = False) -> None:
        super().__init__(message)
        self.fatal = fatal


@dataclass(frozen=True)
class OneTrustConfig:
    hostname: str
    client_id: str
    client_secret: str = field(repr=False)
    language: str = "en"
    domain_ids: tuple[str, ...] = ()


def config_from_env(
    env: Mapping[str, str],
    hostname: str | None = None,
    language: str | None = None,
    domain_ids: Iterable[str] = (),
) -> OneTrustConfig | None:
    """Build the client config from ``ONETRUST_*`` variables; None when credentials are incomplete."""
    host = (hostname or env.get("ONETRUST_HOSTNAME") or "").strip().lower()
    if host and not HOSTNAME_PATTERN.fullmatch(host):
        raise ValueError("The OneTrust hostname must be a *.onetrust.com host such as app-eu.onetrust.com")
    client_id = (env.get("ONETRUST_CLIENT_ID") or "").strip()
    secret = env.get("ONETRUST_CLIENT_SECRET") or ""
    if not (host and client_id and secret):
        return None
    lang = (language or env.get("ONETRUST_LANGUAGE") or "en").strip()
    if not LANGUAGE_PATTERN.fullmatch(lang):
        raise ValueError("The OneTrust language must look like 'en' or 'pt-pt'")
    return OneTrustConfig(host, client_id, secret, lang.lower(), tuple(str(uuid.UUID(v)) for v in domain_ids))


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow redirects, so the bearer token cannot be forwarded to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(proxies: Mapping[str, str] | None, context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [NoRedirects(), urllib.request.HTTPSHandler(context=context)]
    if proxies is not None:
        handlers.append(urllib.request.ProxyHandler(dict(proxies)))
    return urllib.request.build_opener(*handlers)


def retry_after_seconds(headers: Any) -> float:
    value = (headers.get("Retry-After") or "").strip() if headers else ""
    return float(min(int(value), 60)) if value.isdigit() else 5.0


class OneTrustClient:
    """Read-only client for the Cookie Consent API; each route is tried in order until one connects."""

    def __init__(
        self,
        config: OneTrustConfig,
        openers: Iterable[tuple[str, urllib.request.OpenerDirector]],
        timeout: float = 20.0,
        sleep: Callable[[float], None] = time.sleep,
        base_url: str | None = None,
    ) -> None:
        self.config = config
        self.openers = list(openers)
        self.timeout = timeout
        self.sleep = sleep
        self.base_url = base_url or f"https://{config.hostname}"
        self.route: str | None = None
        self._active: tuple[str, urllib.request.OpenerDirector] | None = None
        self._token: str | None = None
        self._token_expiry = 0.0

    def _send(self, template: urllib.request.Request) -> tuple[int, bytes, Any]:
        last_error: BaseException | None = None
        for name, opener in [self._active] if self._active else self.openers:
            # ProxyHandler rewrites the request it receives, so every route gets a fresh copy.
            request = urllib.request.Request(
                template.full_url,
                data=template.data,
                headers=dict(template.header_items()),
                method=template.get_method(),
            )
            try:
                with opener.open(request, timeout=self.timeout) as response:
                    payload = response.read(MAX_RESPONSE_BYTES)
                    self._active, self.route = (name, opener), name
                    return response.status, payload, response.headers
            except urllib.error.HTTPError as error:
                payload, status, headers = error.read(MAX_RESPONSE_BYTES), error.code, error.headers
                error.close()
                if status == 407:
                    last_error = error
                    continue
                self._active, self.route = (name, opener), name
                return status, payload, headers
            except (OSError, http.client.HTTPException) as error:
                last_error = error
        raise OneTrustError(f"connection failed ({type(last_error).__name__})", fatal=True)

    def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expiry:
            return self._token
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/access/v1/oauth/token",
            data=form,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        status, payload, _ = self._send(request)
        if status != 200:
            raise OneTrustError(f"token request failed (HTTP {status}); check the client id and secret", fatal=True)
        try:
            data = json.loads(payload)
        except ValueError:
            raise OneTrustError("token response was not valid JSON", fatal=True) from None
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise OneTrustError("token response did not contain an access_token", fatal=True)
        expires = str(data.get("expires_in", ""))
        ttl = int(expires) if expires.isdigit() else 300
        self._token, self._token_expiry = token, time.monotonic() + max(ttl - 30, 30)
        return token

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        refreshed, rate_limited, server_errors = False, 0, 0
        while True:
            request = urllib.request.Request(
                self.base_url + path,
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Authorization": f"Bearer {self._access_token()}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            status, payload, headers = self._send(request)
            if status == 200:
                try:
                    data = json.loads(payload)
                except ValueError:
                    raise OneTrustError("response was not valid JSON") from None
                if not isinstance(data, dict):
                    raise OneTrustError("unexpected response shape")
                return data
            if status == 401 and not refreshed:
                refreshed, self._token = True, None
                continue
            if status == 429 and rate_limited < MAX_RATE_LIMIT_RETRIES:
                rate_limited += 1
                self.sleep(retry_after_seconds(headers))
                continue
            if status >= 500 and server_errors < MAX_SERVER_ERROR_RETRIES:
                server_errors += 1
                self.sleep(2**server_errors)
                continue
            if status in (401, 403):
                raise OneTrustError(
                    f"access denied (HTTP {status}); check the client credentials and the COOKIE_READ scope", fatal=True
                )
            raise OneTrustError(f"HTTP {status}")

    def find_cookies(self, name: str) -> list[dict[str, Any]]:
        body = {"domains": list(self.config.domain_ids)} if self.config.domain_ids else {}
        found: list[dict[str, Any]] = []
        for page in range(MAX_PAGES):
            query = urllib.parse.urlencode({"cookieName": name, "page": page, "size": PAGE_SIZE})
            data = self._post(f"/api/cmp/v1/webscans/languages/{self.config.language}/cookies/filter?{query}", body)
            content = data.get("content")
            if isinstance(content, list):
                found.extend(item for item in content if isinstance(item, dict))
            if data.get("last", True):
                break
        return found


def host_matches(catalog_host: str, observed_hosts: Iterable[str]) -> bool:
    host = catalog_host.strip().lstrip(".").lower()
    return bool(host) and any(seen == host or seen.endswith("." + host) for seen in observed_hosts)


def describe_match(entries: Sequence[Mapping[str, Any]], name: str, observed_hosts: Iterable[str]) -> dict[str, Any]:
    exact = [entry for entry in entries if entry.get("cookieName") == name]
    if not exact:
        return {"status": "not_found", "category": None}
    preferred = [entry for entry in exact if host_matches(str(entry.get("host") or ""), observed_hosts)]
    entry = (preferred or exact)[0]
    category = entry.get("displayGroupName") or None
    length, unit = entry.get("length"), entry.get("durationType")
    others = sorted({str(e["displayGroupName"]) for e in exact if e.get("displayGroupName")} - {str(category)})
    return {
        "status": "classified" if category else "uncategorized",
        "category": category,
        "third_party": entry.get("thirdParty"),
        "lifespan": entry.get("lifespan"),
        "duration": f"{length} {unit}" if length and unit else None,
        "host": entry.get("host"),
        "source": entry.get("cookieSource"),
        "description": (entry.get("description") or "")[:300] or None,
        "other_categories": others,
    }


def classify_cookies(
    client: OneTrustClient, cookies: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Look up each cookie name; returns ``(summary, results_by_name)``."""
    results: dict[str, dict[str, Any]] = {}
    failures_in_row = 0
    problem: str | None = None
    for index, cookie in enumerate(cookies[:MAX_COOKIES_PER_RUN]):
        if index:
            client.sleep(LOOKUP_PAUSE_SECONDS)
        try:
            entries = client.find_cookies(cookie["name"])
        except OneTrustError as error:
            if error.fatal:
                problem = str(error)
                break
            results[cookie["name"]] = {"status": "lookup_failed", "category": None, "detail": str(error)}
            failures_in_row += 1
            if failures_in_row >= MAX_CONSECUTIVE_LOOKUP_FAILURES:
                problem = "repeated lookup failures"
                break
            continue
        failures_in_row = 0
        results[cookie["name"]] = describe_match(entries, cookie["name"], set(cookie.get("hosts") or []))

    if not problem and len(cookies) > MAX_COOKIES_PER_RUN:
        problem = f"only the first {MAX_COOKIES_PER_RUN} cookie names were looked up"
    counts = Counter(result["status"] for result in results.values())
    if problem and not any(r["status"] != "lookup_failed" for r in results.values()):
        status = "unavailable"
    elif problem or counts["lookup_failed"]:
        status = "partial"
    else:
        status = "ok"
    return {
        "status": status,
        "detail": problem or "",
        "hostname": client.config.hostname,
        "language": client.config.language,
        "route": client.route,
        "domain_filter": bool(client.config.domain_ids),
        "cookies_checked": len(results),
        "cookies_total": len(cookies),
        "counts": dict(counts),
    }, results
