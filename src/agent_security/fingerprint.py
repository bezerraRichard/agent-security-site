"""Best-effort identification of the CDN, CMS and tools behind a site, to say where each fix belongs."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

AEM = "Adobe Experience Manager"
AEM_CLOUD = "Adobe Experience Manager as a Cloud Service"
MAX_PAGES_INSPECTED = 25


def _cdn(headers: Any) -> tuple[str, str] | None:
    """(CDN name, evidence) from response headers."""
    served_by = headers.get("X-Served-By") or ""
    if served_by.startswith("cache-") or headers.get("X-Timer") or "fastly" in (headers.get("Via") or "").lower():
        return "Fastly", f"X-Served-By: {served_by}" if served_by else "X-Timer header"
    if headers.get("CF-RAY"):
        return "Cloudflare", "CF-RAY header"
    if headers.get("X-Amz-Cf-Id"):
        return "Amazon CloudFront", "X-Amz-Cf-Id header"
    if "akamai" in (headers.get("Server") or "").lower() or headers.get("X-Akamai-Transformed"):
        return "Akamai", "Akamai server header"
    if headers.get("X-Azure-Ref"):
        return "Azure Front Door", "X-Azure-Ref header"
    return None


def _aem_header(headers: Any) -> str | None:
    for name in ("X-Vhost", "X-Dispatcher"):
        if headers.get(name):
            return f"{name}: {headers.get(name)}"
    return next((f"{key} header" for key in headers if key.lower().startswith("x-aem")), None)


def detect_platform(pages: Iterable[dict[str, Any]]) -> dict[str, Any]:
    cdn: str | None = None
    technologies: set[str] = set()
    evidence: list[str] = []
    for page in list(pages)[:MAX_PAGES_INSPECTED]:
        headers = page.get("headers")
        if headers is None:
            continue
        found = _cdn(headers) if cdn is None else None
        if found:
            cdn = found[0]
            evidence.append(f"CDN {found[0]}: {found[1]}")
        aem = _aem_header(headers)
        if aem and AEM not in technologies:
            technologies.add(AEM)
            evidence.append(f"{AEM}: {aem}")
        for name in (page.get("facts") or {}).get("technologies", []):
            if name not in technologies:
                technologies.add(name)
                evidence.append(f"{name}: resources loaded by the page")
    cms = None
    if AEM in technologies:
        # AEM as a Cloud Service is delivered through an Adobe-managed Fastly CDN.
        cms = AEM_CLOUD if cdn == "Fastly" else AEM
    return {"cdn": cdn, "cms": cms, "technologies": sorted(technologies - {AEM}), "evidence": evidence}
