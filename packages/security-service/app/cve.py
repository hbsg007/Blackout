"""
cve.py — vulnerability correlation engine.

THE PROBLEM THIS SOLVES
-----------------------
Recon tells us "this host runs nginx 1.18.0". That's a fact, not a risk.
Correlation is the step that turns an observed *fingerprint* into known
*vulnerabilities* — the thing a security team actually acts on.

HOW IT WORKS
------------
1. Parse a banner/header string ("nginx/1.18.0") into (vendor, product, version).
2. Build a CPE 2.3 string — the industry-standard identifier for a piece of
   software. This is the vocabulary NVD speaks.
3. Query NVD (the US government's National Vulnerability Database) using
   `virtualMatchString`, which does CPE range matching — it finds CVEs whose
   affected-version ranges *contain* our version, which plain keyword search
   cannot do.
4. Extract CVSS base scores and severities.

THREE ENGINEERING CONSTRAINTS YOU MUST RESPECT
----------------------------------------------
1. RATE LIMITING. NVD allows 5 requests per 30 seconds without an API key
   (50 with one). Exceed it and you get 403-blocked. We enforce this with an
   async rate limiter, not by hoping.
2. CACHING. The same nginx version will be looked up thousands of times across
   scans. CVE data changes daily at most. We cache aggressively with a TTL.
3. GRACEFUL DEGRADATION. NVD goes down. A scan must still succeed with a
   clear "correlation unavailable" note rather than failing entirely — and
   must never silently report zero CVEs when it simply couldn't ask.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map the product names that show up in banners to their NVD CPE vendor.
# CPE vendor names are frequently NOT what you'd guess (nginx is owned by F5,
# so it's "f5:nginx"). This mapping is why naive keyword search fails.
CPE_VENDOR_MAP: dict[str, str] = {
    "nginx": "f5",
    "apache": "apache",
    "httpd": "apache",
    "openssh": "openbsd",
    "mysql": "oracle",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elastic",
    "php": "php",
    "iis": "microsoft",
    "tomcat": "apache",
    "openssl": "openssl",
    "node.js": "nodejs",
    "express": "openjsf",
}

# Normalize banner product names to their CPE product name.
PRODUCT_ALIASES: dict[str, str] = {
    "httpd": "http_server",
    "apache": "http_server",
    "iis": "internet_information_services",
    "node.js": "node.js",
    "tomcat": "tomcat",
}


@dataclass
class CVERecord:
    cve_id: str
    cvss_score: Optional[float]
    severity: str
    description: str
    published: str

    def dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "published": self.published,
        }


@dataclass
class CorrelationResult:
    """CVEs found for one software fingerprint."""
    product: str
    version: str
    cpe: str
    cves: list[CVERecord] = field(default_factory=list)
    error: Optional[str] = None

    def dict(self) -> dict:
        return {
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "cves": [c.dict() for c in self.cves],
            "error": self.error,
        }


# ---- parsing -------------------------------------------------------------

# Matches "nginx/1.18.0", "Apache/2.4.41", "OpenSSH_8.2p1", "PHP/7.4.3"
_BANNER_RE = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9._+-]*?)[/_ -]v?(?P<version>\d+(?:\.\d+){1,3}[a-z]?\d*)",
    re.IGNORECASE,
)


def parse_fingerprint(banner: str) -> Optional[tuple[str, str]]:
    """Extract (product, version) from a banner or Server header.

    Returns None when there's no version — and that matters. Without a version
    you cannot correlate: "nginx" alone matches every nginx CVE ever filed,
    which is noise, not intelligence. Refusing to guess is the correct
    behaviour. False positives destroy trust in a security tool faster than
    missing findings do.
    """
    if not banner:
        return None
    m = _BANNER_RE.search(banner.strip())
    if not m:
        return None
    product = m.group("product").lower().strip()
    version = m.group("version").strip()
    if product in {"http", "https", "tcp"} or len(product) < 2:
        return None
    return product, version


def build_cpe(product: str, version: str) -> Optional[str]:
    """Build a CPE 2.3 string for NVD's virtualMatchString parameter.

    Format: cpe:2.3:a:<vendor>:<product>:<version>
    ('a' = application. 'o' would be operating system, 'h' hardware.)
    """
    key = product.lower()
    vendor = CPE_VENDOR_MAP.get(key)
    if not vendor:
        return None  # unknown vendor → don't guess, correlation is skipped
    cpe_product = PRODUCT_ALIASES.get(key, key)
    return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}"


# ---- rate limiting + caching --------------------------------------------

class RateLimiter:
    """Token-bucket-ish limiter: at most `rate` calls per `per` seconds.

    NVD blocks aggressive clients. This is not optional politeness — without
    it your scanner gets IP-banned from the vulnerability database it depends
    on, and every subsequent scan silently loses correlation.
    """

    def __init__(self, rate: int = 5, per: float = 30.0):
        self.rate = rate
        self.per = per
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < self.per]
            if len(self._calls) >= self.rate:
                sleep_for = self.per - (now - self._calls[0]) + 0.1
                await asyncio.sleep(max(0.0, sleep_for))
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.per]
            self._calls.append(time.monotonic())


class TTLCache:
    """Tiny in-process cache with expiry.

    In production this is Redis, so the cache is shared across worker
    replicas and survives restarts. In-process is correct for a single
    container and keeps the service dependency-free.
    """

    def __init__(self, ttl: float = 86400.0):
        self.ttl = ttl
        self._store: dict[str, tuple[float, object]] = {}

    def get(self, key: str):
        entry = self._store.get(key)
        if not entry:
            return None
        expires, value = entry
        if time.monotonic() > expires:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value) -> None:
        self._store[key] = (time.monotonic() + self.ttl, value)


_limiter = RateLimiter(rate=5, per=30.0)
_cache = TTLCache(ttl=86400.0)


# ---- NVD query -----------------------------------------------------------

def _extract_cvss(cve: dict) -> tuple[Optional[float], str]:
    """Pull the CVSS base score, preferring v3.1 > v3.0 > v2.

    NVD returns metrics under different keys per CVSS version, and older CVEs
    only have v2. Always prefer the newest available.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = (data.get("baseSeverity")
                        or entries[0].get("baseSeverity")
                        or _severity_from_score(score))
            return score, str(severity).lower()
    return None, "unknown"


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


async def lookup_cves(product: str, version: str, *,
                      limit: int = 10,
                      timeout: float = 30.0) -> CorrelationResult:
    """Query NVD for CVEs affecting product@version."""
    cpe = build_cpe(product, version)
    if not cpe:
        return CorrelationResult(
            product=product, version=version, cpe="",
            error=f"No CPE vendor mapping for '{product}' — correlation skipped.")

    cached = _cache.get(cpe)
    if cached is not None:
        return cached  # type: ignore[return-value]

    result = CorrelationResult(product=product, version=version, cpe=cpe)
    try:
        await _limiter.acquire()
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(NVD_API, params={
                "virtualMatchString": cpe,
                "resultsPerPage": limit,
            }, headers={"User-Agent": "blackout-asm/0.1"})
            resp.raise_for_status()
            data = resp.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            score, severity = _extract_cvss(cve)
            descs = cve.get("descriptions", [])
            desc = next((d.get("value", "") for d in descs
                         if d.get("lang") == "en"), "")
            result.cves.append(CVERecord(
                cve_id=cve.get("id", "UNKNOWN"),
                cvss_score=score,
                severity=severity,
                description=desc[:300],
                published=cve.get("published", ""),
            ))
        # Highest severity first — this ordering IS the prioritization.
        result.cves.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
        _cache.set(cpe, result)
    except Exception as exc:  # noqa: BLE001
        # Surface the failure. Never let "couldn't ask" look like "nothing found".
        result.error = f"NVD lookup failed ({type(exc).__name__}: {exc})"
    return result


async def correlate_all(fingerprints: list[str], *,
                        max_lookups: int = 10) -> list[CorrelationResult]:
    """Correlate a list of banner/header strings against NVD.

    Deduplicates first: scanning 200 hosts running the same nginx should cost
    one NVD call, not two hundred. `max_lookups` bounds worst-case scan time
    given the rate limiter.
    """
    seen: set[tuple[str, str]] = set()
    for raw in fingerprints:
        parsed = parse_fingerprint(raw)
        if parsed:
            seen.add(parsed)

    targets = list(seen)[:max_lookups]
    if not targets:
        return []
    return await asyncio.gather(*[lookup_cves(p, v) for p, v in targets])
