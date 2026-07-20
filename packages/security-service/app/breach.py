"""
breach.py — credential exposure checking.

THE CRYPTOGRAPHY HERE IS THE INTERESTING PART
----------------------------------------------
Checking "has this password been breached?" against a remote service looks
impossible to do safely: you'd have to send the password. Even sending its
hash is bad — hashes of human-chosen passwords are trivially reversible with
a rainbow table.

HaveIBeenPwned solves this with **k-anonymity**:

  1. SHA-1 the password locally.            -> 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  2. Send ONLY the first 5 hex characters.  -> 5BAA6
  3. The server returns every hash suffix it knows beginning with that prefix
     — typically 400-800 of them.
  4. You search that list locally for your own suffix.

The server learns you were interested in one of ~500 passwords. It never
learns which. Your password never leaves your machine, and neither does its
full hash. The "k" in k-anonymity is that bucket size — you're indistinguishable
from k-1 other queries.

Why SHA-1, which is cryptographically broken? Because it isn't being used for
security here. It's a bucketing function over a public dataset. Collision
resistance is irrelevant when the entire corpus is already public. Knowing
*why* a broken primitive is acceptable in a specific context is a genuinely
senior security distinction.

DOMAIN BREACH LOOKUP
--------------------
Separately, HIBP exposes which known breaches affected a given domain. That
endpoint is unauthenticated and tells us "did this organization appear in
LinkedIn 2012, Adobe 2013, Collection #1..." — real attack-surface signal,
since credential reuse from old breaches is one of the most common initial
access vectors in practice.
"""
from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from typing import Optional

import httpx

PWNED_RANGE_API = "https://api.pwnedpasswords.com/range/"
HIBP_BREACHES_API = "https://haveibeenpwned.com/api/v3/breaches"


@dataclass
class BreachRecord:
    name: str
    domain: str
    breach_date: str
    pwn_count: int
    data_classes: list[str]
    is_verified: bool
    description: str

    def dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "pwn_count": self.pwn_count,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "description": self.description,
        }


@dataclass
class BreachResult:
    domain: str
    breaches: list[BreachRecord] = field(default_factory=list)
    total_accounts_exposed: int = 0
    error: Optional[str] = None

    def dict(self) -> dict:
        return {
            "domain": self.domain,
            "breaches": [b.dict() for b in self.breaches],
            "total_accounts_exposed": self.total_accounts_exposed,
            "error": self.error,
        }


# ---- k-anonymity password check -----------------------------------------

def hash_password(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the uppercase SHA-1 hex digest.

    The split point is 5 characters — that's what the API expects, and it
    yields buckets of roughly 400-800 hashes from a corpus of ~850 million.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_response(body: str, suffix: str) -> int:
    """Search the returned bucket for our suffix. Returns breach count, 0 if absent.

    Response format is one 'SUFFIX:COUNT' per line. We do the matching locally —
    that local search is the entire privacy guarantee. If you sent the suffix to
    the server to do the comparison, you'd have given away the password hash and
    destroyed the point of the scheme.
    """
    target = suffix.upper()
    for line in body.splitlines():
        if ":" not in line:
            continue
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == target:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


async def check_password(password: str, timeout: float = 15.0) -> dict:
    """Check a password against HIBP without transmitting it or its full hash."""
    prefix, suffix = hash_password(password)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                PWNED_RANGE_API + prefix,
                headers={
                    "User-Agent": "blackout-asm/0.1",
                    # Pads the response with fake hashes so an observer can't
                    # infer bucket size from traffic length. Defense in depth
                    # against a passive network adversary.
                    "Add-Padding": "true",
                },
            )
            resp.raise_for_status()
        count = parse_range_response(resp.text, suffix)
        return {
            "breached": count > 0,
            "occurrences": count,
            "prefix_sent": prefix,   # surfaced so the UI can show what left the machine
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"breached": None, "occurrences": 0,
                "prefix_sent": prefix, "error": f"{type(exc).__name__}: {exc}"}


# ---- domain breach lookup ------------------------------------------------

_breach_cache: dict[str, BreachResult] = {}


async def check_domain_breaches(domain: str, timeout: float = 25.0) -> BreachResult:
    """Find known breaches associated with a domain.

    Note this queries the full breach catalogue and filters client-side. The
    catalogue is ~800 entries and changes rarely, so we cache it for the
    process lifetime rather than refetching per scan.
    """
    if domain in _breach_cache:
        return _breach_cache[domain]

    result = BreachResult(domain=domain)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                HIBP_BREACHES_API,
                headers={"User-Agent": "blackout-asm/0.1"},
            )
            resp.raise_for_status()
            catalogue = resp.json()

        for entry in catalogue:
            entry_domain = (entry.get("Domain") or "").lower()
            if not entry_domain:
                continue
            if entry_domain == domain or entry_domain.endswith("." + domain):
                result.breaches.append(BreachRecord(
                    name=entry.get("Name", ""),
                    domain=entry_domain,
                    breach_date=entry.get("BreachDate", ""),
                    pwn_count=int(entry.get("PwnCount", 0) or 0),
                    data_classes=entry.get("DataClasses", []) or [],
                    is_verified=bool(entry.get("IsVerified")),
                    description=_strip_html(entry.get("Description", ""))[:280],
                ))

        result.breaches.sort(key=lambda b: b.pwn_count, reverse=True)
        result.total_accounts_exposed = sum(b.pwn_count for b in result.breaches)
        _breach_cache[domain] = result
    except Exception as exc:  # noqa: BLE001
        result.error = f"HIBP breach lookup failed ({type(exc).__name__}: {exc})"
    return result


def _strip_html(text: str) -> str:
    """HIBP descriptions contain anchor tags. Strip them for plain display."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()
