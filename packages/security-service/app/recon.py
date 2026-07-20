"""
recon.py — the reconnaissance engine.

Design notes for a future security engineer:

- We separate PASSIVE from ACTIVE techniques. Passive techniques query
  third-party datasets (crt.sh certificate transparency, DNS) and never send
  a packet to the target's own infrastructure in a way it would log as a scan.
  Active techniques (TCP connect port scans) DO touch the target directly and
  are gated behind an explicit `authorized` flag upstream.

- Everything here is async so a single worker can fan out hundreds of DNS/HTTP
  lookups concurrently. Recon is I/O bound, not CPU bound — asyncio is the
  right tool, threads/processes would just add overhead.

- We bound concurrency with a semaphore. An unbounded gather() against 5,000
  subdomains will exhaust file descriptors and get you rate-limited or
  null-routed. Backpressure is not optional in a scanner.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import aiodns
import httpx

from .breach import check_domain_breaches
from .cve import correlate_all
from .graph import build_attack_graph

# ---- data model ----------------------------------------------------------

@dataclass
class Asset:
    kind: str                       # "subdomain" | "ip" | "port" | "cert"
    value: str
    meta: dict = field(default_factory=dict)


@dataclass
class ReconResult:
    domain: str
    started_at: str
    finished_at: Optional[str] = None
    subdomains: list[str] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    ips: list[str] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    open_ports: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cve_correlations: list[dict] = field(default_factory=list)
    breaches: dict = field(default_factory=dict)
    attack_graph: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def dict(self) -> dict:
        return asdict(self)


# Small, sensible default port list. A real product would tier this
# (top-100, top-1000, full) and make it configurable.
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]


# ---- passive techniques --------------------------------------------------

_HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$")


def _is_valid_hostname(name: str, domain: str) -> bool:
    """CT logs contain junk: descriptive text, wildcards, email addresses,
    and entries with spaces. Validate before treating anything as a host."""
    if not name or len(name) > 253:
        return False
    if not (name == domain or name.endswith("." + domain)):
        return False
    return bool(_HOSTNAME_RE.match(name))


async def enumerate_subdomains_crtsh(
    domain: str, timeout: float = 30.0, retries: int = 2
) -> tuple[list[str], Optional[str]]:
    """Pull subdomains from crt.sh certificate transparency logs.

    CT logs are a goldmine: every TLS cert ever issued for a domain is public.
    Fully passive — we query the public crt.sh index, never the target.

    Returns (subdomains, error). crt.sh is a free community service that is
    frequently slow or rate-limited, so we retry with backoff and SURFACE the
    failure rather than silently returning just the apex domain. Silent
    degradation in a security scanner is dangerous: an empty result looks
    identical to a clean result.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: set[str] = {domain}
    last_error: Optional[str] = None

    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "blackout-asm/0.1"})
                resp.raise_for_status()
                for row in resp.json():
                    for name in str(row.get("name_value", "")).splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if _is_valid_hostname(name, domain):
                            found.add(name)
            return sorted(found), None
        except Exception as exc:  # noqa: BLE001 - recon is best-effort
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)

    return sorted(found), (
        f"crt.sh enumeration failed after {retries + 1} attempts ({last_error}). "
        "Subdomain list is incomplete — only the apex domain is included.")


async def _resolve_via_os(host: str) -> dict:
    """Fallback resolver using the OS stack (getaddrinfo).

    Why this exists: aiodns wraps c-ares, which reads /etc/resolv.conf and
    speaks DNS itself. Inside Docker, resolv.conf points at Docker's embedded
    DNS (127.0.0.11), which c-ares frequently cannot use. glibc's getaddrinfo
    handles it fine. Lesson: never let a single resolver be a single point of
    failure in a scanner — always have a fallback path.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return {}
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    out: dict = {}
    if v4:
        out["A"] = v4
    if v6:
        out["AAAA"] = v6
    return out


async def resolve_dns(host: str, resolver: aiodns.DNSResolver) -> dict:
    """Resolve A/AAAA/MX/NS/TXT for a host. Returns partial results on failure.

    Falls back to the OS resolver if c-ares returns nothing for A/AAAA.
    """
    records: dict = {}
    query_map = {"A": "A", "AAAA": "AAAA", "MX": "MX", "NS": "NS", "TXT": "TXT"}
    for label, qtype in query_map.items():
        try:
            answers = await resolver.query(host, qtype)
            if qtype in ("A", "AAAA"):
                records[label] = [a.host for a in answers]
            elif qtype == "MX":
                records[label] = [f"{a.priority} {a.host}" for a in answers]
            elif qtype == "NS":
                records[label] = [a.host for a in answers]
            elif qtype == "TXT":
                records[label] = ["".join(a.text) if isinstance(a.text, list) else a.text
                                  for a in answers]
        except Exception:  # NXDOMAIN / no record of that type is normal
            continue

    # If c-ares gave us no addresses at all, try the OS resolver before
    # concluding the host doesn't resolve.
    if not records.get("A") and not records.get("AAAA"):
        fallback = await _resolve_via_os(host)
        records.update(fallback)
    return records


async def fetch_certificate(host: str, port: int = 443, timeout: float = 8.0) -> Optional[dict]:
    """Grab the leaf TLS certificate. This is a light active touch (one TLS
    handshake) but is universally expected of any host advertising 443, so we
    treat it as low-impact recon rather than a scan."""
    loop = asyncio.get_running_loop()

    def _grab() -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even bad certs
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return {"raw": cert, "cipher": cipher, "tls_version": ssock.version()}

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _grab), timeout + 2)
    except Exception:
        return None


# ---- active techniques (gated) -------------------------------------------

async def scan_port(host: str, port: int, sem: asyncio.Semaphore,
                    timeout: float = 3.0) -> Optional[dict]:
    """TCP connect scan of a single port. ACTIVE — only call when authorized."""
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            # Attempt a tiny banner grab; many services speak first.
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=1.5)
                banner = data.decode("latin-1", "ignore").strip()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"host": host, "port": port, "state": "open",
                    "service": _guess_service(port), "banner": banner[:120]}
        except Exception:
            return None


def _guess_service(port: int) -> str:
    common = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
              110: "pop3", 143: "imap", 443: "https", 465: "smtps",
              587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
              3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
              8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"}
    return common.get(port, "unknown")


async def fingerprint_http(host: str, timeout: float = 8.0) -> list[str]:
    """Very light tech fingerprinting from HTTP response headers."""
    techs: set[str] = set()
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         verify=False) as client:
                r = await client.get(f"{scheme}://{host}",
                                     headers={"User-Agent": "blackout-asm/0.1"})
                server = r.headers.get("server")
                if server:
                    techs.add(server)
                powered = r.headers.get("x-powered-by")
                if powered:
                    techs.add(powered)
                if "cf-ray" in r.headers:
                    techs.add("Cloudflare")
                return sorted(techs)
        except Exception:
            continue
    return sorted(techs)


# ---- orchestration -------------------------------------------------------

async def run_recon(domain: str, *, authorized: bool = False,
                    ports: Optional[list[int]] = None,
                    max_hosts: int = 50, concurrency: int = 100) -> ReconResult:
    """
    Full recon pipeline. `authorized=True` unlocks active port scanning.
    `max_hosts` caps how many discovered subdomains we deep-scan so a huge
    domain doesn't turn into an hours-long job.
    """
    result = ReconResult(domain=domain,
                         started_at=datetime.now(timezone.utc).isoformat())
    resolver = aiodns.DNSResolver(timeout=5, tries=2)
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)

    # 1. passive subdomain discovery
    result.subdomains, crtsh_error = await enumerate_subdomains_crtsh(domain)
    if crtsh_error:
        result.errors.append(crtsh_error)

    # 2. resolve DNS for each subdomain, collect unique IPs
    hosts = result.subdomains[:max_hosts]
    dns_tasks = [resolve_dns(h, resolver) for h in hosts]
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
    ip_set: set[str] = set()
    for host, records in zip(hosts, dns_results):
        if isinstance(records, dict):
            result.dns_records[host] = records
            for ip in records.get("A", []) + records.get("AAAA", []):
                ip_set.add(ip)
    result.ips = sorted(ip_set)

    # 3. certificate collection for hosts that look web-facing
    cert_tasks = [fetch_certificate(h) for h in hosts]
    certs = await asyncio.gather(*cert_tasks, return_exceptions=True)
    for host, cert in zip(hosts, certs):
        if isinstance(cert, dict) and cert:
            result.certificates.append({"host": host, **_summarize_cert(cert)})

    # 4. tech fingerprint on the apex
    result.technologies = await fingerprint_http(domain)

    # 5. ACTIVE: port scan (only if authorized)
    if authorized and result.ips:
        scan_tasks = [scan_port(ip, p, sem)
                      for ip in result.ips[:max_hosts] for p in ports]
        scanned = await asyncio.gather(*scan_tasks)
        result.open_ports = [s for s in scanned if s]
    elif not authorized:
        result.errors.append(
            "Active port scan skipped: authorization not granted. "
            "Set authorized=true only for infrastructure you own or are "
            "contracted to test.")

    # 6. correlate discovered software versions against NVD.
    #    We feed BOTH HTTP tech fingerprints and port-scan banners, because a
    #    version string can come from either source.
    fingerprints = list(result.technologies)
    fingerprints += [p.get("banner", "") for p in result.open_ports if p.get("banner")]
    if fingerprints:
        correlations = await correlate_all(fingerprints)
        result.cve_correlations = [c.dict() for c in correlations]

    # 7. credential exposure — a parallel entry vector that bypasses the
    #    network path entirely, which is why it's so often the real one.
    breach_result = await check_domain_breaches(domain)
    result.breaches = breach_result.dict()
    if breach_result.error:
        result.errors.append(breach_result.error)

    # 8. attack path graph — turns a findings list into routes an attacker
    #    could take, which is what tells a defender where to cut.
    result.attack_graph = build_attack_graph(result.dict(), result.breaches).dict()

    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result


def _summarize_cert(cert: dict) -> dict:
    raw = cert.get("raw") or {}
    subject = dict(x[0] for x in raw.get("subject", []))
    issuer = dict(x[0] for x in raw.get("issuer", []))
    return {
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_before": raw.get("notBefore"),
        "not_after": raw.get("notAfter"),
        "tls_version": cert.get("tls_version"),
        "cipher": cert.get("cipher", [None])[0] if cert.get("cipher") else None,
    }
