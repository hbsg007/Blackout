"""
scoring.py — deterministic risk scoring.

Why deterministic (rules) and not "just ask an LLM for a score"?
Because a security score that changes when you re-run it, or that you can't
explain to an auditor, is worthless. The LLM's job (see ai_analyst) is to
*explain* the findings in prose. The *number* must be reproducible and
defensible. This is a real design principle: keep the scoring boring and the
narrative smart.

Model: we start every host at 0 risk and add weighted penalties for findings.
Score is clamped 0–100 and bucketed into severity bands. The weights are
first-pass and deliberately simple — a v2 would calibrate against real CVSS
data and exploit-availability feeds (EPSS).
"""
from __future__ import annotations

# Ports that should essentially never be exposed to the internet.
HIGH_RISK_PORTS = {
    3306: ("MySQL exposed to internet", 25),
    5432: ("PostgreSQL exposed to internet", 25),
    6379: ("Redis exposed (often unauthenticated)", 30),
    27017: ("MongoDB exposed to internet", 30),
    9200: ("Elasticsearch exposed to internet", 25),
    3389: ("RDP exposed to internet", 20),
    23:   ("Telnet (cleartext) exposed", 30),
    21:   ("FTP (often cleartext) exposed", 10),
}

MEDIUM_RISK_PORTS = {
    22: ("SSH exposed to internet", 5),
    25: ("SMTP exposed", 3),
    8080: ("HTTP-alt (often unauth admin panels)", 8),
}


def score_target(recon: dict) -> dict:
    """Take a ReconResult dict, return a risk report."""
    findings: list[dict] = []
    score = 0

    # --- exposed dangerous services -------------------------------------
    for port_info in recon.get("open_ports", []):
        port = port_info["port"]
        if port in HIGH_RISK_PORTS:
            desc, weight = HIGH_RISK_PORTS[port]
            score += weight
            findings.append(_finding("critical", desc, port_info, weight))
        elif port in MEDIUM_RISK_PORTS:
            desc, weight = MEDIUM_RISK_PORTS[port]
            score += weight
            findings.append(_finding("medium", desc, port_info, weight))

    # --- expired / expiring certs ---------------------------------------
    for cert in recon.get("certificates", []):
        not_after = cert.get("not_after")
        if not_after and _is_expired(not_after):
            score += 15
            findings.append(_finding(
                "high", f"Expired TLS certificate on {cert.get('host')}",
                cert, 15))
        tls = cert.get("tls_version")
        if tls and tls in ("TLSv1", "TLSv1.1", "SSLv3"):
            score += 10
            findings.append(_finding(
                "high", f"Obsolete TLS version {tls} on {cert.get('host')}",
                cert, 10))

    # --- large attack surface -------------------------------------------
    n_subs = len(recon.get("subdomains", []))
    if n_subs > 100:
        score += 10
        findings.append(_finding(
            "low", f"Large attack surface: {n_subs} subdomains discovered",
            {"count": n_subs}, 10))

    # --- missing HTTPS entirely -----------------------------------------
    open_ports = {p["port"] for p in recon.get("open_ports", [])}
    if 80 in open_ports and 443 not in open_ports:
        score += 8
        findings.append(_finding(
            "medium", "HTTP served without HTTPS", {"port": 80}, 8))

    # --- correlated CVEs -------------------------------------------------
    # Weighting: we scale by CVSS but cap the contribution so that one host
    # with 50 medium CVEs can't outrank a host with an exposed unauthenticated
    # database. Attack-surface risk is about EXPLOITABILITY IN CONTEXT, not
    # raw CVE count. This is the single most common mistake in naive scanners.
    cve_penalty = 0
    for corr in recon.get("cve_correlations", []):
        if corr.get("error"):
            findings.append(_finding(
                "informational",
                f"CVE correlation unavailable for {corr.get('product')}: "
                f"{corr['error']}",
                corr, 0))
            continue
        for cve in corr.get("cves", []):
            sev = cve.get("severity", "unknown")
            weight = {"critical": 12, "high": 7, "medium": 3, "low": 1}.get(sev, 0)
            cve_penalty += weight
            if sev in ("critical", "high"):
                findings.append(_finding(
                    sev,
                    f"{cve['cve_id']} affects {corr['product']} "
                    f"{corr['version']} (CVSS {cve.get('cvss_score')})",
                    {"cve": cve, "product": corr["product"]},
                    weight))
    score += min(cve_penalty, 45)  # cap total CVE contribution

    # --- credential exposure ---------------------------------------------
    breaches = recon.get("breaches", {}) or {}
    for b in breaches.get("breaches", []):
        pwn = b.get("pwn_count", 0)
        # Weight by magnitude: a 150M-account breach is not equivalent to a
        # 5k-account one, but the curve is deliberately flat — any breach means
        # credential reuse risk exists at all, which is most of the signal.
        weight = 12 if pwn > 1_000_000 else (8 if pwn > 10_000 else 5)
        sev = "high" if pwn > 1_000_000 else "medium"
        score += weight
        findings.append(_finding(
            sev,
            f"Credential breach: {b.get('name')} ({pwn:,} accounts, "
            f"{b.get('breach_date')})",
            b, weight))

    score = max(0, min(100, score))
    return {
        "score": score,
        "severity": _band(score),
        "findings": sorted(findings, key=lambda f: -f["weight"]),
        "summary": _summary(score, findings),
    }


def _finding(severity: str, title: str, evidence: dict, weight: int) -> dict:
    return {"severity": severity, "title": title,
            "evidence": evidence, "weight": weight}


def _band(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def _summary(score: int, findings: list[dict]) -> str:
    if not findings:
        return "No significant external exposure detected in this scan."
    crit = sum(1 for f in findings if f["severity"] == "critical")
    return (f"Risk score {score}/100. {len(findings)} finding(s), "
            f"{crit} critical. Highest priority: {findings[0]['title']}.")


def _is_expired(not_after: str) -> bool:
    from datetime import datetime, timezone
    # OpenSSL format: 'Jun  1 12:00:00 2025 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            return dt < datetime.now(timezone.utc)
        except ValueError:
            continue
    return False
