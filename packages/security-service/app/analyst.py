"""
analyst.py — AI security analyst.

THE CORE DESIGN RULE, AND WHY IT MATTERS
-----------------------------------------
The LLM NEVER produces the risk score. It never invents a finding. It never
decides severity. It receives the deterministic scoring engine's output and
writes an *explanation* of it for a human.

Why this separation is non-negotiable:

  1. REPRODUCIBILITY. Run the same scan twice, get the same score. An LLM is
     stochastic; a compliance auditor asking "why was this 72 last quarter and
     68 now?" needs an answer better than "the model felt differently."
  2. NO HALLUCINATED VULNERABILITIES. If the model can invent findings, it
     will eventually invent a CVE that doesn't exist. In security tooling a
     confident false positive burns engineering hours and destroys trust.
  3. AUDITABILITY. Every number traces to a rule in scoring.py that you can
     read, test, and defend.

So: deterministic engine decides WHAT and HOW BAD. The LLM explains WHY IT
MATTERS and WHAT TO DO. This is the pattern you should argue for in an
interview — "we used an LLM for narration, not adjudication."

GRACEFUL DEGRADATION
--------------------
No API key configured → return a template-based summary generated from the
same structured findings. The product still works; it's just less eloquent.
Never make a core feature hard-depend on a third-party LLM being reachable.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import httpx

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.getenv("ANALYST_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are a senior security analyst writing an executive \
summary of an external attack surface scan.

STRICT RULES:
- You will be given structured findings from a deterministic scoring engine.
- Report ONLY findings present in the input. Never invent vulnerabilities, \
CVE IDs, hosts, or ports.
- Never state or modify the risk score; it is computed elsewhere.
- If the input contains errors indicating incomplete data, say so explicitly \
so the reader does not mistake incomplete results for a clean result.

Respond with ONLY a JSON object, no markdown fences, no preamble:
{
  "executive_summary": "2-3 sentences for a non-technical stakeholder",
  "key_risks": ["concise risk statement", ...],
  "recommendations": [
    {"priority": "immediate|short-term|long-term",
     "action": "specific remediation step",
     "rationale": "why this matters"}
  ],
  "data_quality_note": "note about incomplete data, or empty string"
}"""


def _template_summary(domain: str, risk: dict, recon: dict) -> dict:
    """Deterministic fallback used when no LLM is configured.

    Note this produces genuinely useful output — it is not a stub. A user with
    no API key gets a working product.
    """
    findings = risk.get("findings", [])
    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    errors = recon.get("errors", [])

    if not findings:
        summary = (f"The external scan of {domain} surfaced no scored findings. "
                   f"{len(recon.get('subdomains', []))} subdomain(s) and "
                   f"{len(recon.get('ips', []))} IP address(es) were discovered.")
    else:
        summary = (f"The external attack surface of {domain} shows "
                   f"{len(findings)} finding(s), including {len(crit)} critical "
                   f"and {len(high)} high severity. The highest-priority issue "
                   f"is: {findings[0]['title']}.")

    recs = []
    for f in (crit + high)[:5]:
        recs.append({
            "priority": "immediate" if f["severity"] == "critical" else "short-term",
            "action": f"Remediate: {f['title']}",
            "rationale": f"Severity {f['severity']}, contributing {f['weight']} "
                         f"points to the risk score.",
        })

    return {
        "executive_summary": summary,
        "key_risks": [f["title"] for f in findings[:6]],
        "recommendations": recs,
        "data_quality_note": (
            "Scan data is incomplete: " + "; ".join(errors) if errors else ""),
        "generated_by": "template",
    }


def _build_payload(domain: str, risk: dict, recon: dict) -> str:
    """Assemble the structured input. We deliberately send a COMPACT, curated
    view rather than the whole recon dump — smaller prompts are cheaper, faster,
    and give the model less room to wander off-script."""
    return json.dumps({
        "domain": domain,
        "risk_score": risk.get("score"),
        "severity_band": risk.get("severity"),
        "findings": [
            {"severity": f["severity"], "title": f["title"], "weight": f["weight"]}
            for f in risk.get("findings", [])
        ],
        "asset_counts": {
            "subdomains": len(recon.get("subdomains", [])),
            "ips": len(recon.get("ips", [])),
            "open_ports": len(recon.get("open_ports", [])),
            "technologies": recon.get("technologies", []),
        },
        "scan_errors": recon.get("errors", []),
    }, indent=2)


async def analyze(domain: str, risk: dict, recon: dict,
                  timeout: float = 60.0) -> dict:
    """Generate a narrative assessment. Falls back to templates on any failure."""
    if not ANTHROPIC_API_KEY:
        return _template_summary(domain, risk, recon)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": MODEL,
                    "max_tokens": 1500,
                    "system": SYSTEM_PROMPT,
                    "messages": [{
                        "role": "user",
                        "content": _build_payload(domain, risk, recon),
                    }],
                },
            )
            resp.raise_for_status()
            data = resp.json()

        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()
        # Models sometimes wrap JSON in fences despite instructions. Strip them.
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        parsed = json.loads(text.strip())

        # VALIDATE the shape. Never trust model output structurally — a missing
        # key would crash the frontend. Fall back rather than propagate garbage.
        required = {"executive_summary", "key_risks", "recommendations"}
        if not required.issubset(parsed.keys()):
            raise ValueError(f"missing keys: {required - set(parsed.keys())}")

        parsed["generated_by"] = "llm"
        return parsed

    except Exception as exc:  # noqa: BLE001
        fallback = _template_summary(domain, risk, recon)
        fallback["llm_error"] = f"{type(exc).__name__}: {exc}"
        return fallback
