"""
main.py — FastAPI entrypoint for the Blackout security service.

This service is intentionally stateless and internal. It does the CPU/IO-heavy
security work and returns structured JSON. The Node API owns auth, persistence,
and orchestration; this service just answers "scan this and score it".

Splitting it out (rather than doing recon in Node) is a deliberate choice:
  1. Python's security/networking ecosystem (aiodns, scapy, cryptography) is
     far richer than Node's.
  2. It isolates the risky, resource-heavy work in its own container we can
     scale independently and lock down at the network level.
  3. It models a real microservice boundary you can talk about in interviews.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .analyst import analyze
from .recon import run_recon
from .scoring import score_target

app = FastAPI(title="Blackout Security Service", version="0.1.0")

# Simple shared-secret auth between the Node API and this service. In prod this
# lives on a private network / service mesh; the header is defense in depth.
INTERNAL_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "dev-internal-token")


class ScanRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    authorized: bool = Field(
        default=False,
        description="Set true ONLY for infrastructure you own or are "
                    "contracted to test. Unlocks active port scanning.")
    max_hosts: int = Field(default=50, ge=1, le=500)


def _check_auth(token: str | None) -> None:
    if token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="invalid internal token")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/scan")
async def scan(req: ScanRequest,
               x_internal_token: str | None = Header(default=None)) -> dict:
    _check_auth(x_internal_token)

    domain = req.domain.strip().lower()
    if not domain or " " in domain or "/" in domain:
        raise HTTPException(status_code=400, detail="invalid domain")

    recon = await run_recon(domain,
                            authorized=req.authorized,
                            max_hosts=req.max_hosts)
    recon_dict = recon.dict()
    risk = score_target(recon_dict)
    # AI narration of the deterministic findings. Never affects the score.
    analysis = await analyze(domain, risk, recon_dict)
    return {"recon": recon_dict, "risk": risk, "analysis": analysis}
