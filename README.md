# ⬛ Blackout — Autonomous Attack Surface Management

Submit a domain. Blackout discovers its external attack surface (subdomains,
DNS, certificates, IPs, and — when authorized — open ports and services),
scores the risk, and surfaces prioritized findings.

This repo is a **runnable vertical slice** of a larger platform. The core loop
works end to end; the remaining features are laid out in [`ROADMAP.md`](./ROADMAP.md)
for you to build (which is the point — a repo you can explain beats a repo you
can't).

## ⚠️ Legal & ethical use — read this first

Passive recon (certificate transparency, DNS, WHOIS) is fine against any domain.
**Active scanning (port/service scanning) against systems you do not own or have
written authorization to test may be illegal** — in Canada, unauthorized use of
a computer falls under Criminal Code s. 342.1; the US has the CFAA; most
countries have equivalents. Blackout defaults to passive mode. The `authorized`
flag unlocks active scanning and is your attestation that you have permission.
Only scan your own domains or lab targets like `scanme.nmap.org`.

## Run it

Prereqs: Docker + Docker Compose.

```bash
cp .env.example .env      # edit the secrets
docker compose up --build
```

Then open <http://localhost:3000>, click **Register**, and launch a scan against
a domain you own (or `example.com` for a passive-only demo).

Services:
| Service           | Port | Stack                    |
|-------------------|------|--------------------------|
| web               | 3000 | Next.js / React / TS     |
| api               | 4000 | Node / Express / Prisma  |
| security-service  | 8000 | FastAPI / Python         |
| postgres          | 5432 | PostgreSQL 16            |
| redis             | 6379 | Redis 7 (BullMQ queue)   |

## How a scan flows

```
Browser ──POST /api/scans──▶ Express API ──enqueue──▶ Redis (BullMQ)
                                                          │
                                    Worker ◀──dequeue─────┘
                                       │
                                       ├──POST /scan──▶ FastAPI security-service
                                       │                  (recon + risk scoring)
                                       │◀── recon + risk ─┘
                                       │
                                       └──▶ Postgres (raw JSON + normalized assets/findings)

Browser ──GET /api/scans/:id──▶ API ──▶ Postgres ──▶ rendered results
```

## Why the design looks like this

- **Separate Python security service.** Python's networking/security ecosystem
  is stronger, and isolating the risky, resource-heavy work in its own container
  lets us scale and lock it down independently. It's a real microservice boundary.
- **Queue in the middle.** Recon takes seconds to minutes; you never run that
  inside an HTTP request. BullMQ gives async execution, retries with backoff,
  and independent worker scaling.
- **Deterministic scoring, LLM narration.** The risk *number* is rule-based and
  reproducible (auditable). An LLM's job is only to *explain* findings in prose —
  never to invent the score. See `ROADMAP.md` for the AI analyst.
- **Stateless access JWT + stateful refresh token.** Fast auth checks, but
  refresh tokens are hashed in the DB so they're revocable.
- **Multi-tenant from day one.** Scans belong to Organizations; every query is
  scoped by the authenticated org. Retrofitting tenancy later is misery.

## Repo layout

```
blackout/
├── docker-compose.yml
├── packages/
│   ├── security-service/   FastAPI recon + scoring engine
│   ├── api/                Express API, auth, queue worker, Prisma schema
│   └── web/                Next.js frontend
├── ARCHITECTURE.md         Full-system design (incl. unbuilt features)
└── ROADMAP.md              Sprint-by-sprint plan for the rest
```

## Features

| Feature | Status | Where |
|---|---|---|
| Subdomain discovery (certificate transparency) | ✅ | `recon.py` |
| DNS resolution with OS-resolver fallback | ✅ | `recon.py` |
| TLS certificate inspection | ✅ | `recon.py` |
| Technology fingerprinting | ✅ | `recon.py` |
| Authorization-gated port scanning | ✅ | `recon.py` |
| CVE correlation via NVD (CPE 2.3 range matching) | ✅ | `cve.py` |
| Credential breach exposure (HIBP k-anonymity) | ✅ | `breach.py` |
| Attack path graph | ✅ | `graph.py` |
| Deterministic risk scoring | ✅ | `scoring.py` |
| AI security analyst (narration only) | ✅ | `analyst.py` |
| PDF security reports | ✅ | `api/lib/report.ts` |
| Scheduled scans | ✅ | `api/routes/schedules.ts` |
| Email alerting (change-based) | ✅ | `api/lib/mailer.ts` |
| JWT auth + rotating refresh tokens + RBAC | ✅ | `api/auth/` |
| Audit logging | ✅ | `api/db/client.ts` |
| Multi-tenant organizations | ✅ | schema + every query |
| 58 unit tests | ✅ | `security-service/tests/` |

Not yet built: Elasticsearch cross-scan search, team invite UI, AWS Terraform.
See `ROADMAP.md`.

## Testing

```bash
cd packages/security-service && pip install -r requirements.txt && pytest tests/ -q
cd packages/api && npx tsc --noEmit
```

## Known rough edges (good first issues for YOU)

- No real-time scan progress — the UI polls. Add SSE or WebSockets.
- Tokens live in `localStorage` (XSS-exposed). httpOnly cookies are correct.
- The CVE cache is in-process; move it to Redis so it survives restarts and
  shards across workers.
- No tests on the Node side at all.

## Troubleshooting

**`Table 'public.User' does not exist`** — the schema didn't sync. Run:
`docker compose exec api npx prisma db push`

**Port already in use** — something else is on 3000/4000/5432/6379/8000.
Stop it, or change the left-hand side of the port mapping in `docker-compose.yml`.

**Scan stuck on QUEUED** — the worker isn't running or can't reach Redis.
Check `docker compose logs worker`.

**Scan FAILED** — check `docker compose logs security-service`. crt.sh is a free
public service and sometimes rate-limits or times out; retry.

**`docker compose` not found** — you have the old standalone binary; use
`docker-compose up --build` (with a hyphen) instead.
