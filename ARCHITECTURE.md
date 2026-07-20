# Blackout — System Architecture

This documents the *full* target system. The repo implements the core slice
(auth → scan → recon → score → view); everything here is the blueprint you
build toward.

## 1. Component diagram

```
                         ┌────────────────────┐
                         │   Next.js Web App   │  React Query, Shadcn UI
                         └─────────┬──────────┘
                                   │ HTTPS (JWT)
                         ┌─────────▼──────────┐
                         │   Express API      │  auth, RBAC, orchestration
                         │  (Node + TS)       │  rate limiting, audit log
                         └───┬───────┬────────┘
              enqueue jobs   │       │  read/write
                     ┌───────▼──┐ ┌──▼─────────┐
                     │  Redis   │ │ PostgreSQL │  users, orgs, scans,
                     │ (BullMQ) │ │            │  assets, findings, audit
                     └────┬─────┘ └────────────┘
             dequeue      │                ▲
                     ┌────▼─────┐          │ persist
                     │  Worker  │──────────┘
                     │ (Node)   │
                     └────┬─────┘
                          │ POST /scan (internal token)
                     ┌────▼──────────────┐
                     │ Security Service  │  recon engine + scoring
                     │ (FastAPI/Python)  │
                     └────┬──────────────┘
                          │ queries
        ┌─────────────────┼──────────────────┬───────────────┐
        ▼                 ▼                  ▼               ▼
   crt.sh (CT)         DNS resolvers    target TLS/HTTP   CVE feeds*
                                                          (* roadmap)

  Observability sidecar: Prometheus scrapes /metrics on api + security-service,
  Grafana dashboards. Elasticsearch* indexes assets for cross-scan search.
```

## 2. API design (REST)

| Method | Path                     | Role    | Purpose                        |
|--------|--------------------------|---------|--------------------------------|
| POST   | `/api/auth/register`     | —       | Create user + org + tokens     |
| POST   | `/api/auth/login`        | —       | Issue access + refresh tokens  |
| POST   | `/api/auth/refresh`      | —       | Rotate refresh, new access     |
| POST   | `/api/scans`             | MEMBER+ | Launch a scan (returns 202)    |
| GET    | `/api/scans`             | VIEWER+ | List org scans                 |
| GET    | `/api/scans/:id`         | VIEWER+ | Scan detail (org-scoped)       |
| POST   | `/api/scans/:id/report`  | VIEWER+ | Generate PDF report *(roadmap)*|
| GET    | `/api/assets/search`     | VIEWER+ | Cross-scan asset search *(ES)* |
| POST   | `/api/schedules`         | ADMIN+  | Recurring scans *(roadmap)*    |
| POST   | `/api/team/invite`       | ADMIN+  | Invite member *(roadmap)*      |

Conventions: 202 for async accepts, org-scoping on every read, Zod validation
at the boundary, consistent `{ error }` shape.

## 3. Authentication & authorization

- **Access token**: JWT, 15 min, carries `{ sub, orgId, role }`. Stateless.
- **Refresh token**: 48-byte random, 7 days, SHA-256 hash stored in DB,
  rotated on every use, revocable.
- **RBAC**: OWNER > ADMIN > MEMBER > VIEWER, enforced by `requireRole()`.
- **Tenant isolation**: every scan/asset query filters by `req.auth.orgId`.
  An IDOR here would be the worst bug in the system, so it's centralized.
- **Service-to-service**: internal shared-secret header + private network.

## 4. Event-driven workflow

The scan is modeled as a state machine persisted on the `Scan` row:

```
QUEUED ──worker picks up──▶ RUNNING ──success──▶ COMPLETED
                                │
                                └──error (3 retries exhausted)──▶ FAILED
```

Each transition writes an `AuditLog`. A future `scan.completed` event can fan
out to: email alerts, webhook notifications, and Elasticsearch indexing —
publish these to a Redis pub/sub channel or SNS topic so consumers decouple
from the worker.

## 5. Security model (defense in depth)

- Helmet security headers, strict CORS, JSON body size limits.
- Hard rate limits on auth endpoints (brute-force defense).
- bcrypt (cost 12) for passwords; no plaintext, ever.
- Login responds identically for unknown users and bad passwords (no user
  enumeration).
- Input validation with Zod + a strict domain regex before any recon.
- The scanner's `authorized` gate prevents unauthorized active scanning.
- Secrets via environment, never committed; rotate `JWT_ACCESS_SECRET` and
  `INTERNAL_SERVICE_TOKEN` per environment.

## 6. AWS deployment (target)

```
Route53 ─▶ CloudFront ─▶ ALB ─┬─▶ ECS Fargate: web
                              ├─▶ ECS Fargate: api        (auto-scaling)
                              └─▶ ECS Fargate: worker     (scale on queue depth)
                                     │
              ECS Fargate: security-service (private subnet, no inbound ALB)
                                     │
      RDS PostgreSQL (Multi-AZ) ─ ElastiCache Redis ─ OpenSearch
      Secrets Manager · ECR (images) · CloudWatch Logs
```

Key choices: security-service lives in a **private subnet with no public
ingress** — only the worker reaches it. Workers scale on Redis queue depth
(custom CloudWatch metric). RDS Multi-AZ for durability. Images in ECR, built
by CI.

## 7. Observability

- `prom-client` in the API exposes `/metrics`: request latency histograms,
  scan queue depth, scans by status.
- FastAPI exposes recon duration and per-technique timing.
- Prometheus scrapes both; Grafana dashboards for latency, queue depth, error
  rate, and scan throughput. Alertmanager pages on queue backlog or error spike.

## 8. Data model

See `packages/api/prisma/schema.prisma`. Core tables: `User`, `Organization`,
`Membership`, `RefreshToken`, `Scan`, `Asset`, `Finding`, `AuditLog`. The
`Scan.reconData` JSON is the immutable source of truth; `Asset`/`Finding` rows
are queryable projections of it.
