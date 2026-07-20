# Blackout — Roadmap

Build this yourself, sprint by sprint. Commit often, write tests, and keep the
commit history clean — interviewers read it. **What's already built is marked
✅. Everything else is yours.**

## GitHub project board (columns → cards)

**Backlog · Ready · In Progress · Review · Done**

Label cards by epic: `epic:auth` `epic:recon` `epic:scoring` `epic:ai`
`epic:infra` `epic:frontend` `epic:observability`.

## Sprint 0 — Foundations ✅ (done in this scaffold)
- ✅ Monorepo, docker-compose, Postgres + Redis
- ✅ Prisma schema + migrations
- ✅ JWT + refresh-token auth, RBAC middleware
- ✅ Express API skeleton, rate limiting, audit log
- ✅ FastAPI recon engine (crt.sh, DNS, certs, fingerprinting, gated port scan)
- ✅ Deterministic risk scoring
- ✅ BullMQ queue + worker
- ✅ Minimal Next.js UI (login, launch, results)

## Sprint 1 — Harden the core
- [ ] Fix the crt.sh parsing bug (filter malformed entries) + unit test
- [ ] Add `prom-client` `/metrics` to API; recon timing to security-service
- [ ] Vitest + pytest suites; GitHub Actions CI running both
- [ ] Real-time scan status via SSE (replace UI polling)
- [ ] Error boundaries + React Query on the frontend

## Sprint 2 — Vulnerability correlation engine
- [ ] Map fingerprinted services/versions → CVEs via the NVD API (cache in Redis)
- [ ] Enrich with EPSS exploit-probability scores; fold into risk weights
- [ ] Add credential-breach check via HaveIBeenPwned (k-anonymity range API)
- [ ] New `Vulnerability` table + findings linked to CVE IDs

## Sprint 3 — AI security analyst
- [ ] `/analyze` endpoint: feed structured findings to an LLM, get a prose
      executive summary + prioritized remediation. **The LLM explains; it never
      sets the score.** Constrain output with a strict JSON schema.
- [ ] Attack-path graph: build a node/edge model (asset → service → CVE →
      impact), render with a force-directed graph on the frontend.

## Sprint 4 — Scale & collaborate
- [ ] Team invites, role management UI
- [ ] Scheduled scans (BullMQ repeatable jobs) + email alerts (SES/Resend)
- [ ] Elasticsearch/OpenSearch indexing for cross-scan asset search
- [ ] PDF security reports (server-side render)

## Sprint 5 — Production
- [ ] Terraform for the AWS stack in ARCHITECTURE.md §6
- [ ] CI builds/pushes images to ECR, deploys to ECS on tag
- [ ] Grafana dashboards + Alertmanager rules
- [ ] Load test the queue; autoscale workers on queue depth

## Starter CI (`.github/workflows/ci.yml`)

```yaml
name: ci
on: [push, pull_request]
jobs:
  api:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm --prefix packages/api install
      - run: npx --prefix packages/api prisma generate
      - run: npx --prefix packages/api tsc --noEmit
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r packages/security-service/requirements.txt
      - run: python -m pytest packages/security-service  # add tests first
```

## How to talk about this in interviews

Don't say "I built a CrowdStrike competitor." Say: *"I built an attack-surface
management platform with a real reconnaissance engine — certificate-transparency
subdomain discovery, async DNS, live cert inspection, and authorization-gated
port scanning — behind a queue-based microservice architecture. Here's the one
design decision I'd defend hardest and why."* Then pick the deterministic-scoring
vs LLM-narration split, or the private-subnet security service. Depth on one real
decision beats a feature list every time.
