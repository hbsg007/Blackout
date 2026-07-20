import { Queue, Worker, type Job } from "bullmq";
import IORedis from "ioredis";
import { prisma, audit } from "../db/client.js";
import { sendAlert, shouldAlert } from "./mailer.js";

/**
 * Queue architecture:
 *
 *  API request  ──enqueue──▶  Redis (BullMQ)  ──▶  Worker  ──HTTP──▶  security-service
 *                                                     │
 *                                                     └──▶ Postgres (persist results)
 *
 * Why a queue at all? Recon takes seconds to minutes. You never do that inside
 * an HTTP request — the client would time out and you couldn't retry. The queue
 * gives us: async execution, automatic retries with backoff, concurrency
 * control, and a natural place to scale (add more workers). This is the single
 * most important architectural decision in the whole app.
 */

const connection = new IORedis(process.env.REDIS_URL || "redis://localhost:6379", {
  maxRetriesPerRequest: null,
});

const SECURITY_URL = process.env.SECURITY_SERVICE_URL || "http://localhost:8000";
const INTERNAL_TOKEN = process.env.INTERNAL_SERVICE_TOKEN || "dev-internal-token";

export const scanQueue = new Queue("scans", { connection });

interface ScanJobData {
  scanId?: string;          // absent for scheduled jobs — created at run time
  scheduleId?: string;
  domain: string;
  authorized: boolean;
  orgId: string;
  alertEmail?: string | null;
  userId?: string;
}

/** Register a repeating scan. BullMQ handles the cron loop; we just describe it.
 *  The jobId is derived from scheduleId so re-registering is idempotent — a
 *  restart must not silently create duplicate schedules. */
export async function scheduleScan(opts: {
  scheduleId: string; domain: string; authorized: boolean; orgId: string;
  cron: string; alertEmail: string | null; userId: string;
}) {
  await scanQueue.add("scheduled-scan", {
    scheduleId: opts.scheduleId,
    domain: opts.domain,
    authorized: opts.authorized,
    orgId: opts.orgId,
    alertEmail: opts.alertEmail,
    userId: opts.userId,
  }, {
    repeat: { pattern: opts.cron },
    jobId: `sched:${opts.scheduleId}`,
    removeOnComplete: 50,
  });
}

export async function unscheduleScan(scheduleId: string, cron: string) {
  await scanQueue.removeRepeatable("scheduled-scan", { pattern: cron },
                                    `sched:${scheduleId}`);
}

export async function enqueueScan(data: ScanJobData) {
  await scanQueue.add("scan", data, {
    attempts: 3,
    backoff: { type: "exponential", delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 500,
  });
}

/** Start the worker. Run this in a separate process (see worker.ts) so it
 *  scales independently of the HTTP API. */
export function startWorker() {
  const worker = new Worker<ScanJobData>(
    "scans",
    async (job: Job<ScanJobData>) => {
      const { domain, authorized, orgId, scheduleId, alertEmail, userId } = job.data;

      // A scheduled job has no Scan row yet — it creates one per run.
      let scanId = job.data.scanId;
      if (!scanId) {
        const created = await prisma.scan.create({
          data: {
            domain, authorized, orgId,
            createdBy: userId || "scheduler",
            scheduleId: scheduleId ?? null,
            alertEmail: alertEmail ?? null,
            status: "RUNNING",
          },
        });
        scanId = created.id;
        await prisma.schedule.updateMany({
          where: { id: scheduleId ?? "" }, data: { lastRunAt: new Date() },
        });
      } else {
        await prisma.scan.update({
          where: { id: scanId }, data: { status: "RUNNING" },
        });
      }

      // Previous score for this domain — needed to decide if anything changed.
      const previous = await prisma.scan.findFirst({
        where: { orgId, domain, status: "COMPLETED", NOT: { id: scanId } },
        orderBy: { createdAt: "desc" },
        select: { riskScore: true },
      });

      const resp = await fetch(`${SECURITY_URL}/scan`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-internal-token": INTERNAL_TOKEN,
        },
        body: JSON.stringify({ domain, authorized, max_hosts: 50 }),
      });
      if (!resp.ok) {
        throw new Error(`security-service ${resp.status}: ${await resp.text()}`);
      }
      const { recon, risk, analysis } = (await resp.json()) as any;

      // Flatten CVE correlations into Vulnerability rows for querying.
      const vulnRows = (recon.cve_correlations || []).flatMap((c: any) =>
        (c.cves || []).map((v: any) => ({
          scanId,
          cveId: v.cve_id,
          cvssScore: v.cvss_score ?? null,
          severity: v.severity,
          product: c.product,
          version: c.version,
          description: v.description || "",
          publishedAt: v.published || null,
        })),
      );

      // Persist: raw JSON + normalized projections, in one transaction.
      await prisma.$transaction([
        prisma.scan.update({
          where: { id: scanId },
          data: {
            status: "COMPLETED",
            riskScore: risk.score,
            severity: risk.severity,
            reconData: recon,
            riskData: risk,
            analysis: analysis,
            finishedAt: new Date(),
          },
        }),
        prisma.asset.createMany({
          data: [
            ...recon.subdomains.map((v: string) => ({ scanId, kind: "subdomain", value: v })),
            ...recon.ips.map((v: string) => ({ scanId, kind: "ip", value: v })),
            ...recon.open_ports.map((p: any) => ({
              scanId, kind: "port", value: `${p.host}:${p.port}`, meta: p,
            })),
            ...recon.technologies.map((v: string) => ({ scanId, kind: "technology", value: v })),
          ],
        }),
        prisma.finding.createMany({
          data: risk.findings.map((f: any) => ({
            scanId, severity: f.severity, title: f.title,
            weight: f.weight, evidence: f.evidence,
          })),
        }),
        prisma.vulnerability.createMany({ data: vulnRows }),
      ]);

      await audit("scan.completed", { orgId, metadata: { scanId, domain, score: risk.score } });

      // Alert only on material change — see mailer.ts on alert fatigue.
      const recipient = alertEmail ?? null;
      if (recipient) {
        const ctx = {
          to: recipient, domain, scanId, riskScore: risk.score,
          severity: risk.severity,
          newCritical: risk.findings.filter((f: any) => f.severity === "critical").length,
          newHigh: risk.findings.filter((f: any) => f.severity === "high").length,
          previousScore: previous?.riskScore ?? null,
        };
        if (shouldAlert(ctx)) {
          await sendAlert(ctx);
          await audit("alert.sent", { orgId, metadata: { scanId, to: recipient } });
        }
      }

      return { scanId, score: risk.score };
    },
    { connection, concurrency: 3 },
  );

  worker.on("failed", async (job, err) => {
    if (!job) return;
    await prisma.scan.update({
      where: { id: job.data.scanId },
      data: { status: "FAILED", error: err.message, finishedAt: new Date() },
    }).catch(() => {});
  });

  console.log("scan worker started");
  return worker;
}
