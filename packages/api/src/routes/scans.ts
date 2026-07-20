import { Router } from "express";
import { z } from "zod";
import { prisma, audit } from "../db/client.js";
import { requireAuth, requireRole } from "../auth/middleware.js";
import { enqueueScan } from "../lib/queue.js";
import { streamScanReport } from "../lib/report.js";

export const scanRouter = Router();

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

const createSchema = z.object({
  domain: z.string().refine((d) => DOMAIN_RE.test(d), "invalid domain"),
  authorized: z.boolean().default(false),
  alertEmail: z.string().email().optional(),
});

/** Create a scan. MEMBER+ can launch. VIEWER cannot. */
scanRouter.post("/", requireAuth, requireRole("MEMBER"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues });
  const { domain, authorized, alertEmail } = parsed.data;
  const { sub: userId, orgId } = req.auth!;

  const scan = await prisma.scan.create({
    data: { domain, authorized, orgId, createdBy: userId, status: "QUEUED",
            alertEmail: alertEmail ?? null },
  });
  await enqueueScan({ scanId: scan.id, domain, authorized, orgId,
                      alertEmail: alertEmail ?? null, userId });
  await audit("scan.created", { userId, orgId, metadata: { scanId: scan.id, domain, authorized } });
  return res.status(202).json({ id: scan.id, status: scan.status });
});

/** List scans for the caller's org. */
scanRouter.get("/", requireAuth, async (req, res) => {
  const scans = await prisma.scan.findMany({
    where: { orgId: req.auth!.orgId },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: {
      id: true, domain: true, status: true, riskScore: true,
      severity: true, createdAt: true, finishedAt: true,
    },
  });
  return res.json(scans);
});

/** Fetch one scan with full detail — but only if it belongs to your org.
 *  This org check is the core of multi-tenant isolation. Never trust the id
 *  alone; always scope by the authenticated org. */
scanRouter.get("/:id", requireAuth, async (req, res) => {
  const scan = await prisma.scan.findFirst({
    where: { id: req.params.id, orgId: req.auth!.orgId },
    include: {
      findings: { orderBy: { weight: "desc" } },
      assets: true,
      vulns: { orderBy: { cvssScore: "desc" } },
    },
  });
  if (!scan) return res.status(404).json({ error: "not found" });
  return res.json(scan);
});

/** Download a PDF report. Streamed, not buffered — see report.ts. */
scanRouter.get("/:id/report", requireAuth, async (req, res) => {
  const scan = await prisma.scan.findFirst({
    where: { id: req.params.id, orgId: req.auth!.orgId },
    include: {
      findings: { orderBy: { weight: "desc" } },
      vulns: { orderBy: { cvssScore: "desc" } },
    },
  });
  if (!scan) return res.status(404).json({ error: "not found" });
  if (scan.status !== "COMPLETED") {
    return res.status(409).json({ error: "scan not completed" });
  }
  await audit("report.generated", {
    userId: req.auth!.sub, orgId: req.auth!.orgId, metadata: { scanId: scan.id },
  });
  return streamScanReport(scan as any, res);
});
