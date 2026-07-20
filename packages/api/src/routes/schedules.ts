import { Router } from "express";
import { z } from "zod";
import { prisma, audit } from "../db/client.js";
import { requireAuth, requireRole } from "../auth/middleware.js";
import { scheduleScan, unscheduleScan } from "../lib/queue.js";

export const scheduleRouter = Router();

// Named intervals rather than raw cron. Asking a user to hand-write cron is a
// UX failure and a source of silent misconfiguration ("0 0 * * 0" is weekly,
// but which day?). We map friendly names to patterns we control.
const CADENCE: Record<string, string> = {
  hourly: "0 * * * *",
  daily: "0 3 * * *",
  weekly: "0 3 * * 1",
};

const createSchema = z.object({
  domain: z.string().min(3),
  cadence: z.enum(["hourly", "daily", "weekly"]),
  authorized: z.boolean().default(false),
  alertEmail: z.string().email().optional(),
});

scheduleRouter.post("/", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues });
  const { domain, cadence, authorized, alertEmail } = parsed.data;
  const { sub: userId, orgId } = req.auth!;

  const schedule = await prisma.schedule.create({
    data: { domain, cron: CADENCE[cadence], authorized, alertEmail, orgId, createdBy: userId },
  });
  await scheduleScan({
    scheduleId: schedule.id, domain, authorized, orgId,
    cron: CADENCE[cadence], alertEmail: alertEmail ?? null, userId,
  });
  await audit("schedule.created", { userId, orgId, metadata: { domain, cadence } });
  return res.status(201).json(schedule);
});

scheduleRouter.get("/", requireAuth, async (req, res) => {
  return res.json(await prisma.schedule.findMany({
    where: { orgId: req.auth!.orgId }, orderBy: { createdAt: "desc" },
  }));
});

scheduleRouter.delete("/:id", requireAuth, requireRole("ADMIN"), async (req, res) => {
  // Org-scoped delete. Never delete by id alone — that's an IDOR.
  const schedule = await prisma.schedule.findFirst({
    where: { id: req.params.id, orgId: req.auth!.orgId },
  });
  if (!schedule) return res.status(404).json({ error: "not found" });

  await unscheduleScan(schedule.id, schedule.cron);
  await prisma.schedule.delete({ where: { id: schedule.id } });
  await audit("schedule.deleted", {
    userId: req.auth!.sub, orgId: req.auth!.orgId, metadata: { id: schedule.id },
  });
  return res.status(204).end();
});
