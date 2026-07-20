import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient();

/** Fire-and-forget audit logging. Every meaningful action leaves a trail —
 *  this is table stakes for a security product and a compliance requirement. */
export async function audit(action: string, opts: {
  orgId?: string;
  userId?: string;
  metadata?: Record<string, unknown>;
} = {}) {
  try {
    await prisma.auditLog.create({
      data: {
        action,
        orgId: opts.orgId,
        userId: opts.userId,
        metadata: opts.metadata as object,
      },
    });
  } catch (err) {
    console.error("audit log failed", err);
  }
}
