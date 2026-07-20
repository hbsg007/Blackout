import { Router } from "express";
import { z } from "zod";
import { prisma, audit } from "../db/client.js";
import {
  hashPassword, verifyPassword, signAccessToken,
  generateRefreshToken, hashRefreshToken,
} from "../auth/tokens.js";

export const authRouter = Router();

const credsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional(),
  orgName: z.string().min(1).optional(),
});

/** Register: creates a user, a personal org, and an OWNER membership. */
authRouter.post("/register", async (req, res) => {
  const parsed = credsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues });
  const { email, password, name, orgName } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "email already registered" });

  const passwordHash = await hashPassword(password);
  const user = await prisma.user.create({
    data: {
      email, passwordHash, name,
      memberships: {
        create: {
          role: "OWNER",
          org: { create: { name: orgName || `${name || email}'s Org` } },
        },
      },
    },
    include: { memberships: { include: { org: true } } },
  });

  const membership = user.memberships[0];
  await audit("user.registered", { userId: user.id, orgId: membership.orgId });
  return res.status(201).json(await issueTokens(user.id, membership.orgId, membership.role));
});

const loginSchema = z.object({ email: z.string().email(), password: z.string() });

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid input" });
  const { email, password } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { email },
    include: { memberships: true },
  });
  // Constant-ish response regardless of whether the user exists (avoid user enumeration).
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  const membership = user.memberships[0];
  if (!membership) return res.status(403).json({ error: "no org membership" });

  await audit("user.login", { userId: user.id, orgId: membership.orgId });
  return res.json(await issueTokens(user.id, membership.orgId, membership.role));
});

/** Refresh: rotate the refresh token (revoke old, issue new). */
authRouter.post("/refresh", async (req, res) => {
  const raw = z.string().safeParse(req.body?.refreshToken);
  if (!raw.success) return res.status(400).json({ error: "missing refreshToken" });

  const tokenHash = hashRefreshToken(raw.data);
  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: { user: { include: { memberships: true } } },
  });
  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    return res.status(401).json({ error: "invalid refresh token" });
  }
  // rotate
  await prisma.refreshToken.update({ where: { id: stored.id }, data: { revoked: true } });
  const membership = stored.user.memberships[0];
  return res.json(await issueTokens(stored.userId, membership.orgId, membership.role));
});

async function issueTokens(userId: string, orgId: string, role: string) {
  const access = signAccessToken({ sub: userId, orgId, role });
  const { raw, tokenHash, expiresAt } = generateRefreshToken();
  await prisma.refreshToken.create({ data: { tokenHash, userId, expiresAt } });
  return { accessToken: access, refreshToken: raw };
}
