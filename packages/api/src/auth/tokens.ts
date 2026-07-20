import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

/**
 * Token strategy (explain this in interviews):
 *
 *  - ACCESS token: short-lived (15m) stateless JWT. Signed with a secret,
 *    carries userId + orgId + role. Never stored server-side. Fast to verify.
 *  - REFRESH token: long-lived (7d) opaque random string. We store only its
 *    SHA-256 hash in the DB so a DB leak can't be replayed. Rotating and
 *    revocable. This is the standard "stateless access + stateful refresh"
 *    pattern that balances performance against the ability to log people out.
 */

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "dev-access-secret";
const ACCESS_TTL = "15m";
const REFRESH_TTL_DAYS = 7;

export interface AccessClaims {
  sub: string; // userId
  orgId: string;
  role: string;
}

export function hashPassword(pw: string): Promise<string> {
  return bcrypt.hash(pw, 12);
}

export function verifyPassword(pw: string, hash: string): Promise<boolean> {
  return bcrypt.compare(pw, hash);
}

export function signAccessToken(claims: AccessClaims): string {
  return jwt.sign(claims, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}

export function verifyAccessToken(token: string): AccessClaims {
  return jwt.verify(token, ACCESS_SECRET) as AccessClaims;
}

/** Generate a raw refresh token + its hash + expiry. Store the hash only. */
export function generateRefreshToken() {
  const raw = crypto.randomBytes(48).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
  const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 864e5);
  return { raw, tokenHash, expiresAt };
}

export function hashRefreshToken(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}
