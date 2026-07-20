import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken, type AccessClaims } from "./tokens.js";

// Extend Express Request with our auth context.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AccessClaims;
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing bearer token" });
  }
  try {
    req.auth = verifyAccessToken(header.slice(7));
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// RBAC: OWNER > ADMIN > MEMBER > VIEWER.
const RANK: Record<string, number> = {
  OWNER: 4,
  ADMIN: 3,
  MEMBER: 2,
  VIEWER: 1,
};

/** Guard a route by minimum role. Usage: requireRole("ADMIN"). */
export function requireRole(min: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const role = req.auth?.role;
    if (!role || (RANK[role] ?? 0) < (RANK[min] ?? 99)) {
      return res.status(403).json({ error: "insufficient role" });
    }
    next();
  };
}
