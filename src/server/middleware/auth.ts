import crypto from "crypto";
import { NextFunction, Request, Response } from "express";
import { CSRF_HEADER_NAME, SESSION_COOKIE_NAME } from "@server/utils/constants";
import { ROLE_SCHEMA, type UserRole } from "@shared/validation/schemas";

export interface SessionUser {
  username: string;
  role: UserRole;
}

export interface AuthenticatedRequest extends Request {
  user?: SessionUser;
}

export function attachSessionUser(req: AuthenticatedRequest, _res: Response, next: NextFunction) {
  const session = req.session as { user?: SessionUser } | undefined;
  if (session?.user) {
    req.user = session.user;
  }
  next();
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  return next();
}

export function requireRole(role: UserRole) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const parsedRole = ROLE_SCHEMA.safeParse(req.user.role);
    if (!parsedRole.success || parsedRole.data !== role) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  };
}

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  const headerName = CSRF_HEADER_NAME.toLowerCase();
  const csrfToken = req.headers[headerName] || req.body?._csrf;
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return next();
  }
  if (!csrfToken) {
    return res.status(403).json({ error: "CSRF token missing" });
  }
  const session = req.session as { csrfToken?: string } | undefined;
  if (!session?.csrfToken || session.csrfToken !== csrfToken) {
    return res.status(403).json({ error: "CSRF token invalid" });
  }
  return next();
}

export function issueCsrfToken(req: AuthenticatedRequest): string {
  const token = crypto.randomUUID();
  if (!req.session) {
    (req as Request & { session: Record<string, unknown> }).session = {};
  }
  (req.session as { csrfToken?: string }).csrfToken = token;
  return token;
}

export function destroySession(req: AuthenticatedRequest, res: Response) {
  res.clearCookie(SESSION_COOKIE_NAME);
  if (req.session) {
    req.session = null;
  }
}
