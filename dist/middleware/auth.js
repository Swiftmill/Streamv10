import crypto from "crypto";
import { ROLE_SCHEMA } from "../shared/validation/schemas.js";
import { CSRF_HEADER_NAME, SESSION_COOKIE_NAME } from "../utils/constants.js";

export function attachSessionUser(req, _res, next) {
  const session = req.session;
  if (session && session.user) {
    req.user = session.user;
  }
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  return next();
}

export function requireRole(role) {
  return (req, res, next) => {
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

export function csrfProtection(req, res, next) {
  const headerName = CSRF_HEADER_NAME.toLowerCase();
  const csrfToken = req.headers[headerName] || req.body?._csrf;
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return next();
  }
  if (!csrfToken) {
    return res.status(403).json({ error: "CSRF token missing" });
  }
  const session = req.session;
  if (!session || session.csrfToken !== csrfToken) {
    return res.status(403).json({ error: "CSRF token invalid" });
  }
  return next();
}

export function issueCsrfToken(req) {
  const token = crypto.randomUUID();
  if (!req.session) {
    req.session = {};
  }
  req.session.csrfToken = token;
  return token;
}

export function destroySession(req, res) {
  res.clearCookie(SESSION_COOKIE_NAME);
  if (req.session) {
    req.session = null;
  }
}
