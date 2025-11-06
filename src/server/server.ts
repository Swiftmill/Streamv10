import "dotenv/config";
import express, { type Request, type Response } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import cookieSession from "cookie-session";
import rateLimit from "express-rate-limit";
import dayjs from "dayjs";
import { JSDOM } from "jsdom";
import createDOMPurify from "dompurify";
import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  SESSION_COOKIE_NAME,
  SESSION_MAX_AGE_MS,
  VIEW_COOKIE_PREFIX,
  VIEW_COOKIE_TTL_MS
} from "@server/utils/constants";
import {
  appendAudit
} from "@server/utils/audit";
import {
  attachSessionUser,
  csrfProtection,
  destroySession,
  issueCsrfToken,
  requireAuth,
  requireRole,
  type AuthenticatedRequest
} from "@server/middleware/auth";
import {
  LOGIN_SCHEMA,
  MOVIE_SCHEMA,
  SERIES_EPISODE_SCHEMA,
  SERIES_SCHEMA,
  CATEGORY_SCHEMA,
  HISTORY_ENTRY_SCHEMA,
  USER_SCHEMA
} from "@shared/validation/schemas";
import {
  verifyUserCredentials,
  recordHistoryEntry,
  readHistory,
  listUsers,
  resetUserPassword,
  updatePasswordWithToken,
  deactivateUser,
  createUser
} from "@server/services/userService";
import {
  listMovies,
  upsertMovie,
  getMovie,
  deleteMovie,
  listSeries,
  upsertSeries,
  getSeries,
  deleteSeries,
  listCategories,
  upsertCategory,
  deleteCategory
} from "@server/services/catalogService";
import { writeJsonFile, readJsonFile } from "@server/utils/fileStore";
import { VIEW_STATS_FILE } from "@server/utils/constants";
import { v4 as uuid } from "uuid";
import { z } from "zod";

const app = express();
const { window } = new JSDOM("");
const DOMPurify = createDOMPurify(window);

const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? "http://localhost:3000").split(",").map((origin) => origin.trim());

app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(
  cookieSession({
    name: SESSION_COOKIE_NAME,
    keys: [(process.env.SESSION_SECRET as string) || "development-secret"],
    maxAge: SESSION_MAX_AGE_MS,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/"
  })
);
app.use(attachSessionUser);

const adminLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later"
});

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: dayjs().toISOString() });
});

app.get("/api/auth/csrf", (req: AuthenticatedRequest, res: Response) => {
  const token = issueCsrfToken(req);
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_MAX_AGE_MS
  });
  res.json({ csrfToken: token, headerName: CSRF_HEADER_NAME });
});

app.post("/api/auth/login", csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = LOGIN_SCHEMA.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const { username, password } = parseResult.data;
  const user = await verifyUserCredentials(username, password);
  if (!user) {
    await appendAudit({
      timestamp: dayjs().toISOString(),
      user: username,
      action: "auth.login.failed",
      target: username,
      details: "Invalid credentials"
    });
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const session = (req.session ?? {}) as typeof req.session & {
    user?: {
      username: string;
      role: string;
      displayName?: string;
    };
  };
  session.user = {
    username: user.username,
    role: user.role,
    displayName: user.displayName
  };
  req.session = session;
  const csrfToken = issueCsrfToken(req);
  res.cookie(CSRF_COOKIE_NAME, csrfToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_MAX_AGE_MS
  });
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: user.username,
    action: "auth.login.success",
    target: user.username,
    details: "User logged in"
  });
  res.json({
    user: {
      username: user.username,
      role: user.role,
      displayName: user.displayName
    },
    csrfToken
  });
});

app.post("/api/auth/logout", requireAuth, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const username = req.user?.username ?? "anonymous";
  destroySession(req, res);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: username,
    action: "auth.logout",
    target: username,
    details: "User logged out"
  });
  res.json({ success: true });
});

const PASSWORD_RESET_SCHEMA = z.object({
  username: USER_SCHEMA.shape.username,
  token: z.string().min(10).max(120),
  password: LOGIN_SCHEMA.shape.password
});

app.post("/api/auth/reset", csrfProtection, async (req: Request, res: Response) => {
  const parseResult = PASSWORD_RESET_SCHEMA.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const { username, token, password } = parseResult.data;
  try {
    await updatePasswordWithToken(username, token, password);
    await appendAudit({
      timestamp: dayjs().toISOString(),
      user: username,
      action: "auth.reset.complete",
      target: username,
      details: "Password reset completed"
    });
    res.json({ success: true });
  } catch (error) {
    await appendAudit({
      timestamp: dayjs().toISOString(),
      user: username,
      action: "auth.reset.failed",
      target: username,
      details: (error as Error).message
    });
    res.status(400).json({ error: (error as Error).message });
  }
});

app.get("/api/auth/me", requireAuth, (req: AuthenticatedRequest, res: Response) => {
  res.json({ user: req.user });
});

app.get("/api/movies", async (_req, res) => {
  const movies = await listMovies();
  res.json({ movies });
});

app.post("/api/movies", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const sanitized = sanitizePayload(req.body, ["description", "synopsis"]);
  const parseResult = MOVIE_SCHEMA.safeParse({
    ...sanitized,
    id: sanitized.id ?? uuid(),
    createdAt: sanitized.createdAt ?? dayjs().toISOString(),
    updatedAt: dayjs().toISOString(),
    createdBy: req.user?.username ?? "system",
    updatedBy: req.user?.username ?? "system"
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const record = await upsertMovie(parseResult.data, req.user!.username);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "movie.upsert",
    target: record.id,
    details: record.title
  });
  res.status(201).json({ movie: record });
});

app.put("/api/movies/:id", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const movie = await getMovie(req.params.id);
  if (!movie) {
    return res.status(404).json({ error: "Movie not found" });
  }
  const sanitized = sanitizePayload(req.body, ["description", "synopsis"]);
  const parseResult = MOVIE_SCHEMA.safeParse({
    ...movie,
    ...sanitized,
    id: req.params.id,
    updatedAt: dayjs().toISOString(),
    updatedBy: req.user!.username
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const record = await upsertMovie(parseResult.data, req.user!.username);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "movie.update",
    target: record.id,
    details: record.title
  });
  res.json({ movie: record });
});

app.delete("/api/movies/:id", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  await deleteMovie(req.params.id);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "movie.delete",
    target: req.params.id,
    details: "Movie removed"
  });
  res.status(204).send();
});

app.get("/api/series", async (_req, res) => {
  const series = await listSeries();
  res.json({ series });
});

app.post("/api/series", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const sanitized = sanitizePayload(req.body, ["description", "synopsis"]);
  const parseResult = SERIES_SCHEMA.extend({ slug: SERIES_SCHEMA.shape.slug.optional() }).safeParse({
    ...sanitized,
    createdAt: sanitized.createdAt ?? dayjs().toISOString(),
    updatedAt: dayjs().toISOString(),
    createdBy: req.user?.username ?? "system",
    updatedBy: req.user?.username ?? "system"
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const record = await upsertSeries(
    {
      ...parseResult.data,
      slug: parseResult.data.slug
    },
    req.user!.username
  );
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "series.upsert",
    target: record.slug,
    details: record.title
  });
  res.status(201).json({ series: record });
});

app.put("/api/series/:slug", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const series = await getSeries(req.params.slug);
  if (!series) {
    return res.status(404).json({ error: "Series not found" });
  }
  const sanitized = sanitizePayload(req.body, ["description", "synopsis"]);
  const parseResult = SERIES_SCHEMA.safeParse({
    ...series,
    ...sanitized,
    slug: req.params.slug,
    updatedAt: dayjs().toISOString(),
    updatedBy: req.user!.username
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const record = await upsertSeries(parseResult.data, req.user!.username);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "series.update",
    target: record.slug,
    details: record.title
  });
  res.json({ series: record });
});

app.post("/api/series/:slug/episodes", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const series = await getSeries(req.params.slug);
  if (!series) {
    return res.status(404).json({ error: "Series not found" });
  }
  const parseResult = SERIES_EPISODE_SCHEMA.safeParse({
    ...req.body,
    createdAt: dayjs().toISOString(),
    updatedAt: dayjs().toISOString()
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const record = await upsertSeries(
    {
      ...series,
      episodes: [parseResult.data]
    },
    req.user!.username
  );
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "series.episode.upsert",
    target: `${record.slug}:S${parseResult.data.season}E${parseResult.data.episode}`,
    details: parseResult.data.title
  });
  res.status(201).json({ series: record });
});

app.delete("/api/series/:slug", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  await deleteSeries(req.params.slug);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "series.delete",
    target: req.params.slug,
    details: "Series removed"
  });
  res.status(204).send();
});

app.get("/api/categories", async (_req, res) => {
  const categories = await listCategories();
  res.json({ categories });
});

app.post("/api/categories", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = CATEGORY_SCHEMA.partial({ id: true, position: true, createdAt: true, updatedAt: true }).safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const category = await upsertCategory(parseResult.data);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "category.upsert",
    target: category.id,
    details: category.name
  });
  res.status(201).json({ category });
});

app.put("/api/categories/:id", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = CATEGORY_SCHEMA.partial({ position: true }).safeParse({ ...req.body, id: req.params.id });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const category = await upsertCategory(parseResult.data);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "category.update",
    target: category.id,
    details: category.name
  });
  res.json({ category });
});

app.delete("/api/categories/:id", requireAuth, requireRole("admin"), csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  await deleteCategory(req.params.id);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "category.delete",
    target: req.params.id,
    details: "Category removed"
  });
  res.status(204).send();
});

app.get("/api/history", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const history = await readHistory(req.user!.username);
  res.json({ history });
});

app.post("/api/history", requireAuth, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = HISTORY_ENTRY_SCHEMA.safeParse({
    ...req.body,
    lastWatched: dayjs().toISOString()
  });
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  await recordHistoryEntry(req.user!.username, parseResult.data);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "history.record",
    target: parseResult.data.contentId,
    details: JSON.stringify(parseResult.data)
  });
  res.status(201).json({ success: true });
});

app.post("/api/play", requireAuth, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const { contentId } = req.body;
  if (!contentId || typeof contentId !== "string") {
    return res.status(400).json({ error: "contentId is required" });
  }
  const cookieName = `${VIEW_COOKIE_PREFIX}${contentId}`;
  const existing = req.cookies[cookieName];
  if (!existing) {
    await incrementViews(contentId);
    res.cookie(cookieName, "1", {
      maxAge: VIEW_COOKIE_TTL_MS,
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });
    await appendAudit({
      timestamp: dayjs().toISOString(),
      user: req.user!.username,
      action: "content.view",
      target: contentId,
      details: "View incremented"
    });
  }
  res.json({ success: true });
});

app.get("/api/admin/users", requireAuth, requireRole("admin"), adminLimiter, async (_req: AuthenticatedRequest, res: Response) => {
  const users = await listUsers();
  res.json({ users });
});

app.post("/api/admin/users", requireAuth, requireRole("admin"), adminLimiter, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = USER_SCHEMA.pick({ username: true, displayName: true, role: true, active: true })
    .extend({ password: LOGIN_SCHEMA.shape.password })
    .safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: parseResult.error.flatten() });
  }
  const user = await createUser({
    username: parseResult.data.username,
    displayName: parseResult.data.displayName,
    role: parseResult.data.role,
    active: parseResult.data.active,
    password: parseResult.data.password
  });
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "admin.user.create",
    target: user.username,
    details: user.role
  });
  res.status(201).json({ user });
});

app.post("/api/admin/users/:username/reset", requireAuth, requireRole("admin"), adminLimiter, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  const result = await resetUserPassword(req.params.username);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "admin.user.reset",
    target: req.params.username,
    details: "Password reset token generated"
  });
  res.json(result);
});

app.post("/api/admin/users/:username/deactivate", requireAuth, requireRole("admin"), adminLimiter, csrfProtection, async (req: AuthenticatedRequest, res: Response) => {
  await deactivateUser(req.params.username);
  await appendAudit({
    timestamp: dayjs().toISOString(),
    user: req.user!.username,
    action: "admin.user.deactivate",
    target: req.params.username,
    details: "User deactivated"
  });
  res.json({ success: true });
});

const ZodViewStore = {
  parse(value: unknown) {
    if (
      typeof value === "object" &&
      value !== null &&
      Array.isArray((value as { items?: unknown }).items)
    ) {
      const items = (value as { items: Array<{ id: string; views: number; updatedAt: string }> }).items;
      return {
        items: items.map((item) => ({
          id: String(item.id),
          views: Number(item.views),
          updatedAt: String(item.updatedAt)
        }))
      };
    }
    throw new Error("Invalid view store");
  }
} satisfies { parse: (value: unknown) => { items: Array<{ id: string; views: number; updatedAt: string }> } };

async function incrementViews(contentId: string) {
  const stats = await readJsonFile(VIEW_STATS_FILE, ZodViewStore, { items: [] });
  const existing = stats.items.find((entry) => entry.id === contentId);
  if (existing) {
    existing.views += 1;
    existing.updatedAt = dayjs().toISOString();
  } else {
    stats.items.push({ id: contentId, views: 1, updatedAt: dayjs().toISOString() });
  }
  await writeJsonFile(VIEW_STATS_FILE, stats);
}

app.use((err: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
  if (process.env.NODE_ENV !== "production") {
    console.error(err);
  }
  res.status(500).json({ error: "Internal server error" });
});

function sanitizePayload<T extends Record<string, unknown>>(payload: T, fields: string[]): T {
  const sanitized = { ...payload };
  for (const field of fields) {
    const value = sanitized[field];
    if (typeof value === "string") {
      sanitized[field] = DOMPurify.sanitize(value, { SAFE_FOR_TEMPLATES: true });
    }
  }
  return sanitized;
}

export function startServer(port = Number(process.env.PORT ?? 4000)) {
  app.listen(port, () => {
    if (process.env.NODE_ENV !== "production") {
      console.log(`API server listening on port ${port}`);
    }
  });
}

if (process.env.NODE_ENV !== "test") {
  startServer();
}
