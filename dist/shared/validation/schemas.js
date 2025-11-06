import { z } from "zod";

export const ROLE_SCHEMA = z.union([z.literal("admin"), z.literal("user")]);
export const PASSWORD_HASH_REGEX = /^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/;

export const USER_BASE_SCHEMA = z.object({
  username: z
    .string({ required_error: "username is required" })
    .min(3, "username must be at least 3 characters")
    .max(64, "username must be at most 64 characters")
    .regex(/^[a-zA-Z0-9._-]+$/, "username contains invalid characters"),
  displayName: z
    .string({ required_error: "displayName is required" })
    .min(1, "displayName cannot be empty")
    .max(120, "displayName is too long"),
  role: ROLE_SCHEMA,
  active: z.boolean().default(true),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const USER_SCHEMA = USER_BASE_SCHEMA.extend({
  passwordHash: z
    .string({ required_error: "passwordHash is required" })
    .regex(PASSWORD_HASH_REGEX, "password hash must be a bcrypt hash"),
  passwordResetToken: z
    .object({
      token: z.string(),
      expiresAt: z.string().datetime()
    })
    .optional(),
  lastLoginAt: z.string().datetime().optional()
});

export const USER_PUBLIC_SCHEMA = USER_BASE_SCHEMA.omit({
  updatedAt: true
}).extend({
  updatedAt: z.string().datetime().optional(),
  lastLoginAt: z.string().datetime().optional()
});

export const LOGIN_SCHEMA = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(8).max(128)
});

export const STREAM_HOST_WHITELIST = [
  "storage.googleapis.com",
  "stream.mux.com",
  "video-cdn.example.com",
  "public-videos.example.org",
  "d1a2b3c4.cloudfront.net"
];

export const STREAM_URL_SCHEMA = z
  .string({ required_error: "streamUrl is required" })
  .url("streamUrl must be a valid URL")
  .refine((value) => {
    try {
      const host = new URL(value).host;
      return STREAM_HOST_WHITELIST.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
    } catch (error) {
      return false;
    }
  }, "streamUrl domain is not allowed");

export const SUBTITLE_SCHEMA = z.object({
  language: z.string().min(2).max(16),
  label: z.string().min(1).max(64),
  url: z
    .string()
    .url()
    .refine((value) => {
      try {
        const host = new URL(value).host;
        return STREAM_HOST_WHITELIST.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
      } catch {
        return false;
      }
    }, "subtitle url domain is not allowed")
});

export const MOVIE_SCHEMA = z.object({
  id: z.string().uuid(),
  title: z.string().min(1).max(200),
  synopsis: z.string().min(1).max(5000),
  description: z.string().min(1).max(10000),
  genres: z.array(z.string().min(1).max(40)).min(1),
  releaseYear: z.number().int().min(1900).max(new Date().getFullYear() + 1),
  duration: z.number().int().min(1),
  rating: z.number().min(0).max(10).default(0),
  posterUrl: STREAM_URL_SCHEMA,
  backgroundUrl: STREAM_URL_SCHEMA,
  streamUrl: STREAM_URL_SCHEMA,
  subtitles: z.array(SUBTITLE_SCHEMA).default([]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  published: z.boolean().default(true),
  featured: z.boolean().default(false),
  categories: z.array(z.string().min(1).max(80)).default([]),
  createdBy: z.string(),
  updatedBy: z.string()
});

export const SERIES_EPISODE_SCHEMA = z.object({
  season: z.number().int().min(1),
  episode: z.number().int().min(1),
  title: z.string().min(1).max(200),
  synopsis: z.string().min(1).max(5000),
  runtime: z.number().int().min(1),
  streamUrl: STREAM_URL_SCHEMA,
  subtitles: z.array(SUBTITLE_SCHEMA).default([]),
  releasedAt: z.string().datetime(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  published: z.boolean().default(true)
});

export const SERIES_SCHEMA = z.object({
  slug: z.string().min(1).max(160),
  title: z.string().min(1).max(200),
  synopsis: z.string().min(1).max(5000),
  description: z.string().min(1).max(10000),
  genres: z.array(z.string().min(1).max(40)).min(1),
  releaseYear: z.number().int().min(1900).max(new Date().getFullYear() + 1),
  posterUrl: STREAM_URL_SCHEMA,
  backgroundUrl: STREAM_URL_SCHEMA,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  published: z.boolean().default(true),
  featured: z.boolean().default(false),
  categories: z.array(z.string().min(1).max(80)).default([]),
  createdBy: z.string(),
  updatedBy: z.string(),
  episodes: z
    .array(SERIES_EPISODE_SCHEMA)
    .default([])
    .transform((episodes) =>
      [...episodes].sort((a, b) => {
        if (a.season === b.season) {
          return a.episode - b.episode;
        }
        return a.season - b.season;
      })
    )
});

export const CATEGORY_SCHEMA = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(80),
  slug: z.string().min(1).max(120),
  position: z.number().int().min(0),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const HISTORY_ENTRY_SCHEMA = z.object({
  contentId: z.string().min(1),
  type: z.union([z.literal("movie"), z.literal("series")]),
  progress: z.number().min(0).max(1),
  lastWatched: z.string().datetime(),
  season: z.number().int().min(1).optional(),
  episode: z.number().int().min(1).optional()
});

export const VIEW_COUNTER_SCHEMA = z.object({
  id: z.string(),
  views: z.number().int().min(0),
  updatedAt: z.string().datetime()
});

export const CATEGORY_COLLECTION_SCHEMA = z.array(CATEGORY_SCHEMA);
export const MOVIE_COLLECTION_SCHEMA = z.array(MOVIE_SCHEMA);
export const SERIES_COLLECTION_SCHEMA = z.array(SERIES_SCHEMA);
export const USER_COLLECTION_SCHEMA = z.array(USER_SCHEMA);
export const HISTORY_COLLECTION_SCHEMA = z.array(HISTORY_ENTRY_SCHEMA);

export const AUDIT_ENTRY_SCHEMA = z.object({
  timestamp: z.string().datetime(),
  user: z.string(),
  action: z.string(),
  target: z.string(),
  details: z.string()
});

export const AUDIT_LOG_LINE_FORMAT = "TIMESTAMP | USER | ACTION | TARGET | DETAILS";
