export const DATA_ROOT = "data";
export const USERS_ROOT = `${DATA_ROOT}/users`;
export const ADMIN_USERS_FILE = `${USERS_ROOT}/admin.json`;
export const STANDARD_USERS_FILE = `${USERS_ROOT}/users.json`;
export const HISTORY_ROOT = `${USERS_ROOT}/history`;
export const MOVIES_ROOT = `${DATA_ROOT}/catalog/movies`;
export const SERIES_ROOT = `${DATA_ROOT}/catalog/series`;
export const CATEGORIES_FILE = `${DATA_ROOT}/catalog/categories.json`;
export const VIEW_STATS_FILE = `${DATA_ROOT}/views.json`;

export const SESSION_COOKIE_NAME = "streamv10.sid";
export const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7;

export const VIEW_COOKIE_PREFIX = "streamv10_view_";
export const VIEW_COOKIE_TTL_MS = 1000 * 60 * 60 * 24;

export const CSRF_COOKIE_NAME = "streamv10.csrf";
export const CSRF_HEADER_NAME = "x-csrf-token";
