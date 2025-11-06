import { promises as fs } from "fs";
import { join } from "path";
import dayjs from "dayjs";
import slugify from "slugify";
import { v4 as uuid } from "uuid";
import {
  MOVIES_ROOT,
  SERIES_ROOT,
  CATEGORIES_FILE
} from "../utils/constants.js";
import {
  CATEGORY_COLLECTION_SCHEMA,
  CATEGORY_SCHEMA,
  MOVIE_COLLECTION_SCHEMA,
  MOVIE_SCHEMA,
  SERIES_COLLECTION_SCHEMA,
  SERIES_SCHEMA,
  SERIES_EPISODE_SCHEMA
} from "../shared/validation/schemas.js";
import { readJsonFile, writeJsonFile } from "../utils/fileStore.js";

async function readDirectoryFiles(directory, schema) {
  try {
    const entries = await fs.readdir(directory);
    const items = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) {
        continue;
      }
      const filePath = join(directory, entry);
      const content = await readJsonFile(filePath, schema, undefined);
      items.push(content);
    }
    return items;
  } catch (error) {
    if (error.code === "ENOENT") {
      await fs.mkdir(directory, { recursive: true });
      return [];
    }
    throw error;
  }
}

export async function listMovies() {
  const movies = await readDirectoryFiles(MOVIES_ROOT, MOVIE_SCHEMA);
  return MOVIE_COLLECTION_SCHEMA.parse(movies);
}

export async function getMovie(id) {
  try {
    const filePath = join(MOVIES_ROOT, `${id}.json`);
    return await readJsonFile(filePath, MOVIE_SCHEMA, undefined);
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export async function upsertMovie(movie, userId) {
  const now = dayjs().toISOString();
  const movieId = movie.id ?? uuid();
  const existing = await getMovie(movieId);
  const record = MOVIE_SCHEMA.parse({
    ...movie,
    id: movieId,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    createdBy: existing?.createdBy ?? userId,
    updatedBy: userId
  });
  await writeJsonFile(join(MOVIES_ROOT, `${movieId}.json`), record);
  return record;
}

export async function deleteMovie(id) {
  await fs.unlink(join(MOVIES_ROOT, `${id}.json`));
}

export async function listSeries() {
  const series = await readDirectoryFiles(SERIES_ROOT, SERIES_SCHEMA);
  return SERIES_COLLECTION_SCHEMA.parse(series);
}

export async function getSeries(slug) {
  try {
    const filePath = join(SERIES_ROOT, `${slug}.json`);
    return await readJsonFile(filePath, SERIES_SCHEMA, undefined);
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export async function upsertSeries(series, userId) {
  const now = dayjs().toISOString();
  const slug = series.slug ?? slugify(series.title, { lower: true, strict: true });
  const existing = await getSeries(slug);
  const mergedEpisodes = mergeEpisodes(existing?.episodes ?? [], series.episodes ?? []);
  const record = SERIES_SCHEMA.parse({
    ...series,
    slug,
    episodes: mergedEpisodes,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    createdBy: existing?.createdBy ?? userId,
    updatedBy: userId
  });
  await writeJsonFile(join(SERIES_ROOT, `${slug}.json`), record);
  return record;
}

function mergeEpisodes(existing, incoming) {
  const map = new Map();
  for (const episode of existing) {
    map.set(`${episode.season}-${episode.episode}`, episode);
  }
  for (const episode of incoming) {
    const parsed = SERIES_EPISODE_SCHEMA.parse(episode);
    const key = `${parsed.season}-${parsed.episode}`;
    const current = map.get(key);
    map.set(key, {
      ...parsed,
      createdAt: current?.createdAt ?? parsed.createdAt,
      updatedAt: dayjs().toISOString()
    });
  }
  return Array.from(map.values()).sort((a, b) => {
    if (a.season === b.season) {
      return a.episode - b.episode;
    }
    return a.season - b.season;
  });
}

export async function deleteSeries(slug) {
  await fs.unlink(join(SERIES_ROOT, `${slug}.json`));
}

export async function listCategories() {
  return readJsonFile(CATEGORIES_FILE, CATEGORY_COLLECTION_SCHEMA, []);
}

export async function saveCategories(categories) {
  const sorted = [...categories].sort((a, b) => a.position - b.position);
  await writeJsonFile(CATEGORIES_FILE, sorted);
}

export async function upsertCategory(payload) {
  const categories = await listCategories();
  const now = dayjs().toISOString();
  const id = payload.id ?? uuid();
  const existing = categories.find((category) => category.id === id || category.slug === payload.slug);
  const position = payload.position ?? existing?.position ?? categories.length;
  const category = CATEGORY_SCHEMA.parse({
    ...payload,
    id,
    position,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now
  });
  const filtered = categories.filter((item) => item.id !== id);
  filtered.push(category);
  await saveCategories(filtered);
  return category;
}

export async function deleteCategory(id) {
  const categories = await listCategories();
  const filtered = categories.filter((category) => category.id !== id);
  await saveCategories(filtered);
}
