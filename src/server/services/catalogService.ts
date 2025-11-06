import { promises as fs } from "fs";
import { join } from "path";
import dayjs from "dayjs";
import slugify from "slugify";
import { v4 as uuid } from "uuid";
import {
  MOVIES_ROOT,
  SERIES_ROOT,
  CATEGORIES_FILE
} from "@server/utils/constants";
import {
  CATEGORY_COLLECTION_SCHEMA,
  CATEGORY_SCHEMA,
  type CategoryRecord,
  MOVIE_COLLECTION_SCHEMA,
  MOVIE_SCHEMA,
  type MovieRecord,
  SERIES_COLLECTION_SCHEMA,
  SERIES_SCHEMA,
  type SeriesRecord,
  SERIES_EPISODE_SCHEMA,
  type SeriesEpisodeRecord
} from "@shared/validation/schemas";
import { readJsonFile, writeJsonFile } from "@server/utils/fileStore";

async function readDirectoryFiles<T>(directory: string, schema: typeof MOVIE_SCHEMA | typeof SERIES_SCHEMA) {
  try {
    const entries = await fs.readdir(directory);
    const items: T[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) {
        continue;
      }
      const filePath = join(directory, entry);
      const content = await readJsonFile(filePath, schema, undefined as never);
      items.push(content as T);
    }
    return items;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await fs.mkdir(directory, { recursive: true });
      return [];
    }
    throw error;
  }
}

export async function listMovies(): Promise<MovieRecord[]> {
  const movies = await readDirectoryFiles<MovieRecord>(MOVIES_ROOT, MOVIE_SCHEMA);
  return MOVIE_COLLECTION_SCHEMA.parse(movies);
}

export async function getMovie(id: string): Promise<MovieRecord | null> {
  try {
    const filePath = join(MOVIES_ROOT, `${id}.json`);
    return await readJsonFile(filePath, MOVIE_SCHEMA, undefined as never);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export async function upsertMovie(movie: Omit<MovieRecord, "id" | "createdAt" | "updatedAt"> & { id?: string }, userId: string): Promise<MovieRecord> {
  const now = dayjs().toISOString();
  const movieId = movie.id ?? uuid();
  const existing = await getMovie(movieId);
  const record: MovieRecord = MOVIE_SCHEMA.parse({
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

export async function deleteMovie(id: string): Promise<void> {
  await fs.unlink(join(MOVIES_ROOT, `${id}.json`));
}

export async function listSeries(): Promise<SeriesRecord[]> {
  const series = await readDirectoryFiles<SeriesRecord>(SERIES_ROOT, SERIES_SCHEMA);
  return SERIES_COLLECTION_SCHEMA.parse(series);
}

export async function getSeries(slug: string): Promise<SeriesRecord | null> {
  try {
    const filePath = join(SERIES_ROOT, `${slug}.json`);
    return await readJsonFile(filePath, SERIES_SCHEMA, undefined as never);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export async function upsertSeries(
  series: Omit<SeriesRecord, "slug" | "createdAt" | "updatedAt" | "episodes"> & {
    slug?: string;
    episodes?: SeriesEpisodeRecord[];
  },
  userId: string
): Promise<SeriesRecord> {
  const now = dayjs().toISOString();
  const slug = series.slug ?? slugify(series.title, { lower: true, strict: true });
  const existing = await getSeries(slug);
  const mergedEpisodes = mergeEpisodes(existing?.episodes ?? [], series.episodes ?? []);
  const record: SeriesRecord = SERIES_SCHEMA.parse({
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

function mergeEpisodes(existing: SeriesEpisodeRecord[], incoming: SeriesEpisodeRecord[]): SeriesEpisodeRecord[] {
  const map = new Map<string, SeriesEpisodeRecord>();
  for (const episode of existing) {
    map.set(`${episode.season}-${episode.episode}`, episode);
  }
  for (const episode of incoming) {
    const parsed = SERIES_EPISODE_SCHEMA.parse(episode);
    map.set(`${parsed.season}-${parsed.episode}`, {
      ...parsed,
      createdAt: map.get(`${parsed.season}-${parsed.episode}`)?.createdAt ?? parsed.createdAt,
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

export async function deleteSeries(slug: string): Promise<void> {
  await fs.unlink(join(SERIES_ROOT, `${slug}.json`));
}

export async function listCategories(): Promise<CategoryRecord[]> {
  return readJsonFile(CATEGORIES_FILE, CATEGORY_COLLECTION_SCHEMA, []);
}

export async function saveCategories(categories: CategoryRecord[]): Promise<void> {
  const sorted = [...categories].sort((a, b) => a.position - b.position);
  await writeJsonFile(CATEGORIES_FILE, sorted);
}

export async function upsertCategory(
  payload: Omit<CategoryRecord, "id" | "createdAt" | "updatedAt" | "position"> & { id?: string; position?: number }
): Promise<CategoryRecord> {
  const categories = await listCategories();
  const now = dayjs().toISOString();
  const id = payload.id ?? uuid();
  const existing = categories.find((category) => category.id === id || category.slug === payload.slug);
  const position = payload.position ?? existing?.position ?? categories.length;
  const category: CategoryRecord = CATEGORY_SCHEMA.parse({
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

export async function deleteCategory(id: string): Promise<void> {
  const categories = await listCategories();
  const filtered = categories.filter((category) => category.id !== id);
  await saveCategories(filtered);
}
