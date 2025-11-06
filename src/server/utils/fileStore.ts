import fs from "fs";
import { dirname } from "path";
import { promisify } from "util";
import lockfile from "proper-lockfile";
import { z } from "zod";

const mkdir = promisify(fs.mkdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const rename = promisify(fs.rename);

async function ensureDirectory(filePath: string) {
  await mkdir(dirname(filePath), { recursive: true });
}

export async function readJsonFile<TSchema extends z.ZodTypeAny>(
  filePath: string,
  schema: TSchema,
  defaultValue: z.infer<TSchema>
): Promise<z.infer<TSchema>> {
  try {
    const content = await readFile(filePath, "utf-8");
    const json = JSON.parse(content);
    return schema.parse(json);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await ensureDirectory(filePath);
      await writeJsonFile(filePath, defaultValue);
      return defaultValue;
    }
    throw error;
  }
}

export async function writeJsonFile<T>(filePath: string, data: T): Promise<void> {
  await ensureDirectory(filePath);
  const release = await lockfile.lock(filePath, {
    retries: {
      retries: 5,
      factor: 1.5,
      minTimeout: 50,
      maxTimeout: 500
    },
    realpath: false
  }).catch(async (error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await ensureDirectory(filePath);
      return lockfile.lock(filePath, {
        retries: {
          retries: 5,
          factor: 1.5,
          minTimeout: 50,
          maxTimeout: 500
        },
        realpath: false
      });
    }
    throw error;
  });

  try {
    const tempPath = `${filePath}.tmp-${Date.now()}`;
    await writeFile(tempPath, JSON.stringify(data, null, 2), "utf-8");
    await rename(tempPath, filePath);
  } finally {
    await release();
  }
}
