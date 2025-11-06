import fs from "fs";
import { dirname } from "path";
import { promisify } from "util";
import lockfile from "proper-lockfile";

const mkdir = promisify(fs.mkdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const rename = promisify(fs.rename);

async function ensureDirectory(filePath) {
  await mkdir(dirname(filePath), { recursive: true });
}

export async function readJsonFile(filePath, schema, defaultValue) {
  try {
    const content = await readFile(filePath, "utf-8");
    const json = JSON.parse(content);
    return schema.parse(json);
  } catch (error) {
    if (error.code === "ENOENT") {
      await ensureDirectory(filePath);
      await writeJsonFile(filePath, defaultValue);
      return defaultValue;
    }
    throw error;
  }
}

export async function writeJsonFile(filePath, data) {
  await ensureDirectory(filePath);
  const release = await lockfile
    .lock(filePath, {
      retries: {
        retries: 5,
        factor: 1.5,
        minTimeout: 50,
        maxTimeout: 500
      },
      realpath: false
    })
    .catch(async (error) => {
      if (error.code === "ENOENT") {
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
