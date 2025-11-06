import { randomBytes } from "crypto";
import { writeFile, mkdir } from "fs/promises";
import { join } from "path";
import dayjs from "dayjs";
import bcrypt from "bcryptjs";
import { v4 as uuid } from "uuid";
import {
  ADMIN_USERS_FILE,
  HISTORY_ROOT,
  STANDARD_USERS_FILE
} from "@server/utils/constants";
import {
  HISTORY_COLLECTION_SCHEMA,
  HISTORY_ENTRY_SCHEMA,
  type HistoryEntryRecord,
  type UserRecord,
  USER_COLLECTION_SCHEMA,
  USER_SCHEMA
} from "@shared/validation/schemas";
import { writeJsonFile, readJsonFile } from "@server/utils/fileStore";

async function loadUsers(): Promise<UserRecord[]> {
  const adminUsers = await readJsonFile<UserRecord[]>(
    ADMIN_USERS_FILE,
    USER_COLLECTION_SCHEMA,
    []
  );
  const standardUsers = await readJsonFile<UserRecord[]>(
    STANDARD_USERS_FILE,
    USER_COLLECTION_SCHEMA,
    []
  );
  return [...adminUsers, ...standardUsers];
}

async function saveUsers(users: UserRecord[]): Promise<void> {
  const admins = users.filter((user) => user.role === "admin");
  const regulars = users.filter((user) => user.role === "user");
  await writeJsonFile(ADMIN_USERS_FILE, admins);
  await writeJsonFile(STANDARD_USERS_FILE, regulars);
}

export async function findUser(username: string): Promise<UserRecord | undefined> {
  const users = await loadUsers();
  return users.find((user) => user.username === username);
}

export async function verifyUserCredentials(
  username: string,
  password: string
): Promise<UserRecord | null> {
  const user = await findUser(username);
  if (!user || !user.active) {
    return null;
  }
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return null;
  }
  const updated: UserRecord = {
    ...user,
    lastLoginAt: dayjs().toISOString(),
    updatedAt: dayjs().toISOString()
  };
  const users = await loadUsers();
  const updatedUsers = users.map((entry) => (entry.username === username ? updated : entry));
  await saveUsers(updatedUsers);
  return updated;
}

export async function createUser(
  user: Omit<UserRecord, "createdAt" | "updatedAt" | "passwordHash"> & { password: string }
): Promise<UserRecord> {
  const now = dayjs().toISOString();
  const passwordHash = await bcrypt.hash(user.password, 12);
  const record: UserRecord = USER_SCHEMA.parse({
    ...user,
    passwordHash,
    createdAt: now,
    updatedAt: now,
    passwordResetToken: undefined,
    lastLoginAt: undefined
  });
  const users = await loadUsers();
  if (users.some((existing) => existing.username === record.username)) {
    throw new Error("User already exists");
  }
  users.push(record);
  await saveUsers(users);
  return record;
}

export async function resetUserPassword(username: string): Promise<{ token: string; expiresAt: string }> {
  const users = await loadUsers();
  const target = users.find((user) => user.username === username);
  if (!target) {
    throw new Error("User not found");
  }
  const token = randomBytes(32).toString("hex");
  const expiresAt = dayjs().add(1, "day").toISOString();
  const updatedUsers = users.map((user) =>
    user.username === username
      ? {
          ...user,
          passwordResetToken: {
            token,
            expiresAt
          },
          updatedAt: dayjs().toISOString()
        }
      : user
  );
  await saveUsers(updatedUsers);
  return { token, expiresAt };
}

export async function updatePasswordWithToken(
  username: string,
  token: string,
  newPassword: string
): Promise<void> {
  const users = await loadUsers();
  const target = users.find((user) => user.username === username);
  if (!target || !target.passwordResetToken) {
    throw new Error("Invalid reset token");
  }
  if (target.passwordResetToken.token !== token || dayjs().isAfter(target.passwordResetToken.expiresAt)) {
    throw new Error("Reset token expired");
  }
  const passwordHash = await bcrypt.hash(newPassword, 12);
  const updatedUsers = users.map((user) =>
    user.username === username
      ? {
          ...user,
          passwordHash,
          passwordResetToken: undefined,
          updatedAt: dayjs().toISOString()
        }
      : user
  );
  await saveUsers(updatedUsers);
}

export async function deactivateUser(username: string): Promise<void> {
  const users = await loadUsers();
  const updatedUsers = users.map((user) =>
    user.username === username
      ? {
          ...user,
          active: false,
          updatedAt: dayjs().toISOString()
        }
      : user
  );
  await saveUsers(updatedUsers);
}

export async function recordHistoryEntry(username: string, entry: HistoryEntryRecord): Promise<void> {
  await mkdir(HISTORY_ROOT, { recursive: true });
  const historyFile = join(HISTORY_ROOT, `${username}.json`);
  const history = await readJsonFile(historyFile, HISTORY_COLLECTION_SCHEMA, []);
  const filtered = history.filter((item) => {
    if (item.type === "movie") {
      return !(item.contentId === entry.contentId && entry.type === "movie");
    }
    return !(
      item.contentId === entry.contentId &&
      entry.type === "series" &&
      item.season === entry.season &&
      item.episode === entry.episode
    );
  });
  filtered.unshift(HISTORY_ENTRY_SCHEMA.parse(entry));
  await writeJsonFile(historyFile, filtered.slice(0, 100));
}

export async function readHistory(username: string): Promise<HistoryEntryRecord[]> {
  await mkdir(HISTORY_ROOT, { recursive: true });
  const historyFile = join(HISTORY_ROOT, `${username}.json`);
  return readJsonFile(historyFile, HISTORY_COLLECTION_SCHEMA, []);
}

export async function upsertViewToken(userId: string): Promise<string> {
  const token = uuid();
  await writeFile(join(HISTORY_ROOT, `${userId}.view`), token, "utf-8");
  return token;
}

export async function listUsers(): Promise<UserRecord[]> {
  return loadUsers();
}

export async function saveUsersSnapshot(users: UserRecord[]): Promise<void> {
  await saveUsers(users);
}
