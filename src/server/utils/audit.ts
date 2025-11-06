import { appendFile } from "fs/promises";
import { AUDIT_ENTRY_SCHEMA, type AuditEntry } from "@shared/validation/schemas";

const AUDIT_LOG_PATH = "data/audit.log";

export async function appendAudit(entry: AuditEntry): Promise<void> {
  const validated = AUDIT_ENTRY_SCHEMA.parse(entry);
  const line = `${validated.timestamp} | ${validated.user} | ${validated.action} | ${validated.target} | ${validated.details}`;
  await appendFile(AUDIT_LOG_PATH, `${line}\n`, "utf-8");
}
