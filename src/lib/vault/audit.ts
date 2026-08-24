import { randomUUID } from "node:crypto";
import { redactString, redactValue } from "./redaction.ts";
import type { AuditRecord } from "./types.ts";

const MAX_RECORDS = 500;
const records: AuditRecord[] = [];

export function recordAudit(
  entry: Omit<AuditRecord, "id" | "timestamp">,
): AuditRecord {
  const rec: AuditRecord = redactValue({
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry,
    error: entry.error ? redactString(entry.error) : undefined,
  });
  records.unshift(rec);
  if (records.length > MAX_RECORDS) records.length = MAX_RECORDS;
  return rec;
}

export function listAudit(limit = 100): AuditRecord[] {
  return records.slice(0, limit).map((r) => ({ ...r }));
}

export function clearAuditForTests(): void {
  records.length = 0;
}
