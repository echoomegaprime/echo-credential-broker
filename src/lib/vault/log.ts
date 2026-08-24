/**
 * Structured, secret-safe logging for the vault layer. Every line is one JSON
 * object on stderr — never stdout, which the stdio MCP transport owns for
 * protocol frames. Values pass through `redactString` first, so a secret that
 * accidentally lands in a log field is caught by the same redaction armed
 * everywhere else in this broker, not a second, weaker copy of that logic.
 */
import { redactString } from "./redaction.ts";

type Level = "debug" | "info" | "warn" | "error";

function emit(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  const safeFields: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    safeFields[k] = typeof v === "string" ? redactString(v) : v;
  }
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    component: "echo-credential-broker",
    event,
    ...safeFields,
  });
  process.stderr.write(line + "\n");
}

export const log = {
  debug: (event: string, fields?: Record<string, unknown>) => {
    if (process.env.ECHO_VAULT_DEBUG === "1") emit("debug", event, fields);
  },
  info: (event: string, fields?: Record<string, unknown>) => emit("info", event, fields),
  warn: (event: string, fields?: Record<string, unknown>) => emit("warn", event, fields),
  error: (event: string, fields?: Record<string, unknown>) => emit("error", event, fields),
};
