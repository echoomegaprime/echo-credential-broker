#!/usr/bin/env node
/**
 * Stdio MCP adapter for Echo Vault.
 * stdout is protocol only. Secrets never print.
 */
import { handleMcpRequest } from "../src/lib/vault/mcp.ts";
import { ensureImported } from "../src/lib/vault/importer.ts";
import { installProcessRedaction, redactString } from "../src/lib/vault/redaction.ts";
import { ensureV2Configured } from "../src/lib/vault/v2/bootstrap.ts";
import { localIdentity } from "../src/lib/vault/v2/identity.ts";

installProcessRedaction();
ensureV2Configured();

/**
 * Trust = the OS process boundary (see v2/identity.ts). ECHO_AGENT only names
 * this local client in the ledger ("local:<name>"); it grants nothing. Scopes
 * come from ECHO_VAULT_LOCAL_SCOPES and default to read-only.
 */
let identity: ReturnType<typeof localIdentity>;
try {
  identity = localIdentity(process.env.ECHO_AGENT || "local");
} catch {
  process.stderr.write("echo-credential-broker: ECHO_AGENT must be a short lowercase name (a-z, 0-9, . _ -)\n");
  process.exit(2);
}

/** Reply in the framing the client uses: MCP stdio is newline-delimited JSON; Content-Length framing is kept for older clients. */
let framing: "ndjson" | "content-length" = "ndjson";

function writeMessage(payload: unknown): void {
  const json = JSON.stringify(payload);
  if (framing === "ndjson") {
    process.stdout.write(`${json}\n`);
    return;
  }
  const body = Buffer.from(json, "utf8");
  const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8");
  process.stdout.write(Buffer.concat([header, body]));
}

function parseMessages(buffer: Buffer): { messages: unknown[]; rest: Buffer } {
  const messages: unknown[] = [];
  let rest = buffer;
  while (rest.length > 0) {
    const headerEnd = rest.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      const asText = rest.toString("utf8");
      if (asText.startsWith("{")) {
        framing = "ndjson";
        const nl = rest.indexOf("\n");
        if (nl === -1) break;
        const line = rest.subarray(0, nl).toString("utf8").trim();
        rest = rest.subarray(nl + 1);
        if (!line) continue;
        try {
          messages.push(JSON.parse(line));
        } catch {
          /* wait for more */
          rest = Buffer.concat([Buffer.from(line + "\n"), rest]);
          break;
        }
        continue;
      }
      break;
    }
    const header = rest.subarray(0, headerEnd).toString("utf8");
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (match) framing = "content-length";
    if (!match) {
      rest = rest.subarray(headerEnd + 4);
      continue;
    }
    const length = Number(match[1]);
    const start = headerEnd + 4;
    if (rest.length < start + length) break;
    const json = rest.subarray(start, start + length).toString("utf8");
    rest = rest.subarray(start + length);
    try {
      messages.push(JSON.parse(json));
    } catch {
      process.stderr.write(redactString("mcp-stdio: invalid json\n"));
    }
  }
  return { messages, rest };
}

let buf = Buffer.alloc(0);
let ready: Promise<void> = ensureImported().then(() => undefined);

process.stdin.on("data", (chunk: Buffer) => {
  buf = Buffer.concat([buf, chunk]);
  const parsed = parseMessages(buf);
  buf = parsed.rest;
  ready = ready.then(async () => {
    for (const message of parsed.messages) {
      const req = (message ?? {}) as {
        jsonrpc?: string;
        id?: string | number | null;
        method?: string;
      };
      const method = String(req.method ?? "");
      if (method.startsWith("notifications/") && (req.id === undefined || req.id === null)) {
        continue;
      }
      if (method === "ping") {
        writeMessage({ jsonrpc: "2.0", id: req.id ?? null, result: {} });
        continue;
      }
      const result = await handleMcpRequest(message, identity);
      if (result === null) continue;
      writeMessage(result);
    }
  });
});

process.stdin.on("end", () => {
  // Flush the embedded database (if one was opened) before exiting.
  void ready
    .then(async () => {
      const { closeDb } = await import("../src/lib/db.ts");
      await closeDb();
    })
    .catch(() => undefined)
    .finally(() => process.exit(0));
});
if (!process.env.ECHO_SDK_API_KEY) {
  process.stderr.write(
    "echo-credential-broker WARNING: ECHO_SDK_API_KEY is not set — every vault tool call will fail closed (credential_unavailable) until it is configured.\n",
  );
}
process.stderr.write(
  redactString(`echo-credential-broker stdio mcp ready client=${identity.client_id} scopes=${identity.scopes.join(",") || "(none)"}\n`),
);
