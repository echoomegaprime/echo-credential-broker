#!/usr/bin/env node
/**
 * Stdio MCP adapter for Echo Vault.
 * stdout is protocol only. Secrets never print.
 */
import { handleMcpRequest } from "../src/lib/vault/mcp.ts";
import { ensureImported } from "../src/lib/vault/importer.ts";
import { installProcessRedaction, redactString } from "../src/lib/vault/redaction.ts";

installProcessRedaction();

const caller = (
  process.env.ECHO_AGENT ||
  process.env.X_ECHO_AGENT ||
  process.env.X_ECHO_CALLER ||
  "claude"
)
  .trim()
  .toLowerCase();

function writeMessage(payload: unknown): void {
  const json = JSON.stringify(payload);
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
      const result = await handleMcpRequest(message, caller);
      if (
        req.id === undefined &&
        method.startsWith("notifications/")
      ) {
        continue;
      }
      writeMessage(result);
    }
  });
});

process.stdin.on("end", () => process.exit(0));
process.stderr.write(
  redactString(`echo-credential-broker stdio mcp ready caller=${caller}\n`),
);
