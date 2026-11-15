#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Fake Telegram Bot API for the e2e rehearsal.
 *
 * Answers `POST /bot<token>/<method>` the way api.telegram.org does for the
 * methods the vault calls (sendMessage, answerCallbackQuery, editMessageText,
 * setWebhook, getWebhookInfo) and records each payload so the rehearsal can
 * play the owner: tap [Approve] (the inline keyboard's callback_data) or open
 * a card link.
 *
 * The bot token arrives in the URL path. It is compared with the expected one
 * and then dropped: it is never recorded, logged or printed.
 */
import { timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";

const MAX_BODY_BYTES = 256 * 1024;

function same(a, b) {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => reject(new Error("read_failed")));
  });
}

/** Approve / Deny callback_data of a recorded sendMessage payload, or null when it has no keyboard. */
export function approvalButtons(payload) {
  const rows = payload?.reply_markup?.inline_keyboard;
  if (!Array.isArray(rows)) return null;
  const buttons = rows.flat().filter((b) => b && typeof b.callback_data === "string");
  const approve = buttons.find((b) => b.text === "Approve");
  const deny = buttons.find((b) => b.text === "Deny");
  return approve ? { approve: approve.callback_data, deny: deny?.callback_data ?? null } : null;
}

/** The single-use card URL in a recorded sendMessage text, or null. */
export function cardLink(payload) {
  const text = typeof payload?.text === "string" ? payload.text : "";
  const m = /https?:\/\/[^\s]+\/card\/[A-Za-z0-9_-]{20,}/.exec(text);
  return m ? m[0] : null;
}

/**
 * Start the fake Bot API on 127.0.0.1.
 * @param {{ botToken: string, port?: number }} opts
 * Emits "message" with { message_id, method, payload } for every sendMessage.
 */
export async function startFakeTelegram(opts) {
  if (!opts || typeof opts.botToken !== "string" || !opts.botToken) throw new Error("fake telegram: botToken is required");
  const events = new EventEmitter();
  /** Every accepted call: { at, method, payload, message_id? }. Holds no bot token. */
  const calls = [];
  /** Calls refused before a payload was read: { at, reason }. */
  const rejected = [];
  let nextMessageId = 1000;
  let webhook = { url: "", has_custom_certificate: false, pending_update_count: 0 };

  const server = createServer(async (req, res) => {
    const send = (code, body) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    try {
      const path = (req.url ?? "").split("?", 1)[0];
      const m = /^\/bot([^/]+)\/([A-Za-z]+)$/.exec(path);
      if (!m) {
        rejected.push({ at: new Date().toISOString(), reason: "not_a_bot_api_path" });
        send(404, { ok: false, error_code: 404, description: "Not Found" });
        return;
      }
      const method = m[2];
      if (!same(decodeURIComponent(m[1]), opts.botToken)) {
        rejected.push({ at: new Date().toISOString(), reason: "bad_token", method });
        send(401, { ok: false, error_code: 401, description: "Unauthorized" });
        return;
      }
      let payload = {};
      if (req.method === "POST") {
        const raw = await readBody(req);
        try {
          payload = raw ? JSON.parse(raw) : {};
        } catch {
          rejected.push({ at: new Date().toISOString(), reason: "invalid_json", method });
          send(400, { ok: false, error_code: 400, description: "Bad Request" });
          return;
        }
      }
      const entry = { at: new Date().toISOString(), method, payload };
      let result = true;
      if (method === "sendMessage") {
        nextMessageId += 1;
        entry.message_id = nextMessageId;
        result = { message_id: nextMessageId, date: Math.floor(Date.now() / 1000), chat: { id: payload.chat_id, type: "private" }, text: payload.text };
      } else if (method === "editMessageText") {
        result = { message_id: payload.message_id, date: Math.floor(Date.now() / 1000), chat: { id: payload.chat_id, type: "private" }, text: payload.text };
      } else if (method === "setWebhook") {
        // Telegram never returns the secret_token; do not keep it either.
        const { secret_token: _dropped, ...rest } = payload;
        entry.payload = { ...rest, secret_token_present: typeof _dropped === "string" && _dropped.length > 0 };
        webhook = { ...webhook, url: String(payload.url ?? ""), allowed_updates: payload.allowed_updates };
      } else if (method === "getWebhookInfo") {
        result = webhook;
      }
      calls.push(entry);
      send(200, { ok: true, result });
      if (method === "sendMessage") events.emit("message", { message_id: entry.message_id, method, payload });
    } catch {
      send(500, { ok: false, error_code: 500, description: "Internal Server Error" });
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, "127.0.0.1", resolve);
  });
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    calls,
    rejected,
    on: (name, fn) => events.on(name, fn),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
