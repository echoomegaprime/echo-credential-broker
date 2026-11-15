// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Minimal Telegram Bot API client + webhook handler for vault approvals.
 *
 * Grounded in https://core.telegram.org/bots/api (checked 2026-11-14):
 *   - Requests: POST https://api.telegram.org/bot<token>/METHOD_NAME, JSON body;
 *     the response is a JSON object with Boolean `ok`, `result` on success and
 *     optional `description` / `error_code` on failure.
 *   - sendMessage: chat_id, text (1-4096 chars after entity parsing),
 *     link_preview_options {is_disabled}, reply_markup InlineKeyboardMarkup
 *     {inline_keyboard: InlineKeyboardButton[][]}; button {text, callback_data
 *     (1-64 bytes)}. No parse_mode is sent, so text renders literally.
 *   - answerCallbackQuery: callback_query_id, text (0-200 chars). Clients show
 *     a progress indicator until it is called.
 *   - editMessageText: chat_id + message_id (required when inline_message_id
 *     is absent), text (1-4096). The keyboard is not re-sent, so it is removed.
 *   - setWebhook: url, allowed_updates, drop_pending_updates, secret_token
 *     (1-256 chars of A-Z a-z 0-9 _ -), echoed on every webhook request in the
 *     `X-Telegram-Bot-Api-Secret-Token` header. Telegram retries non-2XX
 *     webhook responses, so valid-secret requests always get 200.
 *   - Update.callback_query → CallbackQuery {id, from: User, message?:
 *     MaybeInaccessibleMessage {chat, message_id}, inline_message_id?, data?}.
 *     User/Chat IDs have at most 52 significant bits (exact in a JS number).
 *
 * The bot token is part of the URL, so: it is registered for redaction on
 * every read, the URL is never put in an error or log line, upstream error
 * text (fetch errors, Telegram `description`) is never propagated, and errors
 * carry only a fixed code such as "telegram_http_401".
 */
import { log } from "../log.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import type { ApprovalRecord } from "./contracts.ts";
import {
  approverTelegramId,
  constantTimeEqual,
  decideApproval,
  parseCallbackData,
  sanitizeDisplayText,
} from "./approvals.ts";
import type { ApprovalOptions, DecideResult } from "./approvals.ts";

const API_BASE = "https://api.telegram.org";
const REQUEST_TIMEOUT_MS = 8000;
const MAX_TEXT = 4096;
const MAX_CALLBACK_ANSWER = 200;
const MAX_WEBHOOK_BODY_BYTES = 256 * 1024;
const MIN_WEBHOOK_SECRET_LENGTH = 16;
const WEBHOOK_SECRET_PATTERN = /^[A-Za-z0-9_-]{16,256}$/;

export interface TelegramDeps {
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
}

/** Sanitized Telegram failure. `code` is one of a fixed set; no upstream text. */
export class TelegramApiError extends Error {
  readonly code: string;
  readonly method: string;
  constructor(method: string, code: string) {
    super(`Telegram ${method} failed (${code})`);
    this.name = "TelegramApiError";
    this.code = code;
    this.method = method;
  }
}

function readBotToken(env: NodeJS.ProcessEnv): string {
  const token = env.TELEGRAM_BOT_TOKEN?.trim();
  // Bot API tokens look like "<bot id>:<secret>"; reject anything that could
  // reshape the URL path.
  if (!token || !/^[0-9]{1,20}:[A-Za-z0-9_-]{20,200}$/.test(token)) {
    throw new TelegramApiError("config", "telegram_bot_token_missing");
  }
  registerSecretForRedaction(token);
  return token;
}

/** POST one Bot API method. Never surfaces the URL, the token, or upstream text. */
export async function callBotApi<T = unknown>(
  method: string,
  payload: Record<string, unknown>,
  deps: TelegramDeps = {},
): Promise<T> {
  if (!/^[A-Za-z]+$/.test(method)) throw new TelegramApiError("config", "telegram_bad_method");
  const token = readBotToken(deps.env ?? process.env);
  const doFetch = deps.fetch ?? globalThis.fetch;
  let res: Response;
  try {
    res = await doFetch(`${API_BASE}/bot${token}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    // Deliberately drop the error: undici/URL errors can embed the full URL.
    throw new TelegramApiError(method, "telegram_network_error");
  }
  type BotApiResponse = { ok?: unknown; result?: unknown; error_code?: unknown };
  let body: BotApiResponse | null;
  try {
    body = (await res.json()) as BotApiResponse | null;
  } catch {
    body = null;
  }
  if (!res.ok || !body || body.ok !== true) {
    const code = typeof body?.error_code === "number" ? body.error_code : res.status;
    throw new TelegramApiError(method, `telegram_http_${Number.isInteger(code) ? code : 0}`);
  }
  return body.result as T;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** The approval prompt. Plain text only (no parse_mode); every field sanitized. */
export function formatApprovalText(record: ApprovalRecord, clientName?: string): string {
  const clientId = sanitizeDisplayText(record.client_id, 120);
  const name = clientName ? sanitizeDisplayText(clientName, 80) : "";
  const lines = [
    "ECHO Vault approval request",
    "",
    `Client: ${name ? `${name} (${clientId})` : clientId}`,
    `Action: ${sanitizeDisplayText(record.capability, 128)}`,
    `Resource: ${sanitizeDisplayText(record.resource, 300)}`,
    `Summary: ${record.summary ? sanitizeDisplayText(record.summary) : "(none)"}`,
    `Expires: ${record.expires_at}`,
    `Ref: ${record.id.slice(0, 8)} / ${record.request_digest.slice(0, 12)}`,
  ];
  return clip(lines.join("\n"), MAX_TEXT);
}

/** Send the [Approve] [Deny] prompt to the approver's private chat. */
export async function sendApprovalRequest(
  input: { record: ApprovalRecord; clientName: string; approveData: string; denyData: string },
  deps: TelegramDeps = {},
): Promise<{ message_id: number }> {
  const chatId = approverTelegramId(deps.env ?? process.env);
  if (!chatId) throw new TelegramApiError("sendMessage", "telegram_approver_missing");
  for (const data of [input.approveData, input.denyData]) {
    const bytes = Buffer.byteLength(data, "utf8");
    if (bytes < 1 || bytes > 64) throw new TelegramApiError("sendMessage", "telegram_callback_data_too_long");
  }
  const result = await callBotApi<{ message_id?: unknown }>(
    "sendMessage",
    {
      chat_id: chatId,
      text: formatApprovalText(input.record, input.clientName),
      link_preview_options: { is_disabled: true },
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Approve", callback_data: input.approveData },
            { text: "Deny", callback_data: input.denyData },
          ],
        ],
      },
    },
    deps,
  );
  return { message_id: typeof result?.message_id === "number" ? result.message_id : 0 };
}

export async function answerCallbackQuery(
  callbackQueryId: string,
  text: string,
  deps: TelegramDeps = {},
): Promise<void> {
  await callBotApi(
    "answerCallbackQuery",
    { callback_query_id: callbackQueryId, text: clip(text, MAX_CALLBACK_ANSWER) },
    deps,
  );
}

export async function editMessageText(
  chatId: number | string,
  messageId: number,
  text: string,
  deps: TelegramDeps = {},
): Promise<void> {
  await callBotApi(
    "editMessageText",
    {
      chat_id: chatId,
      message_id: messageId,
      text: clip(text, MAX_TEXT),
      link_preview_options: { is_disabled: true },
    },
    deps,
  );
}

/** Operator helper: point the bot at the webhook with the shared secret, callback queries only. */
export async function setTelegramWebhook(url: string, deps: TelegramDeps = {}): Promise<void> {
  const secret = readWebhookSecret(deps.env ?? process.env);
  if (!secret) throw new TelegramApiError("setWebhook", "telegram_webhook_secret_missing");
  if (!/^https:\/\//.test(url)) throw new TelegramApiError("setWebhook", "telegram_webhook_url_not_https");
  await callBotApi(
    "setWebhook",
    { url, secret_token: secret, allowed_updates: ["callback_query"], drop_pending_updates: true },
    deps,
  );
}

// ------------------------------------------------------------------ webhook

function readWebhookSecret(env: NodeJS.ProcessEnv): string | null {
  const raw = env.ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET;
  if (!raw || raw.length < MIN_WEBHOOK_SECRET_LENGTH || !WEBHOOK_SECRET_PATTERN.test(raw)) return null;
  registerSecretForRedaction(raw);
  return raw;
}

export type WebhookOptions = ApprovalOptions;

const OK_HEADERS = { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" };

function okResponse(): Response {
  return new Response("ok", { status: 200, headers: OK_HEADERS });
}

function outcomeText(record: ApprovalRecord | undefined, outcome: string): string {
  if (!record) return outcome;
  return clip(`${formatApprovalText(record)}\n\n${outcome}`, MAX_TEXT);
}

interface CallbackQueryLike {
  id?: unknown;
  from?: { id?: unknown };
  data?: unknown;
  message?: { message_id?: unknown; chat?: { id?: unknown } };
}

/**
 * Telegram webhook entry point. 401 without the right secret header (fail
 * closed when the secret is unset); every authenticated request gets 200 so
 * Telegram does not retry, with rejections logged by reason only.
 */
export async function handleTelegramWebhook(request: Request, opts: WebhookOptions = {}): Promise<Response> {
  const env = opts.env ?? process.env;
  const expected = readWebhookSecret(env);
  const provided = request.headers.get("x-telegram-bot-api-secret-token") ?? "";
  if (!expected) {
    log.error("telegram_webhook_rejected", { reason: "webhook_secret_not_configured" });
    return new Response("unauthorized", { status: 401, headers: OK_HEADERS });
  }
  if (!constantTimeEqual(provided, expected)) {
    log.warn("telegram_webhook_rejected", { reason: "bad_secret" });
    return new Response("unauthorized", { status: 401, headers: OK_HEADERS });
  }
  if (request.method !== "POST") return okResponse();

  const deps: TelegramDeps = { fetch: opts.fetch, env };
  try {
    const declared = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > MAX_WEBHOOK_BODY_BYTES) {
      log.warn("telegram_webhook_ignored", { reason: "body_too_large" });
      return okResponse();
    }
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_WEBHOOK_BODY_BYTES) {
      log.warn("telegram_webhook_ignored", { reason: "body_too_large" });
      return okResponse();
    }
    type UpdateLike = { callback_query?: CallbackQueryLike };
    let update: UpdateLike | null;
    try {
      update = JSON.parse(raw) as UpdateLike | null;
    } catch {
      log.warn("telegram_webhook_ignored", { reason: "invalid_json" });
      return okResponse();
    }
    const cq = update?.callback_query;
    if (!cq || typeof cq !== "object" || typeof cq.id !== "string") {
      log.debug("telegram_webhook_ignored", { reason: "not_a_callback_query" });
      return okResponse();
    }

    const parsed = parseCallbackData(cq.data);
    const fromId =
      typeof cq.from?.id === "number" && Number.isSafeInteger(cq.from.id) ? String(cq.from.id) : "";
    let result: DecideResult;
    if (!parsed) {
      log.warn("telegram_webhook_rejected", { reason: "bad_callback_data" });
      result = { ok: false, reason: "bad_mac" };
    } else {
      result = await decideApproval(parsed.id, parsed.action, fromId, parsed.mac, opts);
    }

    let answer: string;
    let edit: string | null = null;
    const when = new Date((opts.now ?? Date.now)()).toISOString();
    if (result.ok) {
      answer = result.status === "approved" ? "Approved" : "Denied";
      edit = outcomeText(
        result.record,
        result.status === "approved" ? `Approved by you at ${when}` : `Denied by you at ${when}`,
      );
    } else if (result.reason === "expired") {
      answer = "Expired";
      edit = outcomeText(result.record, "Expired");
    } else if (result.reason === "not_pending") {
      answer = "Already decided";
    } else {
      // unauthorized user, bad MAC, unknown id, misconfiguration: no state change, no edit.
      answer = "Not permitted";
    }

    await answerCallbackQuery(cq.id, answer, deps).catch((err: unknown) => {
      log.warn("telegram_answer_failed", { code: err instanceof TelegramApiError ? err.code : "unknown" });
    });

    const chatId = cq.message?.chat?.id;
    const messageId = cq.message?.message_id;
    if (edit && (typeof chatId === "number" || typeof chatId === "string") && typeof messageId === "number") {
      await editMessageText(chatId, messageId, edit, deps).catch((err: unknown) => {
        log.warn("telegram_edit_failed", { code: err instanceof TelegramApiError ? err.code : "unknown" });
      });
    }
  } catch (err) {
    log.error("telegram_webhook_error", {
      code: err instanceof TelegramApiError ? err.code : err instanceof Error ? err.name : "unknown",
    });
  }
  return okResponse();
}
