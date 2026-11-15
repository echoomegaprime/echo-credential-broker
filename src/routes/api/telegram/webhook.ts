// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * Telegram Bot API webhook for vault v2 approvals. Authenticated by the
 * X-Telegram-Bot-Api-Secret-Token header (setWebhook secret_token); all logic
 * — secret check, decision, answerCallbackQuery, message edit — lives in
 * handleTelegramWebhook. No secret ever appears in the response.
 */
export const Route = createFileRoute("/api/telegram/webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleTelegramWebhook } = await import("@/lib/vault/v2/telegram.ts");
        return handleTelegramWebhook(request);
      },
    },
  },
});
