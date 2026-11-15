// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * REHEARSAL ONLY. Loaded into the vault server process with
 * `NODE_OPTIONS=--import=<this file>` by scripts/e2e/rehearsal.mjs.
 *
 * It wraps `globalThis.fetch` so that requests to `https://api.telegram.org/`
 * (and nothing else) go to the local fake Bot API named by
 * `ECHO_E2E_FAKE_TELEGRAM_URL`. Nothing under src/ is changed or aware of it:
 * the server still builds the real api.telegram.org URL and calls fetch.
 *
 * Guard rails:
 *   - It does nothing unless ECHO_E2E_FAKE_TELEGRAM_URL is set, and refuses to
 *     start the process when that value is not an http://127.0.0.1:<port> origin,
 *     so it cannot be used to send a real bot token to another host.
 *   - Only the origin is swapped. Path, method, headers and body are untouched.
 *   - It logs nothing: the Bot API URL contains the bot token.
 *
 * Never put this file in NODE_OPTIONS on a real host. With it loaded the owner
 * receives no Telegram message at all.
 */
const TELEGRAM_ORIGIN = "https://api.telegram.org";
const target = process.env.ECHO_E2E_FAKE_TELEGRAM_URL;

if (target) {
  let origin;
  try {
    const url = new URL(target);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.pathname !== "/" || url.search || url.username) {
      throw new Error("not loopback");
    }
    origin = url.origin;
  } catch {
    // Fixed message: never echo the value.
    console.error("[e2e telegram-preload] ECHO_E2E_FAKE_TELEGRAM_URL must be http://127.0.0.1:<port>; refusing to start.");
    process.exit(78);
  }

  const realFetch = globalThis.fetch;
  const marker = Symbol.for("echo.e2e.telegramPreload");
  if (!globalThis[marker]) {
    globalThis[marker] = true;
    globalThis.fetch = function e2eTelegramFetch(input, init) {
      const href = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url;
      if (typeof href === "string" && href.startsWith(`${TELEGRAM_ORIGIN}/`)) {
        const rewritten = origin + href.slice(TELEGRAM_ORIGIN.length);
        if (typeof input === "string" || input instanceof URL) return realFetch.call(globalThis, rewritten, init);
        return realFetch.call(globalThis, new Request(rewritten, input), init);
      }
      return realFetch.call(globalThis, input, init);
    };
  }
}
