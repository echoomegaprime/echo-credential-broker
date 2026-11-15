// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import type { ClientIdentity } from "./contracts.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { escapeHtml, handleCardRequest, MAX_CARD_BODY_BYTES, sameOriginPost } from "./card-pages.ts";
import { getCardStatus, listEntries, MemoryCardStore, MemoryEntryStore, requestCard } from "./cards.ts";
import type { CardsDeps, RequestCardInput } from "./cards.ts";

const ORIGIN = "https://vault.example.test";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: "424242",
  ECHO_VAULT_PUBLIC_URL: ORIGIN,
};
const SECRET = "page-test secret/with+odd&chars=1 <b>";
const XSS = `"><script>alert(1)</script><img src=x onerror='alert(2)'>`;
const CLIENT: ClientIdentity = { client_id: "oc_claude_test", name: "Claude", kind: "oauth", scopes: [] };

function makeWorld() {
  const texts: string[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    texts.push(String(JSON.parse(String(init?.body ?? "{}")).text ?? ""));
    return new Response(JSON.stringify({ ok: true, result: { message_id: 1 } }), { status: 200 });
  }) as typeof fetch;
  const entries = new MemoryEntryStore();
  const cards = new MemoryCardStore();
  const backend = new FakeVaultBackend();
  const ledger = new Ledger({ store: new MemoryLedgerStore() });
  const clock = { t: Date.parse("2026-11-14T12:00:00.000Z") };
  const deps: CardsDeps = {
    entries,
    cards,
    backend,
    ledger: (input) => ledger.append(input),
    fetch: fetchImpl,
    env: ENV,
    now: () => clock.t,
  };
  const card = async (over: Partial<RequestCardInput> = {}) => {
    const receipt = await requestCard(
      { client: CLIENT, site: "github.com", account: "bobmcw", purpose: "personal", kind: "password", reason: "page test", ...over },
      deps,
    );
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(texts[texts.length - 1])![1];
    return { receipt, token };
  };
  return { deps, entries, cards, backend, ledger, clock, card };
}

function get(token: string): Request {
  return new Request(`${ORIGIN}/card/${token}`, { method: "GET" });
}

function post(token: string, fields: Record<string, string>, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}/card/${token}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin", ...headers },
    body: new URLSearchParams(fields).toString(),
  });
}

/** Silence + capture structured logs for the duration of fn. */
async function withLogs<T>(fn: () => Promise<T>): Promise<{ value: T; logs: string }> {
  const chunks: string[] = [];
  const orig = process.stderr.write;
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    return { value: await fn(), logs: chunks.join("") };
  } finally {
    process.stderr.write = orig;
  }
}

function assertSecureHeaders(res: Response, form: boolean): void {
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(res.headers.get("content-type") ?? "", /^text\/html; charset=utf-8$/);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, form ? /form-action 'self'/ : /form-action 'none'/);
  assert.ok(!/script-src|unsafe-inline|unsafe-eval|\*/.test(csp), "no script source, no unsafe-*, no wildcard");
  assert.match(csp, /style-src 'sha256-[A-Za-z0-9+/]{43}='(;|$)/);
}

describe("vault v2 card pages", () => {
  it("GET renders a minimal, script-free form under a strict CSP and never consumes the token", async () => {
    const w = makeWorld();
    const { token, receipt } = await w.card();
    const res = await handleCardRequest(get(token), token, w.deps);
    const html = await res.text();

    assert.equal(res.status, 200);
    assertSecureHeaders(res, true);
    // The only inline style is exactly the one the CSP hashes.
    const styles = [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => m[1]);
    assert.equal(styles.length, 1);
    const hash = createHash("sha256").update(styles[0], "utf8").digest("base64");
    assert.ok((res.headers.get("content-security-policy") ?? "").includes(`'sha256-${hash}'`));
    assert.ok(!/<script|javascript:|\son[a-z]+\s*=|style=|<link|<img|<iframe/i.test(html), "no script, handlers, inline style attrs or external resources");

    assert.match(html, /<form method="post" autocomplete="off">/);
    assert.ok(!/<form[^>]*action=/.test(html), "form posts to its own URL");
    assert.match(html, /<input id="f-secret" name="secret" type="password" autocomplete="off"[^>]* required>/);
    assert.ok(!/name="secret"[^>]*value=/.test(html), "secret field is never prefilled");
    assert.match(html, /name="site" type="text" value="github.com"/);
    assert.match(html, /name="account" type="text" value="bobmcw"/);
    assert.match(html, /name="purpose" type="text" value="personal"/);
    assert.equal([...html.matchAll(/<input /g)].length, 4);
    assert.ok(!html.includes(token), "the token is not in the page");
    assert.ok(!html.includes(receipt.card_id));

    // Repeated GETs (link scanners, reloads) do not burn the card.
    assert.equal((await handleCardRequest(get(token), token, w.deps)).status, 200);
    assert.equal((await handleCardRequest(new Request(`${ORIGIN}/card/${token}`, { method: "HEAD" }), token, w.deps)).status, 200);
    assert.equal((await getCardStatus(receipt.card_id, w.deps)).status, "pending");

    // Account/purpose not supplied by the agent → empty, editable.
    const open = await w.card({ account: undefined, purpose: undefined, site: "gitlab.com" });
    const openHtml = await (await handleCardRequest(get(open.token), open.token, w.deps)).text();
    assert.match(openHtml, /name="account" type="text" value=""/);
    assert.match(openHtml, /name="purpose" type="text" value="general"/);
  });

  it("HTML-escapes every agent-supplied value", async () => {
    const w = makeWorld();
    const { token } = await w.card({ client: { ...CLIENT, name: XSS, client_id: `oc_${XSS}` }, reason: XSS, account: `a${XSS.replace(/\s/g, "")}` });
    const res = await handleCardRequest(get(token), token, w.deps);
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.ok(!html.includes("<script>"), "no raw script tag");
    assert.ok(!html.includes("<img"), "no raw img tag");
    assert.ok(!/onerror='/.test(html), "no raw attribute breakout");
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(html.includes("&quot;&gt;&lt;script&gt;"));
    // Exactly the tags this module emits — nothing injected.
    const tags = new Set([...html.matchAll(/<\/?([a-z0-9]+)/gi)].map((m) => m[1].toLowerCase()));
    for (const tag of tags) {
      assert.ok(
        ["html", "head", "meta", "title", "style", "body", "main", "h1", "p", "dl", "dt", "dd", "form", "label", "input", "button"].includes(tag),
        `unexpected tag <${tag}>`,
      );
    }
    assert.equal(escapeHtml(`<a href="x" onclick='y'>&\``), "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;");
    assert.equal(escapeHtml(null), "");
  });

  it("POST stores the secret through the vault backend and shows a success page that does not echo it", async () => {
    const w = makeWorld();
    const { token, receipt } = await w.card();
    const { value: res, logs } = await withLogs(() =>
      handleCardRequest(post(token, { site: "GitHub.com", account: "bobmcw", purpose: "personal", secret: SECRET }), token, w.deps),
    );
    const html = await res.text();
    assert.equal(res.status, 200);
    assertSecureHeaders(res, false);
    assert.match(html, /Stored in vault/);
    assert.ok(html.includes("github.com — bobmcw — personal"));

    const [entry] = await listEntries({}, w.deps);
    assert.equal((await w.backend.get(`echo_vault_entry_${entry.id}`, "entry", "t")).secret, SECRET);
    for (const text of [html, logs, JSON.stringify([...res.headers]), JSON.stringify(w.entries.dumpForTests()), JSON.stringify(w.cards.dumpForTests())]) {
      assert.ok(!text.includes(SECRET), "raw secret echoed");
      assert.ok(!text.includes(escapeHtml(SECRET)), "escaped secret echoed");
      assert.ok(!text.includes(encodeURIComponent(SECRET)), "url-encoded secret echoed");
      assert.ok(!text.includes(token), "token echoed");
    }
    assert.match(logs, /vault_card_completed/);

    const status = await getCardStatus(receipt.card_id, w.deps);
    assert.equal(status.status, "completed");
    assert.equal(status.entry_id, entry.id);
    const created = await w.ledger.list({ capability: "vault.entry.create" });
    assert.equal(created.length, 1);
    assert.equal(created[0].client_id, "oc_claude_test");
    assert.equal(created[0].resource, "entry:github.com/bobmcw");
    assert.ok(!JSON.stringify(await w.ledger.list()).includes(SECRET));

    // Single use: replaying the POST or reloading the page is refused.
    const { value: replay } = await withLogs(() => handleCardRequest(post(token, { secret: "another-secret-value" }), token, w.deps));
    assert.equal(replay.status, 410);
    assertSecureHeaders(replay, false);
    assert.equal((await handleCardRequest(get(token), token, w.deps)).status, 410);
    assert.equal((await listEntries({}, w.deps)).length, 1);
    assert.equal((await w.backend.get(`echo_vault_entry_${entry.id}`, "entry", "t")).secret, SECRET);
  });

  it("rejects a POST without a valid token and stores nothing", async () => {
    const w = makeWorld();
    const { token } = await w.card();
    const flipped = (token[0] === "A" ? "B" : "A") + token.slice(1);
    const { logs } = await withLogs(async () => {
      for (const bad of [undefined, "", "nope", "x".repeat(43), flipped, `${token}/../x`]) {
        const res = await handleCardRequest(post(bad ?? "", { account: "bobmcw", secret: SECRET }), bad, w.deps);
        const html = await res.text();
        assert.equal(res.status, 404, `token ${String(bad).slice(0, 6)}…`);
        assertSecureHeaders(res, false);
        assert.ok(!html.includes("<form"));
        assert.ok(!html.includes(SECRET));
        assert.equal((await handleCardRequest(get(bad ?? ""), bad, w.deps)).status, 404);
      }
      // Expired token.
      w.clock.t += 30 * 60 * 1000;
      const late = await handleCardRequest(post(token, { account: "bobmcw", secret: SECRET }), token, w.deps);
      assert.equal(late.status, 410);
      assert.equal((await handleCardRequest(get(token), token, w.deps)).status, 410);
    });
    assert.ok(!logs.includes(SECRET) && !logs.includes(token));
    assert.equal((await listEntries({}, w.deps)).length, 0);
    assert.equal(w.entries.dumpForTests().length, 0);
  });

  it("enforces same-origin, form encoding, size limit and method on POST", async () => {
    const w = makeWorld();
    const { token } = await w.card();
    const fields = { account: "bobmcw", secret: SECRET };
    const { logs } = await withLogs(async () => {
      for (const headers of [
        { origin: "https://evil.example", "sec-fetch-site": "cross-site" },
        { origin: "https://evil.example", "sec-fetch-site": "same-origin" },
        { origin: ORIGIN, "sec-fetch-site": "same-site" },
        { origin: ORIGIN, "sec-fetch-site": "none" },
      ]) {
        const res = await handleCardRequest(post(token, fields, headers), token, w.deps);
        assert.equal(res.status, 403, JSON.stringify(headers));
        assertSecureHeaders(res, false);
      }
      // Origin: null is what a no-referrer page sends; without fetch metadata it proves nothing.
      const bare = new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null" },
        body: new URLSearchParams(fields).toString(),
      });
      assert.equal((await handleCardRequest(bare, token, w.deps)).status, 403);

      const json = new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/json", "sec-fetch-site": "same-origin" },
        body: JSON.stringify(fields),
      });
      assert.equal((await handleCardRequest(json, token, w.deps)).status, 415);

      const huge = post(token, { account: "bobmcw", secret: "s".repeat(MAX_CARD_BODY_BYTES) });
      assert.equal((await handleCardRequest(huge, token, w.deps)).status, 413);
      // A lying content-length does not get an oversized body buffered either.
      const lying = new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "same-origin" },
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(`secret=${"s".repeat(MAX_CARD_BODY_BYTES)}`));
            controller.close();
          },
        }),
        duplex: "half",
      } as RequestInit);
      assert.equal((await handleCardRequest(lying, token, w.deps)).status, 413);

      const del = await handleCardRequest(new Request(`${ORIGIN}/card/${token}`, { method: "DELETE" }), token, w.deps);
      assert.equal(del.status, 405);
      assert.equal(del.headers.get("allow"), "GET, HEAD, POST");
    });
    assert.ok(!logs.includes(SECRET));
    assert.equal((await listEntries({}, w.deps)).length, 0, "none of the refused requests stored anything");

    // The card survived all of that; a proper same-origin POST still works. Both header shapes are accepted.
    const ok = await withLogs(() => handleCardRequest(post(token, fields, { origin: ORIGIN }), token, w.deps));
    assert.equal(ok.value.status, 200);

    const req = (h: Record<string, string>) => new Request(`http://internal:8080/card/x`, { method: "POST", headers: h });
    assert.equal(sameOriginPost(req({}), ENV), true, "non-browser client without either header");
    assert.equal(sameOriginPost(req({ origin: ORIGIN }), ENV), true, "public origin behind a proxy");
    assert.equal(sameOriginPost(req({ origin: "http://internal:8080" }), ENV), true);
    assert.equal(sameOriginPost(req({ origin: "https://vault.example.test.evil.io" }), ENV), false);
    assert.equal(sameOriginPost(req({ origin: "null", "sec-fetch-site": "same-origin" }), ENV), true);
    assert.equal(sameOriginPost(req({ origin: "null" }), ENV), false);
  });

  it("re-renders the form on a validation error without echoing anything that was submitted", async () => {
    const w = makeWorld();
    const { token, receipt } = await w.card({ account: undefined });
    const { value: results, logs } = await withLogs(async () => {
      const short = await handleCardRequest(post(token, { account: "bobmcw", secret: "short" }), token, w.deps);
      // Operator pastes the secret into the account field.
      const pasted = SECRET.replace(/\s/g, "");
      const wrongField = await handleCardRequest(post(token, { account: pasted, secret: pasted }), token, w.deps);
      const noAccount = await handleCardRequest(post(token, { account: "", secret: SECRET }), token, w.deps);
      const badSite = await handleCardRequest(post(token, { site: XSS, account: "bobmcw", secret: SECRET }), token, w.deps);
      return { short, wrongField, noAccount, badSite, pasted };
    });
    for (const res of [results.short, results.wrongField, results.noAccount, results.badSite]) {
      const html = await res.text();
      assert.equal(res.status, 400);
      assertSecureHeaders(res, true);
      assert.match(html, /class="err" role="alert"/);
      assert.match(html, /name="secret" type="password"/);
      assert.match(html, /name="account" type="text" value=""/, "prefill comes from the card, not the submission");
      for (const s of [SECRET, results.pasted, escapeHtml(SECRET), escapeHtml(results.pasted), "<script>"]) {
        assert.ok(!html.includes(s), "submitted content echoed");
      }
    }
    assert.ok(!logs.includes(SECRET) && !logs.includes(results.pasted));
    assert.equal((await listEntries({}, w.deps)).length, 0);
    assert.equal((await getCardStatus(receipt.card_id, w.deps)).status, "pending", "validation errors do not burn the card");

    // Re-entry page: metadata is fixed (no editable inputs) and the same entry id is kept.
    const first = await withLogs(() => handleCardRequest(post(token, { account: "bobmcw", secret: SECRET }), token, w.deps));
    assert.equal(first.value.status, 200);
    const [entry] = await listEntries({}, w.deps);
    const re = await w.card({ account: "bobmcw" });
    const reHtml = await (await handleCardRequest(get(re.token), re.token, w.deps)).text();
    assert.match(reHtml, /Re-enter credential/);
    assert.equal([...reHtml.matchAll(/<input /g)].length, 1, "only the secret field");
    const replaced = "replacement-secret-value-42";
    const done = await withLogs(() =>
      handleCardRequest(post(re.token, { site: "evil.example", account: "x", secret: replaced }), re.token, w.deps),
    );
    assert.equal(done.value.status, 200);
    const doneHtml = await done.value.text();
    assert.ok(!doneHtml.includes(replaced));
    const [afterEntry, ...rest] = await listEntries({}, w.deps);
    assert.equal(rest.length, 0);
    assert.equal(afterEntry.id, entry.id);
    assert.equal(afterEntry.site, "github.com");
    assert.notEqual(afterEntry.fingerprint, entry.fingerprint);
    assert.equal((await w.backend.get(`echo_vault_entry_${entry.id}`, "entry", "t")).secret, replaced);
  });
});
