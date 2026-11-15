// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * pinnedFetch against a real TLS server on loopback. The certificate is
 * self-signed, generated here with openssl (the suite skips when openssl is
 * absent), and is trusted ONLY through the explicit test-only `ca` option;
 * loopback is reachable ONLY through the explicit test-only allowance. The
 * production default path is asserted to refuse both.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import https from "node:https";
import type { AddressInfo, LookupFunction } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { after, before, describe, it } from "node:test";
import { pinnedFetch, PinnedFetchError, pinnedLookup, type PinnedFetchOptions } from "./pinned-fetch.ts";

const HOSTNAME = "vault-pin-test.invalid"; // RFC 6761: never resolves
const SECRET = "PINNED-FETCH-test-secret-4f7a91c2d8e3";
const hasOpenssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;

interface Seen {
  path: string;
  method: string;
  host: string | undefined;
  sni: string | false | null;
  authorization: string | undefined;
  body: string;
}

describe("pinnedFetch", { skip: hasOpenssl ? false : "openssl not available to mint a test certificate" }, () => {
  let dir = "";
  let ca: Buffer;
  let server: https.Server;
  let port = 0;
  const seen: Seen[] = [];
  let connections = 0;
  let landed = 0;

  const base = () => `https://${HOSTNAME}:${port}`;
  const loopback = (extra: Partial<PinnedFetchOptions> = {}): PinnedFetchOptions => ({
    addresses: ["127.0.0.1"],
    ...extra,
    testOnly: { allowPrivateAddresses: true, ca, ...extra.testOnly },
  });
  const rejectsWith = async (p: Promise<unknown>, code: string): Promise<PinnedFetchError> => {
    let caught: unknown;
    try {
      await p;
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof PinnedFetchError, `expected PinnedFetchError(${code}), got ${String(caught)}`);
    assert.equal(caught.code, code);
    assert.equal(caught.message, code);
    // Whatever went wrong, the credential is not in the error.
    const blob = `${caught.message} ${caught.detail ?? ""} ${caught.stack ?? ""} ${JSON.stringify(caught)}`;
    assert.equal(blob.includes(SECRET), false, "error carries the secret");
    return caught;
  };

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "pinned-fetch-"));
    const key = join(dir, "key.pem");
    const cert = join(dir, "cert.pem");
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-keyout", key, "-out", cert,
        "-subj", `/CN=${HOSTNAME}`, "-addext", `subjectAltName=DNS:${HOSTNAME}`],
      { stdio: "ignore" },
    );
    ca = readFileSync(cert);
    server = https.createServer({ key: readFileSync(key), cert: ca }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const path = req.url ?? "";
        const record: Seen = {
          path,
          method: req.method ?? "",
          host: req.headers.host,
          sni: (req.socket as TLSSocket).servername,
          authorization: req.headers.authorization,
          body: Buffer.concat(chunks).toString("utf8"),
        };
        seen.push(record);
        if (path === "/redirect") {
          res.writeHead(302, { location: "/landed" });
          res.end();
        } else if (path === "/landed") {
          landed += 1;
          res.writeHead(200).end("landed");
        } else if (path === "/big") {
          res.writeHead(200, { "content-type": "text/plain", "content-length": String(64 * 1024) });
          res.end(Buffer.alloc(64 * 1024, 0x61));
        } else if (path === "/big-chunked") {
          res.writeHead(200, { "content-type": "text/plain" });
          for (let i = 0; i < 64; i += 1) res.write(Buffer.alloc(1024, 0x62));
          res.end();
        } else if (path === "/hang") {
          // never answers
        } else if (path === "/slow-body") {
          res.writeHead(200, { "content-type": "text/plain" });
          res.write("partial");
        } else if (path === "/nocontent") {
          res.writeHead(204).end();
        } else {
          res.writeHead(200, { "content-type": "application/json", "set-cookie": ["a=1", "b=2"] });
          res.end(JSON.stringify(record));
        }
      });
    });
    // TCP accepts, not finished handshakes: a client that hangs up right after
    // its own side of the handshake may never complete the server's.
    server.on("connection", () => {
      connections += 1;
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  after(async () => {
    server?.closeAllConnections();
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("(a)+(b) connects to the pinned address for a hostname that does not resolve; Host and SNI carry the hostname", async () => {
    const connected: string[] = [];
    const res = await pinnedFetch(
      `${base()}/echo?x=1`,
      { method: "GET", headers: { authorization: `Bearer ${SECRET}`, host: "evil.example" } },
      loopback({ onConnect: (a) => connected.push(a) }),
    );
    assert.equal(res.status, 200);
    assert.ok(res instanceof Response);
    const echoed = (await res.json()) as Seen;
    assert.equal(echoed.path, "/echo?x=1");
    assert.equal(echoed.host, `${HOSTNAME}:${port}`, "Host header is the original hostname, not a caller override");
    assert.equal(echoed.sni, HOSTNAME, "SNI is the original hostname");
    assert.equal(echoed.authorization, `Bearer ${SECRET}`);
    assert.deepEqual(connected, ["127.0.0.1"]);
    assert.deepEqual(res.headers.getSetCookie(), ["a=1", "b=2"]);
  });

  it("sends a body with a content-length and returns bodiless statuses", async () => {
    const res = await pinnedFetch(`${base()}/post`, { method: "POST", headers: new Headers({ "content-type": "application/json" }), body: '{"n":1}' }, loopback());
    const echoed = (await res.json()) as Seen;
    assert.equal(echoed.method, "POST");
    assert.equal(echoed.body, '{"n":1}');
    const none = await pinnedFetch(`${base()}/nocontent`, {}, loopback());
    assert.equal(none.status, 204);
    assert.equal(none.body, null);
    const head = await pinnedFetch(`${base()}/echo`, { method: "HEAD" }, loopback());
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
  });

  it("(b) the certificate is verified against the hostname: wrong name or untrusted issuer fails before any request is sent", async () => {
    const before = seen.length;
    const wrongName = await rejectsWith(
      pinnedFetch(`https://other-name.invalid:${port}/echo`, { headers: { authorization: `Bearer ${SECRET}` } }, loopback()),
      "site_request_failed",
    );
    assert.equal(wrongName.detail, "ERR_TLS_CERT_ALTNAME_INVALID");
    const untrusted = await rejectsWith(
      pinnedFetch(`${base()}/echo`, { headers: { authorization: `Bearer ${SECRET}` } }, { addresses: ["127.0.0.1"], testOnly: { allowPrivateAddresses: true } }),
      "site_request_failed",
    );
    assert.match(String(untrusted.detail), /SELF_SIGNED|UNABLE_TO_VERIFY/);
    assert.equal(seen.length, before, "no HTTP request reached the server");
  });

  it("(c) the response cap is enforced, with and without a declared length", async () => {
    await rejectsWith(pinnedFetch(`${base()}/big`, {}, loopback({ maxResponseBytes: 4096 })), "response_too_large");
    await rejectsWith(pinnedFetch(`${base()}/big-chunked`, {}, loopback({ maxResponseBytes: 4096 })), "response_too_large");
    const ok = await pinnedFetch(`${base()}/big`, {}, loopback({ maxResponseBytes: 64 * 1024 }));
    assert.equal((await ok.arrayBuffer()).byteLength, 64 * 1024);
  });

  it("(c) the timeout covers a silent server, a stalled body and a caller signal", async () => {
    const started = Date.now();
    const silent = await rejectsWith(pinnedFetch(`${base()}/hang`, { headers: { authorization: `Bearer ${SECRET}` } }, loopback({ timeoutMs: 150 })), "request_timeout");
    assert.equal(silent.name, "TimeoutError");
    await rejectsWith(pinnedFetch(`${base()}/slow-body`, {}, loopback({ timeoutMs: 150 })), "request_timeout");
    await rejectsWith(pinnedFetch(`${base()}/hang`, { signal: AbortSignal.timeout(100) }, loopback({ timeoutMs: 5000 })), "request_timeout");
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    await rejectsWith(pinnedFetch(`${base()}/hang`, { signal: controller.signal }, loopback({ timeoutMs: 5000 })), "request_aborted");
    assert.ok(Date.now() - started < 4000, "timeouts fired promptly");
  });

  it("(d) redirects are not followed: status and Location pass through", async () => {
    landed = 0;
    for (const redirect of [undefined, "follow", "manual"] as const) {
      const res = await pinnedFetch(`${base()}/redirect`, { headers: { authorization: `Bearer ${SECRET}` }, redirect }, loopback());
      assert.equal(res.status, 302);
      assert.equal(res.headers.get("location"), "/landed");
    }
    assert.equal(landed, 0, "the redirect target was never requested");
  });

  it("(e) a socket that connects outside the pinned set fails closed and nothing is sent", async () => {
    const before = seen.length;
    // A resolver that ignores the pin (the rebinding answer): the name now points at loopback.
    const rebound: LookupFunction = (_host, options, cb) => {
      if (typeof options === "object" && options.all) (cb as unknown as (e: null, a: unknown[]) => void)(null, [{ address: "127.0.0.1", family: 4 }]);
      else cb(null, "127.0.0.1", 4);
    };
    const connBefore = connections;
    await rejectsWith(
      pinnedFetch(`${base()}/echo`, { headers: { authorization: `Bearer ${SECRET}` } }, { addresses: ["203.0.113.10"], testOnly: { ca, lookup: rebound } }),
      "hostname_not_allowed",
    );
    // Even with the private-address allowance, membership in the pinned set is still required.
    await rejectsWith(
      pinnedFetch(`${base()}/echo`, { headers: { authorization: `Bearer ${SECRET}` } }, { addresses: ["127.0.0.9"], testOnly: { ca, lookup: rebound, allowPrivateAddresses: true } }),
      "hostname_not_allowed",
    );
    assert.ok(connections > connBefore, "the socket really did reach the wrong server");
    assert.equal(seen.length, before, "…but no request, and no Authorization header, was written to it");
  });

  it("the production default refuses loopback, private, non-IP and empty pins without connecting", async () => {
    const connBefore = connections;
    const init = { headers: { authorization: `Bearer ${SECRET}` } };
    for (const addresses of [
      ["127.0.0.1"],
      ["::1"],
      ["93.184.216.34", "10.0.0.1"],
      ["169.254.169.254"],
      ["::ffff:127.0.0.1"],
      ["64:ff9b::7f00:1"],
      ["localhost"],
      [HOSTNAME],
      [],
    ]) {
      await rejectsWith(pinnedFetch(`${base()}/echo`, init, { addresses, testOnly: { ca } }), "hostname_not_allowed");
    }
    await rejectsWith(pinnedFetch(`http://${HOSTNAME}:${port}/echo`, init, loopback()), "hostname_not_allowed");
    await rejectsWith(pinnedFetch(`https://user:pw@${HOSTNAME}:${port}/echo`, init, loopback()), "hostname_not_allowed");
    await rejectsWith(pinnedFetch("not a url", init, loopback()), "hostname_not_allowed");
    // An IP-literal URL bypasses lookup in Node, so it must itself be in the pinned set.
    await rejectsWith(pinnedFetch(`https://127.0.0.1:${port}/echo`, init, { addresses: ["127.0.0.2"], testOnly: { ca, allowPrivateAddresses: true } }), "hostname_not_allowed");
    assert.equal(connections, connBefore, "no connection was attempted");
  });

  it("a refused connection is a fixed code", async () => {
    const closed = https.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const deadPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const err = await rejectsWith(pinnedFetch(`https://${HOSTNAME}:${deadPort}/echo`, { headers: { authorization: `Bearer ${SECRET}` } }, loopback()), "site_request_failed");
    assert.equal(err.detail, "ECONNREFUSED");
  });
});

describe("pinnedLookup", () => {
  const ask = (lookup: LookupFunction, options: { all?: boolean; family?: number }) =>
    new Promise<unknown>((resolve) => {
      (lookup as unknown as (h: string, o: object, cb: (...args: unknown[]) => void) => void)("anything.example", options, (...args) => resolve(args));
    });

  it("answers only from the pinned addresses, whatever name is asked", async () => {
    const lookup = pinnedLookup(["93.184.216.34", "2606:4700::1111"]);
    assert.deepEqual(await ask(lookup, { all: true }), [null, [{ address: "93.184.216.34", family: 4 }, { address: "2606:4700::1111", family: 6 }]]);
    assert.deepEqual(await ask(lookup, {}), [null, "93.184.216.34", 4]);
    assert.deepEqual(await ask(lookup, { family: 6 }), [null, "2606:4700::1111", 6]);
    assert.deepEqual(await ask(lookup, { family: 4, all: true }), [null, [{ address: "93.184.216.34", family: 4 }]]);
  });

  it("fails rather than falling back to DNS when no pinned address has the wanted family", async () => {
    const [err] = (await ask(pinnedLookup(["93.184.216.34"]), { family: 6 })) as [NodeJS.ErrnoException];
    assert.equal(err.code, "ENOTFOUND");
  });
});
