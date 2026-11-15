// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * cookie-jar.ts: parsing (three formats, hostile input), RFC 6265 selection and
 * Set-Cookie merging, metadata. Pure functions; no network, no vault.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CookieInputError,
  cookieHeaderFor,
  describeJar,
  domainMatches,
  isPublicSuffix,
  jarRedactionForms,
  MAX_COOKIE_INPUT_CHARS,
  MAX_COOKIE_JAR_CHARS,
  MAX_COOKIE_VALUE_CHARS,
  MAX_COOKIES,
  mergeSetCookie,
  parseCookieInput,
  parseStoredJar,
  pathMatches,
  serializeJar,
  type CookieJar,
  type StoredCookie,
} from "./cookie-jar.ts";

const NOW = Date.parse("2026-11-14T12:00:00.000Z");
const NOW_S = NOW / 1000;
const SITE = "example.com";
// Deliberately not provider-shaped.
const V1 = "sessvalue-AAAA-0001";
const V2 = "csrfvalue-BBBB-0002";
const V3 = "othervalue-CCCC-0003";

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof CookieInputError, `expected CookieInputError, got ${(err as Error).name}`);
    // The message is the code: nothing typed can ride in it.
    assert.equal(err.message, err.code);
    return err.code;
  }
  throw new assert.AssertionError({ message: "expected a CookieInputError" });
}

function cookie(over: Partial<StoredCookie> = {}): StoredCookie {
  return { name: "sid", value: V1, domain: "", path: "/", secure: false, httpOnly: false, hostOnly: true, expires: null, ...over };
}

function jarOf(...cookies: StoredCookie[]): CookieJar {
  return { v: 1, cookies };
}

const ctx = (host: string, path = "/", now = NOW) => ({ host, path, now, site: SITE });

describe("parseCookieInput: Cookie header string", () => {
  it("parses name=value pairs, with or without the header name, and binds them host-only to the site", () => {
    for (const text of [`sid=${V1}; csrf=${V2}`, `Cookie: sid=${V1};csrf=${V2};`, `  cookie:sid=${V1} ;  csrf=${V2}  `]) {
      const { jar, format, skipped } = parseCookieInput(text, { site: SITE, now: NOW });
      assert.equal(format, "header");
      assert.deepEqual(skipped, { short_value: 0, expired: 0, other_site: 0 });
      assert.deepEqual(jar.cookies, [cookie({ name: "sid", value: V1 }), cookie({ name: "csrf", value: V2 })]);
    }
    // "=" inside a value is kept.
    assert.equal(parseCookieInput(`t=abc=def==xyz`).jar.cookies[0].value, "abc=def==xyz");
  });

  it("canonical stored form is compact JSON with a fixed key order", () => {
    const { jar } = parseCookieInput(`sid=${V1}`, { site: SITE, now: NOW });
    assert.equal(
      serializeJar(jar),
      `{"v":1,"cookies":[{"name":"sid","value":"${V1}","domain":"","path":"/","secure":false,"httpOnly":false,"hostOnly":true,"expires":null}]}`,
    );
    assert.deepEqual(parseStoredJar(serializeJar(jar)), jar);
  });

  it("refuses header injection and malformed pairs with a code, never echoing input", () => {
    assert.equal(code(() => parseCookieInput(`sid=${V1}\r\nX-Injected: 1`)), "invalid_cookie_header");
    assert.equal(code(() => parseCookieInput(`sid=${V1}\nSet-Cookie: evil=1`)), "invalid_cookie_header");
    assert.equal(code(() => parseCookieInput(`novalue; sid=${V1}`)), "invalid_cookie_header");
    assert.equal(code(() => parseCookieInput(`=${V1}`)), "invalid_cookie_header");
    assert.equal(code(() => parseCookieInput(`bad name=${V1}`)), "invalid_cookie_name");
    assert.equal(code(() => parseCookieInput(`s(id)=${V1}`)), "invalid_cookie_name");
    assert.equal(code(() => parseCookieInput(`sid=${V1}\u0007bell`)), "invalid_cookie_value");
    assert.equal(code(() => parseCookieInput(`sid=${V1}\u0000`)), "invalid_cookie_value");
    assert.equal(code(() => parseCookieInput(`sid=café-value-0001`)), "invalid_cookie_value");
    assert.equal(code(() => parseCookieInput("")), "cookie_input_empty");
    assert.equal(code(() => parseCookieInput("   \n ")), "cookie_input_empty");
    assert.equal(code(() => parseCookieInput(42)), "cookie_input_empty");
    assert.equal(code(() => parseCookieInput(`sid=${V1}; sid=${V2}`)), "duplicate_cookie");
  });

  it("skips values shorter than 8 characters (redaction cannot protect them) and reports the count", () => {
    const { jar, skipped } = parseCookieInput(`theme=dark; sid=${V1}; n=1; empty=`, { site: SITE, now: NOW });
    assert.deepEqual(jar.cookies.map((c) => c.name), ["sid"]);
    assert.equal(skipped.short_value, 3);
    assert.equal(code(() => parseCookieInput("theme=dark; n=1")), "no_usable_cookie");
  });
});

describe("parseCookieInput: JSON export", () => {
  const exported = [
    { name: "sid", value: V1, domain: ".example.com", path: "/", secure: true, httpOnly: true, hostOnly: false, expirationDate: NOW_S + 3600.75, sameSite: "lax", storeId: "0" },
    { name: "csrf", value: V2, domain: "app.example.com", path: "/app", secure: true, httpOnly: false, hostOnly: true, session: true },
    { name: "pp", value: V3, domain: "example.com", expires: -1 },
  ];

  it("reads devtools/extension objects: domain dot, hostOnly, expiry variants, session", () => {
    for (const input of [JSON.stringify(exported), exported, JSON.stringify({ cookies: exported })]) {
      const { jar, format } = parseCookieInput(input, { site: SITE, now: NOW });
      assert.equal(format, "json");
      assert.deepEqual(jar.cookies, [
        { name: "sid", value: V1, domain: "example.com", path: "/", secure: true, httpOnly: true, hostOnly: false, expires: NOW_S + 3600 },
        { name: "csrf", value: V2, domain: "app.example.com", path: "/app", secure: true, httpOnly: false, hostOnly: true, expires: null },
        { name: "pp", value: V3, domain: "example.com", path: "/", secure: false, httpOnly: false, hostOnly: true, expires: null },
      ]);
    }
    // Without hostOnly, a leading dot decides. ISO / millisecond expiries are accepted.
    const { jar } = parseCookieInput(
      [
        { name: "a", value: V1, domain: ".example.com", expires: "2027-01-01T00:00:00Z" },
        { name: "b", value: V2, domain: "example.com", expires: (NOW_S + 60) * 1000 },
      ],
      { site: SITE, now: NOW },
    );
    assert.deepEqual(jar.cookies.map((c) => [c.hostOnly, c.expires]), [[false, Date.parse("2027-01-01T00:00:00Z") / 1000], [true, NOW_S + 60]]);
  });

  it("drops expired cookies and cookies of unrelated sites; keeps a parent-domain cookie", () => {
    const { jar, skipped } = parseCookieInput(
      [
        { name: "old", value: V1, domain: "app.example.com", expirationDate: NOW_S - 1 },
        { name: "foreign", value: V2, domain: ".other-site.org" },
        { name: "lookalike", value: V2, domain: "notexample.com" },
        { name: "parent", value: V3, domain: ".example.com" },
        { name: "parenthost", value: V3, domain: "example.com", hostOnly: true },
      ],
      { site: "app.example.com", now: NOW },
    );
    assert.deepEqual(jar.cookies.map((c) => c.name), ["parent"]);
    assert.deepEqual(skipped, { short_value: 0, expired: 1, other_site: 3 });
  });

  it("refuses hostile or malformed JSON", () => {
    const one = (o: Record<string, unknown>) => () => parseCookieInput([{ name: "sid", value: V1, domain: "example.com", ...o }], { site: SITE, now: NOW });
    assert.equal(code(() => parseCookieInput("[{")), "invalid_cookie_json");
    assert.equal(code(() => parseCookieInput('{"not":"cookies"}')), "invalid_cookie_json");
    assert.equal(code(() => parseCookieInput('["sid=x"]')), "invalid_cookie_json");
    assert.equal(code(() => parseCookieInput("[]")), "cookie_input_empty");
    assert.equal(code(one({ value: `${V1}; Domain=evil.com` })), "invalid_cookie_value");
    assert.equal(code(one({ value: `${V1}\r\nSet-Cookie: x=y` })), "invalid_cookie_value");
    assert.equal(code(one({ value: ` ${V1}` })), "invalid_cookie_value");
    assert.equal(code(one({ value: 12345678 })), "invalid_cookie_value");
    assert.equal(code(one({ value: "x".repeat(MAX_COOKIE_VALUE_CHARS + 1) })), "cookie_value_too_long");
    assert.equal(code(one({ name: "si;d" })), "invalid_cookie_name");
    assert.equal(code(one({ name: "" })), "invalid_cookie_name");
    assert.equal(code(one({ name: "n".repeat(129) })), "invalid_cookie_name");
    assert.equal(code(one({ path: "no-slash" })), "invalid_cookie_path");
    assert.equal(code(one({ path: "/a;b" })), "invalid_cookie_path");
    assert.equal(code(one({ path: "/a\nb" })), "invalid_cookie_path");
    assert.equal(code(one({ expirationDate: "not a date" })), "invalid_cookie_expiry");
    assert.equal(code(one({ expirationDate: Number.NaN })), "invalid_cookie_expiry");
    // Domains: syntax, IP literals, public-suffix-ish.
    assert.equal(code(one({ domain: "exa mple.com" })), "invalid_cookie_domain");
    assert.equal(code(one({ domain: "example.com/path" })), "invalid_cookie_domain");
    assert.equal(code(one({ domain: "evil.com\r\nx" })), "invalid_cookie_domain");
    assert.equal(code(one({ domain: "192.168.1.10" })), "invalid_cookie_domain");
    assert.equal(code(one({ domain: 7 })), "invalid_cookie_domain");
    for (const d of ["com", ".com", "localhost", "co.uk", ".co.uk", "github.io", "com.au"]) {
      assert.equal(code(one({ domain: d })), "public_suffix_domain", d);
    }
    // Same (name, domain, path) twice is ambiguous; same name on another path is not.
    assert.equal(code(() => parseCookieInput([{ name: "sid", value: V1, domain: "example.com" }, { name: "sid", value: V2, domain: ".example.com" }], { site: SITE })), "duplicate_cookie");
    assert.equal(parseCookieInput([{ name: "sid", value: V1, domain: "example.com" }, { name: "sid", value: V2, domain: "example.com", path: "/x" }], { site: SITE }).jar.cookies.length, 2);
  });

  it("caps count and size", () => {
    const many = (n: number) => Array.from({ length: n }, (_v, i) => ({ name: `c${i}`, value: `value-${String(i).padStart(6, "0")}`, domain: "example.com" }));
    assert.equal(parseCookieInput(many(MAX_COOKIES), { site: SITE, now: NOW }).jar.cookies.length, MAX_COOKIES);
    assert.equal(code(() => parseCookieInput(many(MAX_COOKIES + 1), { site: SITE, now: NOW })), "too_many_cookies");
    assert.equal(code(() => parseCookieInput(many(5001))), "too_many_cookies");
    assert.equal(code(() => parseCookieInput(`sid=${"x".repeat(MAX_COOKIE_INPUT_CHARS)}`)), "cookie_input_too_large");
    const fat = Array.from({ length: 12 }, (_v, i) => ({ name: `c${i}`, value: "v".repeat(4000), domain: "example.com" }));
    assert.equal(code(() => parseCookieInput(fat, { site: SITE, now: NOW })), "cookie_jar_too_large");
    assert.ok(serializeJar(parseCookieInput(fat.slice(0, 7), { site: SITE, now: NOW }).jar).length <= MAX_COOKIE_JAR_CHARS);
  });
});

describe("parseCookieInput: Netscape cookies.txt", () => {
  it("reads the seven-column format, #HttpOnly_ lines, comments and CRLF", () => {
    const text = [
      "# Netscape HTTP Cookie File",
      "# https://curl.se/docs/http-cookies.html",
      "",
      `.example.com\tTRUE\t/\tTRUE\t${NOW_S + 86400}\tsid\t${V1}`,
      `#HttpOnly_app.example.com\tFALSE\t/app\tTRUE\t0\tcsrf\t${V2}`,
      `other.org\tFALSE\t/\tFALSE\t0\tforeign\t${V3}`,
      `example.com\tFALSE\t/\tFALSE\t${NOW_S - 10}\texpired\t${V3}`,
      `example.com\tFALSE\t/\tFALSE\t0\tflag\t1`,
    ].join("\r\n");
    const { jar, format, skipped } = parseCookieInput(text, { site: SITE, now: NOW });
    assert.equal(format, "netscape");
    assert.deepEqual(jar.cookies, [
      { name: "sid", value: V1, domain: "example.com", path: "/", secure: true, httpOnly: false, hostOnly: false, expires: NOW_S + 86400 },
      { name: "csrf", value: V2, domain: "app.example.com", path: "/app", secure: true, httpOnly: true, hostOnly: true, expires: null },
    ]);
    assert.deepEqual(skipped, { short_value: 1, expired: 1, other_site: 1 });
  });

  it("refuses malformed lines", () => {
    assert.equal(code(() => parseCookieInput(`.example.com\tTRUE\t/\tTRUE\tsid\t${V1}`)), "invalid_cookies_txt");
    assert.equal(code(() => parseCookieInput(`.example.com\tMAYBE\t/\tTRUE\t0\tsid\t${V1}`)), "invalid_cookies_txt");
    assert.equal(code(() => parseCookieInput(`.example.com\tTRUE\t/\tTRUE\tnever\tsid\t${V1}`)), "invalid_cookies_txt");
    assert.equal(code(() => parseCookieInput(`.example.com\tTRUE\t/\tTRUE\t0\tsid\t${V1}\textra`)), "invalid_cookies_txt");
    assert.equal(code(() => parseCookieInput(`.example.com\tTRUE\t/\tTRUE\t0\tsid\t${V1};x=y`)), "invalid_cookie_value");
    assert.equal(code(() => parseCookieInput(`.com\tTRUE\t/\tTRUE\t0\tsid\t${V1}`)), "public_suffix_domain");
    assert.equal(code(() => parseCookieInput(`# Netscape HTTP Cookie File\n\tTRUE\t/\tTRUE\t0\tsid\t${V1}`)), "invalid_cookie_domain");
  });
});

describe("parseStoredJar", () => {
  it("accepts only the canonical shape", () => {
    const good = serializeJar(jarOf(cookie(), cookie({ name: "d", domain: "example.com", hostOnly: false, expires: NOW_S + 5 })));
    assert.equal(parseStoredJar(good).cookies.length, 2);
    const mutate = (fn: (o: { v: number; cookies: Array<Record<string, unknown>> }) => void): string => {
      const o = JSON.parse(good);
      fn(o);
      return JSON.stringify(o);
    };
    for (const bad of [
      "not json",
      "[]",
      mutate((o) => { o.v = 2; }),
      mutate((o) => { o.cookies[0].value = "a;b-12345678"; }),
      mutate((o) => { o.cookies[0].value = "short"; }),
      mutate((o) => { o.cookies[0].name = "bad name"; }),
      mutate((o) => { o.cookies[0].hostOnly = false; }), // "" domain must be host-only
      mutate((o) => { o.cookies[1].domain = ".Example.com"; }),
      mutate((o) => { o.cookies[1].domain = "com"; }),
      mutate((o) => { o.cookies[1].expires = "soon"; }),
      mutate((o) => { o.cookies[1].secure = "yes"; }),
      mutate((o) => { delete o.cookies[1].path; o.cookies[1].path = "x"; }),
    ]) {
      assert.equal(code(() => parseStoredJar(bad)), "invalid_cookie_jar");
    }
  });
});

describe("cookieHeaderFor: RFC 6265 selection", () => {
  it("domain-match and path-match primitives", () => {
    assert.equal(domainMatches("example.com", "example.com"), true);
    assert.equal(domainMatches("a.b.example.com", "example.com"), true);
    assert.equal(domainMatches("notexample.com", "example.com"), false);
    assert.equal(domainMatches("example.com", "a.example.com"), false);
    assert.equal(domainMatches("10.0.0.1", "0.1"), false);
    assert.equal(pathMatches("/", "/"), true);
    assert.equal(pathMatches("/app/x", "/app"), true);
    assert.equal(pathMatches("/app/x", "/app/"), true);
    assert.equal(pathMatches("/application", "/app"), false);
    assert.equal(pathMatches("/", "/app"), false);
    assert.equal(isPublicSuffix("com"), true);
    assert.equal(isPublicSuffix("co.uk"), true);
    assert.equal(isPublicSuffix("example.co.uk"), false);
    assert.equal(isPublicSuffix("example.com"), false);
  });

  it("host-only cookies need the exact host; domain cookies cover subdomains", () => {
    const jar = jarOf(
      cookie({ name: "bound", value: V1 }), // "" → the entry's site, host-only
      cookie({ name: "wide", value: V2, domain: "example.com", hostOnly: false }),
      cookie({ name: "apphost", value: V3, domain: "app.example.com", hostOnly: true }),
    );
    assert.equal(cookieHeaderFor(jar, ctx("example.com")), `bound=${V1}; wide=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("api.example.com")), `wide=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("app.example.com")), `wide=${V2}; apphost=${V3}`);
    assert.equal(cookieHeaderFor(jar, ctx("x.app.example.com")), `wide=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("EXAMPLE.com")), `bound=${V1}; wide=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("evil.com")), null);
    assert.equal(cookieHeaderFor(jar, ctx("example.com.evil.com")), null);
    assert.equal(cookieHeaderFor(jar, ctx("notexample.com")), null);
    // A site-bound cookie without a site never matches anything.
    assert.equal(cookieHeaderFor(jarOf(cookie()), { host: "example.com", path: "/", now: NOW }), null);
    // A stored public-suffix domain cookie (should never exist) is still never sent.
    assert.equal(cookieHeaderFor(jarOf(cookie({ domain: "com", hostOnly: false })), ctx("example.com")), null);
    assert.equal(cookieHeaderFor(jarOf(cookie({ domain: "co.uk", hostOnly: false })), { host: "shop.co.uk", path: "/", now: NOW, site: "shop.co.uk" }), null);
  });

  it("path-match, query ignored, longest path first then jar order", () => {
    const jar = jarOf(
      cookie({ name: "root", value: V1 }),
      cookie({ name: "app", value: V2, path: "/app" }),
      cookie({ name: "deep", value: V3, path: "/app/admin" }),
      cookie({ name: "root2", value: V2 }),
    );
    assert.equal(cookieHeaderFor(jar, ctx("example.com", "/")), `root=${V1}; root2=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("example.com", "/app/admin/users?x=/zzz")), `deep=${V3}; app=${V2}; root=${V1}; root2=${V2}`);
    assert.equal(cookieHeaderFor(jar, ctx("example.com", "/application")), `root=${V1}; root2=${V2}`);
    assert.equal(cookieHeaderFor(jarOf(cookie({ path: "/app" })), ctx("example.com", "/other")), null);
  });

  it("skips expired cookies; Secure and HttpOnly cookies are sent (requests are https, not script)", () => {
    const jar = jarOf(
      cookie({ name: "live", value: V1, expires: NOW_S + 1, secure: true, httpOnly: true }),
      cookie({ name: "dead", value: V2, expires: NOW_S }),
      cookie({ name: "long-dead", value: V3, expires: 1 }),
    );
    assert.equal(cookieHeaderFor(jar, ctx("example.com")), `live=${V1}`);
    assert.equal(cookieHeaderFor(jar, ctx("example.com", "/", NOW + 2000)), null);
  });
});

describe("mergeSetCookie: RFC 6265 storage", () => {
  const base = jarOf(cookie({ name: "sid", value: V1 }), cookie({ name: "keep", value: V2, domain: "example.com", hostOnly: false }));

  it("updates a value and expiry, adds a new cookie, and reports no change for an identical one", () => {
    const rotated = "rotated-session-0009";
    const r = mergeSetCookie(base, [`sid=${rotated}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax`, `fresh=${V3}; Path=/app`], ctx("example.com", "/login"));
    assert.equal(r.changed, true);
    assert.deepEqual(r.jar.cookies, [
      // still site-bound ("" domain): the site itself refreshed it host-only
      { name: "sid", value: rotated, domain: "", path: "/", secure: true, httpOnly: true, hostOnly: true, expires: NOW_S + 3600 },
      { name: "keep", value: V2, domain: "example.com", path: "/", secure: false, httpOnly: false, hostOnly: false, expires: null },
      { name: "fresh", value: V3, domain: "example.com", path: "/app", secure: false, httpOnly: false, hostOnly: true, expires: null },
    ]);
    assert.equal(base.cookies[0].value, V1, "the input jar is not mutated");
    const again = mergeSetCookie(r.jar, [`sid=${rotated}; Path=/; Max-Age=3600; Secure; HttpOnly`], ctx("example.com", "/login"));
    assert.equal(again.changed, false);
    assert.equal(mergeSetCookie(base, [], ctx("example.com")).changed, false);
  });

  it("default-path comes from the request path; Expires is honoured; Max-Age wins", () => {
    const r = mergeSetCookie(jarOf(), [`a=${V1}`, `b=${V2}; Expires=Wed, 01 Jan 2031 00:00:00 GMT`, `c=${V3}; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Max-Age=10`], ctx("example.com", "/account/settings/x"));
    assert.deepEqual(r.jar.cookies.map((c) => [c.name, c.path, c.expires]), [
      ["a", "/account/settings", null],
      ["b", "/account/settings", Date.parse("2031-01-01T00:00:00Z") / 1000],
      ["c", "/account/settings", NOW_S + 10],
    ]);
    assert.equal(mergeSetCookie(jarOf(), [`a=${V1}`], ctx("example.com", "/top")).jar.cookies[0].path, "/");
  });

  it("deletes on Max-Age=0, a negative Max-Age or a past Expires", () => {
    for (const attr of ["Max-Age=0", "Max-Age=-1", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"]) {
      const r = mergeSetCookie(base, [`sid=deleted; Path=/; ${attr}`], ctx("example.com"));
      assert.equal(r.changed, true, attr);
      assert.deepEqual(r.jar.cookies.map((c) => c.name), ["keep"], attr);
    }
    // Deleting something that is not stored changes nothing.
    assert.equal(mergeSetCookie(base, [`ghost=deleted; Max-Age=0`], ctx("example.com")).changed, false);
    // A different path is a different cookie.
    assert.equal(mergeSetCookie(base, [`sid=deleted; Path=/other; Max-Age=0`], ctx("example.com")).changed, false);
  });

  it("honours Domain only when the request host belongs to it; foreign and public-suffix domains are ignored", () => {
    const from = (host: string, header: string) => mergeSetCookie(jarOf(), [header], ctx(host, "/"));
    // Own domain / parent domain of the responding host: stored as a domain cookie.
    assert.deepEqual(from("app.example.com", `w=${V1}; Domain=example.com`).jar.cookies.map((c) => [c.domain, c.hostOnly]), [["example.com", false]]);
    assert.deepEqual(from("example.com", `w=${V1}; Domain=.Example.COM`).jar.cookies.map((c) => [c.domain, c.hostOnly]), [["example.com", false]]);
    // Another site, a sibling, a subdomain the host is not part of: ignored.
    for (const d of ["evil.com", "other.example.com", "sub.app.example.com", "notexample.com", "ample.com"]) {
      const r = from("app.example.com", `w=${V1}; Domain=${d}`);
      assert.equal(r.changed, false, d);
      assert.equal(r.jar.cookies.length, 0, d);
    }
    // Superdomain / public suffix: refused.
    for (const d of ["com", ".com", "co.uk", "github.io"]) {
      assert.equal(from(d === "github.io" ? "me.github.io" : d.endsWith("uk") ? "shop.co.uk" : "example.com", `w=${V1}; Domain=${d}`).changed, false, d);
    }
    // An overwrite attempt from a foreign Domain leaves the stored cookie alone.
    const r = mergeSetCookie(base, [`sid=attacker-value-0001; Domain=evil.com; Path=/`], ctx("example.com"));
    assert.equal(r.changed, false);
    assert.equal(r.jar.cookies[0].value, V1);
    // A Set-Cookie received from api.<site> cannot touch the site-bound cookie either: it is a host-only api cookie.
    const api = mergeSetCookie(base, [`sid=api-host-value-0001; Path=/`], ctx("api.example.com"));
    assert.equal(api.jar.cookies.find((c) => c.domain === "")?.value, V1);
    assert.deepEqual(api.jar.cookies.at(-1), { name: "sid", value: "api-host-value-0001", domain: "api.example.com", path: "/", secure: false, httpOnly: false, hostOnly: true, expires: null });
  });

  it("ignores malformed headers, enforces cookie prefixes, and never stores a short value", () => {
    const junk = [
      "novalue",
      "=nameless-value-01",
      `bad name=${V1}`,
      `sid=${V1}\r\nSet-Cookie: x=y`,
      `sid=has;semicolon-inside-is-an-attribute`, // parses as value "has" (short) + unknown attribute
      `x=${"v".repeat(MAX_COOKIE_VALUE_CHARS + 1)}`,
      `__Secure-a=${V1}`, // no Secure
      `__Host-b=${V1}; Secure; Domain=example.com; Path=/`,
      `__Host-c=${V1}; Secure; Path=/sub`,
      `p=${V1}; Domain=exa mple.com`,
    ];
    const r = mergeSetCookie(jarOf(cookie({ name: "other", value: V2 })), junk, ctx("example.com"));
    assert.equal(r.changed, false);
    assert.deepEqual(r.jar.cookies.map((c) => c.name), ["other"]);
    const ok = mergeSetCookie(jarOf(), [`__Host-b=${V1}; Secure; Path=/`, `__Secure-a=${V2}; Secure`], ctx("example.com"));
    assert.deepEqual(ok.jar.cookies.map((c) => c.name), ["__Host-b", "__Secure-a"]);
    // A short replacement value cannot be stored: the stale cookie is removed rather than kept.
    const short = mergeSetCookie(base, ["sid=x; Path=/", "newshort=1"], ctx("example.com"));
    assert.equal(short.changed, true);
    assert.deepEqual(short.jar.cookies.map((c) => c.name), ["keep"]);
    // The jar never grows past the cap.
    const full = jarOf(...Array.from({ length: MAX_COOKIES }, (_v, i) => cookie({ name: `c${i}` })));
    assert.equal(mergeSetCookie(full, [`extra=${V1}`], ctx("example.com")).jar.cookies.length, MAX_COOKIES);
  });
});

describe("describeJar / jarRedactionForms", () => {
  it("describeJar returns names, domains and earliest expiry — never a value", () => {
    const jar = jarOf(
      cookie({ name: "sid", value: V1, expires: NOW_S + 500 }),
      cookie({ name: "wide", value: V2, domain: "example.com", hostOnly: false, expires: NOW_S + 100 }),
      cookie({ name: "sid", value: V3, path: "/x" }),
    );
    const d = describeJar(jar, SITE);
    assert.deepEqual(d, {
      count: 3,
      names: ["sid", "wide"],
      domains: [".example.com", "example.com"],
      truncated: false,
      expires_at: new Date((NOW_S + 100) * 1000).toISOString(),
      session_cookies: 1,
    });
    for (const v of [V1, V2, V3]) assert.ok(!JSON.stringify(d).includes(v));
    assert.equal(describeJar(jarOf(cookie())).expires_at, null);
    const big = describeJar(jarOf(...Array.from({ length: 80 }, (_v, i) => cookie({ name: `n${i}` }))), SITE);
    assert.equal(big.names.length, 50);
    assert.equal(big.truncated, true);
    assert.equal(big.count, 80);
  });

  it("jarRedactionForms covers raw, URL-encoded, URL-decoded, base64 and base64url", () => {
    const value = "a/b+c=d%20e&f-12345";
    const forms = jarRedactionForms(jarOf(cookie({ value })));
    for (const f of [
      value,
      encodeURIComponent(value),
      decodeURIComponent(value),
      new URLSearchParams({ v: value }).toString().slice(2),
      Buffer.from(value).toString("base64"),
      Buffer.from(value).toString("base64url"),
    ]) {
      assert.ok(forms.includes(f), f);
    }
    assert.ok(forms.every((f) => f.length >= 8));
  });
});
