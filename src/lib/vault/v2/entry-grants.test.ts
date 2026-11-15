// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Entry consent grant store (entry-grants.ts): scoped, expiring, use-capped
 * grants. All in-memory; the SQL store mirrors this behaviour (exercised through
 * the gateway and migrations, not here).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  MemoryEntryGrantStore,
  listEntryGrants,
  pathUnderPrefix,
  revokeEntryGrant,
  type EntryGrant,
} from "./entry-grants.ts";

const ENTRY_A = `ve_${"a".repeat(32)}`;
const ENTRY_B = `ve_${"b".repeat(32)}`;
const CLIENT = "oc_client";
const APPROVAL = "A".repeat(24);
const T0 = Date.UTC(2026, 0, 1, 12, 0, 0); // fixed epoch ms
const HOUR = 3_600_000;

function grant(over: Partial<EntryGrant> = {}): EntryGrant {
  const granted = over.granted_at ?? new Date(T0).toISOString();
  return {
    client_id: CLIENT,
    entry_id: ENTRY_A,
    host: "api.github.com",
    path_prefix: "/user/repos",
    approval_id: APPROVAL,
    granted_at: granted,
    expires_at: over.expires_at ?? new Date(T0 + 24 * HOUR).toISOString(),
    max_uses: over.max_uses ?? 500,
    uses_remaining: over.uses_remaining ?? 500,
    ...over,
  };
}

describe("pathUnderPrefix", () => {
  it("matches the exact path and anything under it, but not a sibling", () => {
    assert.equal(pathUnderPrefix("/user/repos", "/user/repos"), true);
    assert.equal(pathUnderPrefix("/user/repos/123", "/user/repos"), true);
    // The root is not a wildcard: a grant for "/" covers "/" and nothing under it.
    assert.equal(pathUnderPrefix("/", "/"), true);
    assert.equal(pathUnderPrefix("/user", "/"), false);
    assert.equal(pathUnderPrefix("/user/reposX", "/user/repos"), false);
    assert.equal(pathUnderPrefix("/user", "/user/repos"), false);
    assert.equal(pathUnderPrefix("/user/emails", "/user/repos"), false);
  });
});

describe("MemoryEntryGrantStore.find", () => {
  it("returns a grant for the exact path and for a path under it", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant());
    assert.ok(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1));
    assert.ok(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos/echo/x", T0 + 1));
  });

  it("returns null for a sibling path not under the prefix", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant());
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/emails", T0 + 1), null);
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user", T0 + 1), null);
  });

  it("returns null for a different host, entry or client", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant());
    assert.equal(await s.find(CLIENT, ENTRY_A, "github.com", "/user/repos", T0 + 1), null);
    assert.equal(await s.find(CLIENT, ENTRY_B, "api.github.com", "/user/repos", T0 + 1), null);
    assert.equal(await s.find("oc_other", ENTRY_A, "api.github.com", "/user/repos", T0 + 1), null);
  });

  it("returns null once expired", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ expires_at: new Date(T0 + HOUR).toISOString() }));
    assert.ok(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + HOUR - 1));
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + HOUR + 1), null);
  });

  it("returns null once spent (uses_remaining 0)", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ max_uses: 1, uses_remaining: 0 }));
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), null);
  });
});

describe("MemoryEntryGrantStore.consume", () => {
  it("decrements a capped grant and stops matching after the cap is reached", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ max_uses: 2, uses_remaining: 2 }));
    assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), true); // 2 → 1
    assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), true); // 1 → 0
    assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), false); // spent
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), null);
    const [row] = await s.list({ client_id: CLIENT });
    assert.equal(row.uses_remaining, 0);
  });

  it("never decrements an unlimited grant (uses_remaining null)", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ max_uses: null, uses_remaining: null }));
    for (let i = 0; i < 5; i += 1) {
      assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 1), true);
    }
    const [row] = await s.list({ client_id: CLIENT });
    assert.equal(row.uses_remaining, null);
  });

  it("returns false (and changes nothing) when no grant matches", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant());
    assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/emails", T0 + 1), false);
    assert.equal(await s.consume(CLIENT, ENTRY_A, "api.github.com", "/user/repos", T0 + 25 * HOUR), false); // expired
  });
});

describe("MemoryEntryGrantStore: add / remove / two grants", () => {
  it("add is idempotent on the full primary key", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ uses_remaining: 500 }));
    await s.add(grant({ uses_remaining: 3 })); // same PK → ignored
    const [row] = await s.list({});
    assert.equal(row.uses_remaining, 500);
  });

  it("two narrow grants for one entry coexist and are matched independently", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ path_prefix: "/user/repos" }));
    await s.add(grant({ path_prefix: "/orgs" }));
    assert.equal((await s.list({ entry_id: ENTRY_A })).length, 2);
    assert.equal((await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos/x", T0 + 1))?.path_prefix, "/user/repos");
    assert.equal((await s.find(CLIENT, ENTRY_A, "api.github.com", "/orgs/echo", T0 + 1))?.path_prefix, "/orgs");
    assert.equal(await s.find(CLIENT, ENTRY_A, "api.github.com", "/gists", T0 + 1), null);
  });

  it("the most specific (longest) prefix wins when grants overlap", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ path_prefix: "/user" }));
    await s.add(grant({ path_prefix: "/user/repos" }));
    assert.equal((await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/repos/x", T0 + 1))?.path_prefix, "/user/repos");
    assert.equal((await s.find(CLIENT, ENTRY_A, "api.github.com", "/user/emails", T0 + 1))?.path_prefix, "/user");
  });

  it("remove targets one narrow grant or every grant for the pair", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ path_prefix: "/user/repos" }));
    await s.add(grant({ path_prefix: "/orgs" }));
    assert.equal(await s.remove(CLIENT, ENTRY_A, "api.github.com", "/orgs"), true);
    assert.equal((await s.list({ entry_id: ENTRY_A })).length, 1);
    assert.equal(await s.remove(CLIENT, ENTRY_A, "api.github.com", "/nope"), false);
    assert.equal(await s.remove(CLIENT, ENTRY_A), true); // remaining grant, no host/prefix
    assert.equal((await s.list({ entry_id: ENTRY_A })).length, 0);
  });
});

describe("revokeEntryGrant / listEntryGrants helpers", () => {
  it("revoke one narrow grant leaves the others, revoke-all clears the pair", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant({ path_prefix: "/user/repos" }));
    await s.add(grant({ path_prefix: "/orgs" }));
    await s.add(grant({ entry_id: ENTRY_B, path_prefix: "/user" }));
    assert.equal(await revokeEntryGrant(CLIENT, ENTRY_A, s, "api.github.com", "/user/repos"), true);
    assert.deepEqual((await listEntryGrants({ entry_id: ENTRY_A }, s)).map((g) => g.path_prefix), ["/orgs"]);
    assert.equal(await revokeEntryGrant(CLIENT, ENTRY_A, s), true);
    assert.equal((await listEntryGrants({ entry_id: ENTRY_A }, s)).length, 0);
    assert.equal((await listEntryGrants({ entry_id: ENTRY_B }, s)).length, 1);
    assert.equal(await revokeEntryGrant(CLIENT, ENTRY_A, s), false); // nothing left
  });

  it("listEntryGrants filters by client and entry", async () => {
    const s = new MemoryEntryGrantStore();
    await s.add(grant());
    await s.add(grant({ entry_id: ENTRY_B, path_prefix: "/user" }));
    await s.add(grant({ client_id: "oc_other", path_prefix: "/user" }));
    assert.equal((await listEntryGrants({ client_id: CLIENT }, s)).length, 2);
    assert.equal((await listEntryGrants({ entry_id: ENTRY_B }, s)).length, 1);
  });
});
