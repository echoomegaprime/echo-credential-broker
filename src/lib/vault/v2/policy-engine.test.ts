// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, describe, it } from "node:test";
import type { CapabilityRequest, ClientIdentity } from "./contracts.ts";
import {
  evaluatePolicy,
  loadPolicyRules,
  PolicyConfigError,
  requestDigest,
  requiredScope,
  SlidingWindowRateLimiter,
} from "./policy-engine.ts";
import type { PolicyRule } from "./policy-engine.ts";

const ALL_SCOPES = [
  "github.read",
  "github.write",
  "cloudflare.read",
  "cloudflare.write",
  "audit.read",
  "vault.read",
  "vault.write",
  "deploy.write",
  "email.write",
  "payment.write",
];

function client(scopes: string[] = ALL_SCOPES, id = "oc_test"): ClientIdentity {
  return { client_id: id, name: "Claude", kind: "oauth", scopes };
}

function req(
  capability: string,
  resource = "github:echoomegaprime/cleanbrees",
  params: Record<string, unknown> = {},
  c: ClientIdentity = client(),
): CapabilityRequest {
  return { client: c, capability, resource, params };
}

describe("policy engine: default tiers", () => {
  const tier0 = [
    "github.repo.read",
    "github.contents.read",
    "github.user.read",
    "cloudflare.zone.read",
    "audit.read",
    "vault.list",
    "vault.metadata",
  ];
  const tier1 = ["github.branch.create", "github.pr.create_draft"];
  const tier2 = [
    "github.repo.transfer",
    "github.pr.merge",
    "github.repo.delete",
    "cloudflare.dns.write",
    "deploy.production",
    "email.send",
  ];
  const tier3 = [
    "vault.secret.reveal",
    "vault.policy.write",
    "vault.client.add",
    "vault.secret.rotate",
    "vault.secret.delete",
    "payment.charge",
    "payment.refund.create",
  ];

  for (const cap of tier0) {
    it(`${cap} → tier 0 allow`, () => {
      const d = evaluatePolicy(req(cap), []);
      assert.equal(d.decision, "allow");
      assert.equal(d.tier, 0);
    });
  }
  for (const cap of tier1) {
    it(`${cap} → tier 1 allow`, () => {
      const d = evaluatePolicy(req(cap), []);
      assert.equal(d.decision, "allow");
      assert.equal(d.tier, 1);
    });
  }
  for (const cap of tier2) {
    it(`${cap} → tier 2 escalate`, () => {
      const d = evaluatePolicy(req(cap), []);
      assert.equal(d.decision, "escalate");
      assert.equal(d.tier, 2);
      assert.equal(d.reason, "approval_required");
    });
  }
  for (const cap of tier3) {
    it(`${cap} → tier 3 deny even with every scope`, () => {
      const d = evaluatePolicy(req(cap), []);
      assert.equal(d.decision, "deny");
      assert.equal(d.tier, 3);
      assert.equal(d.reason, "tier3_human_only");
    });
  }

  it("github.contents.write to agent/* is tier 1, anything else tier 2", () => {
    assert.deepEqual(
      [
        evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "agent/fix-1" }), []).tier,
        evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "refs/heads/agent/x/y" }), []).tier,
        evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "main" }), []).tier,
        evaluatePolicy(req("github.contents.write", "github:o/r", {}), []).tier,
        evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "agent/../main" }), []).tier,
        evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "feature/agent/x" }), []).tier,
      ],
      [1, 1, 2, 2, 2, 2],
    );
    assert.equal(evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "main" }), []).decision, "escalate");
  });

  it("unknown capability is denied", () => {
    for (const cap of ["github.repo.nuke", "shell.exec", "", "GITHUB.REPO.READ", "github", "github.repo.read.extra"]) {
      const d = evaluatePolicy(req(cap), []);
      assert.equal(d.decision, "deny", cap);
      assert.equal(d.reason, "unknown_capability", cap);
    }
  });

  it("malformed request is denied", () => {
    const bad = { client: client(), capability: "github.repo.read", resource: "", params: {} };
    assert.equal(evaluatePolicy(bad, []).reason, "invalid_request");
    assert.equal(evaluatePolicy({ ...bad, resource: "x", params: [] as never }, []).reason, "invalid_request");
  });
});

describe("policy engine: scopes", () => {
  it("documents the scope mapping", () => {
    assert.equal(requiredScope("github.repo.read"), "github.read");
    assert.equal(requiredScope("github.pr.merge"), "github.write");
    assert.equal(requiredScope("cloudflare.dns.write"), "cloudflare.write");
    assert.equal(requiredScope("vault.list"), "vault.read");
    assert.equal(requiredScope("email.send"), "email.write");
    assert.equal(requiredScope("nope.nope"), undefined);
  });

  it("missing scope is denied for tier 0, 1 and 2", () => {
    const readOnly = client(["github.read"]);
    assert.equal(evaluatePolicy(req("github.repo.read", "github:o/r", {}, readOnly), []).decision, "allow");
    for (const cap of ["github.branch.create", "github.pr.merge", "cloudflare.zone.read"]) {
      const d = evaluatePolicy(req(cap, "github:o/r", {}, readOnly), []);
      assert.equal(d.decision, "deny", cap);
      assert.equal(d.reason, "missing_scope", cap);
    }
  });

  it("write scope does not imply read scope", () => {
    const d = evaluatePolicy(req("github.repo.read", "github:o/r", {}, client(["github.write"])), []);
    assert.equal(d.reason, "missing_scope");
  });
});

describe("policy engine: per-client rules", () => {
  it("a rule can raise a tier", () => {
    const rules: PolicyRule[] = [
      { id: "raise", client_id: "oc_test", capability: "github.*", tier_override: { "github.branch.create": 2 } },
    ];
    const d = evaluatePolicy(req("github.branch.create"), rules);
    assert.equal(d.decision, "escalate");
    assert.equal(d.tier, 2);
    assert.equal(d.rule_id, "raise");
  });

  it("a rule can raise to tier 3 or deny outright", () => {
    const to3 = evaluatePolicy(req("github.repo.read"), [
      { client_id: "*", capability: "github.repo.read", tier_override: { "github.repo.*": 3 } },
    ]);
    assert.equal(to3.decision, "deny");
    assert.equal(to3.reason, "tier3_human_only");
    const denied = evaluatePolicy(req("github.repo.read"), [
      { id: "no", client_id: "oc_test", capability: "*", tier_override: { "*": "deny" } },
    ]);
    assert.equal(denied.decision, "deny");
    assert.equal(denied.reason, "denied_by_rule");
    assert.equal(denied.rule_id, "no");
  });

  it("a rule can never lower a tier", () => {
    const rules: PolicyRule[] = [
      { client_id: "*", capability: "*", tier_override: { "github.repo.transfer": 0, "vault.secret.reveal": 0 } },
    ];
    const transfer = evaluatePolicy(req("github.repo.transfer"), rules);
    assert.equal(transfer.decision, "escalate");
    assert.equal(transfer.tier, 2);
    const reveal = evaluatePolicy(req("vault.secret.reveal"), rules);
    assert.equal(reveal.decision, "deny");
    assert.equal(reveal.reason, "tier3_human_only");
    const contents = evaluatePolicy(req("github.contents.write", "github:o/r", { branch: "main" }), [
      { client_id: "*", capability: "*", tier_override: { "github.contents.write": 1 } },
    ]);
    assert.equal(contents.tier, 2);
  });

  it("rules for other clients do not apply", () => {
    const d = evaluatePolicy(req("github.repo.read"), [
      { client_id: "oc_other", capability: "*", tier_override: { "*": "deny" } },
    ]);
    assert.equal(d.decision, "allow");
  });

  it("resource allowlist", () => {
    const rules: PolicyRule[] = [
      { id: "repos", client_id: "oc_test", capability: "github.*", resources: ["github:echoomegaprime/*"] },
    ];
    assert.equal(evaluatePolicy(req("github.repo.read", "github:echoomegaprime/cleanbrees"), rules).decision, "allow");
    const d = evaluatePolicy(req("github.repo.read", "github:someone-else/repo"), rules);
    assert.equal(d.decision, "deny");
    assert.equal(d.reason, "resource_not_allowed");
    assert.equal(d.rule_id, "repos");
    // Case-sensitive, literal dots.
    assert.equal(evaluatePolicy(req("github.repo.read", "github:ECHOOMEGAPRIME/x"), rules).decision, "deny");
    // An empty allowlist allows nothing.
    const none = evaluatePolicy(req("github.repo.read"), [{ client_id: "*", capability: "*", resources: [] }]);
    assert.equal(none.reason, "resource_not_allowed");
    // Allowlist does not apply to capabilities outside the rule's glob.
    assert.equal(evaluatePolicy(req("audit.read", "audit:all"), rules).decision, "allow");
  });

  it("rate limit uses a sliding one-hour window with an injectable clock", () => {
    const limiter = new SlidingWindowRateLimiter();
    let now = 1_000_000;
    const opts = { limiter, now: () => now };
    const rules: PolicyRule[] = [{ id: "rl", client_id: "oc_test", capability: "github.repo.read", max_per_hour: 2 }];
    assert.equal(evaluatePolicy(req("github.repo.read"), rules, opts).decision, "allow");
    now += 10 * 60 * 1000;
    assert.equal(evaluatePolicy(req("github.repo.read"), rules, opts).decision, "allow");
    now += 10 * 60 * 1000;
    const limited = evaluatePolicy(req("github.repo.read"), rules, opts);
    assert.equal(limited.decision, "deny");
    assert.equal(limited.reason, "rate_limited");
    assert.equal(limited.rule_id, "rl");
    // Other clients have their own window.
    const other = req("github.repo.read", "github:o/r", {}, client(ALL_SCOPES, "oc_test"));
    assert.equal(evaluatePolicy({ ...other, client: { ...other.client, client_id: "oc_x" } }, rules, opts).decision, "allow");
    // First hit leaves the window after an hour.
    now = 1_000_000 + 60 * 60 * 1000 + 1;
    assert.equal(evaluatePolicy(req("github.repo.read"), rules, opts).decision, "allow");
    assert.equal(evaluatePolicy(req("github.repo.read"), rules, opts).decision, "deny");
  });

  it("denied requests do not consume rate-limit slots", () => {
    const limiter = new SlidingWindowRateLimiter();
    const opts = { limiter, now: () => 5 };
    const rules: PolicyRule[] = [
      { client_id: "*", capability: "github.*", max_per_hour: 1, resources: ["github:ok/*"] },
    ];
    assert.equal(evaluatePolicy(req("github.repo.read", "github:bad/x"), rules, opts).reason, "resource_not_allowed");
    assert.equal(evaluatePolicy(req("github.repo.read", "github:ok/x"), rules, opts).decision, "allow");
    assert.equal(evaluatePolicy(req("github.repo.read", "github:ok/x"), rules, opts).reason, "rate_limited");
  });
});

describe("policy engine: policy file", () => {
  const original = process.env.ECHO_VAULT_POLICY_FILE;
  const dir = mkdtempSync(join(tmpdir(), "vault-policy-"));
  afterEach(() => {
    if (original === undefined) delete process.env.ECHO_VAULT_POLICY_FILE;
    else process.env.ECHO_VAULT_POLICY_FILE = original;
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("no file → built-in default (tiers + scopes only)", () => {
    delete process.env.ECHO_VAULT_POLICY_FILE;
    assert.deepEqual(loadPolicyRules(), []);
    assert.equal(evaluatePolicy(req("github.repo.read")).decision, "allow");
  });

  it("loads a valid file", () => {
    const path = join(dir, "ok.json");
    writeFileSync(
      path,
      JSON.stringify({ version: 1, rules: [{ client_id: "oc_test", capability: "github.*", resources: ["github:a/*"] }] }),
    );
    process.env.ECHO_VAULT_POLICY_FILE = path;
    assert.equal(loadPolicyRules().length, 1);
    assert.equal(evaluatePolicy(req("github.repo.read", "github:a/b")).decision, "allow");
    assert.equal(evaluatePolicy(req("github.repo.read", "github:z/b")).reason, "resource_not_allowed");
  });

  it("malformed policy file fails closed", () => {
    const cases: Record<string, string> = {
      "bad-json.json": "{ not json",
      "typo-key.json": JSON.stringify([{ client_id: "*", capability: "*", resource: ["github:a/*"] }]),
      "bad-tier.json": JSON.stringify([{ client_id: "*", capability: "*", tier_override: { "*": 7 } }]),
      "bad-rate.json": JSON.stringify([{ client_id: "*", capability: "*", max_per_hour: -1 }]),
      "no-client.json": JSON.stringify([{ capability: "*" }]),
      "not-array.json": JSON.stringify({ rules: "nope" }),
    };
    for (const [name, content] of Object.entries(cases)) {
      const path = join(dir, name);
      writeFileSync(path, content);
      process.env.ECHO_VAULT_POLICY_FILE = path;
      assert.throws(() => loadPolicyRules(), PolicyConfigError, name);
      const d = evaluatePolicy(req("github.repo.read"));
      assert.equal(d.decision, "deny", name);
      assert.equal(d.reason, "policy_unavailable", name);
    }
    process.env.ECHO_VAULT_POLICY_FILE = join(dir, "missing.json");
    assert.equal(evaluatePolicy(req("github.repo.read")).decision, "deny");
  });
});

describe("requestDigest", () => {
  it("is stable across key order and sensitive to every field", () => {
    const a = requestDigest(req("github.pr.merge", "github:o/r", { pr: 7, opts: { squash: true, title: "t" } }));
    const b = requestDigest({
      params: { opts: { title: "t", squash: true }, pr: 7 },
      resource: "github:o/r",
      capability: "github.pr.merge",
      client: { scopes: [], kind: "local", name: "other display name", client_id: "oc_test" },
    });
    assert.equal(a, b);
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.notEqual(a, requestDigest(req("github.pr.merge", "github:o/r", { pr: 8, opts: { squash: true, title: "t" } })));
    assert.notEqual(a, requestDigest(req("github.pr.merge", "github:o/r2", { pr: 7, opts: { squash: true, title: "t" } })));
    assert.notEqual(
      a,
      requestDigest(req("github.pr.merge", "github:o/r", { pr: 7, opts: { squash: true, title: "t" } }, client(ALL_SCOPES, "oc_2"))),
    );
  });
});
