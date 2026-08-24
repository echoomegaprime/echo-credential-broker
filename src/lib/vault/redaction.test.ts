import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  containsSecretPrefix,
  redactString,
  redactValue,
  registerSecretForRedaction,
  sanitizeError,
  safeJson,
} from "./redaction.ts";

const GITHUB_PAT = "github_pat_TESTONLY_NOTAREALSECRET_ABCDEF0123456789";
const GHP = "ghp_TESTONLY0000000000000000000000000000";
const OPENAI = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD";

describe("redaction", () => {
  it("redacts github_pat_ tokens to the required placeholder", () => {
    const out = redactString(`token=${GITHUB_PAT}`);
    assert.equal(out.includes(GITHUB_PAT), false);
    assert.equal(out.includes("[REDACTED_GITHUB_TOKEN]"), true);
  });

  it("redacts ghp_ classic tokens", () => {
    const out = redactString(`Authorization: Bearer ${GHP}`);
    assert.equal(out.includes(GHP), false);
    assert.equal(out.includes("[REDACTED_GITHUB_TOKEN]") || out.includes("[REDACTED]"), true);
  });

  it("redacts registered secrets even without a known prefix", () => {
    const odd = "super-secret-value-xyz-9876543210";
    registerSecretForRedaction(odd);
    const out = redactString(`leaked ${odd} here`);
    assert.equal(out.includes(odd), false);
    assert.equal(out.includes("[REDACTED_SECRET]"), true);
  });

  it("strips sensitive keys from objects", () => {
    const out = redactValue({
      ref: "vault://github/echoomegaprime",
      token: GITHUB_PAT,
      password: "hunter2-not-a-real-pass-word",
    }) as Record<string, unknown>;
    assert.equal(out.token, "[REDACTED_SECRET]");
    assert.equal(out.password, "[REDACTED_SECRET]");
    assert.equal(out.ref, "vault://github/echoomegaprime");
    assert.equal(JSON.stringify(out).includes(GITHUB_PAT), false);
  });

  it("sanitizes exceptions so tokens never appear in message or stack", () => {
    const err = sanitizeError(new Error(`failed Authorization: Bearer ${GHP}`));
    assert.equal(err.message.includes(GHP), false);
    assert.equal(containsSecretPrefix(err.message), false);
  });

  it("safeJson never emits sk- secrets", () => {
    const json = safeJson({ key: OPENAI });
    assert.equal(json.includes(OPENAI), false);
  });
});
