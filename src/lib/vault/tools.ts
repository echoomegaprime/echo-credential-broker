/**
 * v1 executors for the vault:// credential tools. These functions perform the
 * action; they do NOT authenticate or authorize. The only caller is
 * v2/gateway.ts (dispatchTool), which authenticates the client, evaluates
 * policy, handles approvals and writes the ledger before and after.
 * There is deliberately no generic "call a tool by name" function here.
 */
import type { BrokerContext } from "./broker.ts";
import { ensureImported } from "./importer.ts";
import { githubGetUser } from "./providers.ts";
import { PROVIDER_POLICIES } from "./policy.ts";
import { installProcessRedaction, redactValue } from "./redaction.ts";
import { parseVaultRef } from "./refs.ts";
import { getStore } from "./store.ts";
import { INVARIANT, type ToolResult } from "./types.ts";

if (!process.env.NODE_TEST_CONTEXT) {
  installProcessRedaction();
}

export async function vaultStatus(ctx: BrokerContext): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  if (!ctx.store) await ensureImported();
  const report = ctx.store
    ? { imported: store.listMetadata().map((m) => m.ref), skipped: [] as string[] }
    : await ensureImported();
  return redactValue({
    ok: true as const,
    data: {
      invariant: INVARIANT,
      imported: report.imported,
      credential_count: store.count(),
      redaction: "armed",
      fail_closed: true,
      get_secret: false,
      providers: Object.keys(PROVIDER_POLICIES),
    },
  });
}

export async function vaultList(ctx: BrokerContext): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  if (!ctx.store) await ensureImported();
  return redactValue({
    ok: true as const,
    data: { credentials: store.listMetadata() },
  });
}

export async function vaultFind(ctx: BrokerContext, query: string): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  if (!query || query.trim().length < 2) {
    return { ok: false, error: "query_too_short" };
  }
  const result = await store.find(query.trim());
  return redactValue({
    ok: true as const,
    data: {
      status: result.status,
      candidates: result.candidates.map((c) => ({ service: c.actual_service, username: c.username, key_shape: c.key_shape })),
      hint: result.hint ?? null,
      did_you_mean: result.did_you_mean ?? [],
    },
  });
}

export async function vaultMetadata(
  ctx: BrokerContext,
  credential_ref: string,
): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  if (!ctx.store) await ensureImported();
  const parsed = parseVaultRef(credential_ref);
  if (!parsed) {
    return { ok: false, error: "invalid_credential_ref", credential_ref };
  }
  const meta = store.getMetadata(parsed.raw);
  if (!meta) {
    return { ok: false, error: "credential_unavailable", credential_ref: parsed.raw };
  }
  return redactValue({ ok: true as const, data: meta });
}

export async function credentialHealth(
  ctx: BrokerContext,
  credential_ref: string,
): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  if (!ctx.store) await ensureImported();
  const parsed = parseVaultRef(credential_ref);
  if (!parsed) {
    return { ok: false, error: "invalid_credential_ref", credential_ref };
  }
  if (!(await store.has(parsed.raw))) {
    return { ok: false, error: "credential_unavailable", credential_ref: parsed.raw };
  }
  if (parsed.provider === "github") {
    const identity = await githubGetUser(ctx, parsed.raw);
    if (!identity.ok) {
      store.updateMetadata(parsed.raw, { status: "unhealthy" });
      return identity;
    }
    const data = identity.data as { login?: string; id?: number; authenticated?: boolean };
    const expected = parsed.account;
    const status =
      data.login && data.login.toLowerCase() === expected.toLowerCase()
        ? "healthy"
        : "identity_mismatch";
    store.updateMetadata(parsed.raw, {
      status,
      last_verified: new Date().toISOString(),
      account: data.login ?? expected,
    });
    return redactValue({
      ok: true as const,
      data: {
        provider: "github",
        ref: parsed.raw,
        authenticated: Boolean(data.authenticated),
        account: data.login ?? null,
        account_id: data.id ?? null,
        status,
      },
    });
  }
  store.updateMetadata(parsed.raw, {
    status: "imported",
    last_verified: new Date().toISOString(),
  });
  const meta = store.getMetadata(parsed.raw);
  return redactValue({
    ok: true as const,
    data: {
      provider: parsed.provider,
      ref: parsed.raw,
      authenticated: Boolean(meta),
      account: parsed.account,
      account_id: null,
      status: meta?.status ?? "imported",
    },
  });
}

