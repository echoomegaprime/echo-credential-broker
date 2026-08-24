import { createServerFn } from "@tanstack/react-start";

type RpcJson = {
  ok: boolean;
  error?: string;
  credential_ref?: string;
  detail?: string;
  data?: {
    invariant?: string;
    imported?: string[];
    credential_count?: number;
    redaction?: string;
    fail_closed?: boolean;
    get_secret?: boolean;
    providers?: string[];
    credentials?: Array<{
      ref: string;
      provider: string;
      account: string;
      type: string;
      status: string;
      last_verified: string | null;
      fingerprint: string | null;
      source: string;
    }>;
    tools?: Array<{
      name: string;
      description: string;
    }>;
    records?: Array<{
      id: string;
      timestamp: string;
      caller: string;
      credential_ref: string;
      provider: string;
      operation: string;
      resource: string;
      http_status: number | null;
      duration_ms: number;
      result: string;
      error?: string;
    }>;
    provider?: string;
    ref?: string;
    authenticated?: boolean;
    account?: string;
    account_id?: number | null;
    status?: string;
    full_name?: string;
    name?: string;
    private?: boolean;
    description?: string | null;
    default_branch?: string;
    html_url?: string;
    owner?: string;
    visibility?: string;
    rotated?: string;
    revoked?: string;
    login?: string;
    id?: number | null;
    repositories?: Array<{
      full_name?: string;
      private?: boolean;
      description?: string | null;
      updated_at?: string;
    }>;
  };
};

type ToolArgs = Record<string, string | number | boolean>;

function asRpc(value: unknown): RpcJson {
  return JSON.parse(JSON.stringify(value)) as RpcJson;
}

function parseArgs(raw: unknown): ToolArgs {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const out: ToolArgs = {};
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        out[key] = value;
      }
    }
    return out;
  }
  if (typeof raw === "string") {
    try {
      return parseArgs(JSON.parse(raw));
    } catch {
      return {};
    }
  }
  return {};
}

export const rpcVaultStatus = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => {
    const { callTool } = await import("./vault/tools.ts");
    return asRpc(await callTool("vault_status", {}, { caller: "vault-console" }));
  },
);

export const rpcVaultList = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => {
    const { callTool } = await import("./vault/tools.ts");
    return asRpc(await callTool("vault_list", {}, { caller: "vault-console" }));
  },
);

export const rpcAuditList = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => {
    const { callTool } = await import("./vault/tools.ts");
    return asRpc(await callTool("audit_list", { limit: 50 }, { caller: "vault-console" }));
  },
);

export const rpcListTools = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => {
    const { listTools } = await import("./vault/tools.ts");
    return asRpc({
      ok: true,
      data: {
        tools: listTools().map((t) => ({
          name: t.name,
          description: t.description,
        })),
      },
    });
  },
);

/**
 * HUMAN-ONLY secret reveal — deliberately NOT an MCP tool and NOT reachable
 * from `/api/mcp`. This is the one legitimate place a raw secret crosses the
 * server/client boundary: the Commander asking the console, in his own
 * browser, to show him a credential so he can copy/paste it somewhere. No
 * agent (Claude/GPT/Grok/Codex) has any tool that calls this — the MCP tool
 * surface (`vault/tools.ts`) still has zero `get_secret`-shaped tool and
 * never will. Every reveal is audited as a distinct `human_reveal` operation.
 *
 * Trust boundary today: same as every other console/MCP operation on this
 * broker — reachable to whoever can reach the FORGE LAN port. `provider_request`
 * / `credential_use` already let any caller on that boundary perform an
 * authenticated action with any vault credential, so a reveal is not a wider
 * blast radius than what already exists ungated. Real per-user login is a
 * natural hardening step if this ever needs a *tighter* boundary than that.
 */
export const rpcRevealSecret = createServerFn({ method: "POST" })
  .validator((data: { credential_ref: string }) => ({
    credential_ref: String(data.credential_ref),
  }))
  .handler(async ({ data }): Promise<{ ok: true; secret: string } | { ok: false; error: string }> => {
    const { getStore } = await import("./vault/store.ts");
    const { recordAudit } = await import("./vault/audit.ts");
    const { parseVaultRef } = await import("./vault/refs.ts");
    const started = Date.now();
    const parsed = parseVaultRef(data.credential_ref);
    if (!parsed) return { ok: false, error: "invalid_credential_ref" };
    const store = getStore();
    const secret = await store.resolveSecret(parsed.raw);
    recordAudit({
      caller: "vault-console:human",
      credential_ref: parsed.raw,
      provider: parsed.provider,
      operation: "human_reveal",
      resource: parsed.raw,
      http_status: null,
      duration_ms: Date.now() - started,
      result: secret ? "ok" : "error",
      error: secret ? undefined : "credential_unavailable",
    });
    if (!secret) return { ok: false, error: "credential_unavailable" };
    // Deliberately bypassed: asRpc()/redactValue()/safeJson() elsewhere in this
    // file exist to STRIP secrets from every other response. This is the one
    // response that must carry the real value, so it must never pass through them.
    return { ok: true, secret };
  });

export const rpcCallTool = createServerFn({ method: "POST" })
  .validator((data: { name: string; arguments?: ToolArgs; argsJson?: string }) => ({
    name: String(data.name),
    arguments: data.arguments ?? {},
    argsJson: data.argsJson ?? "",
  }))
  .handler(async ({ data }): Promise<RpcJson> => {
    const { callTool } = await import("./vault/tools.ts");
    const args = {
      ...parseArgs(data.arguments),
      ...parseArgs(data.argsJson),
    };
    return asRpc(await callTool(data.name, args, { caller: "vault-console" }));
  });
