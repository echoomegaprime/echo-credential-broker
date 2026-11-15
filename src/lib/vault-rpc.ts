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

/**
 * Owner console RPCs. These are plain server functions: anyone who can reach
 * the web port can call them, and there is no login in front of them. So:
 *
 *   - They are OFF unless `ECHO_VAULT_CONSOLE=local` is set. Set it only when
 *     the port is reachable by the owner alone (localhost / a private LAN),
 *     never on the public deployment.
 *   - When on, every call goes through the same gateway as any agent
 *     (dispatchTool) as the fixed identity `local:vault-console`, which holds
 *     READ scopes only and is NOT a local/owner identity for the gateway.
 *     Writes, approvals-required actions and tier-3 actions (every admin_*
 *     tool) get the same answers an under-scoped agent would get. Owner
 *     management lives in the passkey console under /console.
 *   - There is no reveal. Reading a secret value is tier 3 ("never through
 *     this broker"): use the canonical vault directly.
 */
const CONSOLE_SCOPES = [
  "github.read",
  "cloudflare.read",
  "openai.read",
  "stripe.read",
  "xai.read",
  "vault.read",
  "audit.read",
];

function consoleEnabled(): boolean {
  return process.env.ECHO_VAULT_CONSOLE?.trim().toLowerCase() === "local";
}

async function consoleCall(name: string, args: Record<string, unknown>): Promise<RpcJson> {
  if (!consoleEnabled()) {
    return { ok: false, error: "console_disabled", detail: "Set ECHO_VAULT_CONSOLE=local on a private, owner-only host to enable the console." };
  }
  const { dispatchTool } = await import("./vault/v2/gateway.ts");
  return asRpc(
    // kind "workload", NOT "local": this is an unauthenticated web RPC, not the
    // stdio process. With kind "local" the gateway's admin carve-out would hand
    // every admin_* tool (purge, revoke, console bootstrap) to anyone who can
    // reach the port. As a workload it gets tier3_human_only like any agent.
    await dispatchTool({ client_id: "local:vault-console", name: "Vault console", kind: "workload", scopes: [...CONSOLE_SCOPES] }, name, args),
  );
}

export const rpcVaultStatus = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => consoleCall("vault_status", {}),
);

export const rpcVaultList = createServerFn({ method: "GET" }).handler(
  async (): Promise<RpcJson> => consoleCall("vault_list", {}),
);

export const rpcAuditList = createServerFn({ method: "GET" }).handler(async (): Promise<RpcJson> => {
  const res = await consoleCall("audit_list", { limit: 50 });
  if (!res.ok) return res;
  // Ledger rows → the record shape the console table renders.
  const rows = ((res.data as { records?: Array<Record<string, unknown>> } | undefined)?.records ?? []).map((r) => ({
    id: String(r.id ?? ""),
    timestamp: String(r.timestamp ?? ""),
    caller: String(r.client_id ?? ""),
    credential_ref: typeof r.credential_ref === "string" ? r.credential_ref : "",
    provider: String(r.capability ?? "").split(".")[0],
    operation: String(r.capability ?? ""),
    resource: String(r.resource ?? ""),
    http_status: typeof r.http_status === "number" ? r.http_status : null,
    duration_ms: typeof r.duration_ms === "number" ? r.duration_ms : 0,
    result: String(r.result ?? ""),
    error: typeof r.error === "string" ? r.error : undefined,
  }));
  return { ok: true, data: { records: rows } };
});

export const rpcListTools = createServerFn({ method: "GET" }).handler(async (): Promise<RpcJson> => {
  if (!consoleEnabled()) return { ok: false, error: "console_disabled" };
  const { listTools } = await import("./vault/v2/gateway.ts");
  return asRpc({
    ok: true,
    data: { tools: listTools().map((t) => ({ name: t.name, description: t.description })) },
  });
});

/**
 * Removed in v2. This used to return a raw secret to whoever could reach the
 * web port. Nothing in this process returns a secret any more; the function
 * stays so the console compiles and always answers `reveal_disabled`.
 */
export const rpcRevealSecret = createServerFn({ method: "POST" })
  .validator((data: { credential_ref: string }) => ({
    credential_ref: String(data.credential_ref),
  }))
  .handler(async (): Promise<{ ok: true; secret: string } | { ok: false; error: string }> => {
    const { log } = await import("./vault/log.ts");
    log.warn("console_reveal_refused", { reason: "tier3_human_only" });
    return { ok: false, error: "reveal_disabled" };
  });

export const rpcCallTool = createServerFn({ method: "POST" })
  .validator((data: { name: string; arguments?: ToolArgs; argsJson?: string }) => ({
    name: String(data.name),
    arguments: data.arguments ?? {},
    argsJson: data.argsJson ?? "",
  }))
  .handler(async ({ data }): Promise<RpcJson> => {
    const args = {
      ...parseArgs(data.arguments),
      ...parseArgs(data.argsJson),
    };
    return consoleCall(data.name, args);
  });
