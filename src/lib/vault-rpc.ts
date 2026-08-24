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
