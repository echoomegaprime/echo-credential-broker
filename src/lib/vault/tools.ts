import { listAudit, recordAudit } from "./audit.ts";
import { useCredential, type BrokerContext } from "./broker.ts";
import { ensureImported, importSandboxCredentials } from "./importer.ts";
import {
  githubGetFile,
  githubGetRepository,
  githubGetUser,
  githubListRepositories,
  githubCreateBranch,
  githubCreateOrUpdateFile,
  cloudflareZoneGet,
  openaiAccountStatus,
  stripeBalance,
  xaiAccountStatus,
} from "./providers.ts";
import { isApprovedCaller, PROVIDER_POLICIES } from "./policy.ts";
import { installProcessRedaction, redactValue, sanitizeError } from "./redaction.ts";
import { parseVaultRef } from "./refs.ts";
import { getStore } from "./store.ts";
import {
  FORBIDDEN_TOOLS,
  INVARIANT,
  type HttpMethod,
  type ProviderId,
  type ToolResult,
} from "./types.ts";

if (!process.env.NODE_TEST_CONTEXT) {
  installProcessRedaction();
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "vault_status",
    description:
      "Return broker status, invariant, and whether sandbox credentials were imported. Never returns secrets.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_list",
    description:
      "List opaque vault:// credential references with metadata only. Never returns tokens.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_find",
    description:
      "Search the canonical vault for candidate credentials matching a name (e.g. a vendor). Returns service/username candidates only — never a secret. Use this to discover the right account before calling a tool with an explicit credential_ref.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  },
  {
    name: "vault_metadata",
    description: "Return metadata for a single vault:// reference. Never returns the secret.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
      required: ["credential_ref"],
    },
  },
  {
    name: "credential_health",
    description:
      "Verify a credential by performing a provider identity check (GitHub GET /user). Returns account metadata, never the PAT.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
      required: ["credential_ref"],
    },
  },
  {
    name: "credential_use",
    description:
      "Perform an authenticated provider action using an opaque vault:// reference. The model never receives the credential.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        provider: { type: "string" },
        operation: { type: "string" },
        resource: { type: "string" },
        body: {},
      },
      required: ["credential_ref", "provider", "operation", "resource"],
    },
  },
  {
    name: "provider_request",
    description:
      "Constrained HTTPS request to an allowlisted provider host. No caller-supplied Authorization header. No arbitrary URLs.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        provider: { type: "string" },
        method: { type: "string" },
        path: { type: "string" },
        body: {},
      },
      required: ["credential_ref", "provider", "method", "path"],
    },
  },
  {
    name: "credential_rotate",
    description:
      "Re-import the credential from the trusted sandbox source. Does not return the new secret.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
      required: ["credential_ref"],
    },
  },
  {
    name: "credential_revoke",
    description:
      "Revoke a vault:// handle inside the broker. The secret is overwritten and can no longer be used.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
      required: ["credential_ref"],
    },
  },
  {
    name: "github_get_user",
    description: "Safe GitHub identity check via GET /user. Returns login and id only.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
    },
  },
  {
    name: "github_get_repository",
    description: "Fetch repository metadata. Authorization is injected server-side.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        owner: { type: "string" },
        repo: { type: "string" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "github_get_file",
    description: "Read a file from a GitHub repository using the vault credential.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        owner: { type: "string" },
        repo: { type: "string" },
        path: { type: "string" },
        ref: { type: "string" },
      },
      required: ["owner", "repo", "path"],
    },
  },
  {
    name: "github_list_repositories",
    description: "List repositories visible to the vault GitHub credential.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        per_page: { type: "number" },
      },
    },
  },
  {
    name: "github_create_branch",
    description: "Create a branch in a GitHub repository using the vault credential.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        owner: { type: "string" },
        repo: { type: "string" },
        branch: { type: "string" },
        from_sha: { type: "string" },
      },
      required: ["owner", "repo", "branch", "from_sha"],
    },
  },
  {
    name: "github_create_or_update_file",
    description: "Create or update a file in a GitHub repository using the vault credential.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        owner: { type: "string" },
        repo: { type: "string" },
        path: { type: "string" },
        message: { type: "string" },
        content_base64: { type: "string" },
        branch: { type: "string" },
        sha: { type: "string" },
      },
      required: ["owner", "repo", "path", "message", "content_base64"],
    },
  },
  {
    name: "cloudflare_zone_get",
    description: "Fetch a Cloudflare zone by id using vault://cloudflare/echo.",
    inputSchema: {
      type: "object",
      properties: {
        credential_ref: { type: "string" },
        zone_id: { type: "string" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "openai_account_status",
    description: "List OpenAI models as an account-status probe. Never returns the API key.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
    },
  },
  {
    name: "stripe_balance",
    description: "Fetch Stripe balance using vault://stripe/production. Never returns the secret key.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
    },
  },
  {
    name: "xai_account_status",
    description: "Probe xAI account via GET /v1/models using vault://xai/primary.",
    inputSchema: {
      type: "object",
      properties: { credential_ref: { type: "string" } },
    },
  },
  {
    name: "audit_list",
    description: "Return recent broker audit records. Secrets are never recorded.",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number" } },
    },
  },
];

function asRecord(args: unknown): Record<string, unknown> {
  if (args && typeof args === "object" && !Array.isArray(args)) {
    return args as Record<string, unknown>;
  }
  return {};
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
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

export async function credentialRotate(
  ctx: BrokerContext,
  credential_ref: string,
): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  const parsed = parseVaultRef(credential_ref);
  if (!parsed) {
    return { ok: false, error: "invalid_credential_ref", credential_ref };
  }
  const report = await importSandboxCredentials(store);
  const meta = store.getMetadata(parsed.raw);
  if (!meta) {
    return { ok: false, error: "credential_unavailable", credential_ref: parsed.raw };
  }
  recordAudit({
    caller: ctx.caller,
    credential_ref: parsed.raw,
    provider: parsed.provider,
    operation: "rotate",
    resource: parsed.raw,
    http_status: null,
    duration_ms: 0,
    result: "ok",
  });
  return redactValue({
    ok: true as const,
    data: { rotated: parsed.raw, imported: report.imported, metadata: meta },
  });
}

export async function credentialRevoke(
  ctx: BrokerContext,
  credential_ref: string,
): Promise<ToolResult> {
  const store = ctx.store ?? getStore();
  const parsed = parseVaultRef(credential_ref);
  if (!parsed) {
    return { ok: false, error: "invalid_credential_ref", credential_ref };
  }
  const ok = await store.revoke(parsed.raw);
  if (!ok) {
    return { ok: false, error: "credential_unavailable", credential_ref: parsed.raw };
  }
  recordAudit({
    caller: ctx.caller,
    credential_ref: parsed.raw,
    provider: parsed.provider,
    operation: "revoke",
    resource: parsed.raw,
    http_status: null,
    duration_ms: 0,
    result: "ok",
  });
  return redactValue({ ok: true as const, data: { revoked: parsed.raw } });
}

export async function callTool(
  name: string,
  args: unknown,
  ctx: BrokerContext,
): Promise<ToolResult> {
  if (!isApprovedCaller(ctx.caller)) {
    return { ok: false, error: "caller_not_allowed" };
  }
  if ((FORBIDDEN_TOOLS as readonly string[]).includes(name)) {
    return { ok: false, error: "tool_forbidden" };
  }
  const a = asRecord(args);
  try {
    switch (name) {
      case "vault_status":
        return await vaultStatus(ctx);
      case "vault_list":
        return await vaultList(ctx);
      case "vault_find":
        return await vaultFind(ctx, String(a.query ?? ""));
      case "vault_metadata":
        return await vaultMetadata(ctx, String(a.credential_ref ?? ""));
      case "credential_health":
        return await credentialHealth(ctx, String(a.credential_ref ?? ""));
      case "credential_use":
        return await useCredential(ctx, {
          credential_ref: String(a.credential_ref ?? ""),
          provider: a.provider as ProviderId,
          operation: String(a.operation ?? "GET"),
          resource: String(a.resource ?? ""),
          body: a.body,
        });
      case "provider_request":
        return await useCredential(ctx, {
          credential_ref: String(a.credential_ref ?? ""),
          provider: a.provider as ProviderId,
          operation: String(a.method ?? "GET") as HttpMethod,
          resource: String(a.path ?? ""),
          body: a.body,
        });
      case "credential_rotate":
        return await credentialRotate(ctx, String(a.credential_ref ?? ""));
      case "credential_revoke":
        return await credentialRevoke(ctx, String(a.credential_ref ?? ""));
      case "github_get_user":
        return await githubGetUser(ctx, str(a.credential_ref));
      case "github_get_repository":
        return await githubGetRepository(ctx, {
          credential_ref: str(a.credential_ref),
          owner: String(a.owner ?? ""),
          repo: String(a.repo ?? ""),
        });
      case "github_get_file":
        return await githubGetFile(ctx, {
          credential_ref: str(a.credential_ref),
          owner: String(a.owner ?? ""),
          repo: String(a.repo ?? ""),
          path: String(a.path ?? ""),
          ref: str(a.ref),
        });
      case "github_list_repositories":
        return await githubListRepositories(ctx, {
          credential_ref: str(a.credential_ref),
          per_page: typeof a.per_page === "number" ? a.per_page : undefined,
        });
      case "github_create_branch":
        return await githubCreateBranch(ctx, {
          credential_ref: str(a.credential_ref),
          owner: String(a.owner ?? ""),
          repo: String(a.repo ?? ""),
          branch: String(a.branch ?? ""),
          from_sha: String(a.from_sha ?? ""),
        });
      case "github_create_or_update_file":
        return await githubCreateOrUpdateFile(ctx, {
          credential_ref: str(a.credential_ref),
          owner: String(a.owner ?? ""),
          repo: String(a.repo ?? ""),
          path: String(a.path ?? ""),
          message: String(a.message ?? ""),
          content_base64: String(a.content_base64 ?? ""),
          branch: str(a.branch),
          sha: str(a.sha),
        });
      case "cloudflare_zone_get":
        return await cloudflareZoneGet(ctx, {
          credential_ref: str(a.credential_ref),
          zone_id: String(a.zone_id ?? ""),
        });
      case "openai_account_status":
        return await openaiAccountStatus(ctx, {
          credential_ref: str(a.credential_ref),
        });
      case "stripe_balance":
        return await stripeBalance(ctx, { credential_ref: str(a.credential_ref) });
      case "xai_account_status":
        return await xaiAccountStatus(ctx, { credential_ref: str(a.credential_ref) });
      case "audit_list":
        return redactValue({
          ok: true as const,
          data: {
            records: listAudit(typeof a.limit === "number" ? a.limit : 100),
          },
        });
      default:
        return { ok: false, error: "unknown_tool" };
    }
  } catch (error) {
    const clean = sanitizeError(error);
    return { ok: false, error: "internal_error", detail: clean.message };
  }
}

export function listTools(): ToolDefinition[] {
  return TOOL_DEFINITIONS;
}
