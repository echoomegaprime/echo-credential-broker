import { useCredential, type BrokerContext } from "./broker.ts";
import { authorizedProviderFetch, githubAuthHeaders } from "./http.ts";
import { buildProviderUrl } from "./policy.ts";
import { redactValue, sanitizeError } from "./redaction.ts";
import { getStore } from "./store.ts";
import type { ToolResult } from "./types.ts";

const GITHUB_REF = "vault://github/echoomegaprime";

async function githubSecret(ctx: BrokerContext, ref: string): Promise<ToolResult<string>> {
  const store = ctx.store ?? getStore();
  const secret = await store.resolveSecret(ref);
  if (!secret) {
    return { ok: false, error: "credential_unavailable", credential_ref: ref };
  }
  return { ok: true, data: secret };
}

export async function githubGetUser(
  ctx: BrokerContext,
  credential_ref = GITHUB_REF,
): Promise<ToolResult> {
  const resolved = await githubSecret(ctx, credential_ref);
  if (!resolved.ok) return resolved;
  try {
    const result = await authorizedProviderFetch({
      provider: "github",
      url: buildProviderUrl("github", "/user"),
      method: "GET",
      secret: resolved.data,
      extraHeaders: githubAuthHeaders(),
      accept: "application/vnd.github+json",
    });
    if (!result.ok || !result.json || typeof result.json !== "object") {
      return {
        ok: false,
        error: "credential_unavailable",
        credential_ref,
        detail: `http_${result.status}`,
      };
    }
    const body = result.json as { login?: string; id?: number };
    return redactValue({
      ok: true as const,
      data: {
        login: body.login ?? null,
        id: body.id ?? null,
        authenticated: Boolean(body.login),
      },
    });
  } catch (error) {
    return {
      ok: false,
      error: "credential_unavailable",
      credential_ref,
      detail: sanitizeError(error).message,
    };
  }
}

export async function githubGetRepository(
  ctx: BrokerContext,
  input: { credential_ref?: string; owner: string; repo: string },
): Promise<ToolResult> {
  const ref = input.credential_ref ?? GITHUB_REF;
  return useCredential(ctx, {
    credential_ref: ref,
    provider: "github",
    operation: "GET",
    resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}`,
  }).then((res) => {
    if (!res.ok) return res;
    const body = res.data as { body?: Record<string, unknown>; status?: number };
    const repo = (body.body ?? body) as Record<string, unknown>;
    return redactValue({
      ok: true as const,
      data: {
        full_name: repo.full_name,
        name: repo.name,
        private: repo.private,
        description: repo.description,
        default_branch: repo.default_branch,
        html_url: repo.html_url,
        owner: (repo.owner as { login?: string } | undefined)?.login,
        visibility: repo.visibility ?? (repo.private ? "private" : "public"),
      },
    });
  });
}

export async function githubGetFile(
  ctx: BrokerContext,
  input: {
    credential_ref?: string;
    owner: string;
    repo: string;
    path: string;
    ref?: string;
  },
): Promise<ToolResult> {
  const ref = input.credential_ref ?? GITHUB_REF;
  const qs = input.ref ? `?ref=${encodeURIComponent(input.ref)}` : "";
  const path = input.path.replace(/^\/+/, "");
  return useCredential(ctx, {
    credential_ref: ref,
    provider: "github",
    operation: "GET",
    resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/contents/${path}${qs}`,
  }).then((res) => {
    if (!res.ok) return res;
    const body = (res.data as { body?: Record<string, unknown> }).body ?? {};
    return redactValue({
      ok: true as const,
      data: {
        name: body.name,
        path: body.path,
        sha: body.sha,
        size: body.size,
        type: body.type,
        encoding: body.encoding,
        content: body.content,
        html_url: body.html_url,
      },
    });
  });
}

export async function githubListRepositories(
  ctx: BrokerContext,
  input: { credential_ref?: string; per_page?: number } = {},
): Promise<ToolResult> {
  const ref = input.credential_ref ?? GITHUB_REF;
  const perPage = Math.min(Math.max(input.per_page ?? 30, 1), 100);
  return useCredential(ctx, {
    credential_ref: ref,
    provider: "github",
    operation: "GET",
    resource: `/user/repos?per_page=${perPage}&sort=updated`,
  }).then((res) => {
    if (!res.ok) return res;
    const body = (res.data as { body?: unknown }).body;
    const repos = Array.isArray(body) ? body : [];
    return redactValue({
      ok: true as const,
      data: {
        repositories: repos.map((repo) => {
          const r = repo as Record<string, unknown>;
          return {
            full_name: r.full_name,
            private: r.private,
            description: r.description,
            updated_at: r.updated_at,
          };
        }),
      },
    });
  });
}

export async function githubCreateBranch(
  ctx: BrokerContext,
  input: {
    credential_ref?: string;
    owner: string;
    repo: string;
    branch: string;
    from_sha: string;
  },
): Promise<ToolResult> {
  const ref = input.credential_ref ?? GITHUB_REF;
  return useCredential(ctx, {
    credential_ref: ref,
    provider: "github",
    operation: "POST",
    resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/git/refs`,
    body: {
      ref: `refs/heads/${input.branch}`,
      sha: input.from_sha,
    },
  });
}

export async function githubCreateOrUpdateFile(
  ctx: BrokerContext,
  input: {
    credential_ref?: string;
    owner: string;
    repo: string;
    path: string;
    message: string;
    content_base64: string;
    branch?: string;
    sha?: string;
  },
): Promise<ToolResult> {
  const ref = input.credential_ref ?? GITHUB_REF;
  const path = input.path.replace(/^\/+/, "");
  return useCredential(ctx, {
    credential_ref: ref,
    provider: "github",
    operation: "PUT",
    resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/contents/${path}`,
    body: {
      message: input.message,
      content: input.content_base64,
      branch: input.branch,
      sha: input.sha,
    },
  });
}

export async function cloudflareZoneGet(
  ctx: BrokerContext,
  input: { credential_ref?: string; zone_id: string },
): Promise<ToolResult> {
  return useCredential(ctx, {
    credential_ref: input.credential_ref ?? "vault://cloudflare/echo",
    provider: "cloudflare",
    operation: "GET",
    resource: `/client/v4/zones/${encodeURIComponent(input.zone_id)}`,
  });
}

export async function openaiAccountStatus(
  ctx: BrokerContext,
  input: { credential_ref?: string } = {},
): Promise<ToolResult> {
  return useCredential(ctx, {
    credential_ref: input.credential_ref ?? "vault://openai/primary",
    provider: "openai",
    operation: "GET",
    resource: "/v1/models",
  });
}

export async function stripeBalance(
  ctx: BrokerContext,
  input: { credential_ref?: string } = {},
): Promise<ToolResult> {
  return useCredential(ctx, {
    credential_ref: input.credential_ref ?? "vault://stripe/production",
    provider: "stripe",
    operation: "GET",
    resource: "/v1/balance",
  });
}

export async function xaiAccountStatus(
  ctx: BrokerContext,
  input: { credential_ref?: string } = {},
): Promise<ToolResult> {
  return useCredential(ctx, {
    credential_ref: input.credential_ref ?? "vault://xai/primary",
    provider: "xai",
    operation: "GET",
    resource: "/v1/models",
  });
}
