// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 GitHub capabilities, built on github-app.ts. Each handler takes
 * `(params, { client, deps })`, validates `params` strictly (unknown keys are
 * refused; only `approval_id` is tolerated and ignored), acts for exactly one
 * account from GITHUB_ACCOUNT_REGISTRY, and returns
 * `{ ok, data | error, audit }` with no secret material. `audit` carries the
 * non-secret facts the integrator should put in the ledger (credential_ref,
 * credential path + fallback reason, last GitHub HTTP status).
 *
 * Grounded in GitHub's REST docs (fetched 2026-11-14):
 *  - Transfer (`POST /repos/{owner}/{repo}/transfer`, body `new_owner`
 *    required, `new_name` / `team_ids` optional, 202 Accepted). Among
 *    fine-grained tokens it lists ONLY GitHub App *user* access tokens
 *    ("Administration" write) — not installation tokens, not fine-grained
 *    PATs — so it always runs on the owner's PAT (a classic PAT is needed).
 *    A personal → personal transfer must be accepted by the new owner within
 *    one day; the 202 response still shows the original owner.
 *  - Contents (`PUT …/contents/{path}`: message + base64 content required,
 *    `sha` required when updating, `branch` defaults to the default branch;
 *    `.github/workflows/*` additionally needs Workflows write).
 *  - Pulls (`POST …/pulls`: `head` and `base` required, `draft` optional;
 *    draft PRs in private repos need a paid plan).
 * Installation tokens are down-scoped to the one repository and the minimum
 * permissions for each action; if GitHub answers 403 "Resource not accessible
 * by integration", the action is retried once on the exact-identity PAT. Every
 * handler performs its single write as its LAST GitHub call, so that retry
 * can never repeat a write that succeeded.
 */
import { log } from "../log.ts";
import { PROVIDER_POLICIES } from "../policy.ts";
import { containsSecretPrefix, redactString, redactValue, sanitizeError } from "../redaction.ts";
import type { ClientIdentity } from "./contracts.ts";
import {
  getGithubCredential,
  GITHUB_ACCOUNT_REGISTRY,
  GithubCredentialError,
  isValidRepoName,
  type GithubAppDeps,
  type GithubCredentialHandle,
  type GithubCredentialMetadata,
  type GithubCredentialRequest,
  type GithubRequester,
  type GithubResponse,
} from "./github-app.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GithubCapabilityContext {
  client: ClientIdentity;
  deps?: GithubAppDeps;
}

/** Non-secret facts for the ledger. */
export interface GithubCapabilityAudit {
  credential_ref?: string;
  credential_path?: "installation" | "pat_fallback";
  fallback_reason?: string;
  installation_id?: number;
  http_status?: number;
}

export type GithubCapabilityResult<T = Record<string, unknown>> =
  | { ok: true; data: T; audit: GithubCapabilityAudit }
  | { ok: false; error: string; detail?: string; audit: GithubCapabilityAudit };

export type GithubCapabilityHandler = (
  params: Record<string, unknown>,
  ctx: GithubCapabilityContext,
) => Promise<GithubCapabilityResult>;

class CapabilityError extends Error {
  readonly code: string;
  constructor(code: string, detail: string) {
    super(detail);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Pure validation helpers (exported for the integrator / policy engine)
// ---------------------------------------------------------------------------

/** GitHub login / org name: alphanumerics and single inner hyphens, ≤ 39 chars. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
// eslint-disable-next-line no-control-regex -- refusing control characters is the point
const REF_FORBIDDEN_CHARS = /[\u0000- \u007f~^:?*[\\]/;
const SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function isValidGithubOwner(value: unknown): value is string {
  return typeof value === "string" && OWNER_RE.test(value);
}

export { isValidRepoName };

/** `git check-ref-format`-style branch name check (no `refs/` prefix, ≤ 255 chars). */
export function isValidBranchName(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 255) return false;
  if (value === "HEAD" || value === "@" || value.startsWith("refs/") || value.startsWith("-")) return false;
  if (REF_FORBIDDEN_CHARS.test(value) || value.includes("..") || value.includes("@{") || value.includes("//")) return false;
  if (value.startsWith("/") || value.endsWith("/") || value.endsWith(".")) return false;
  return value.split("/").every((part) => part.length > 0 && !part.startsWith(".") && !part.endsWith(".lock"));
}

/**
 * Validate a repository file path and return it URL-encoded per segment, or
 * null. Refuses traversal (`.`/`..`), empty segments, leading/trailing `/`,
 * backslashes, control characters, `%`, and anything under `.git/`.
 */
export function encodeContentPath(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) return null;
  // eslint-disable-next-line no-control-regex -- refusing control characters is the point
  if (value.includes("\\") || value.includes("%") || /[\u0000-\u001f\u007f]/.test(value)) return null;
  const segments = value.split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) return null;
  if (segments[0].toLowerCase() === ".git") return null;
  return segments.map(encodeURIComponent).join("/");
}

/** Writing workflows lets repository code read repository secrets in CI — refused for agents. */
export function isWorkflowPath(path: string): boolean {
  return /^\.github\/workflows\//i.test(path);
}

export type ContentsWriteTarget = "agent_branch" | "default_branch" | "other_branch";

/** Branch prefixes treated as agent-owned scratch space. */
export const DEFAULT_AGENT_BRANCH_PREFIXES: readonly string[] = Object.freeze(["agent/", "claude/"]);

/**
 * Pure: classify a contents write so the integrator can choose the capability
 * ID / tier (default-branch writes are tier 2). An empty branch means GitHub's
 * default, so it classifies as "default_branch". Comparison is exact (git
 * branch names are case-sensitive).
 */
export function classifyContentsWrite(input: {
  branch: string;
  default_branch: string;
  agent_branch_prefixes?: readonly string[];
}): ContentsWriteTarget {
  const strip = (b: string) => (typeof b === "string" ? b.trim().replace(/^refs\/heads\//, "") : "");
  const branch = strip(input.branch);
  if (!branch || branch === strip(input.default_branch)) return "default_branch";
  const prefixes = input.agent_branch_prefixes ?? DEFAULT_AGENT_BRANCH_PREFIXES;
  return prefixes.some((p) => p.length > 0 && branch.startsWith(p) && branch.length > p.length) ? "agent_branch" : "other_branch";
}

/** Canonical policy resource for a GitHub capability's params, e.g. "github:ECHO-OMEGA-PRIME/cleanbrees". */
export function githubResourceFor(params: Record<string, unknown>): string | null {
  return isValidGithubOwner(params?.owner) && isValidRepoName(params?.repo) ? `github:${params.owner}/${params.repo}` : null;
}

// ---------------------------------------------------------------------------
// Param parsing
// ---------------------------------------------------------------------------

const IGNORED_PARAM_KEYS: ReadonlySet<string> = new Set(["approval_id"]);

function readParams(params: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!params || typeof params !== "object" || Array.isArray(params)) throw new CapabilityError("invalid_params", "params must be an object");
  for (const key of Object.keys(params)) {
    if (!allowed.includes(key) && !IGNORED_PARAM_KEYS.has(key)) {
      throw new CapabilityError("invalid_params", `unknown param: ${key.slice(0, 64)}`);
    }
  }
  return params as Record<string, unknown>;
}

function registeredOwner(p: Record<string, unknown>, key: string): string {
  const value = p[key];
  if (!isValidGithubOwner(value)) throw new CapabilityError("invalid_params", `${key}: not a valid GitHub login`);
  if (!Object.hasOwn(GITHUB_ACCOUNT_REGISTRY, value)) {
    throw new CapabilityError(`${key}_not_allowed`, `${key} must be exactly one of: ${Object.keys(GITHUB_ACCOUNT_REGISTRY).join(", ")}`);
  }
  return value;
}

function repoName(p: Record<string, unknown>, key: string): string {
  const value = p[key];
  if (!isValidRepoName(value)) throw new CapabilityError("invalid_params", `${key}: not a valid repository name`);
  return value;
}

function branchName(p: Record<string, unknown>, key: string): string {
  const value = p[key];
  if (!isValidBranchName(value)) throw new CapabilityError("invalid_params", `${key}: not a valid branch name`);
  return value;
}

const SECRET_PLACEHOLDER_RE = /\[REDACTED_(?:GITHUB_TOKEN|OPENAI_KEY|STRIPE_KEY|XAI_KEY|PRIVATE_KEY|SECRET)\]/g;

/** Provider tokens, private keys, or a value registered with redaction.ts — not mere mentions of "Authorization". */
function looksSecret(text: string): boolean {
  if (containsSecretPrefix(text) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text) || /gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/.test(text)) {
    return true;
  }
  const before = text.match(SECRET_PLACEHOLDER_RE)?.length ?? 0;
  return (redactString(text).match(SECRET_PLACEHOLDER_RE)?.length ?? 0) > before;
}

function boundedText(p: Record<string, unknown>, key: string, max: number, required: boolean): string | undefined {
  const value = p[key];
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || (required && !value.trim()) || value.length > max) {
    throw new CapabilityError("invalid_params", `${key}: expected a string of at most ${max} characters`);
  }
  if (looksSecret(value)) throw new CapabilityError("content_contains_secret", `${key} contains credential-shaped text; refusing to publish it`);
  return value;
}

const repoPath = (owner: string, repo: string) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

// ---------------------------------------------------------------------------
// Credential + GitHub plumbing
// ---------------------------------------------------------------------------

function recordCredential(audit: GithubCapabilityAudit, meta: GithubCredentialMetadata): void {
  audit.credential_ref = meta.credential_ref;
  audit.credential_path = meta.path;
  audit.fallback_reason = meta.fallback_reason;
  audit.installation_id = meta.installation_id;
}

function integrationDenied(res: GithubResponse): boolean {
  const message = (res.json as { message?: unknown } | null)?.message;
  return res.status === 403 && typeof message === "string" && /resource not accessible by integration/i.test(message);
}

/**
 * Run `fn` with a credential for `req`. If an installation token is refused
 * with "Resource not accessible by integration", retry once on the PAT path.
 * `fn` must make its only write as its last request (see header).
 */
async function withGithub(
  req: GithubCredentialRequest,
  ctx: GithubCapabilityContext,
  audit: GithubCapabilityAudit,
  fn: (gh: GithubRequester, cred: GithubCredentialMetadata) => Promise<GithubCapabilityResult>,
): Promise<GithubCapabilityResult> {
  const run = async (handle: GithubCredentialHandle) => {
    recordCredential(audit, handle.metadata());
    let denied = false;
    const result = await handle.use((gh) =>
      fn(
        {
          async request(method, path, opts) {
            const res = await gh.request(method, path, opts);
            audit.http_status = res.status;
            if (integrationDenied(res)) denied = true;
            return res;
          },
        },
        handle.metadata(),
      ),
    );
    return { result, denied };
  };
  const first = await getGithubCredential(req, ctx.deps);
  const attempt = await run(first);
  if (!attempt.denied || first.kind !== "installation") return attempt.result;
  log.warn("github_installation_denied_retrying_with_pat", { purpose: req.purpose, account: req.account_login });
  const retry = await getGithubCredential({ ...req, installation_unsupported_reason: "installation_forbidden_for_operation" }, ctx.deps);
  return (await run(retry)).result;
}

function githubFailure(res: GithubResponse, audit: GithubCapabilityAudit, hint?: string): GithubCapabilityResult {
  audit.http_status = res.status;
  const message = (res.json as { message?: unknown } | null)?.message;
  const detail = [typeof message === "string" ? redactString(message).slice(0, 300) : undefined, hint].filter(Boolean).join(" — ");
  return { ok: false, error: `github_http_${res.status}`, detail: detail || undefined, audit };
}

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function defineCapability(
  id: string,
  impl: (params: Record<string, unknown>, ctx: GithubCapabilityContext, audit: GithubCapabilityAudit) => Promise<GithubCapabilityResult>,
): GithubCapabilityHandler {
  return async (params, ctx) => {
    const started = Date.now();
    const audit: GithubCapabilityAudit = {};
    let result: GithubCapabilityResult;
    try {
      if (!ctx?.client || typeof ctx.client.client_id !== "string" || !ctx.client.client_id) {
        throw new CapabilityError("invalid_client", "an authenticated client identity is required");
      }
      result = await impl(params, ctx, audit);
    } catch (error) {
      if (error instanceof CapabilityError) result = { ok: false, error: error.code, detail: error.message, audit };
      else if (error instanceof GithubCredentialError) result = { ok: false, error: error.code, detail: error.detail, audit };
      else result = { ok: false, error: "github_request_failed", detail: sanitizeError(error).message.slice(0, 300), audit };
    }
    log.info("github_capability", {
      capability: id,
      client_id: ctx?.client?.client_id ?? null,
      ok: result.ok,
      error: result.ok ? null : result.error,
      http_status: result.audit.http_status ?? null,
      credential_path: result.audit.credential_path ?? null,
      fallback_reason: result.audit.fallback_reason ?? null,
      duration_ms: Date.now() - started,
    });
    for (const key of Object.keys(result.audit) as Array<keyof GithubCapabilityAudit>) {
      if (result.audit[key] === undefined) delete result.audit[key];
    }
    return redactValue(result);
  };
}

function safeRepo(json: unknown): Record<string, unknown> {
  const r = (json ?? {}) as Record<string, unknown>;
  const owner = (r.owner ?? {}) as Record<string, unknown>;
  return {
    full_name: str(r.full_name),
    name: str(r.name),
    owner: str(owner.login),
    owner_type: str(owner.type),
    private: typeof r.private === "boolean" ? r.private : undefined,
    visibility: str(r.visibility),
    default_branch: str(r.default_branch),
    archived: typeof r.archived === "boolean" ? r.archived : undefined,
    html_url: str(r.html_url),
    description: str(r.description),
  };
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/** github.repo.read — repository metadata. */
export const githubRepoGet: GithubCapabilityHandler = defineCapability("github.repo.read", async (params, ctx, audit) => {
  const p = readParams(params, ["owner", "repo"]);
  const owner = registeredOwner(p, "owner");
  const repo = repoName(p, "repo");
  return withGithub(
    { account_login: owner, account_id: GITHUB_ACCOUNT_REGISTRY[owner], purpose: "github.repo.read", repositories: [repo], permissions: { metadata: "read" } },
    ctx,
    audit,
    async (gh) => {
      const res = await gh.request("GET", repoPath(owner, repo));
      if (!res.ok) return githubFailure(res, audit);
      return { ok: true, data: safeRepo(res.json), audit };
    },
  );
});

/** github.repo.transfer — move a repository between registry accounts. */
export const githubRepoTransfer: GithubCapabilityHandler = defineCapability("github.repo.transfer", async (params, ctx, audit) => {
  const p = readParams(params, ["owner", "repo", "new_owner", "new_name"]);
  const owner = registeredOwner(p, "owner");
  const repo = repoName(p, "repo");
  const newOwner = registeredOwner(p, "new_owner");
  const newName = p.new_name === undefined ? undefined : repoName(p, "new_name");
  if (owner === newOwner) throw new CapabilityError("invalid_params", "new_owner must differ from owner (that is a rename, not a transfer)");
  return withGithub(
    {
      account_login: owner,
      account_id: GITHUB_ACCOUNT_REGISTRY[owner],
      purpose: "github.repo.transfer",
      // GitHub lists only App *user* tokens for this endpoint — installation tokens cannot transfer.
      installation_unsupported_reason: "transfer_requires_user_token",
    },
    ctx,
    audit,
    async (gh, cred) => {
      // Exact identity of the destination too: a renamed/re-registered login must not receive the repo.
      const target = await gh.request("GET", `/users/${encodeURIComponent(newOwner)}`);
      if (!target.ok) return githubFailure(target, audit, "new_owner lookup failed");
      const t = (target.json ?? {}) as { login?: unknown; id?: unknown; type?: unknown };
      if (t.login !== newOwner || t.id !== GITHUB_ACCOUNT_REGISTRY[newOwner]) {
        return { ok: false, error: "identity_mismatch", detail: `new_owner ${newOwner} does not resolve to account ${GITHUB_ACCOUNT_REGISTRY[newOwner]}`, audit };
      }
      const body: Record<string, string> = { new_owner: newOwner };
      if (newName) body.new_name = newName;
      const res = await gh.request("POST", `${repoPath(owner, repo)}/transfer`, { body });
      if (!res.ok) {
        const hint =
          cred.pat_kind === "fine_grained" && (res.status === 403 || res.status === 404)
            ? "GitHub documents this endpoint for App user tokens only; a fine-grained PAT is likely insufficient — use a classic PAT"
            : undefined;
        return githubFailure(res, audit, hint);
      }
      const r = (res.json ?? {}) as Record<string, unknown>;
      const sourceType = str((r.owner as Record<string, unknown> | undefined)?.type);
      const targetType = str(t.type);
      const requiresAcceptance = sourceType && targetType ? sourceType === "User" && targetType === "User" : null;
      return {
        ok: true,
        data: {
          status: res.status,
          accepted_for_processing: res.status === 202,
          full_name: str(r.full_name),
          html_url: str(r.html_url),
          from: `${owner}/${repo}`,
          to: `${newOwner}/${newName ?? repo}`,
          source_owner_type: sourceType,
          target_owner_type: targetType,
          requires_new_owner_acceptance: requiresAcceptance,
          note:
            requiresAcceptance === false
              ? "GitHub transfers asynchronously; the response still shows the original owner. Transfers into an organization need repo-creation permission there and can be blocked by organization policy."
              : "GitHub may require the new owner to accept: a personal-account to personal-account transfer emails the new owner, who must accept within one day or the invitation expires. Until then the repository stays at the original owner.",
        },
        audit,
      };
    },
  );
});

/** Look up the default branch and classify a prospective write (for capability/tier selection). */
export async function resolveContentsWriteTarget(
  params: { owner: string; repo: string; branch: string; agent_branch_prefixes?: readonly string[] },
  ctx: GithubCapabilityContext,
): Promise<GithubCapabilityResult<{ classification: ContentsWriteTarget; default_branch: string }>> {
  const repo = await githubRepoGet({ owner: params.owner, repo: params.repo }, ctx);
  if (!repo.ok) return repo;
  const defaultBranch = str(repo.data.default_branch);
  if (!defaultBranch) return { ok: false, error: "default_branch_unknown", audit: repo.audit };
  return {
    ok: true,
    data: {
      classification: classifyContentsWrite({ branch: params.branch, default_branch: defaultBranch, agent_branch_prefixes: params.agent_branch_prefixes }),
      default_branch: defaultBranch,
    },
    audit: repo.audit,
  };
}

/** github.contents.write — create/update one file; refuses the default branch unless allow_default_branch: true. */
export const githubContentsWrite: GithubCapabilityHandler = defineCapability("github.contents.write", async (params, ctx, audit) => {
  const p = readParams(params, ["owner", "repo", "path", "branch", "content_base64", "message", "sha", "allow_default_branch"]);
  const owner = registeredOwner(p, "owner");
  const repo = repoName(p, "repo");
  const path = p.path;
  const encodedPath = encodeContentPath(path);
  if (!encodedPath || typeof path !== "string") throw new CapabilityError("invalid_params", "path: not a valid repository file path");
  if (isWorkflowPath(path)) {
    throw new CapabilityError("workflow_path_refused", "writing .github/workflows/* would let CI read repository secrets; refused for agents");
  }
  const branch = branchName(p, "branch");
  const message = boundedText(p, "message", 4096, true) as string;
  if (p.sha !== undefined && (typeof p.sha !== "string" || !SHA_RE.test(p.sha))) throw new CapabilityError("invalid_params", "sha: expected a blob SHA");
  if (p.allow_default_branch !== undefined && typeof p.allow_default_branch !== "boolean") {
    throw new CapabilityError("invalid_params", "allow_default_branch: expected a boolean");
  }
  if (typeof p.content_base64 !== "string") throw new CapabilityError("invalid_params", "content_base64: expected a base64 string");
  const content = p.content_base64.replace(/[\r\n]/g, "");
  if (content.length % 4 !== 0 || !BASE64_RE.test(content)) throw new CapabilityError("invalid_params", "content_base64: not valid base64");
  if (content.length > PROVIDER_POLICIES.github.maxRequestBytes - 8192) throw new CapabilityError("content_too_large", "content exceeds the broker request limit");
  if (looksSecret(Buffer.from(content, "base64").toString("utf8"))) {
    throw new CapabilityError("content_contains_secret", "file content contains credential-shaped text; refusing to commit it");
  }

  return withGithub(
    {
      account_login: owner,
      account_id: GITHUB_ACCOUNT_REGISTRY[owner],
      purpose: "github.contents.write",
      repositories: [repo],
      permissions: { contents: "write", metadata: "read" },
    },
    ctx,
    audit,
    async (gh) => {
      const repoRes = await gh.request("GET", repoPath(owner, repo));
      if (!repoRes.ok) return githubFailure(repoRes, audit);
      const defaultBranch = str((repoRes.json as Record<string, unknown> | null)?.default_branch);
      if (!defaultBranch) return { ok: false, error: "default_branch_unknown", audit };
      const classification = classifyContentsWrite({ branch, default_branch: defaultBranch });
      if (classification === "default_branch" && p.allow_default_branch !== true) {
        return {
          ok: false,
          error: "default_branch_write_refused",
          detail: `${branch} is the default branch of ${owner}/${repo}; writing it requires allow_default_branch: true (tier 2)`,
          audit,
        };
      }
      const body: Record<string, string> = { message, content, branch };
      if (typeof p.sha === "string") body.sha = p.sha;
      const put = await gh.request("PUT", `${repoPath(owner, repo)}/contents/${encodedPath}`, { body });
      if (!put.ok) return githubFailure(put, audit);
      const j = (put.json ?? {}) as { content?: Record<string, unknown>; commit?: Record<string, unknown> };
      return {
        ok: true,
        data: {
          full_name: `${owner}/${repo}`,
          path: str(j.content?.path) ?? path,
          branch,
          classification,
          default_branch: defaultBranch,
          created: put.status === 201,
          content_sha: str(j.content?.sha),
          commit_sha: str(j.commit?.sha),
          commit_html_url: str(j.commit?.html_url),
        },
        audit,
      };
    },
  );
});

/** github.pr.create_draft — open a draft pull request within one repository. */
export const githubPrCreateDraft: GithubCapabilityHandler = defineCapability("github.pr.create_draft", async (params, ctx, audit) => {
  const p = readParams(params, ["owner", "repo", "title", "head", "base", "body"]);
  const owner = registeredOwner(p, "owner");
  const repo = repoName(p, "repo");
  const title = boundedText(p, "title", 256, true) as string;
  const prBody = boundedText(p, "body", 65_536, false);
  const head = branchName(p, "head");
  const requestedBase = p.base === undefined ? undefined : branchName(p, "base");
  if (requestedBase !== undefined && requestedBase === head) throw new CapabilityError("invalid_params", "head and base must differ");

  return withGithub(
    {
      account_login: owner,
      account_id: GITHUB_ACCOUNT_REGISTRY[owner],
      purpose: "github.pr.create_draft",
      repositories: [repo],
      permissions: { pull_requests: "write", metadata: "read" },
    },
    ctx,
    audit,
    async (gh) => {
      let base = requestedBase;
      if (base === undefined) {
        const repoRes = await gh.request("GET", repoPath(owner, repo));
        if (!repoRes.ok) return githubFailure(repoRes, audit);
        base = str((repoRes.json as Record<string, unknown> | null)?.default_branch);
        if (!base) return { ok: false, error: "default_branch_unknown", audit };
        if (base === head) return { ok: false, error: "invalid_params", detail: "head is the default branch; nothing to propose", audit };
      }
      const body: Record<string, unknown> = { title, head, base, draft: true };
      if (prBody !== undefined) body.body = prBody;
      const res = await gh.request("POST", `${repoPath(owner, repo)}/pulls`, { body });
      if (!res.ok) return githubFailure(res, audit);
      const pr = (res.json ?? {}) as Record<string, unknown>;
      return {
        ok: true,
        data: {
          number: typeof pr.number === "number" ? pr.number : undefined,
          html_url: str(pr.html_url),
          draft: typeof pr.draft === "boolean" ? pr.draft : undefined,
          state: str(pr.state),
          head: str((pr.head as Record<string, unknown> | undefined)?.ref) ?? head,
          base: str((pr.base as Record<string, unknown> | undefined)?.ref) ?? base,
        },
        audit,
      };
    },
  );
});

/** Capability ID → handler. */
export const GITHUB_CAPABILITIES: Readonly<Record<string, GithubCapabilityHandler>> = Object.freeze({
  "github.repo.read": githubRepoGet,
  "github.repo.transfer": githubRepoTransfer,
  "github.contents.write": githubContentsWrite,
  "github.pr.create_draft": githubPrCreateDraft,
});
