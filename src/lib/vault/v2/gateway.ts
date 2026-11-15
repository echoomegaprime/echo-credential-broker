// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 gateway — the ONE entry point for every tool call, on every
 * transport (HTTP MCP, REST, stdio). Nothing else may execute a tool.
 *
 *   dispatchTool(identity, name, args)
 *     1. tool name → { capability, resource, params } (a "plan"; no side effects
 *        beyond metadata lookups)
 *     2. evaluatePolicy(request)
 *     3. deny      → ledger(denied), { ok:false, error:<reason> }
 *        escalate  → with args.approval_id: consumeApproval(id, request) must be
 *                    "ok" (single use, same client, same params, unexpired);
 *                    without: createApproval → Telegram, ledger(pending_approval),
 *                    { ok:false, error:"approval_required", approval_id, expires_at }
 *        allow     → run
 *     4. ledger(ok | error). A result that cannot be ledgered is not returned.
 *
 * `identity` comes from the transport's authentication (OAuth bearer token,
 * workload token, or the local stdio process) — never from a caller-supplied
 * header or argument. `approval_id` is never part of the digested params, so a
 * retry with the approval hashes to the same request the owner approved.
 *
 * Tiers come from policy-engine.ts. Three rules live here because they depend
 * on the tool rather than the capability:
 *
 *   Generic proxy (`credential_use`, `provider_request`): the broker cannot
 *   know what an arbitrary request does, so it classifies by HTTP method only.
 *   GET/HEAD → `<provider>.api.read` (tier 0). Anything else →
 *   `<provider>.api.write` (tier 2: every single request is approved on
 *   Telegram), except Stripe, where a non-GET is a payment operation
 *   (`payment.stripe.write`, tier 3: refused). There is no tier-1 carve-out
 *   inside the proxy: reversible writes have their own tools
 *   (github_create_branch, github_create_or_update_file, github_create_draft_pr)
 *   whose handlers validate what is written.
 *
 *   Entry use (`entry_use`): one HTTPS request to the entry's own site with
 *   the secret injected server-side. GET/HEAD → `vault.entry.use.read`
 *   (tier 0) PLUS consent: a read-only use is allowed without a prompt only
 *   when the client holds a matching, unexpired, unspent grant
 *   (entry-grants.ts) scoped to that exact entry, host and request path (or a
 *   path under it); otherwise the first such read needs one Telegram approval,
 *   which creates a narrow grant (host + path_prefix, TTL ECHO_VAULT_GRANT_TTL_MS,
 *   cap ECHO_VAULT_GRANT_MAX_USES). Each later covered read spends one use. The
 *   owner withdraws a grant with revokeEntryGrant. Any other method →
 *   `vault.entry.use.write` (tier 2): approved per request, every time, and it
 *   neither needs nor creates a grant. A 401 from the site (bad credential)
 *   flags that one entry for re-entry; a 403 (forbidden) returns site_forbidden
 *   and leaves the entry active.
 *
 *   Contents write (`github_create_or_update_file`): policy-engine.ts makes
 *   `agent/*` branches tier 1 and every other branch tier 2. The handler
 *   (github-capabilities.ts, classifyContentsWrite) refuses the repository's
 *   default branch unless this gateway passes allow_default_branch, which it
 *   does only when an approval for this exact request was consumed.
 *
 * Secrets: results pass through redaction before they are returned; ledger
 * rows are sanitized by ledger.ts; approval summaries by approvals.ts. Entry
 * metadata returned to agents omits the secret's fingerprint and length.
 */
import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { useCredential, type BrokerContext } from "../broker.ts";
import { log } from "../log.ts";
import { isBlockedHost, isPrivateOrLinkLocalIp, normalizeResourcePath, PROVIDER_POLICIES } from "../policy.ts";
import {
  cloudflareZoneGet,
  githubCreateBranch,
  githubGetFile,
  githubGetRepository,
  githubGetUser,
  githubListRepositories,
  openaiAccountStatus,
  stripeBalance,
  xaiAccountStatus,
} from "../providers.ts";
import { redactString, redactValue, registerSecretForRedaction, sanitizeError } from "../redaction.ts";
import { isProviderId, parseVaultRef } from "../refs.ts";
import type { CredentialStore } from "../store.ts";
import { credentialHealth, vaultFind, vaultList, vaultMetadata, vaultStatus } from "../tools.ts";
import { FORBIDDEN_TOOLS, INVARIANT, type ProviderId } from "../types.ts";
import {
  ApprovalError,
  consumeApproval,
  createApproval,
  getApproval,
  sanitizeDisplayText,
  type ApprovalOptions,
} from "./approvals.ts";
import {
  CardError,
  ENTRY_KINDS,
  EntryError,
  flagForReentry,
  getCardStatus,
  listEntries,
  listRotationDue,
  requestCard,
  resolveEntry,
  useEntry,
  type CardsDeps,
  type EntryKind,
  type EntryMetadata,
} from "./cards.ts";
import type { CapabilityRequest, ClientIdentity, LedgerEntryInput, PolicyDecision } from "./contracts.ts";
import { getDefaultEntryGrantStore, listEntryGrants, revokeEntryGrant, type EntryGrantStore } from "./entry-grants.ts";
import { listClients, revokeClient, setClientScopes } from "./identity.ts";
import type { GithubAppDeps } from "./github-app.ts";
import {
  GITHUB_CAPABILITIES,
  isValidBranchName,
  isValidGithubOwner,
  isValidRepoName,
  type GithubCapabilityResult,
} from "./github-capabilities.ts";
import { appendLedger, ledgerHead, listLedger, verifyLedger, type LedgerVerifyResult } from "./ledger.ts";
import { purgeEntry, rotateEntry, setEntryRotation, type RotationDeps } from "./rotation.ts";
import {
  evaluatePolicy,
  lookupCapability,
  requiredScope,
  type EvaluateOptions,
  type PolicyRule,
} from "./policy-engine.ts";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export type GatewayResult =
  | { ok: true; data: unknown }
  | ({ ok: false; error: string; detail?: string } & Record<string, unknown>);

/** Everything is optional: production passes nothing. Tests inject in-memory stores and fakes. */
export interface GatewayDeps {
  /** Ledger sink. Default: appendLedger (SQL, hash-chained). */
  ledger?: (input: LedgerEntryInput) => Promise<unknown>;
  listLedger?: typeof listLedger;
  verifyLedger?: () => Promise<LedgerVerifyResult>;
  ledgerHead?: typeof ledgerHead;
  /** Approval store / notifier / clock / env. */
  approvals?: ApprovalOptions;
  /** Policy rules. Default: ECHO_VAULT_POLICY_FILE or the built-in rules. */
  rules?: PolicyRule[];
  policy?: EvaluateOptions;
  /** v1 credential store (`vault://<provider>/<account>` refs). Tests MUST pass one over FakeVaultBackend. */
  store?: CredentialStore;
  github?: GithubAppDeps;
  /** Entries + cards wiring. */
  cards?: CardsDeps;
  grants?: EntryGrantStore;
  /** Transport for entry_use site requests. Default: globalThis.fetch. */
  fetch?: typeof fetch;
  /** Host → IP addresses, for the private-address check before an entry_use request. Default: DNS. */
  resolveHost?: (host: string) => Promise<string[]>;
  now?: () => number;
  /** Source for ECHO_VAULT_GRANT_* consent-grant config. Default: process.env. */
  env?: NodeJS.ProcessEnv;
}

/** Consent-grant TTL and use cap from the environment (change #1). */
const GRANT_TTL_DEFAULT_MS = 86_400_000; // 24 h
const GRANT_MAX_USES_DEFAULT = 500;

export function grantConfig(env: NodeJS.ProcessEnv = process.env): { ttlMs: number; maxUses: number | null } {
  const ttlRaw = env.ECHO_VAULT_GRANT_TTL_MS?.trim();
  let ttlMs = GRANT_TTL_DEFAULT_MS;
  if (ttlRaw) {
    const n = Number(ttlRaw);
    if (Number.isFinite(n) && n >= 1) ttlMs = Math.floor(n);
  }
  const usesRaw = env.ECHO_VAULT_GRANT_MAX_USES?.trim();
  let maxUses: number | null = GRANT_MAX_USES_DEFAULT;
  if (usesRaw) {
    if (usesRaw.toLowerCase() === "unlimited") maxUses = null;
    else {
      const n = Number(usesRaw);
      if (Number.isInteger(n) && n >= 0) maxUses = n;
    }
  }
  return { ttlMs, maxUses };
}

// ---------------------------------------------------------------------------
// Tool definitions (what tools/list returns)
// ---------------------------------------------------------------------------

const APPROVAL_ID_PROP = {
  type: "string",
  description:
    "Only when retrying after an `approval_required` result: the approval_id it returned. Send the SAME arguments; the approval is single-use and bound to them.",
} as const;
const CREDENTIAL_REF_PROP = {
  type: "string",
  description: "Opaque vault://<provider>/<account> reference. Never a secret value.",
} as const;
const OWNER_PROP = { type: "string", description: "GitHub owner login." } as const;
const REPO_PROP = { type: "string", description: "Repository name." } as const;
const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
const PROVIDERS = ["github", "cloudflare", "openai", "stripe", "xai"] as const;
const ENTRY_USE_CONTENT_TYPES = ["application/json", "application/x-www-form-urlencoded", "text/plain"] as const;

function schema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return {
    type: "object",
    properties: { ...properties, approval_id: APPROVAL_ID_PROP },
    required,
    additionalProperties: false,
  };
}

const PROXY_NOTE =
  " GET is a read (tier 0). Any other method is tier 2: it returns `approval_required` and runs only after the owner approves that exact request; Stripe writes are refused.";

export const TOOL_DEFINITIONS: readonly ToolDefinition[] = Object.freeze([
  {
    name: "vault_status",
    description: "Broker status and invariant. Tier 0, scope vault.read. Never returns secrets.",
    inputSchema: schema({}),
  },
  {
    name: "vault_list",
    description: "List opaque vault:// credential references with metadata only. Tier 0, scope vault.read.",
    inputSchema: schema({}),
  },
  {
    name: "vault_find",
    description:
      "Search the canonical vault for candidate credentials by name. Returns service/username candidates only. Tier 0, scope vault.read.",
    inputSchema: schema({ query: { type: "string", minLength: 2 } }, ["query"]),
  },
  {
    name: "vault_metadata",
    description: "Metadata for one vault:// reference. Tier 0, scope vault.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }, ["credential_ref"]),
  },
  {
    name: "credential_health",
    description:
      "Verify a credential with a provider identity check (GitHub: GET /user). Returns account metadata. Tier 0, scope vault.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }, ["credential_ref"]),
  },
  {
    name: "github_get_user",
    description: "GitHub identity check via GET /user. Returns login and id. Tier 0, scope github.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
  {
    name: "github_get_repository",
    description: "Repository metadata. Tier 0, scope github.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP, owner: OWNER_PROP, repo: REPO_PROP }, ["owner", "repo"]),
  },
  {
    name: "github_get_file",
    description: "Read one file from a repository. Tier 0, scope github.read.",
    inputSchema: schema(
      {
        credential_ref: CREDENTIAL_REF_PROP,
        owner: OWNER_PROP,
        repo: REPO_PROP,
        path: { type: "string" },
        ref: { type: "string", description: "Branch, tag or commit SHA. Default: the default branch." },
      },
      ["owner", "repo", "path"],
    ),
  },
  {
    name: "github_list_repositories",
    description: "Repositories visible to the GitHub credential. Tier 0, scope github.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP, per_page: { type: "integer", minimum: 1, maximum: 100 } }),
  },
  {
    name: "github_create_branch",
    description: "Create a branch from a commit SHA. Tier 1 (reversible), scope github.write.",
    inputSchema: schema(
      {
        credential_ref: CREDENTIAL_REF_PROP,
        owner: OWNER_PROP,
        repo: REPO_PROP,
        branch: { type: "string", description: "New branch name, without refs/heads/." },
        from_sha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      },
      ["owner", "repo", "branch", "from_sha"],
    ),
  },
  {
    name: "github_create_or_update_file",
    description:
      "Create or update one file. Scope github.write. Tier 1 on an `agent/*` branch; any other branch is tier 2 (returns `approval_required`; the owner approves that exact write, which is also the only way to write the default branch). Owner must be a registered account. Refuses .github/workflows/* and secret-shaped content.",
    inputSchema: schema(
      {
        owner: OWNER_PROP,
        repo: REPO_PROP,
        path: { type: "string" },
        branch: { type: "string", description: "Target branch (required), without refs/heads/." },
        message: { type: "string", maxLength: 4096 },
        content_base64: { type: "string", description: "File content, base64." },
        sha: { type: "string", description: "Blob SHA of the file being replaced (required when updating)." },
      },
      ["owner", "repo", "path", "branch", "message", "content_base64"],
    ),
  },
  {
    name: "github_create_draft_pr",
    description: "Open a draft pull request within one repository. Tier 1, scope github.write. Owner must be a registered account.",
    inputSchema: schema(
      {
        owner: OWNER_PROP,
        repo: REPO_PROP,
        title: { type: "string", maxLength: 256 },
        head: { type: "string", description: "Branch with the changes." },
        base: { type: "string", description: "Branch to merge into. Default: the default branch." },
        body: { type: "string", maxLength: 65536 },
      },
      ["owner", "repo", "title", "head"],
    ),
  },
  {
    name: "github_repo_transfer",
    description:
      "Transfer a repository between the owner's registered GitHub accounts. Tier 2, scope github.write: returns `approval_required`; after the owner approves on Telegram, call again with the same arguments plus approval_id.",
    inputSchema: schema(
      { owner: OWNER_PROP, repo: REPO_PROP, new_owner: { type: "string" }, new_name: { type: "string" } },
      ["owner", "repo", "new_owner"],
    ),
  },
  {
    name: "cloudflare_zone_get",
    description: "Fetch a Cloudflare zone by id. Tier 0, scope cloudflare.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP, zone_id: { type: "string" } }, ["zone_id"]),
  },
  {
    name: "openai_account_status",
    description: "List OpenAI models as an account-status probe. Tier 0, scope openai.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
  {
    name: "xai_account_status",
    description: "Probe the xAI account via GET /v1/models. Tier 0, scope xai.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
  {
    name: "stripe_balance",
    description: "Fetch the Stripe balance. Tier 0, scope stripe.read.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
  {
    name: "credential_use",
    description:
      "One authenticated request to an allowlisted provider API using a vault:// reference; the credential is injected server-side." +
      PROXY_NOTE,
    inputSchema: schema(
      {
        credential_ref: CREDENTIAL_REF_PROP,
        provider: { type: "string", enum: PROVIDERS },
        operation: { type: "string", enum: HTTP_METHODS, description: "HTTP method." },
        resource: { type: "string", description: "Path on the provider's API host, starting with /." },
        body: { description: "JSON request body (non-GET only)." },
      },
      ["credential_ref", "provider", "operation", "resource"],
    ),
  },
  {
    name: "provider_request",
    description:
      "Same as credential_use with method/path naming. No caller-supplied Authorization header, no arbitrary hosts." + PROXY_NOTE,
    inputSchema: schema(
      {
        credential_ref: CREDENTIAL_REF_PROP,
        provider: { type: "string", enum: PROVIDERS },
        method: { type: "string", enum: HTTP_METHODS },
        path: { type: "string", description: "Path on the provider's API host, starting with /." },
        body: { description: "JSON request body (non-GET only)." },
      },
      ["credential_ref", "provider", "method", "path"],
    ),
  },
  {
    name: "entry_list",
    description:
      "List credential entries (site, account, purpose, kind, status) — metadata only, never a secret. A site can have several accounts. Tier 0, scope vault.read.",
    inputSchema: schema({
      site: { type: "string", description: "Limit to one site, e.g. github.com." },
      query: { type: "string", description: "Case-insensitive substring of the entry label." },
    }),
  },
  {
    name: "entry_request_card",
    description:
      "Ask the owner to type a credential you do not have (or re-enter one that stopped working). The owner gets a single-use link on Telegram; you get only a card_id. Poll entry_card_status. Tier 1, scope vault.write.",
    inputSchema: schema(
      {
        site: { type: "string", description: "Domain, e.g. github.com." },
        account: { type: "string", description: "Username or email, if known." },
        purpose: { type: "string", description: "Short tag, e.g. personal." },
        kind: { type: "string", enum: ENTRY_KINDS },
        reason: { type: "string", description: "Why you need it; shown to the owner.", maxLength: 300 },
        entry_id: { type: "string", description: "Re-enter the secret of this existing entry." },
      },
      ["site", "kind", "reason"],
    ),
  },
  {
    name: "entry_card_status",
    description: "Status of a card you requested: pending, completed (with entry metadata) or expired. Tier 0, scope vault.read.",
    inputSchema: schema({ card_id: { type: "string" } }, ["card_id"]),
  },
  {
    name: "entry_use",
    description:
      "Use a credential entry without seeing it: one HTTPS request to the entry's own site (host = the site or api.<site>) with the secret injected server-side (api_key / oauth_token: Authorization: Bearer; password: HTTP Basic with the account). Returns status and a redacted body. GET/HEAD need scope vault.read and the owner's consent, scoped to this entry, host and path: the first such read returns `approval_required`; later reads to that host at that path or under it run without a prompt until the grant expires or its uses run out. Other methods need scope vault.write and are approved per request. A 401 from the site flags that entry for re-entry (site_rejected_credential); a 403 returns site_forbidden and leaves the entry active.",
    inputSchema: schema(
      {
        site: { type: "string", description: "Domain of the entry, e.g. github.com." },
        account: { type: "string", description: "Which account on that site. Default: the site's default entry." },
        kind: { type: "string", enum: ENTRY_KINDS, description: "Only needed when the account has entries of several kinds." },
        method: { type: "string", enum: HTTP_METHODS },
        host: { type: "string", description: "Exactly the site or api.<site>. Default: the site." },
        url_path: { type: "string", description: "Path and query, starting with /." },
        body: { description: "Request body for non-GET: a JSON value, or a string sent as is." },
        content_type: { type: "string", enum: ENTRY_USE_CONTENT_TYPES, description: "For a string body. Default text/plain." },
        task: { type: "string", description: "What you are doing and why. Required; recorded in the audit ledger.", maxLength: 300 },
      },
      ["site", "method", "url_path", "task"],
    ),
  },
  {
    name: "approval_status",
    description: "Status of an approval you were asked to wait for: pending, approved, denied, expired or consumed. Tier 0, scope vault.read.",
    inputSchema: {
      type: "object",
      properties: { approval_id: { type: "string", description: "The approval_id from an `approval_required` result." } },
      required: ["approval_id"],
      additionalProperties: false,
    },
  },
  {
    name: "audit_list",
    description: "Recent ledger entries (who, what, decision, result). Secrets are never recorded. Tier 0, scope audit.read.",
    inputSchema: schema({
      limit: { type: "integer", minimum: 1, maximum: 1000 },
      client_id: { type: "string" },
      capability: { type: "string" },
    }),
  },
  {
    name: "audit_verify",
    description: "Recompute the ledger's hash chain and report whether it is intact. Tier 0, scope audit.read.",
    inputSchema: schema({}),
  },
  {
    name: "admin_list_clients",
    description:
      "OWNER ONLY (local stdio): list the OAuth clients, their status and granted scopes. Any remote/OAuth/workload caller is refused (tier 3).",
    inputSchema: schema({}),
  },
  {
    name: "admin_set_client_scopes",
    description:
      "OWNER ONLY (local stdio): set an approved client's granted scopes. Any remote caller is refused (tier 3).",
    inputSchema: schema(
      {
        client_id: { type: "string" },
        scopes: { type: "array", items: { type: "string" }, description: "The scopes to grant, e.g. [\"github.read\"]." },
      },
      ["client_id", "scopes"],
    ),
  },
  {
    name: "admin_revoke_client",
    description:
      "OWNER ONLY (local stdio): revoke a client (kill switch): drop its grant and tokens. Any remote caller is refused (tier 3).",
    inputSchema: schema({ client_id: { type: "string" } }, ["client_id"]),
  },
  {
    name: "admin_list_grants",
    description:
      "OWNER ONLY (local stdio): list entry consent grants (metadata only), optionally filtered by client or entry. Any remote caller is refused (tier 3).",
    inputSchema: schema({ client_id: { type: "string" }, entry_id: { type: "string" } }),
  },
  {
    name: "admin_revoke_grant",
    description:
      "OWNER ONLY (local stdio): revoke a client's consent for an entry — one narrow grant (give host + path_prefix) or all grants for the pair. The client's next read re-prompts. Any remote caller is refused (tier 3).",
    inputSchema: schema(
      {
        client_id: { type: "string" },
        entry_id: { type: "string" },
        host: { type: "string", description: "Only this host's grant." },
        path_prefix: { type: "string", description: "Only the grant with this exact path_prefix (requires host)." },
      },
      ["client_id", "entry_id"],
    ),
  },
  {
    name: "admin_list_entries",
    description:
      "OWNER ONLY (local stdio): list credential entries with full metadata (including fingerprint and length). Still never a secret value. Any remote caller is refused (tier 3).",
    inputSchema: schema({
      site: { type: "string", description: "Limit to one site." },
      query: { type: "string", description: "Case-insensitive substring of the entry label." },
    }),
  },
  {
    name: "admin_set_rotation",
    description:
      "OWNER ONLY (local stdio): set an entry's rotation policy. mode manual = re-enter on a card; mode auto = the provider rotator rolls it (Cloudflare API tokens: provider_token_id is the 32-hex token ID, never the token). Metadata only. Any remote caller is refused (tier 3).",
    inputSchema: schema(
      {
        entry_id: { type: "string" },
        mode: { type: "string", enum: ["manual", "auto"] },
        interval_days: { type: "integer", minimum: 1, maximum: 3650, description: "Rotate every N days. Omit to keep the current interval." },
        provider_token_id: { type: "string", description: "The provider's NON-SECRET token ID. Omit to keep the current one." },
      },
      ["entry_id", "mode"],
    ),
  },
  {
    name: "admin_rotate_entry",
    description:
      "OWNER ONLY (local stdio): auto-rotate one entry now through its provider rotator. The new secret goes straight to the vault; the result is metadata only. Any remote caller is refused (tier 3).",
    inputSchema: schema({ entry_id: { type: "string" } }, ["entry_id"]),
  },
  {
    name: "admin_rotation_due",
    description:
      "OWNER ONLY (local stdio): list entries whose rotation is due (metadata only). Any remote caller is refused (tier 3).",
    inputSchema: schema({}),
  },
  {
    name: "admin_purge_entry",
    description:
      "OWNER ONLY (local stdio): IRREVERSIBLY destroy an entry — its stored secret, its row, its cards and all consent grants. confirm must be exactly \"PURGE <entry_id>\". Any remote caller is refused (tier 3).",
    inputSchema: schema({ entry_id: { type: "string" }, confirm: { type: "string" } }, ["entry_id", "confirm"]),
  },
  {
    name: "credential_rotate",
    description: "Tier 3: always refused. Rotating a credential is a human-only operation on the canonical vault.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
  {
    name: "credential_revoke",
    description: "Tier 3: always refused. Revoking a credential is a human-only operation on the canonical vault.",
    inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }),
  },
]);

export function listTools(): ToolDefinition[] {
  return TOOL_DEFINITIONS.map((t) => ({ ...t }));
}

// ---------------------------------------------------------------------------
// Internals: errors, argument checks, small helpers
// ---------------------------------------------------------------------------

class ToolInputError extends Error {
  readonly code: string;
  constructor(code: string, detail: string) {
    super(detail);
    this.code = code;
  }
}

interface Audit {
  credential_ref?: string;
  http_status?: number;
  credential_path?: "installation" | "pat_fallback";
  fallback_reason?: string;
}

interface Outcome {
  result: GatewayResult;
  audit?: Audit;
  /** The run already wrote its own ledger row(s) through the gateway's sink (entry_use via cards.useEntry). */
  ledgered?: boolean;
}

interface RunContext {
  decision: PolicyDecision;
  /** An approval for this exact request was consumed in this call. */
  approved: boolean;
  approvalId?: string;
}

interface Plan {
  capability: string;
  resource: string;
  /** Digested for approvals. No secrets, no approval_id. */
  params: Record<string, unknown>;
  /** One line for the owner's phone. */
  summary: string;
  task?: string;
  /** Read-only entry use: needs the owner's consent, scoped to (client, entry, host, path). */
  consentEntryId?: string;
  /** The exact host the read targets; the consent grant is scoped to it. */
  consentHost?: string;
  /** The read's request path (no query); the consent grant covers this path and anything under it. */
  consentPath?: string;
  run(ctx: RunContext): Promise<Outcome>;
}

interface Env {
  identity: ClientIdentity;
  deps: GatewayDeps;
  broker: BrokerContext;
}

type Planner = (a: Record<string, unknown>, env: Env) => Promise<Plan> | Plan;

const MAX_RESOURCE = 512;
const SHA_RE = /^[0-9a-f]{40}$/;

/**
 * Tool names that would hand a secret to the caller. Refused before anything
 * else, whatever the arguments, in addition to the fixed FORBIDDEN_TOOLS list.
 */
const REVEAL_LIKE =
  /(?:^|[_.-])(?:reveal|unwrap|unmask|decrypt|dump|export|exfiltrate|plaintext)(?:[_.-]|$)|(?:get|read|show|fetch|print|copy|view)[_.-]?(?:secret|token|pat|password|passwd|private[_.-]?key|credential|api[_.-]?key)s?(?:[_.-]|$)|(?:secret|password|token|credential)[_.-](?:get|read|show|reveal|value|plaintext)/i;

export function isForbiddenToolName(name: string): boolean {
  return (FORBIDDEN_TOOLS as readonly string[]).includes(name) || REVEAL_LIKE.test(name);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Check args against the tool's published schema: unknown keys, missing required, wrong primitive types. */
function checkArgs(def: ToolDefinition, a: Record<string, unknown>): void {
  const props = (def.inputSchema.properties ?? {}) as Record<string, { type?: string; enum?: readonly unknown[] }>;
  for (const key of Object.keys(a)) {
    if (!Object.hasOwn(props, key)) throw new ToolInputError("invalid_arguments", `unknown argument: ${clip(key, 64)}`);
  }
  for (const key of (def.inputSchema.required ?? []) as string[]) {
    if (a[key] === undefined || a[key] === null || a[key] === "") {
      throw new ToolInputError("invalid_arguments", `missing required argument: ${key}`);
    }
  }
  for (const [key, value] of Object.entries(a)) {
    if (value === undefined) continue;
    const spec = props[key];
    const type = spec.type;
    const ok =
      type === undefined ||
      (type === "string" && typeof value === "string") ||
      (type === "integer" && typeof value === "number" && Number.isInteger(value)) ||
      (type === "number" && typeof value === "number" && Number.isFinite(value)) ||
      (type === "boolean" && typeof value === "boolean") ||
      (type === "array" && Array.isArray(value));
    if (!ok) throw new ToolInputError("invalid_arguments", `${key}: expected ${type}`);
    if (spec.enum && !spec.enum.includes(typeof value === "string" && key === "method" ? value.toUpperCase() : value)) {
      if (!(key === "operation" && typeof value === "string" && spec.enum.includes(value.toUpperCase()))) {
        throw new ToolInputError("invalid_arguments", `${key}: must be one of ${spec.enum.join(", ")}`);
      }
    }
  }
}

function optStr(a: Record<string, unknown>, key: string): string | undefined {
  const v = a[key];
  return typeof v === "string" && v !== "" ? v : undefined;
}

function reqStr(a: Record<string, unknown>, key: string): string {
  const v = optStr(a, key);
  if (v === undefined) throw new ToolInputError("invalid_arguments", `missing required argument: ${key}`);
  return v;
}

/** A vault:// ref that belongs to `provider` (a secret must never be sent to another provider's host). */
function providerRef(a: Record<string, unknown>, provider: ProviderId, fallback: string): string {
  const raw = optStr(a, "credential_ref") ?? fallback;
  const parsed = parseVaultRef(raw);
  if (!parsed) throw new ToolInputError("invalid_credential_ref", "credential_ref must look like vault://<provider>/<account>");
  if (parsed.provider !== provider) {
    throw new ToolInputError("provider_mismatch", `credential_ref must be a vault://${provider}/… reference for this tool`);
  }
  return parsed.raw;
}

function anyRef(a: Record<string, unknown>): string {
  const parsed = parseVaultRef(reqStr(a, "credential_ref"));
  if (!parsed) throw new ToolInputError("invalid_credential_ref", "credential_ref must look like vault://<provider>/<account>");
  return parsed.raw;
}

function githubRepoResource(a: Record<string, unknown>): { owner: string; repo: string; resource: string } {
  const owner = a.owner;
  const repo = a.repo;
  if (!isValidGithubOwner(owner)) throw new ToolInputError("invalid_arguments", "owner: not a valid GitHub login");
  if (!isValidRepoName(repo)) throw new ToolInputError("invalid_arguments", "repo: not a valid repository name");
  return { owner, repo, resource: `github:${owner}/${repo}` };
}

/** Outcome of a v1 executor ({ok, data|error, credential_ref?, detail?}). */
function fromV1(result: unknown, credentialRef?: string): Outcome {
  const r = (isRecord(result) ? result : { ok: false, error: "internal_error" }) as Record<string, unknown>;
  const audit: Audit = {};
  if (credentialRef) audit.credential_ref = credentialRef;
  if (r.ok === true) {
    const status = isRecord(r.data) && typeof r.data.status === "number" ? r.data.status : undefined;
    if (status !== undefined && status >= 100 && status <= 599) audit.http_status = status;
    return { result: { ok: true, data: r.data }, audit };
  }
  const out: GatewayResult = { ok: false, error: typeof r.error === "string" ? r.error : "internal_error" };
  if (typeof r.detail === "string") out.detail = r.detail;
  if (typeof r.credential_ref === "string") out.credential_ref = r.credential_ref;
  return { result: out, audit };
}

function fromGithub(result: GithubCapabilityResult): Outcome {
  const audit: Audit = {
    credential_ref: result.audit.credential_ref,
    http_status: result.audit.http_status,
    credential_path: result.audit.credential_path,
    fallback_reason: result.audit.fallback_reason,
  };
  if (result.ok) return { result: { ok: true, data: result.data }, audit };
  const out: GatewayResult = { ok: false, error: result.error };
  if (result.detail) out.detail = result.detail;
  return { result: out, audit };
}

/** Entry metadata as agents see it: no fingerprint, no secret length. */
function agentEntryView(e: EntryMetadata): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: e.id,
    ref: e.ref,
    site: e.site,
    account: e.account,
    purpose: e.purpose,
    label: e.label,
    kind: e.kind,
    is_default: e.is_default,
    status: e.status,
    created_at: e.created_at,
    updated_at: e.updated_at,
    last_used_at: e.last_used_at,
    last_verified_at: e.last_verified_at,
  };
  if (e.reentry_reason) out.reentry_reason = e.reentry_reason;
  return out;
}

function entryFailure(err: unknown): GatewayResult {
  if (err instanceof EntryError || err instanceof CardError) {
    return { ok: false, error: err.code, detail: err.message };
  }
  return { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) };
}

// ---------------------------------------------------------------------------
// Generic injecting proxy (credential_use / provider_request)
// ---------------------------------------------------------------------------

function proxyPlan(
  a: Record<string, unknown>,
  env: Env,
  keys: { method: "operation" | "method"; path: "resource" | "path" },
): Plan {
  const providerRaw = reqStr(a, "provider");
  if (!isProviderId(providerRaw)) throw new ToolInputError("invalid_arguments", "provider: unknown provider");
  const provider: ProviderId = providerRaw;
  const method = reqStr(a, keys.method).toUpperCase();
  if (!(HTTP_METHODS as readonly string[]).includes(method)) {
    throw new ToolInputError("invalid_arguments", `${keys.method}: unsupported HTTP method`);
  }
  const ref = providerRef(a, provider, "");
  let path: string;
  try {
    path = normalizeResourcePath(reqStr(a, keys.path));
  } catch (err) {
    throw new ToolInputError(clip(sanitizeError(err).message, 64) || "invalid_resource", "path must be a relative path starting with /");
  }
  const host = PROVIDER_POLICIES[provider].hosts[0];
  const pathname = new URL(`https://${host}${path}`).pathname;
  const repo = provider === "github" ? /^\/repos\/([^/]+)\/([^/]+)(?:\/|$)/.exec(pathname) : null;
  const resource = clip(repo ? `github:${decodeURIComponent(repo[1])}/${decodeURIComponent(repo[2])}` : `${provider}:${pathname}`, MAX_RESOURCE);

  const read = method === "GET" || method === "HEAD";
  // Method is the only thing the broker can know about an arbitrary request.
  const capability = read ? `${provider}.api.read` : provider === "stripe" ? "payment.stripe.write" : `${provider}.api.write`;
  const body = read ? undefined : a.body;
  const bodyText = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
  const params: Record<string, unknown> = { credential_ref: ref, provider, method, path };
  if (bodyText !== undefined) params.body_sha256 = sha256(bodyText);

  return {
    capability,
    resource,
    params,
    summary: `${method} https://${host}${clip(path, 200)} using ${ref}${bodyText !== undefined ? ` (body ${Buffer.byteLength(bodyText)} bytes)` : ""}`,
    run: async () => fromV1(await useCredential(env.broker, { credential_ref: ref, provider, operation: method, resource: path, body }), ref),
  };
}

// ---------------------------------------------------------------------------
// entry_use: one HTTPS request to the entry's own site
// ---------------------------------------------------------------------------

const ENTRY_USE_LIMITS = { maxRequestBytes: 256 * 1024, maxResponseBytes: 1024 * 1024, timeoutMs: 12_000, maxTextChars: 16_384 };

async function defaultResolveHost(host: string): Promise<string[]> {
  const found = await dnsLookup(host, { all: true });
  return found.map((f) => f.address);
}

async function readLimited(res: Response, limit: number): Promise<Buffer> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new Error("response_too_large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

interface SiteRequest {
  host: string;
  method: string;
  path: string;
  bodyText?: string;
  contentType?: string;
}

/**
 * Runs INSIDE cards.useEntry: the only code that holds the secret. Returns
 * status + redacted body; never headers (Set-Cookie and friends can be
 * credentials). Redirects are not followed, so the Authorization header can
 * never be replayed to another host.
 */
async function siteRequest(
  secret: string,
  entry: EntryMetadata,
  req: SiteRequest,
  deps: GatewayDeps,
): Promise<{ status: number; content_type: string | null; location?: string; body: unknown; truncated?: true }> {
  const url = new URL(`https://${req.host}${req.path}`);
  if (url.protocol !== "https:" || url.hostname !== req.host || url.username || url.password || url.port) {
    throw new Error("hostname_not_allowed");
  }
  if (isBlockedHost(url.hostname)) throw new Error("hostname_not_allowed");
  let addresses: string[];
  try {
    addresses = await (deps.resolveHost ?? defaultResolveHost)(url.hostname);
  } catch {
    throw new Error("dns_lookup_failed");
  }
  if (addresses.length === 0) throw new Error("dns_lookup_failed");
  if (addresses.some((ip) => isBlockedHost(ip) || isPrivateOrLinkLocalIp(ip))) throw new Error("hostname_not_allowed");

  const headers = new Headers({
    "user-agent": "Echo-Credential-Broker/2.0",
    accept: "application/json, text/plain;q=0.9, */*;q=0.5",
  });
  if (entry.kind === "password") {
    const basic = Buffer.from(`${entry.account}:${secret}`, "utf8").toString("base64");
    registerSecretForRedaction(basic); // a site that echoes headers must not hand the pair back
    headers.set("authorization", `Basic ${basic}`);
  } else {
    headers.set("authorization", `Bearer ${secret}`);
  }
  const encoded = encodeURIComponent(secret);
  if (encoded !== secret) registerSecretForRedaction(encoded);

  const init: RequestInit = {
    method: req.method,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(ENTRY_USE_LIMITS.timeoutMs),
  };
  if (req.bodyText !== undefined) {
    headers.set("content-type", req.contentType ?? "text/plain");
    init.body = req.bodyText;
  }
  const res = await (deps.fetch ?? globalThis.fetch)(url, init);
  const raw = await readLimited(res, ENTRY_USE_LIMITS.maxResponseBytes);
  const text = redactString(raw.toString("utf8"));
  const contentType = res.headers.get("content-type");
  let body: unknown = null;
  let truncated = false;
  if (text.length > 0) {
    let parsed: unknown;
    let isJson = false;
    if ((contentType ?? "").includes("json") || text.startsWith("{") || text.startsWith("[")) {
      try {
        parsed = JSON.parse(text);
        isJson = true;
      } catch {
        isJson = false;
      }
    }
    if (isJson) body = parsed;
    else {
      truncated = text.length > ENTRY_USE_LIMITS.maxTextChars;
      body = text.slice(0, ENTRY_USE_LIMITS.maxTextChars);
    }
  }
  const out: { status: number; content_type: string | null; location?: string; body: unknown; truncated?: true } = {
    status: res.status,
    content_type: contentType ? clip(redactString(contentType), 200) : null,
    body,
  };
  const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
  if (location) out.location = clip(redactString(location), 500);
  if (truncated) out.truncated = true;
  return out;
}

async function entryUsePlan(a: Record<string, unknown>, env: Env): Promise<Plan> {
  const method = reqStr(a, "method").toUpperCase();
  if (!(HTTP_METHODS as readonly string[]).includes(method)) throw new ToolInputError("invalid_arguments", "method: unsupported HTTP method");
  const read = method === "GET" || method === "HEAD";
  const capability = read ? "vault.entry.use.read" : "vault.entry.use.write";
  const task = sanitizeDisplayText(reqStr(a, "task"), 300);
  if (!task) throw new ToolInputError("invalid_task", "task: describe what you are doing and why");
  let path: string;
  try {
    path = normalizeResourcePath(reqStr(a, "url_path"));
  } catch {
    throw new ToolInputError("invalid_arguments", "url_path must be a relative path starting with /");
  }
  if (a.kind !== undefined && !ENTRY_KINDS.includes(a.kind as EntryKind)) {
    throw new ToolInputError("invalid_arguments", `kind: must be one of ${ENTRY_KINDS.join(", ")}`);
  }
  if (read && a.body !== undefined) throw new ToolInputError("invalid_arguments", "body is not allowed with GET/HEAD");
  const bodyText = a.body === undefined ? undefined : typeof a.body === "string" ? a.body : JSON.stringify(a.body);
  if (bodyText !== undefined && Buffer.byteLength(bodyText) > ENTRY_USE_LIMITS.maxRequestBytes) {
    throw new ToolInputError("request_too_large", "body exceeds the broker request limit");
  }
  const contentType =
    bodyText === undefined ? undefined : typeof a.body === "string" ? (optStr(a, "content_type") ?? "text/plain") : "application/json";

  const siteArg = reqStr(a, "site");
  const accountArg = optStr(a, "account");
  const unresolved = (reason: string): Plan => ({
    capability,
    resource: clip(`entry:${sanitizeDisplayText(siteArg, 253) || "?"}/${accountArg ? sanitizeDisplayText(accountArg, 200) : "default"}`, MAX_RESOURCE),
    params: { method, url_path: path, task },
    summary: "",
    task,
    run: async () => ({ result: { ok: false, error: reason } }),
  });
  // Without the scope the policy engine denies; do not resolve (or confirm the existence of) an entry first.
  const scope = requiredScope(capability);
  if (!scope || !env.identity.scopes.includes(scope)) return unresolved("missing_scope");

  let entry: EntryMetadata;
  try {
    entry = await resolveEntry({ site: siteArg, account: accountArg, kind: a.kind as EntryKind | undefined }, env.deps.cards);
  } catch (err) {
    if (err instanceof EntryError) throw new ToolInputError(err.code, err.message);
    throw err;
  }
  if (entry.kind === "operator_secret") {
    throw new ToolInputError("entry_kind_not_usable", "operator_secret entries cannot be injected into a request");
  }
  const host = (optStr(a, "host") ?? entry.site).trim().toLowerCase();
  if (host !== entry.site && host !== `api.${entry.site}`) {
    throw new ToolInputError("hostname_not_allowed", `host must be ${entry.site} or api.${entry.site}`);
  }
  if (isBlockedHost(host)) throw new ToolInputError("hostname_not_allowed", "that host is not reachable through the broker");

  const params: Record<string, unknown> = { entry_id: entry.id, method, host, url_path: path, task };
  if (bodyText !== undefined) {
    params.body_sha256 = sha256(bodyText);
    params.content_type = contentType;
  }
  // The grant is scoped to the pathname (no query); it covers this path and anything under it.
  const grantPath = path.split(/[?#]/)[0];
  const what = `${method} https://${host}${clip(path, 160)}${bodyText !== undefined ? ` (body ${Buffer.byteLength(bodyText)} bytes)` : ""}`;
  let summary: string;
  if (read) {
    const { ttlMs, maxUses } = grantConfig(env.deps.env);
    const expiresIso = new Date((env.deps.now ?? Date.now)() + ttlMs).toISOString();
    const scopeLine =
      `Approving also lets this client make GET/HEAD requests to https://${host}${clip(grantPath, 160)}(/*) with this entry, ` +
      `without asking again, until ${expiresIso}${maxUses === null ? "" : ` or ${maxUses} uses`}.`;
    summary = `FIRST USE of "${entry.label}" by this client: ${what}. Task: ${task}. ${scopeLine}`;
  } else {
    summary = `Use "${entry.label}": ${what}. Task: ${task}`;
  }

  return {
    capability,
    resource: clip(`entry:${entry.site}/${entry.account}`, MAX_RESOURCE),
    params,
    summary,
    task,
    consentEntryId: read ? entry.id : undefined,
    consentHost: read ? host : undefined,
    consentPath: read ? grantPath : undefined,
    run: async (ctx) => {
      const ledger = env.deps.ledger ?? appendLedger;
      let seen: { status: number } | null = null;
      let ledgered = false;
      const audit: Audit = { credential_ref: entry.ref };
      const status = () => (seen as { status: number } | null)?.status;
      const is401 = () => status() === 401;
      const is403 = () => status() === 403;
      try {
        const used = await useEntry(
          entry.id,
          env.identity,
          task,
          async (secret, meta) => {
            const response = await siteRequest(secret, meta, { host, method, path, bodyText, contentType }, env.deps);
            seen = { status: response.status };
            // A 401 means the site rejected the credential: flag THIS entry for
            // re-entry (other accounts on the same site are untouched). A 403 is
            // usually a scope or rate-limit problem, not a bad login, so the
            // entry stays active and is never flagged on it.
            if (is401()) {
              await flagForReentry(meta.id, `${host} answered ${response.status} to ${method}`, env.deps.cards).catch(() => {
                log.error("vault_entry_flag_failed", { entry_id: meta.id });
              });
            }
            return response;
          },
          {
            ...env.deps.cards,
            decision: ctx.decision.decision,
            tier: ctx.decision.tier,
            approval_id: ctx.approvalId,
            // One row per use, written by useEntry (which fails closed when it
            // cannot be written), under this gateway's capability and outcome.
            ledger: async (input) => {
              ledgered = true;
              const row: LedgerEntryInput = { ...input, capability, task };
              const s = status();
              if (s !== undefined) row.http_status = s;
              if (is401()) {
                row.result = "error";
                row.error = "site_rejected_credential";
              } else if (is403()) {
                row.result = "error";
                row.error = "site_forbidden";
              }
              await ledger(row);
            },
          },
        );
        const response = used.result;
        audit.http_status = response.status;
        if (is401()) {
          return {
            ledgered,
            audit,
            result: {
              ok: false,
              error: "site_rejected_credential",
              detail: `${host} answered ${response.status}. This entry is now flagged; ask the owner to re-enter it with entry_request_card (entry_id).`,
              status: response.status,
              entry_id: entry.id,
              entry_flagged_for_reentry: true,
            },
          };
        }
        if (is403()) {
          // Not a credential failure: report it, keep the entry usable.
          return {
            ledgered,
            audit,
            result: {
              ok: false,
              error: "site_forbidden",
              detail: `${host} answered ${response.status}. The credential was accepted but this request is not allowed; the entry is unchanged.`,
              status: response.status,
              body: response.body,
              entry_id: entry.id,
            },
          };
        }
        return { ledgered, audit, result: { ok: true, data: { entry: agentEntryView(used.entry), ...response } } };
      } catch (err) {
        return { ledgered, audit, result: entryFailure(err) };
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Tool → plan
// ---------------------------------------------------------------------------

const GITHUB_DEFAULT_REF = "vault://github/echoomegaprime";

const PLANNERS: Readonly<Record<string, Planner>> = Object.freeze({
  vault_status: (_a, env) => ({
    capability: "vault.status",
    resource: "vault:status",
    params: {},
    summary: "Read broker status",
    run: async () => fromV1(await vaultStatus(env.broker)),
  }),
  vault_list: (_a, env) => ({
    capability: "vault.list",
    resource: "vault:*",
    params: {},
    summary: "List credential references",
    run: async () => fromV1(await vaultList(env.broker)),
  }),
  vault_find: (a, env) => {
    const query = reqStr(a, "query");
    return {
      capability: "vault.find",
      resource: "vault:*",
      params: { query },
      summary: `Search the vault for "${clip(query, 80)}"`,
      run: async () => fromV1(await vaultFind(env.broker, query)),
    };
  },
  vault_metadata: (a, env) => {
    const ref = anyRef(a);
    return {
      capability: "vault.metadata",
      resource: ref,
      params: { credential_ref: ref },
      summary: `Read metadata of ${ref}`,
      run: async () => fromV1(await vaultMetadata(env.broker, ref), ref),
    };
  },
  credential_health: (a, env) => {
    const ref = anyRef(a);
    return {
      capability: "vault.credential.health",
      resource: ref,
      params: { credential_ref: ref },
      summary: `Check that ${ref} still authenticates`,
      run: async () => fromV1(await credentialHealth(env.broker, ref), ref),
    };
  },
  github_get_user: (a, env) => {
    const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
    return {
      capability: "github.user.read",
      resource: "github:user",
      params: { credential_ref: ref },
      summary: `GitHub identity check with ${ref}`,
      run: async () => fromV1(await githubGetUser(env.broker, ref), ref),
    };
  },
  github_get_repository: (a, env) => {
    const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
    const { owner, repo, resource } = githubRepoResource(a);
    return {
      capability: "github.repo.read",
      resource,
      params: { credential_ref: ref, owner, repo },
      summary: `Read repository ${owner}/${repo}`,
      run: async () => fromV1(await githubGetRepository(env.broker, { credential_ref: ref, owner, repo }), ref),
    };
  },
  github_get_file: (a, env) => {
    const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
    const { owner, repo, resource } = githubRepoResource(a);
    const path = reqStr(a, "path");
    const gitRef = optStr(a, "ref");
    return {
      capability: "github.contents.read",
      resource,
      params: { credential_ref: ref, owner, repo, path, ref: gitRef },
      summary: `Read ${clip(path, 120)} from ${owner}/${repo}`,
      run: async () => fromV1(await githubGetFile(env.broker, { credential_ref: ref, owner, repo, path, ref: gitRef }), ref),
    };
  },
  github_list_repositories: (a, env) => {
    const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
    const perPage = typeof a.per_page === "number" ? a.per_page : undefined;
    return {
      capability: "github.repo.list",
      resource: "github:user/repos",
      params: { credential_ref: ref, per_page: perPage },
      summary: `List repositories visible to ${ref}`,
      run: async () => fromV1(await githubListRepositories(env.broker, { credential_ref: ref, per_page: perPage }), ref),
    };
  },
  github_create_branch: (a, env) => {
    const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
    const { owner, repo, resource } = githubRepoResource(a);
    const branch = a.branch;
    if (!isValidBranchName(branch)) throw new ToolInputError("invalid_arguments", "branch: not a valid branch name");
    const fromSha = reqStr(a, "from_sha");
    if (!SHA_RE.test(fromSha)) throw new ToolInputError("invalid_arguments", "from_sha: expected a 40-character commit SHA");
    return {
      capability: "github.branch.create",
      resource,
      params: { credential_ref: ref, owner, repo, branch, from_sha: fromSha },
      summary: `Create branch ${branch} in ${owner}/${repo} at ${fromSha.slice(0, 12)}`,
      run: async () => fromV1(await githubCreateBranch(env.broker, { credential_ref: ref, owner, repo, branch, from_sha: fromSha }), ref),
    };
  },
  github_create_or_update_file: (a, env) => {
    const { owner, repo, resource } = githubRepoResource(a);
    const path = reqStr(a, "path");
    const branch = a.branch;
    if (!isValidBranchName(branch)) throw new ToolInputError("invalid_arguments", "branch: not a valid branch name");
    const message = reqStr(a, "message");
    const content = reqStr(a, "content_base64");
    const sha = optStr(a, "sha");
    return {
      capability: "github.contents.write",
      resource,
      params: { owner, repo, path, branch, sha, message_sha256: sha256(message), content_sha256: sha256(content) },
      summary: `Write ${clip(path, 120)} to ${owner}/${repo} on branch "${branch}" (not an agent/* branch; this may be the default branch). Commit message: ${clip(message, 120)}`,
      run: async (ctx) => {
        const params: Record<string, unknown> = { owner, repo, path, branch, message, content_base64: content };
        if (sha !== undefined) params.sha = sha;
        // Only an approval for this exact request unlocks the default branch.
        if (ctx.approved) params.allow_default_branch = true;
        return fromGithub(await GITHUB_CAPABILITIES["github.contents.write"](params, { client: env.identity, deps: env.deps.github }));
      },
    };
  },
  github_create_draft_pr: (a, env) => {
    const { owner, repo, resource } = githubRepoResource(a);
    const title = reqStr(a, "title");
    const head = reqStr(a, "head");
    const base = optStr(a, "base");
    const body = optStr(a, "body");
    return {
      capability: "github.pr.create_draft",
      resource,
      params: { owner, repo, title, head, base, body_sha256: body === undefined ? undefined : sha256(body) },
      summary: `Open a draft PR in ${owner}/${repo}: ${head} → ${base ?? "default branch"} — ${clip(title, 120)}`,
      run: async () => {
        const params: Record<string, unknown> = { owner, repo, title, head };
        if (base !== undefined) params.base = base;
        if (body !== undefined) params.body = body;
        return fromGithub(await GITHUB_CAPABILITIES["github.pr.create_draft"](params, { client: env.identity, deps: env.deps.github }));
      },
    };
  },
  github_repo_transfer: (a, env) => {
    const { owner, repo, resource } = githubRepoResource(a);
    const newOwner = reqStr(a, "new_owner");
    const newName = optStr(a, "new_name");
    return {
      capability: "github.repo.transfer",
      resource,
      params: { owner, repo, new_owner: newOwner, new_name: newName },
      summary: `TRANSFER repository ${owner}/${repo} to ${clip(newOwner, 60)}${newName ? ` as ${clip(newName, 100)}` : ""}`,
      run: async () => {
        const params: Record<string, unknown> = { owner, repo, new_owner: newOwner };
        if (newName !== undefined) params.new_name = newName;
        return fromGithub(await GITHUB_CAPABILITIES["github.repo.transfer"](params, { client: env.identity, deps: env.deps.github }));
      },
    };
  },
  cloudflare_zone_get: (a, env) => {
    const ref = providerRef(a, "cloudflare", "vault://cloudflare/global_api_key");
    const zone = reqStr(a, "zone_id");
    return {
      capability: "cloudflare.zone.read",
      resource: clip(`cloudflare:zone/${sanitizeDisplayText(zone, 80)}`, MAX_RESOURCE),
      params: { credential_ref: ref, zone_id: zone },
      summary: `Read Cloudflare zone ${clip(zone, 40)}`,
      run: async () => fromV1(await cloudflareZoneGet(env.broker, { credential_ref: ref, zone_id: zone }), ref),
    };
  },
  openai_account_status: (a, env) => {
    const ref = providerRef(a, "openai", "vault://openai/api_key");
    return {
      capability: "openai.account.read",
      resource: "openai:account",
      params: { credential_ref: ref },
      summary: "Probe the OpenAI account",
      run: async () => fromV1(await openaiAccountStatus(env.broker, { credential_ref: ref }), ref),
    };
  },
  xai_account_status: (a, env) => {
    const ref = providerRef(a, "xai", "vault://xai/api_key");
    return {
      capability: "xai.account.read",
      resource: "xai:account",
      params: { credential_ref: ref },
      summary: "Probe the xAI account",
      run: async () => fromV1(await xaiAccountStatus(env.broker, { credential_ref: ref }), ref),
    };
  },
  stripe_balance: (a, env) => {
    const ref = providerRef(a, "stripe", "vault://stripe/secret_key");
    return {
      capability: "stripe.balance.read",
      resource: "stripe:balance",
      params: { credential_ref: ref },
      summary: "Read the Stripe balance",
      run: async () => fromV1(await stripeBalance(env.broker, { credential_ref: ref }), ref),
    };
  },
  credential_use: (a, env) => proxyPlan(a, env, { method: "operation", path: "resource" }),
  provider_request: (a, env) => proxyPlan(a, env, { method: "method", path: "path" }),
  entry_list: (a, env) => {
    const site = optStr(a, "site");
    const query = optStr(a, "query");
    return {
      capability: "vault.entry.list",
      resource: clip(`entry:${site ? sanitizeDisplayText(site, 253) : "*"}`, MAX_RESOURCE),
      params: { site, query },
      summary: "List credential entries (metadata only)",
      run: async () => {
        try {
          const entries = await listEntries({ site, query }, env.deps.cards);
          return { result: { ok: true, data: { entries: entries.map(agentEntryView) } } };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  entry_request_card: (a, env) => {
    const site = reqStr(a, "site");
    const account = optStr(a, "account");
    const purpose = optStr(a, "purpose");
    const kind = reqStr(a, "kind") as EntryKind;
    const reason = reqStr(a, "reason");
    const entryId = optStr(a, "entry_id");
    return {
      capability: "vault.card.request",
      resource: clip(`entry:${sanitizeDisplayText(site, 253) || "?"}/${account ? sanitizeDisplayText(account, 200) : "*"}`, MAX_RESOURCE),
      params: { site, account, purpose, kind, reason, entry_id: entryId },
      summary: `Ask the owner to enter a ${kind} for ${clip(site, 80)}${account ? ` (${clip(account, 80)})` : ""}: ${clip(reason, 200)}`,
      run: async () => {
        try {
          // The gateway writes the one ledger row for this call.
          const receipt = await requestCard(
            { client: env.identity, site, account, purpose, kind, reason, entry_id: entryId },
            { ...env.deps.cards, ledger: async () => undefined },
          );
          return {
            result: {
              ok: true,
              data: {
                ...receipt,
                next: "The owner received a single-use link. Poll entry_card_status; when it is completed, use the entry with entry_use.",
              },
            },
          };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  entry_card_status: (a, env) => {
    const cardId = reqStr(a, "card_id");
    return {
      capability: "vault.card.status",
      resource: clip(`card:${sanitizeDisplayText(cardId, 64) || "?"}`, MAX_RESOURCE),
      params: { card_id: cardId },
      summary: "Read the status of a credential card",
      run: async () => {
        try {
          // Visible only to the client that requested it.
          const status = await getCardStatus(cardId, { ...env.deps.cards, client: env.identity });
          const data: Record<string, unknown> = { card_id: status.card_id, status: status.status, expires_at: status.expires_at };
          if (status.entry_id) data.entry_id = status.entry_id;
          if (status.entry) data.entry = agentEntryView(status.entry);
          return { result: { ok: true, data }, audit: status.entry ? { credential_ref: status.entry.ref } : undefined };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  entry_use: entryUsePlan,
  approval_status: (a, env) => {
    const id = reqStr(a, "approval_id");
    return {
      capability: "vault.approval.status",
      resource: clip(`approval:${sanitizeDisplayText(id, 32) || "?"}`, MAX_RESOURCE),
      params: { approval_id: id },
      summary: "Read the status of an approval",
      run: async () => {
        const record = await getApproval(id, env.deps.approvals);
        // Another client's approval is indistinguishable from a missing one.
        if (!record || record.client_id !== env.identity.client_id) return { result: { ok: false, error: "approval_not_found" } };
        const data: Record<string, unknown> = {
          approval_id: record.id,
          status: record.status,
          capability: record.capability,
          resource: record.resource,
          created_at: record.created_at,
          expires_at: record.expires_at,
        };
        if (record.decided_at) data.decided_at = record.decided_at;
        return { result: { ok: true, data } };
      },
    };
  },
  audit_list: (a, env) => {
    const limit = typeof a.limit === "number" ? a.limit : 100;
    const clientId = optStr(a, "client_id");
    const capability = optStr(a, "capability");
    return {
      capability: "audit.read",
      resource: "ledger",
      params: { limit, client_id: clientId, capability },
      summary: "Read the audit ledger",
      run: async () => {
        const records = await (env.deps.listLedger ?? listLedger)({ limit, client_id: clientId, capability });
        return { result: { ok: true, data: { records } } };
      },
    };
  },
  audit_verify: (_a, env) => ({
    capability: "audit.verify",
    resource: "ledger",
    params: {},
    summary: "Verify the audit ledger's hash chain",
    run: async () => {
      const verification = await (env.deps.verifyLedger ?? verifyLedger)();
      const head = await (env.deps.ledgerHead ?? ledgerHead)();
      return { result: { ok: true, data: { ...verification, head } } };
    },
  }),
  // Owner-only admin surface (local stdio identity only; see dispatchTool).
  admin_list_clients: (_a, _env) => ({
    capability: "vault.admin.clients.list",
    resource: "vault:clients",
    params: {},
    summary: "List OAuth clients",
    run: async () => {
      try {
        return { result: { ok: true, data: { clients: await listClients() } } };
      } catch (err) {
        return { result: { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) } };
      }
    },
  }),
  admin_set_client_scopes: (a) => {
    const clientId = reqStr(a, "client_id");
    const scopes = Array.isArray(a.scopes) ? a.scopes : undefined;
    if (!scopes || !scopes.every((s) => typeof s === "string")) {
      throw new ToolInputError("invalid_arguments", "scopes: must be an array of strings");
    }
    return {
      capability: "vault.admin.clients.scopes",
      resource: clip(`vault:client/${sanitizeDisplayText(clientId, 120)}`, MAX_RESOURCE),
      params: { client_id: clientId, scopes: [...scopes] },
      summary: `Set granted scopes for ${clip(clientId, 80)}`,
      run: async () => {
        try {
          return { result: { ok: true, data: { client: await setClientScopes(clientId, scopes as string[]) } } };
        } catch (err) {
          return { result: { ok: false, error: err instanceof Error ? err.message : "internal_error" } };
        }
      },
    };
  },
  admin_revoke_client: (a) => {
    const clientId = reqStr(a, "client_id");
    return {
      capability: "vault.admin.clients.revoke",
      resource: clip(`vault:client/${sanitizeDisplayText(clientId, 120)}`, MAX_RESOURCE),
      params: { client_id: clientId },
      summary: `Revoke client ${clip(clientId, 80)}`,
      run: async () => {
        try {
          return { result: { ok: true, data: await revokeClient(clientId) } };
        } catch (err) {
          return { result: { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) } };
        }
      },
    };
  },
  admin_list_grants: (a, env) => {
    const clientId = optStr(a, "client_id");
    const entryId = optStr(a, "entry_id");
    return {
      capability: "vault.admin.grants.list",
      resource: "vault:grants",
      params: { client_id: clientId, entry_id: entryId },
      summary: "List entry consent grants",
      run: async () => {
        try {
          const grants = await listEntryGrants(
            { client_id: clientId, entry_id: entryId },
            env.deps.grants ?? getDefaultEntryGrantStore(),
          );
          return { result: { ok: true, data: { grants } } };
        } catch (err) {
          return { result: { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) } };
        }
      },
    };
  },
  admin_revoke_grant: (a, env) => {
    const clientId = reqStr(a, "client_id");
    const entryId = reqStr(a, "entry_id");
    const host = optStr(a, "host");
    const pathPrefix = optStr(a, "path_prefix");
    if (pathPrefix !== undefined && host === undefined) {
      throw new ToolInputError("invalid_arguments", "path_prefix requires host");
    }
    return {
      capability: "vault.admin.grants.revoke",
      resource: clip(`vault:grant/${sanitizeDisplayText(clientId, 120)}/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
      params: { client_id: clientId, entry_id: entryId, host, path_prefix: pathPrefix },
      summary: `Revoke consent of ${clip(clientId, 60)} for ${clip(entryId, 40)}${host ? ` on ${clip(host, 60)}${pathPrefix ? ` ${clip(pathPrefix, 80)}` : ""}` : ""}`,
      run: async () => {
        try {
          const removed = await revokeEntryGrant(
            clientId,
            entryId,
            env.deps.grants ?? getDefaultEntryGrantStore(),
            host,
            pathPrefix,
          );
          return { result: { ok: true, data: { removed } } };
        } catch (err) {
          return { result: { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) } };
        }
      },
    };
  },
  admin_list_entries: (a, env) => {
    const site = optStr(a, "site");
    const query = optStr(a, "query");
    return {
      capability: "vault.admin.entries.list",
      resource: clip(`entry:${site ? sanitizeDisplayText(site, 253) : "*"}`, MAX_RESOURCE),
      params: { site, query },
      summary: "List credential entries (owner view)",
      run: async () => {
        try {
          // Owner view: full EntryMetadata, including fingerprint and length. Still no secret value.
          const entries = await listEntries({ site, query }, env.deps.cards);
          return { result: { ok: true, data: { entries } } };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  // Rotation + real delete (logic in rotation.ts / cards.ts). Results are metadata only.
  admin_set_rotation: (a, env) => {
    const entryId = reqStr(a, "entry_id");
    const mode = reqStr(a, "mode") as "manual" | "auto";
    const intervalDays = typeof a.interval_days === "number" ? a.interval_days : undefined;
    const providerTokenId = optStr(a, "provider_token_id");
    return {
      capability: "vault.admin.entries.rotation.set",
      resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
      params: { entry_id: entryId, mode, interval_days: intervalDays, provider_token_id: providerTokenId },
      summary: `Set rotation policy of ${clip(entryId, 40)}`,
      run: async () => {
        try {
          const policy = { mode, interval_days: intervalDays, provider_token_id: providerTokenId };
          return { result: { ok: true, data: await setEntryRotation(entryId, policy, rotationDeps(env)) } };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  admin_rotate_entry: (a, env) => {
    const entryId = reqStr(a, "entry_id");
    return {
      capability: "vault.admin.entries.rotate",
      resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
      params: { entry_id: entryId },
      summary: `Rotate ${clip(entryId, 40)} now`,
      run: async () => {
        try {
          return { result: { ok: true, data: await rotateEntry(entryId, rotationDeps(env)) } };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  admin_rotation_due: (_a, env) => ({
    capability: "vault.admin.entries.rotation.due",
    resource: "entry:*",
    params: {},
    summary: "List entries due for rotation",
    run: async () => {
      try {
        const entries = await listRotationDue((env.deps.now ?? Date.now)(), env.deps.cards);
        return { result: { ok: true, data: { entries } } };
      } catch (err) {
        return { result: entryFailure(err) };
      }
    },
  }),
  admin_purge_entry: (a, env) => {
    const entryId = reqStr(a, "entry_id");
    const confirm = reqStr(a, "confirm");
    return {
      capability: "vault.admin.entries.purge",
      resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
      params: { entry_id: entryId },
      summary: `PURGE ${clip(entryId, 40)} (irreversible)`,
      run: async () => {
        if (confirm !== `PURGE ${entryId}`) {
          return { result: { ok: false, error: "confirmation_required", detail: 'confirm must be exactly "PURGE <entry_id>"' } };
        }
        try {
          return { result: { ok: true, data: await purgeEntry(entryId, rotationDeps(env)) } };
        } catch (err) {
          return { result: entryFailure(err) };
        }
      },
    };
  },
  credential_rotate: (a) => tier3Plan("vault.secret.rotate", a),
  credential_revoke: (a) => tier3Plan("vault.secret.delete", a),
});

/** Wiring for rotation.ts: the gateway's entry stores, grant store and transport, ledgered under the caller. */
function rotationDeps(env: Env): RotationDeps {
  return {
    ...env.deps.cards,
    rotatorFetch: env.deps.fetch,
    grants: env.deps.grants,
    actor: env.identity.client_id,
    ...(env.deps.now ? { now: env.deps.now } : {}),
  };
}

/** Tier 3: the policy engine always denies; `run` exists only to fail closed if that ever changed. */
function tier3Plan(capability: string, a: Record<string, unknown>): Plan {
  const ref = parseVaultRef(optStr(a, "credential_ref") ?? "")?.raw;
  return {
    capability,
    resource: ref ?? "vault:*",
    params: { credential_ref: ref },
    summary: "",
    run: async () => ({ result: { ok: false, error: "tier3_human_only" } }),
  };
}

const DEFINITIONS_BY_NAME: ReadonlyMap<string, ToolDefinition> = new Map(TOOL_DEFINITIONS.map((t) => [t.name, t]));

// ---------------------------------------------------------------------------
// dispatchTool
// ---------------------------------------------------------------------------

function validIdentity(identity: unknown): identity is ClientIdentity {
  const i = identity as ClientIdentity | null;
  return (
    !!i &&
    typeof i === "object" &&
    typeof i.client_id === "string" &&
    i.client_id.length > 0 &&
    i.client_id.length <= 200 &&
    (i.kind === "oauth" || i.kind === "local" || i.kind === "workload") &&
    Array.isArray(i.scopes) &&
    i.scopes.every((s) => typeof s === "string")
  );
}

/**
 * Execute one tool call for an authenticated client. Never throws; never
 * returns secret material. See the module header for the flow.
 */
export async function dispatchTool(
  identity: ClientIdentity,
  name: string,
  args: unknown,
  deps: GatewayDeps = {},
): Promise<GatewayResult> {
  if (!validIdentity(identity)) return { ok: false, error: "unauthenticated" };
  const started = Date.now();
  const ledger = deps.ledger ?? appendLedger;
  const toolName = typeof name === "string" ? name : "";
  const base = { client_id: identity.client_id };

  /** Best effort: a refusal is still a refusal when the ledger is down. */
  const record = async (row: LedgerEntryInput): Promise<boolean> => {
    try {
      await ledger({ ...row, duration_ms: Date.now() - started });
      return true;
    } catch (err) {
      log.error("vault_gateway_ledger_failed", {
        capability: row.capability,
        client_id: row.client_id,
        result: row.result,
        error: (err as { code?: string } | null)?.code ?? "ledger_error",
      });
      return false;
    }
  };
  const finish = (result: GatewayResult): GatewayResult => redactValue(result);

  try {
    if (isForbiddenToolName(toolName)) {
      await record({
        ...base,
        capability: "vault.secret.reveal",
        resource: clip(`tool:${sanitizeDisplayText(toolName, 64) || "?"}`, MAX_RESOURCE),
        decision: "deny",
        tier: 3,
        result: "denied",
        error: "tool_forbidden",
      });
      return finish({ ok: false, error: "tool_forbidden" });
    }
    const definition = DEFINITIONS_BY_NAME.get(toolName);
    const planner = definition ? PLANNERS[toolName] : undefined;
    if (!definition || !planner) {
      await record({
        ...base,
        capability: "vault.tool.unknown",
        resource: clip(`tool:${sanitizeDisplayText(toolName, 64) || "?"}`, MAX_RESOURCE),
        decision: "deny",
        tier: 3,
        result: "denied",
        error: "unknown_tool",
      });
      return finish({ ok: false, error: "unknown_tool" });
    }

    // approval_status takes approval_id as its subject, not as a retry token.
    const raw = args === undefined || args === null ? {} : args;
    let approvalId: string | undefined;
    let plan: Plan;
    try {
      if (!isRecord(raw)) throw new ToolInputError("invalid_arguments", "arguments must be an object");
      checkArgs(definition, raw);
      const a: Record<string, unknown> = { ...raw };
      if (toolName !== "approval_status") {
        approvalId = typeof a.approval_id === "string" && a.approval_id ? a.approval_id : undefined;
        delete a.approval_id;
      }
      plan = await planner(a, { identity, deps, broker: { caller: identity.client_id, store: deps.store } });
    } catch (err) {
      const code = err instanceof ToolInputError ? err.code : "internal_error";
      const detail = err instanceof ToolInputError ? err.message : clip(sanitizeError(err).message, 300);
      await record({
        ...base,
        capability: `tool.${toolName}`,
        resource: `tool:${toolName}`,
        decision: "deny",
        tier: 0,
        result: "error",
        error: `${code}: ${detail}`,
      });
      return finish({ ok: false, error: code, detail });
    }

    const request: CapabilityRequest = {
      client: identity,
      capability: plan.capability,
      resource: plan.resource,
      params: plan.params,
    };
    let decision = evaluatePolicy(request, deps.rules, deps.policy);
    // Owner-only admin surface: vault.admin.* is tier 3, so evaluatePolicy denies
    // it for EVERY client. The one exception is the local stdio identity — the
    // owner on their own machine — which we allow here. This carve-out is keyed
    // solely on kind==="local"; it never loosens the tier-3 deny that every remote
    // OAuth/workload agent still receives above.
    if (plan.capability.startsWith("vault.admin.") && decision.decision === "deny" && identity.kind === "local") {
      log.warn("vault_admin_local_allow", { capability: plan.capability, client_id: identity.client_id });
      decision = { decision: "allow", tier: decision.tier, reason: "owner_local" };
    }
    const row = {
      ...base,
      capability: plan.capability,
      resource: plan.resource,
      decision: decision.decision,
      tier: decision.tier,
      task: plan.task,
    };

    if (decision.decision === "deny") {
      await record({ ...row, result: "denied", error: decision.reason });
      return finish({ ok: false, error: decision.reason, tier: decision.tier });
    }

    const grants = deps.grants ?? getDefaultEntryGrantStore();
    const nowMs = (deps.now ?? Date.now)();
    // Read-only entry use: a matching narrow grant (this entry, this host, this
    // request path or a parent of it, unexpired and with uses left) means no
    // approval is needed; its use is spent before the action runs.
    const grant =
      decision.decision === "allow" && plan.consentEntryId !== undefined && plan.consentHost && plan.consentPath
        ? await grants.find(identity.client_id, plan.consentEntryId, plan.consentHost, plan.consentPath, nowMs)
        : null;
    const needsConsent = decision.decision === "allow" && plan.consentEntryId !== undefined && grant === null;
    let approved = false;

    if (decision.decision === "escalate" || needsConsent) {
      const ledgerDecision = "escalate" as const;
      if (!approvalId) {
        let approval;
        try {
          approval = await createApproval(request, plan.summary || `${plan.capability} on ${plan.resource}`, deps.approvals);
        } catch (err) {
          const code = err instanceof ApprovalError ? err.code : "approval_error";
          await record({ ...row, decision: ledgerDecision, result: "error", error: `approval_unavailable: ${code}` });
          return finish({ ok: false, error: "approval_unavailable", detail: code });
        }
        await record({ ...row, decision: ledgerDecision, result: "pending_approval", approval_id: approval.id });
        return finish({
          ok: false,
          error: "approval_required",
          approval_id: approval.id,
          expires_at: approval.expires_at,
          tier: decision.tier,
          detail: needsConsent
            ? "The owner must approve this client's first use of this entry on Telegram. Then call again with the same arguments plus approval_id."
            : "The owner must approve this exact request on Telegram. Then call again with the same arguments plus approval_id. Use approval_status to check.",
        });
      }
      const consumed = await consumeApproval(approvalId, request, deps.approvals);
      if (consumed !== "ok") {
        await record({
          ...row,
          decision: ledgerDecision,
          result: consumed === "pending" ? "pending_approval" : "denied",
          approval_id: approvalId,
          error: `approval_${consumed}`,
        });
        return finish({ ok: false, error: `approval_${consumed}`, approval: consumed, approval_id: approvalId, tier: decision.tier });
      }
      approved = true;
      if (needsConsent && plan.consentEntryId && plan.consentHost && plan.consentPath) {
        // The approval creates a NARROW, expiring, use-capped grant: this entry,
        // this host, this request path (and anything under it) only.
        const { ttlMs, maxUses } = grantConfig(deps.env);
        await grants.add({
          client_id: identity.client_id,
          entry_id: plan.consentEntryId,
          host: plan.consentHost,
          path_prefix: plan.consentPath,
          approval_id: approvalId as string,
          granted_at: new Date(nowMs).toISOString(),
          expires_at: new Date(nowMs + ttlMs).toISOString(),
          max_uses: maxUses,
          uses_remaining: maxUses,
        });
        log.info("vault_entry_grant_created", {
          client_id: identity.client_id,
          entry_id: plan.consentEntryId,
          host: plan.consentHost,
          path_prefix: plan.consentPath,
          approval_id: approvalId,
        });
      }
    } else if (grant && plan.consentEntryId && plan.consentHost && plan.consentPath) {
      // An existing grant covers this read: spend one use before the action runs.
      await grants.consume(identity.client_id, plan.consentEntryId, plan.consentHost, plan.consentPath, nowMs);
    }

    const runRow = { ...row, decision: approved ? ("escalate" as const) : decision.decision, approval_id: approved ? approvalId : undefined };

    // Pre-commit (intent) audit row for an approved MUTATION: record the
    // authorization on the chain BEFORE the side-effect, so a ledger outage after
    // the action can never leave it unaudited. Reads need no commit row, and
    // entry_use self-ledgers (fails closed) under its own capability, so both are
    // excluded — only genuine mutating capabilities get a "committing" row here.
    const isEntryUse = plan.capability.startsWith("vault.entry.use.");
    const isRead = lookupCapability(plan.capability)?.access === "read";
    if (approved && !isEntryUse && !isRead) {
      const committed = await record({ ...runRow, result: "committing" });
      if (!committed) {
        return finish({
          ok: false,
          error: "ledger_unavailable",
          action_performed: false,
          detail: "Refused: the authorization could not be recorded before acting.",
        });
      }
    }

    let outcome: Outcome;
    try {
      outcome = await plan.run({ decision: { ...decision, decision: runRow.decision }, approved, approvalId: approved ? approvalId : undefined });
    } catch (err) {
      outcome = { result: { ok: false, error: "internal_error", detail: clip(sanitizeError(err).message, 300) } };
    }
    const result = outcome.result;
    if (!outcome.ledgered) {
      const status = outcome.audit?.http_status;
      const failed = !result.ok || (status !== undefined && status >= 400);
      const written = await record({
        ...runRow,
        result: failed ? "error" : "ok",
        credential_ref: outcome.audit?.credential_ref,
        http_status: status,
        credential_path: outcome.audit?.credential_path,
        fallback_reason: outcome.audit?.fallback_reason,
        error: !result.ok ? result.error : failed ? `http_${status}` : undefined,
      });
      // Fail closed: an action that could not be audited is not reported as a success.
      if (!written) {
        return finish({
          ok: false,
          error: "ledger_unavailable",
          detail: result.ok
            ? "The action ran but could not be recorded in the audit ledger, so its result is withheld."
            : "The action failed and could not be recorded in the audit ledger.",
          action_performed: result.ok,
        });
      }
    }
    return finish(result);
  } catch (err) {
    // Nothing above should throw; if it does, refuse and say nothing specific.
    log.error("vault_gateway_internal_error", { tool: toolName, client_id: identity.client_id, error: clip(sanitizeError(err).message, 200) });
    return finish({ ok: false, error: "internal_error" });
  }
}

export { INVARIANT };
