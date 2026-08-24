import { recordAudit } from "./audit.ts";
import { authorizedProviderFetch, githubAuthHeaders } from "./http.ts";
import { ensureImported } from "./importer.ts";
import {
  assertSafeDestination,
  buildProviderUrl,
  isAllowedMethod,
  isApprovedCaller,
  PROVIDER_POLICIES,
} from "./policy.ts";
import { installProcessRedaction, redactValue, sanitizeError } from "./redaction.ts";
import { parseVaultRef } from "./refs.ts";
import { getStore, type CredentialStore } from "./store.ts";
import type {
  CredentialMetadata,
  HttpMethod,
  ProviderId,
  ToolFailure,
  ToolResult,
} from "./types.ts";

if (!process.env.NODE_TEST_CONTEXT) {
  installProcessRedaction();
}

export interface BrokerContext {
  caller: string;
  store?: CredentialStore;
}

export interface UseCredentialInput {
  credential_ref: string;
  provider: ProviderId;
  operation: HttpMethod | string;
  resource: string;
  body?: unknown;
}

function fail(error: string, credential_ref?: string, detail?: string): ToolFailure {
  return redactValue({
    ok: false as const,
    error,
    credential_ref,
    detail,
  });
}

function resolveOrFail(
  ctx: BrokerContext,
  credential_ref: string,
  provider: ProviderId,
): { secret: string; meta: CredentialMetadata } | ToolFailure {
  const parsed = parseVaultRef(credential_ref);
  if (!parsed) return fail("invalid_credential_ref", credential_ref);
  if (parsed.provider !== provider) {
    return fail("provider_mismatch", credential_ref);
  }
  const store = ctx.store ?? getStore();
  const meta = store.getMetadata(parsed.raw);
  if (!meta || meta.status === "revoked") {
    return fail("credential_unavailable", parsed.raw);
  }
  const secret = store.resolveSecret(parsed.raw);
  if (!secret) return fail("credential_unavailable", parsed.raw);
  return { secret, meta };
}

export async function useCredential(
  ctx: BrokerContext,
  input: UseCredentialInput,
): Promise<ToolResult> {
  const started = Date.now();
  const caller = ctx.caller || "unknown";
  if (!isApprovedCaller(caller)) {
    recordAudit({
      caller,
      credential_ref: input.credential_ref,
      provider: input.provider,
      operation: String(input.operation),
      resource: input.resource,
      http_status: null,
      duration_ms: Date.now() - started,
      result: "denied",
      error: "caller_not_allowed",
    });
    return fail("caller_not_allowed", input.credential_ref);
  }

  if (!ctx.store) {
    await ensureImported();
  }

  const resolved = resolveOrFail(ctx, input.credential_ref, input.provider);
  if ("ok" in resolved && resolved.ok === false) {
    recordAudit({
      caller,
      credential_ref: input.credential_ref,
      provider: input.provider,
      operation: String(input.operation),
      resource: input.resource,
      http_status: null,
      duration_ms: Date.now() - started,
      result: "error",
      error: resolved.error,
    });
    return resolved;
  }

  const { secret, meta } = resolved as {
    secret: string;
    meta: CredentialMetadata;
  };

  if (!isAllowedMethod(input.provider, String(input.operation))) {
    return fail("operation_not_allowed", meta.ref);
  }
  const method = String(input.operation).toUpperCase() as HttpMethod;

  let url: URL;
  try {
    url = buildProviderUrl(input.provider, input.resource);
    assertSafeDestination(url, input.provider);
  } catch (error) {
    const clean = sanitizeError(error);
    recordAudit({
      caller,
      credential_ref: meta.ref,
      provider: input.provider,
      operation: method,
      resource: input.resource,
      http_status: null,
      duration_ms: Date.now() - started,
      result: "denied",
      error: clean.message,
    });
    return fail(clean.message, meta.ref);
  }

  try {
    const extra =
      input.provider === "github" ? githubAuthHeaders() : undefined;
    const result = await authorizedProviderFetch({
      provider: input.provider,
      url,
      method,
      secret,
      extraHeaders: extra,
      body: input.body,
      accept:
        input.provider === "github"
          ? "application/vnd.github+json"
          : "application/json",
    });
    recordAudit({
      caller,
      credential_ref: meta.ref,
      provider: input.provider,
      operation: method,
      resource: input.resource,
      http_status: result.status,
      duration_ms: Date.now() - started,
      result: result.ok ? "ok" : "error",
      error: result.ok ? undefined : `http_${result.status}`,
    });
    return redactValue({
      ok: true as const,
      data: {
        status: result.status,
        body: result.json ?? result.text,
      },
    });
  } catch (error) {
    const clean = sanitizeError(error);
    recordAudit({
      caller,
      credential_ref: meta.ref,
      provider: input.provider,
      operation: method,
      resource: input.resource,
      http_status: null,
      duration_ms: Date.now() - started,
      result: "error",
      error: clean.message,
    });
    return fail("provider_request_failed", meta.ref, clean.message);
  }
}

export function probeUnapprovedUrl(hostname: string, secret: string): never {
  const url = new URL(`https://${hostname}/`);
  assertSafeDestination(url, "github");
  void secret;
  throw new Error("unreachable");
}

export { PROVIDER_POLICIES };
