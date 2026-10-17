export const INVARIANT =
  "Agents may USE credentials. Agents may NEVER READ credentials.";

export type ProviderId =
  | "github"
  | "cloudflare"
  | "openai"
  | "stripe"
  | "xai";

export type CredentialType =
  | "pat"
  | "api_key"
  | "bearer"
  | "service_token";

export type CredentialStatus =
  | "imported"
  | "healthy"
  | "unhealthy"
  | "revoked"
  | "unavailable"
  | "identity_mismatch";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface VaultRef {
  scheme: "vault";
  provider: ProviderId;
  account: string;
  raw: string;
}

export interface CredentialMetadata {
  ref: string;
  provider: ProviderId;
  account: string;
  type: CredentialType;
  status: CredentialStatus;
  last_verified: string | null;
  fingerprint: string | null;
  source: string;
}


export interface AuditRecord {
  id: string;
  timestamp: string;
  caller: string;
  credential_ref: string;
  provider: string;
  operation: string;
  resource: string;
  http_status: number | null;
  duration_ms: number;
  result: "ok" | "error" | "denied";
  error?: string;
}

export interface ToolFailure {
  ok: false;
  error: string;
  credential_ref?: string;
  detail?: string;
}

export interface ToolSuccess<T = unknown> {
  ok: true;
  data: T;
}

export type ToolResult<T = unknown> = ToolSuccess<T> | ToolFailure;

export const FORBIDDEN_TOOLS = [
  // Private operator actions must never inherit public caller-label authority.
  "sdk_action_review",
  "sdk_operator_execute",
  "get_secret",
  "get_token",
  "get_pat",
  "get_password",
  "get_private_key",
  "read_secret",
  "read_credential",
  "export_vault",
  "dump_vault",
  "dump_credentials",
  "reveal_credential",
  "unwrap_secret",
] as const;

export const SENSITIVE_RESPONSE_KEYS = new Set([
  "token",
  "secret",
  "password",
  "private_key",
  "refresh_token",
  "cookie",
  "authorization_header",
  "authorization",
  "access_token",
  "id_token",
  "client_secret",
  "api_key",
  "pat",
]);
