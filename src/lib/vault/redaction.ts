import { SENSITIVE_RESPONSE_KEYS } from "./types.ts";

const knownSecrets = new Set<string>();

const PLACEHOLDERS = {
  github: "[REDACTED_GITHUB_TOKEN]",
  openai: "[REDACTED_OPENAI_KEY]",
  stripe: "[REDACTED_STRIPE_KEY]",
  xai: "[REDACTED_XAI_KEY]",
  cloudflare: "[REDACTED_CLOUDFLARE_TOKEN]",
  bearer: "Bearer [REDACTED]",
  authorization: "Authorization: [REDACTED]",
  jwt: "[REDACTED_JWT]",
  privateKey: "[REDACTED_PRIVATE_KEY]",
  cookie: "[REDACTED_COOKIE]",
  session: "[REDACTED_SESSION]",
  refresh: "[REDACTED_REFRESH_TOKEN]",
  generic: "[REDACTED_SECRET]",
} as const;

const PATTERN_RULES: Array<{ re: RegExp; replacement: string }> = [
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, replacement: PLACEHOLDERS.github },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replacement: PLACEHOLDERS.github },
  { re: /\bsk-live-[A-Za-z0-9]{16,}\b/g, replacement: PLACEHOLDERS.stripe },
  { re: /\bsk-test-[A-Za-z0-9]{16,}\b/g, replacement: PLACEHOLDERS.stripe },
  { re: /\bsk-[A-Za-z0-9]{20,}\b/g, replacement: PLACEHOLDERS.openai },
  { re: /\bxai-[A-Za-z0-9_-]{20,}\b/g, replacement: PLACEHOLDERS.xai },
  { re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi, replacement: PLACEHOLDERS.bearer },
  {
    re: /\bAuthorization\s*:\s*[^\r\n]+/gi,
    replacement: PLACEHOLDERS.authorization,
  },
  { re: /\bx-access-token\s*[:=]\s*\S+/gi, replacement: "[REDACTED_ACCESS_TOKEN]" },
  {
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    replacement: PLACEHOLDERS.privateKey,
  },
  {
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    replacement: PLACEHOLDERS.jwt,
  },
  {
    re: /\b(?:refresh_token)\s*[:=]\s*[^\s;&]+/gi,
    replacement: `refresh_token=${PLACEHOLDERS.refresh}`,
  },
  {
    re: /\b(?:sessionid|session_id|session)\s*[:=]\s*[^\s;&]+/gi,
    replacement: `session=${PLACEHOLDERS.session}`,
  },
  {
    re: /\b(?:Set-Cookie|Cookie)\s*:\s*[^\r\n]+/gi,
    replacement: `Cookie: ${PLACEHOLDERS.cookie}`,
  },
];

function placeholderForSecret(secret: string): string {
  if (/^github_pat_|^gh[pousr]_/.test(secret)) return PLACEHOLDERS.github;
  if (/^sk-live-|^sk-test-/.test(secret)) return PLACEHOLDERS.stripe;
  if (/^sk-/.test(secret)) return PLACEHOLDERS.openai;
  if (/^xai-/.test(secret)) return PLACEHOLDERS.xai;
  return PLACEHOLDERS.generic;
}

export function registerSecretForRedaction(secret: string): void {
  const trimmed = secret.trim();
  if (trimmed.length >= 8) knownSecrets.add(trimmed);
}

export function clearRegisteredSecrets(): void {
  knownSecrets.clear();
}

export function registeredSecretCount(): number {
  return knownSecrets.size;
}

export function redactString(input: string): string {
  let out = input;
  if (knownSecrets.size > 0) {
    const secrets = [...knownSecrets].sort((a, b) => b.length - a.length);
    for (const secret of secrets) {
      if (secret && out.includes(secret)) {
        out = out.split(secret).join(placeholderForSecret(secret));
      }
    }
  }
  for (const rule of PATTERN_RULES) {
    out = out.replace(rule.re, rule.replacement);
  }
  return out;
}

export function redactValue<T>(value: T): T {
  if (value == null) return value;
  if (typeof value === "string") return redactString(value) as T;
  if (typeof value !== "object") return value;
  try {
    const stripped = stripSensitiveKeys(value);
    return JSON.parse(redactString(JSON.stringify(stripped))) as T;
  } catch {
    return { error: "unserializable_redacted" } as T;
  }
}

function stripSensitiveKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripSensitiveKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_RESPONSE_KEYS.has(key.toLowerCase())) {
        out[key] = PLACEHOLDERS.generic;
      } else {
        out[key] = stripSensitiveKeys(val);
      }
    }
    return out;
  }
  return value;
}

export function sanitizeError(error: unknown): Error {
  if (error instanceof Error) {
    const clean = new Error(redactString(error.message));
    clean.name = error.name;
    if (error.stack) clean.stack = redactString(error.stack);
    return clean;
  }
  return new Error(redactString(String(error)));
}

export function safeJson(value: unknown): string {
  try {
    return redactString(JSON.stringify(redactValue(value)));
  } catch {
    return '{"error":"unserializable_redacted"}';
  }
}

let processHookInstalled = false;
const originalWrites: {
  stdout?: typeof process.stdout.write;
  stderr?: typeof process.stderr.write;
} = {};

function wrapStream(stream: NodeJS.WriteStream, key: "stdout" | "stderr"): void {
  if (originalWrites[key]) return;
  const orig = stream.write.bind(stream);
  originalWrites[key] = orig;
  stream.write = ((chunk: unknown, encoding?: unknown, cb?: unknown) => {
    try {
      if (typeof chunk === "string") {
        chunk = redactString(chunk);
      } else if (chunk instanceof Uint8Array) {
        const enc =
          typeof encoding === "string" && encoding !== "buffer"
            ? encoding
            : "utf8";
        chunk = Buffer.from(
          redactString(Buffer.from(chunk).toString(enc as BufferEncoding)),
        );
      }
    } catch {
      chunk = "[REDACTED_OUTPUT]\n";
    }
    return orig(chunk as string | Uint8Array, encoding as never, cb as never);
  }) as typeof stream.write;
}

export function installProcessRedaction(): void {
  if (processHookInstalled) return;
  processHookInstalled = true;
  wrapStream(process.stdout, "stdout");
  wrapStream(process.stderr, "stderr");

  const origConsoleError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    origConsoleError(
      ...args.map((arg) =>
        typeof arg === "string" ? redactString(arg) : redactValue(arg),
      ),
    );
  };
  const origConsoleLog = console.log.bind(console);
  console.log = (...args: unknown[]) => {
    origConsoleLog(
      ...args.map((arg) =>
        typeof arg === "string" ? redactString(arg) : redactValue(arg),
      ),
    );
  };
  const origConsoleWarn = console.warn.bind(console);
  console.warn = (...args: unknown[]) => {
    origConsoleWarn(
      ...args.map((arg) =>
        typeof arg === "string" ? redactString(arg) : redactValue(arg),
      ),
    );
  };

  process.on("uncaughtException", (err) => {
    const clean = sanitizeError(err);
    origConsoleError("[vault] uncaughtException", clean.message);
  });
}

export function isProcessRedactionInstalled(): boolean {
  return processHookInstalled;
}

export function containsSecretPrefix(text: string): boolean {
  return (
    /\bgithub_pat_[A-Za-z0-9_]{8,}/.test(text) ||
    /\bgh[pousr]_[A-Za-z0-9]{8,}/.test(text) ||
    /\bsk-[A-Za-z0-9]{12,}/.test(text)
  );
}
