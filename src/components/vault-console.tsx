import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowRight,
  KeyRound,
  List,
  Lock,
  Plug,
  Radar,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Unplug,
  Wrench,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  rpcAuditList,
  rpcCallTool,
  rpcListTools,
  rpcRevealSecret,
  rpcVaultList,
  rpcVaultStatus,
} from "@/lib/vault-rpc";
import { cn } from "@/lib/utils";
import { InstallPanel } from "@/components/install-panel";

type Tab = "overview" | "credentials" | "tools" | "audit" | "policy" | "install";

const TABS: { id: Tab; label: string; icon: typeof Lock }[] = [
  { id: "overview", label: "Overview", icon: ShieldCheck },
  { id: "credentials", label: "Credentials", icon: KeyRound },
  { id: "tools", label: "Tools", icon: Wrench },
  { id: "audit", label: "Audit", icon: ScrollText },
  { id: "policy", label: "Policy", icon: Lock },
  { id: "install", label: "Install", icon: Plug },
];

function statusTone(status?: string) {
  if (status === "healthy") return "healthy" as const;
  if (status === "identity_mismatch" || status === "unhealthy") return "danger" as const;
  if (status === "imported") return "warn" as const;
  if (status === "revoked") return "danger" as const;
  return "default" as const;
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-md bg-bg p-3 font-mono text-xs leading-relaxed text-fg shadow-[0_0_0_1px_var(--color-border)]">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function VaultConsole() {
  const [tab, setTab] = useState<Tab>("overview");
  const queryClient = useQueryClient();

  const statusQ = useQuery({
    queryKey: ["vault-status"],
    queryFn: () => rpcVaultStatus(),
  });
  const listQ = useQuery({
    queryKey: ["vault-list"],
    queryFn: () => rpcVaultList(),
  });
  const toolsQ = useQuery({
    queryKey: ["vault-tools"],
    queryFn: () => rpcListTools(),
  });
  const auditQ = useQuery({
    queryKey: ["vault-audit"],
    queryFn: () => rpcAuditList(),
  });
  const healthQ = useQuery({
    queryKey: ["credential-health"],
    queryFn: () =>
      rpcCallTool({
        data: {
          name: "credential_health",
          arguments: {
            credential_ref: "vault://github/echoomegaprime",
          },
        },
      }),
  });
  const repoQ = useQuery({
    queryKey: ["github-repo"],
    queryFn: () =>
      rpcCallTool({
        data: {
          name: "github_get_repository",
          arguments: {
            owner: "echoomegaprime",
            repo: "echo-continuity-fabric",
          },
        },
      }),
  });

  const refresh = () => {
    void queryClient.invalidateQueries();
  };

  const revoke = useMutation({
    mutationFn: (ref: string) =>
      rpcCallTool({
        data: {
          name: "credential_revoke",
          arguments: { credential_ref: ref },
        },
      }),
    onSuccess: refresh,
  });
  const rotate = useMutation({
    mutationFn: (ref: string) =>
      rpcCallTool({
        data: {
          name: "credential_rotate",
          arguments: { credential_ref: ref },
        },
      }),
    onSuccess: refresh,
  });
  const invoke = useMutation({
    mutationFn: (payload: { name: string; arguments?: Record<string, unknown> }) =>
      rpcCallTool({
        data: {
          name: payload.name,
          arguments: Object.fromEntries(
            Object.entries(payload.arguments ?? {}).flatMap(([k, v]) =>
              typeof v === "string" || typeof v === "number" || typeof v === "boolean"
                ? [[k, v]]
                : [],
            ),
          ),
        },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vault-audit"] });
      void queryClient.invalidateQueries({ queryKey: ["vault-list"] });
    },
  });

  const credentials =
    listQ.data && listQ.data.ok
      ? (
          listQ.data.data as {
            credentials: Array<{
              ref: string;
              provider: string;
              account: string;
              type: string;
              status: string;
              last_verified: string | null;
              fingerprint: string | null;
              source: string;
            }>;
          }
        ).credentials
      : [];

  const health =
    healthQ.data && healthQ.data.ok
      ? (healthQ.data.data as {
          account?: string;
          account_id?: number;
          authenticated?: boolean;
          status?: string;
          ref?: string;
        })
      : null;

  const repo =
    repoQ.data && repoQ.data.ok
      ? (repoQ.data.data as {
          full_name?: string;
          private?: boolean;
          description?: string;
          default_branch?: string;
        })
      : null;

  const tools =
    toolsQ.data && toolsQ.data.ok
      ? (
          toolsQ.data.data as {
            tools: Array<{ name: string; description: string }>;
          }
        ).tools
      : [];

  const audit =
    auditQ.data && auditQ.data.ok
      ? (
          auditQ.data.data as {
            records: Array<{
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
            }>;
          }
        ).records
      : [];

  const statusData =
    statusQ.data && statusQ.data.ok
      ? (statusQ.data.data as {
          invariant: string;
          credential_count: number;
          redaction: string;
          fail_closed: boolean;
          imported: string[];
        })
      : null;

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <div className="vault-grid pointer-events-none fixed inset-0 opacity-40" />
      <div className="relative mx-auto flex min-h-dvh max-w-7xl flex-col lg:flex-row">
        <aside className="flex flex-col border-b border-border lg:w-64 lg:border-b-0 lg:border-r">
          <div className="flex items-center gap-3 px-5 py-5">
            <span className="flex size-10 items-center justify-center rounded-md bg-bg-elevated shadow-[0_0_0_1px_var(--color-border)]">
              <Lock className="size-4 text-accent" strokeWidth={1.75} />
            </span>
            <div>
              <p className="text-sm font-medium tracking-tight">Echo Vault</p>
              <p className="text-xs text-muted">Credential Broker</p>
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:px-3">
            {TABS.map((item) => {
              const Icon = item.icon;
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setTab(item.id)}
                  className={cn(
                    "flex min-h-11 min-w-11 items-center gap-2 rounded-sm px-3 text-sm transition-colors duration-150",
                    active
                      ? "bg-bg-subtle text-fg"
                      : "text-muted hover:bg-bg-subtle hover:text-fg",
                  )}
                >
                  <Icon className="size-4 shrink-0" strokeWidth={1.75} />
                  {item.label}
                </button>
              );
            })}
          </nav>
          <div className="mt-auto hidden px-5 py-5 lg:block">
            <p className="font-mono text-[11px] leading-relaxed text-subtle">
              Agents may USE credentials.
              <br />
              Agents may NEVER READ credentials.
            </p>
          </div>
        </aside>

        <main className="flex-1 px-4 py-6 sm:px-8">
          <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="stagger-in">
              <p className="mb-2 text-xs font-medium uppercase tracking-[0.18em] text-muted">
                Trusted server side
              </p>
              <h1 className="text-3xl font-medium tracking-tight sm:text-4xl">
                {TABS.find((t) => t.id === tab)?.label}
              </h1>
            </div>
            <Button variant="secondary" onClick={refresh} className="self-start">
              <RefreshCw className="size-4" />
              Refresh
            </Button>
          </header>

          {tab === "overview" && (
            <div className="grid gap-4">
              <Card className="stagger-in rounded-xl p-5">
                <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted">
                  Invariant
                </p>
                <p className="mt-2 max-w-2xl text-lg font-medium tracking-tight">
                  Agents may USE credentials. Agents may NEVER READ credentials.
                </p>
                <p className="mt-2 max-w-xl text-sm text-muted">
                  A vault reference is a capability handle, not a secret-retrieval
                  mechanism. Raw PATs, API keys, and tokens never leave the broker
                  process.
                </p>
              </Card>

              <div className="grid gap-4 sm:grid-cols-3">
                <Stat
                  label="Credentials"
                  value={String(statusData?.credential_count ?? "—")}
                  hint="opaque refs only"
                />
                <Stat
                  label="Redaction"
                  value={statusData?.redaction === "armed" ? "Armed" : "—"}
                  hint="stdout, logs, MCP"
                />
                <Stat
                  label="Fail closed"
                  value={statusData?.fail_closed ? "On" : "—"}
                  hint="no anonymous fallback"
                />
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <Card className="p-5">
                  <CardHeader>
                    <div className="flex items-center justify-between gap-3">
                      <CardTitle>GitHub identity</CardTitle>
                      <Badge tone={statusTone(health?.status)}>
                        {health?.status ?? (healthQ.isLoading ? "checking" : "unknown")}
                      </Badge>
                    </div>
                    <CardDescription>
                      Safe GET /user. The PAT never appears in this response.
                    </CardDescription>
                  </CardHeader>
                  {healthQ.isLoading ? (
                    <p className="text-sm text-muted">Verifying credential…</p>
                  ) : health ? (
                    <dl className="grid grid-cols-2 gap-3 text-sm">
                      <Field label="Account" value={health.account ?? "—"} mono />
                      <Field label="Account ID" value={String(health.account_id ?? "—")} mono />
                      <Field
                        label="Authenticated"
                        value={health.authenticated ? "true" : "false"}
                      />
                      <Field label="Ref" value={health.ref ?? "vault://github/echoomegaprime"} mono />
                    </dl>
                  ) : (
                    <p className="text-sm text-danger">
                      Credential unavailable. Broker failed closed.
                    </p>
                  )}
                </Card>

                <Card className="p-5">
                  <CardHeader>
                    <div className="flex items-center justify-between gap-3">
                      <CardTitle>Private repository</CardTitle>
                      <Badge tone={repo?.private ? "accent" : "default"}>
                        {repo?.private ? "private" : repo ? "public" : "—"}
                      </Badge>
                    </div>
                    <CardDescription>
                      echoomegaprime/echo-continuity-fabric via the vault handle.
                    </CardDescription>
                  </CardHeader>
                  {repoQ.isLoading ? (
                    <p className="text-sm text-muted">Reading repository metadata…</p>
                  ) : repo ? (
                    <dl className="grid gap-3 text-sm">
                      <Field label="Full name" value={repo.full_name ?? "—"} mono />
                      <Field label="Default branch" value={repo.default_branch ?? "—"} mono />
                      <Field
                        label="Description"
                        value={repo.description ?? "—"}
                      />
                    </dl>
                  ) : (
                    <p className="text-sm text-danger">
                      Repository lookup failed closed.
                    </p>
                  )}
                </Card>
              </div>

              <Card className="p-5">
                <CardHeader>
                  <CardTitle>Request path</CardTitle>
                  <CardDescription>
                    The model only ever holds the opaque reference.
                  </CardDescription>
                </CardHeader>
                <ol className="grid gap-2 sm:grid-cols-4">
                  {[
                    { title: "Agent", body: "vault://github/echoomegaprime" },
                    { title: "Policy", body: "caller · scope · audit" },
                    { title: "Vault", body: "raw secret stays here" },
                    { title: "Provider", body: "api.github.com only" },
                  ].map((step, i) => (
                    <li
                      key={step.title}
                      className="flex items-start gap-3 rounded-md bg-bg p-3 shadow-[0_0_0_1px_var(--color-border)]"
                    >
                      <span className="font-mono text-xs text-subtle">{i + 1}</span>
                      <div>
                        <p className="text-sm font-medium">{step.title}</p>
                        <p className="mt-1 font-mono text-xs text-muted">{step.body}</p>
                      </div>
                    </li>
                  ))}
                </ol>
              </Card>
            </div>
          )}

          {tab === "credentials" && (
            <div className="grid gap-3">
              {credentials.length === 0 ? (
                <Card className="p-6">
                  <p className="text-sm text-muted">
                    No credentials imported. The broker fails closed until a trusted
                    sandbox source is available.
                  </p>
                </Card>
              ) : (
                credentials.map((cred) => (
                  <Card key={cred.ref} className="p-5">
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="font-mono text-sm">{cred.ref}</p>
                          <Badge tone={statusTone(cred.status)}>{cred.status}</Badge>
                        </div>
                        <p className="mt-2 text-sm text-muted">
                          {cred.provider} · {cred.account} · {cred.type}
                        </p>
                        <p className="mt-1 font-mono text-xs text-subtle">
                          source {cred.source}
                          {cred.fingerprint ? ` · fp ${cred.fingerprint}` : ""}
                          {cred.last_verified
                            ? ` · verified ${cred.last_verified}`
                            : ""}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => rotate.mutate(cred.ref)}
                          disabled={rotate.isPending}
                        >
                          <RefreshCw className="size-3.5" />
                          Rotate
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revoke.mutate(cred.ref)}
                          disabled={revoke.isPending}
                        >
                          <Unplug className="size-3.5" />
                          Revoke
                        </Button>
                      </div>
                    </div>
                    <RevealSecret credRef={cred.ref} />
                  </Card>
                ))
              )}
            </div>
          )}

          {tab === "tools" && (
            <ToolsPanel tools={tools} invoke={invoke} />
          )}

          {tab === "audit" && (
            <Card className="overflow-hidden p-0">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-muted">
                    <tr className="border-b border-border">
                      <th className="px-4 py-3 font-medium">Time</th>
                      <th className="px-4 py-3 font-medium">Caller</th>
                      <th className="px-4 py-3 font-medium">Op</th>
                      <th className="px-4 py-3 font-medium">Resource</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium">Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.length === 0 ? (
                      <tr>
                        <td className="px-4 py-8 text-muted" colSpan={6}>
                          No audited operations yet.
                        </td>
                      </tr>
                    ) : (
                      audit.map((row) => (
                        <tr key={row.id} className="border-b border-border/70">
                          <td className="px-4 py-3 font-mono text-xs tabular-nums text-muted">
                            {row.timestamp.replace("T", " ").slice(0, 19)}
                          </td>
                          <td className="px-4 py-3">{row.caller}</td>
                          <td className="px-4 py-3 font-mono text-xs">
                            {row.operation}
                          </td>
                          <td className="max-w-48 truncate px-4 py-3 font-mono text-xs">
                            {row.resource}
                          </td>
                          <td className="px-4 py-3 tabular-nums">
                            {row.http_status ?? "—"}
                          </td>
                          <td className="px-4 py-3">
                            <Badge tone={row.result === "ok" ? "healthy" : "danger"}>
                              {row.result}
                            </Badge>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {tab === "policy" && <PolicyPanel />}
          {tab === "install" && <InstallPanel />}
        </main>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <Card className="p-5">
      <p className="text-xs uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2 text-2xl font-medium tracking-tight">{value}</p>
      <p className="mt-1 text-xs text-subtle">{hint}</p>
    </Card>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={cn("mt-1 break-all", mono && "font-mono text-xs")}>{value}</dd>
    </div>
  );
}

/**
 * Human-only reveal + copy. Calls `rpcRevealSecret` (never an MCP tool — no
 * agent can reach this path). The value lives only in this component's local
 * state: never cached by React Query, never logged, auto-hidden after 30s or
 * on unmount. Every reveal is separately audited server-side as `human_reveal`.
 */
function RevealSecret({ credRef }: { credRef: string }) {
  const [state, setState] = useState<
    | { phase: "hidden" }
    | { phase: "loading" }
    | { phase: "shown"; value: string }
    | { phase: "error"; message: string }
  >({ phase: "hidden" });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (state.phase !== "shown") return;
    const t = setTimeout(() => setState({ phase: "hidden" }), 30_000);
    return () => clearTimeout(t);
  }, [state.phase]);

  const reveal = async () => {
    setState({ phase: "loading" });
    try {
      const res = await rpcRevealSecret({ data: { credential_ref: credRef } });
      if (res.ok) setState({ phase: "shown", value: res.secret });
      else setState({ phase: "error", message: res.error });
    } catch {
      setState({ phase: "error", message: "request_failed" });
    }
  };

  const copy = async () => {
    if (state.phase !== "shown") return;
    await navigator.clipboard.writeText(state.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (state.phase === "hidden" || state.phase === "loading") {
    return (
      <Button variant="secondary" size="sm" onClick={reveal} disabled={state.phase === "loading"}>
        <KeyRound className="size-3.5" />
        {state.phase === "loading" ? "Revealing…" : "Reveal"}
      </Button>
    );
  }

  if (state.phase === "error") {
    return (
      <div className="mt-3 flex items-center gap-2 text-sm text-danger">
        <span>Reveal failed: {state.message}</span>
        <Button variant="ghost" size="sm" onClick={() => setState({ phase: "hidden" })}>
          Dismiss
        </Button>
      </div>
    );
  }

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md bg-bg p-3 shadow-[0_0_0_1px_var(--color-border)]">
      <code className="min-w-0 flex-1 select-all break-all font-mono text-xs text-fg">
        {state.value}
      </code>
      <Button variant="secondary" size="sm" onClick={copy}>
        {copied ? "Copied" : "Copy"}
      </Button>
      <Button variant="ghost" size="sm" onClick={() => setState({ phase: "hidden" })}>
        Hide
      </Button>
      <span className="basis-full text-[11px] text-subtle">
        Auto-hides in 30s · this reveal is audited
      </span>
    </div>
  );
}

function ToolsPanel({
  tools,
  invoke,
}: {
  tools: Array<{ name: string; description: string }>;
  invoke: {
    mutate: (payload: { name: string; arguments?: Record<string, unknown> }) => void;
    isPending: boolean;
    data?: unknown;
  };
}) {
  const [selected, setSelected] = useState("github_get_repository");
  const presets = useMemo(
    () => ({
      vault_list: {},
      vault_status: {},
      credential_health: { credential_ref: "vault://github/echoomegaprime" },
      github_get_user: { credential_ref: "vault://github/echoomegaprime" },
      github_get_repository: {
        owner: "echoomegaprime",
        repo: "echo-continuity-fabric",
      },
      github_list_repositories: { per_page: 10 },
      provider_request: {
        credential_ref: "vault://github/echoomegaprime",
        provider: "github",
        method: "GET",
        path: "/user",
      },
    }),
    [],
  );
  const args =
    (presets as Record<string, Record<string, unknown>>)[selected] ?? {};

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card className="p-5">
        <CardHeader>
          <CardTitle>MCP tools</CardTitle>
          <CardDescription>
            No get_secret. Invoke by reference only.
          </CardDescription>
        </CardHeader>
        <ul className="grid max-h-[28rem] gap-1 overflow-auto pr-1">
          {tools.map((tool) => (
            <li key={tool.name}>
              <button
                type="button"
                onClick={() => setSelected(tool.name)}
                className={cn(
                  "flex min-h-11 w-full items-start gap-3 rounded-sm px-3 py-2 text-left transition-colors duration-150",
                  selected === tool.name
                    ? "bg-bg-subtle"
                    : "hover:bg-bg-subtle/70",
                )}
              >
                <List className="mt-0.5 size-4 shrink-0 text-muted" />
                <span>
                  <span className="block font-mono text-xs">{tool.name}</span>
                  <span className="mt-0.5 block text-xs text-muted">
                    {tool.description}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      <Card className="p-5">
        <CardHeader>
          <CardTitle className="font-mono text-sm">{selected}</CardTitle>
          <CardDescription>Arguments are never Authorization headers.</CardDescription>
        </CardHeader>
        <JsonBlock value={args} />
        <div className="mt-4 flex gap-2">
          <Button
            onClick={() => invoke.mutate({ name: selected, arguments: args })}
            disabled={invoke.isPending}
          >
            Invoke
            <ArrowRight className="size-4" />
          </Button>
        </div>
        {invoke.data != null && (
          <div className="mt-4">
            <p className="mb-2 text-xs uppercase tracking-wide text-muted">
              Result
            </p>
            <JsonBlock value={invoke.data} />
          </div>
        )}
      </Card>
    </div>
  );
}

function PolicyPanel() {
  return (
    <div className="grid gap-4">
      <Card className="p-5">
        <CardHeader>
          <CardTitle>Allowlists</CardTitle>
          <CardDescription>
            HTTPS only. No caller-supplied Authorization. No redirects to untrusted
            hosts.
          </CardDescription>
        </CardHeader>
        <ul className="grid gap-2 text-sm">
          {[
            ["github", "api.github.com"],
            ["cloudflare", "api.cloudflare.com"],
            ["openai", "api.openai.com"],
            ["stripe", "api.stripe.com"],
            ["xai", "api.x.ai"],
          ].map(([provider, host]) => (
            <li
              key={provider}
              className="flex items-center justify-between gap-3 rounded-md bg-bg px-3 py-3 shadow-[0_0_0_1px_var(--color-border)]"
            >
              <span className="font-mono text-xs">{provider}</span>
              <span className="font-mono text-xs text-muted">{host}</span>
            </li>
          ))}
        </ul>
      </Card>
      <Card className="p-5">
        <CardHeader>
          <CardTitle>Blocked destinations</CardTitle>
          <CardDescription>
            Metadata services, localhost, and private networks cannot receive a
            resolved credential.
          </CardDescription>
        </CardHeader>
        <div className="flex flex-wrap gap-2">
          {[
            "169.254.169.254",
            "localhost",
            "127.0.0.1",
            "10.0.0.0/8",
            "attacker.example",
          ].map((host) => (
            <Badge key={host}>{host}</Badge>
          ))}
        </div>
      </Card>
      <Card className="flex items-start gap-3 p-5">
        <Radar className="mt-0.5 size-4 text-accent" />
        <div>
          <p className="text-sm font-medium">Canonical layer</p>
          <p className="mt-1 text-sm text-muted">
            Echo GitHub Autonomy and future provider plugins must call this broker
            with vault:// references. They must never read connector token files,
            .env, or PATs from disk.
          </p>
        </div>
      </Card>
      <Separator />
      <p className="flex items-center gap-2 text-xs text-subtle">
        <Activity className="size-3.5" />
        MCP endpoint at /api/mcp — tools/list and tools/call only.
      </p>
    </div>
  );
}
