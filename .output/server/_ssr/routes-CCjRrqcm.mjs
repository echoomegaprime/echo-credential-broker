import { o as __toESM } from "../_runtime.mjs";
import { n as require_react } from "../_libs/@radix-ui/react-compose-refs+[...].mjs";
import { a as require_jsx_runtime, i as useQueryClient, n as useQuery, t as useMutation } from "../_libs/react+tanstack__react-query.mjs";
import { a as ScrollText, c as Plug, d as KeyRound, f as ExternalLink, g as Activity, h as ArrowRight, i as ShieldCheck, l as Lock, m as Check, n as Unplug, o as RefreshCw, p as Copy, s as Radar, t as Wrench, u as List } from "../_libs/lucide-react.mjs";
import { n as TSS_SERVER_FUNCTION, r as getServerFnById, t as createServerFn } from "./ssr.mjs";
import { n as clsx, t as cva } from "../_libs/class-variance-authority+clsx.mjs";
import { t as twMerge } from "../_libs/tailwind-merge.mjs";
import { t as Slot } from "../_libs/radix-ui__react-slot.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-CCjRrqcm.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function cn(...inputs) {
	return twMerge(clsx(inputs));
}
var badgeVariants = cva("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium tracking-wide", {
	variants: { tone: {
		default: "bg-bg-subtle text-muted shadow-[0_0_0_1px_var(--color-border)]",
		healthy: "bg-healthy/15 text-healthy",
		warn: "bg-warn/15 text-warn",
		danger: "bg-danger/15 text-danger",
		accent: "bg-accent/15 text-accent"
	} },
	defaultVariants: { tone: "default" }
});
function Badge({ className, tone, ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: cn(badgeVariants({ tone }), className),
		...props
	});
}
var buttonVariants = cva("inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-sm text-sm font-medium transition-[opacity,transform,background-color,color,box-shadow] duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-40 active:not-disabled:scale-[0.96] [&_svg]:size-4 [&_svg]:shrink-0 min-h-11 px-4", {
	variants: {
		variant: {
			default: "bg-accent text-accent-fg hover:opacity-90",
			secondary: "bg-bg-subtle text-fg shadow-[0_0_0_1px_var(--color-border)] hover:shadow-[0_0_0_1px_var(--color-border-strong)]",
			ghost: "bg-transparent text-muted hover:text-fg hover:bg-bg-subtle",
			danger: "bg-danger text-fg hover:opacity-90"
		},
		size: {
			default: "h-11",
			sm: "h-9 min-h-9 px-3 text-xs",
			lg: "h-12 px-5"
		}
	},
	defaultVariants: {
		variant: "default",
		size: "default"
	}
});
var Button = import_react.forwardRef(({ className, variant, size, asChild = false, ...props }, ref) => {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(asChild ? Slot : "button", {
		className: cn(buttonVariants({
			variant,
			size,
			className
		})),
		ref,
		...props
	});
});
Button.displayName = "Button";
function Card({ className, ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: cn("rounded-xl bg-bg-elevated p-4 shadow-[0_0_0_1px_var(--color-border)]", className),
		...props
	});
}
function CardHeader({ className, ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: cn("mb-4 flex flex-col gap-1", className),
		...props
	});
}
function CardTitle({ className, ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
		className: cn("text-base font-medium tracking-tight", className),
		...props
	});
}
function CardDescription({ className, ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
		className: cn("text-sm text-muted", className),
		...props
	});
}
function Separator({ className }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		role: "separator",
		className: cn("h-px w-full bg-border", className)
	});
}
var createSsrRpc = (functionId) => {
	const url = "/_serverFn/" + functionId;
	const serverFnMeta = { id: functionId };
	const fn = async (...args) => {
		return (await getServerFnById(functionId, { origin: "server" }))(...args);
	};
	return Object.assign(fn, {
		url,
		serverFnMeta,
		[TSS_SERVER_FUNCTION]: true
	});
};
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
var rpcVaultStatus = createServerFn({ method: "GET" }).handler(createSsrRpc("7de7d760af88b04ea9d4e820acb24cb8cdfcbc57d5ea27e3886c7c5e21152f89"));
var rpcVaultList = createServerFn({ method: "GET" }).handler(createSsrRpc("f3b9d1532a52b5ed55e93854c737120df7ab25b75f43d753af8cdeb144f4e1b5"));
var rpcAuditList = createServerFn({ method: "GET" }).handler(createSsrRpc("fd7f0c45e8a49f6617b6a6fa9c534dfe82c12897a1b2513a793eb7b2bad27c7d"));
var rpcListTools = createServerFn({ method: "GET" }).handler(createSsrRpc("9f2c35a1dc0f94f879b7903158711646d9e84ed0a6ba962227effb9147eae5f0"));
/**
* Removed in v2. This used to return a raw secret to whoever could reach the
* web port. Nothing in this process returns a secret any more; the function
* stays so the console compiles and always answers `reveal_disabled`.
*/
var rpcRevealSecret = createServerFn({ method: "POST" }).validator((data) => ({ credential_ref: String(data.credential_ref) })).handler(createSsrRpc("f5a7b5df8d869f2e44c798107adc9abfe9fe44c57af389e2331420d7aeb85a64"));
var rpcCallTool = createServerFn({ method: "POST" }).validator((data) => ({
	name: String(data.name),
	arguments: data.arguments ?? {},
	argsJson: data.argsJson ?? ""
})).handler(createSsrRpc("5c20bb8e029b0ca180892b4f5efc9cb0c005ca569ee3c44cff4e51ed2db65653"));
var APPS = [
	{
		id: "grok",
		name: "Grok",
		caller: "grok",
		blurb: "GitHub app for the repo, then HTTP MCP in Grok connectors.",
		github: "https://github.com/apps/grok-by-xai/installations/new"
	},
	{
		id: "gpt",
		name: "GPT / Codex",
		caller: "chatgpt",
		blurb: "Codex GitHub app, then Custom GPT Action or Developer Mode MCP.",
		github: "https://github.com/apps/chatgpt-codex-connector/installations/new"
	},
	{
		id: "claude",
		name: "Claude",
		caller: "claude",
		blurb: "Claude GitHub app, then Desktop stdio or Claude Code .mcp.json.",
		github: "https://github.com/apps/claude/installations/new"
	}
];
function CopyBlock({ label, value }) {
	const [copied, setCopied] = (0, import_react.useState)(false);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-2",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex items-center justify-between gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-xs uppercase tracking-wide text-muted",
				children: label
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
				type: "button",
				variant: "ghost",
				className: "h-8 px-2 text-xs",
				onClick: async () => {
					try {
						await navigator.clipboard.writeText(value);
						setCopied(true);
						window.setTimeout(() => setCopied(false), 1400);
					} catch {}
				},
				children: [copied ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Check, { className: "size-3.5" }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Copy, { className: "size-3.5" }), copied ? "Copied" : "Copy"]
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("pre", {
			className: "max-h-64 overflow-auto rounded-md bg-bg p-3 font-mono text-[11px] leading-relaxed text-fg shadow-[0_0_0_1px_var(--color-border)]",
			children: value
		})]
	});
}
function InstallPanel() {
	const [origin, setOrigin] = (0, import_react.useState)("https://YOUR-HOST");
	(0, import_react.useEffect)(() => {
		setOrigin(window.location.origin);
	}, []);
	const grokHttp = JSON.stringify({ mcpServers: { "echo-credential-broker": {
		type: "http",
		url: `${origin}/api/mcp`
	} } }, null, 2);
	const gptAction = `Import OpenAPI: ${origin}/install/chatgpt.openapi.json
Server: ${origin}
Auth: OAuth 2.1 (the client registers itself; you approve it on Telegram)
MCP URL: ${origin}/api/mcp`;
	const claudeDesktop = JSON.stringify({ mcpServers: { "echo-credential-broker": {
		command: "node",
		args: ["--experimental-strip-types", "scripts/mcp-stdio.ts"],
		cwd: "/ABSOLUTE/PATH/TO/echo-credential-broker",
		env: { ECHO_AGENT: "claude-desktop" }
	} } }, null, 2);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Clone once — three clients" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Same broker. Secrets stay in env. Chat only ever sees vault:// handles." })] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CopyBlock, {
						label: "Repo",
						value: `git clone https://github.com/echoomegaprime/echo-credential-broker.git
cd echo-credential-broker
npm install
cp .env.example .env
npm run mcp`
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-3 text-sm text-muted",
						children: [
							"Source:",
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
								className: "text-fg underline-offset-2 hover:underline",
								href: "https://github.com/echoomegaprime/echo-credential-broker",
								target: "_blank",
								rel: "noreferrer",
								children: "echoomegaprime/echo-credential-broker"
							})
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "grid gap-4 lg:grid-cols-3",
				children: APPS.map((app) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
					className: "flex flex-col gap-3 p-5",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: app.name }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: app.blurb })] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
							href: app.github,
							target: "_blank",
							rel: "noreferrer",
							className: "inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
							children: ["Install GitHub app", /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ExternalLink, { className: "size-3.5" })]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "font-mono text-[11px] text-subtle",
							children: "Connects with OAuth — approved on your phone"
						})
					]
				}, app.id))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Grok MCP" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Settings → Connectors → add MCP. The client signs in with OAuth; approve it on Telegram." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CopyBlock, {
					label: "HTTP connector",
					value: grokHttp
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "GPT Action / MCP" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Custom GPT Actions import the OpenAPI. Developer Mode uses the MCP URL." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CopyBlock, {
					label: "ChatGPT",
					value: gptAction
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Claude Desktop / Code" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Merge into claude_desktop_config.json, then restart. Claude Code reads .mcp.json in the repo." })] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CopyBlock, {
						label: "claude_desktop_config.json",
						value: claudeDesktop
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-3",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CopyBlock, {
							label: "Claude Code",
							value: "claude mcp add echo-credential-broker --env ECHO_AGENT=claude-code -- node --experimental-strip-types scripts/mcp-stdio.ts"
						})
					})
				]
			})
		]
	});
}
var TABS = [
	{
		id: "overview",
		label: "Overview",
		icon: ShieldCheck
	},
	{
		id: "credentials",
		label: "Credentials",
		icon: KeyRound
	},
	{
		id: "tools",
		label: "Tools",
		icon: Wrench
	},
	{
		id: "audit",
		label: "Audit",
		icon: ScrollText
	},
	{
		id: "policy",
		label: "Policy",
		icon: Lock
	},
	{
		id: "install",
		label: "Install",
		icon: Plug
	}
];
function statusTone(status) {
	if (status === "healthy") return "healthy";
	if (status === "identity_mismatch" || status === "unhealthy") return "danger";
	if (status === "imported") return "warn";
	if (status === "revoked") return "danger";
	return "default";
}
function JsonBlock({ value }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("pre", {
		className: "max-h-80 overflow-auto rounded-md bg-bg p-3 font-mono text-xs leading-relaxed text-fg shadow-[0_0_0_1px_var(--color-border)]",
		children: JSON.stringify(value, null, 2)
	});
}
function VaultConsole() {
	const [tab, setTab] = (0, import_react.useState)("overview");
	const queryClient = useQueryClient();
	const statusQ = useQuery({
		queryKey: ["vault-status"],
		queryFn: () => rpcVaultStatus()
	});
	const listQ = useQuery({
		queryKey: ["vault-list"],
		queryFn: () => rpcVaultList()
	});
	const toolsQ = useQuery({
		queryKey: ["vault-tools"],
		queryFn: () => rpcListTools()
	});
	const auditQ = useQuery({
		queryKey: ["vault-audit"],
		queryFn: () => rpcAuditList()
	});
	const healthQ = useQuery({
		queryKey: ["credential-health"],
		queryFn: () => rpcCallTool({ data: {
			name: "credential_health",
			arguments: { credential_ref: "vault://github/echoomegaprime" }
		} })
	});
	const repoQ = useQuery({
		queryKey: ["github-repo"],
		queryFn: () => rpcCallTool({ data: {
			name: "github_get_repository",
			arguments: {
				owner: "echoomegaprime",
				repo: "echo-continuity-fabric"
			}
		} })
	});
	const refresh = () => {
		queryClient.invalidateQueries();
	};
	const revoke = useMutation({
		mutationFn: (ref) => rpcCallTool({ data: {
			name: "credential_revoke",
			arguments: { credential_ref: ref }
		} }),
		onSuccess: refresh
	});
	const rotate = useMutation({
		mutationFn: (ref) => rpcCallTool({ data: {
			name: "credential_rotate",
			arguments: { credential_ref: ref }
		} }),
		onSuccess: refresh
	});
	const invoke = useMutation({
		mutationFn: (payload) => rpcCallTool({ data: {
			name: payload.name,
			arguments: Object.fromEntries(Object.entries(payload.arguments ?? {}).flatMap(([k, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? [[k, v]] : []))
		} }),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["vault-audit"] });
			queryClient.invalidateQueries({ queryKey: ["vault-list"] });
		}
	});
	const credentials = listQ.data && listQ.data.ok ? listQ.data.data.credentials : [];
	const health = healthQ.data && healthQ.data.ok ? healthQ.data.data : null;
	const repo = repoQ.data && repoQ.data.ok ? repoQ.data.data : null;
	const tools = toolsQ.data && toolsQ.data.ok ? toolsQ.data.data.tools : [];
	const audit = auditQ.data && auditQ.data.ok ? auditQ.data.data.records : [];
	const statusData = statusQ.data && statusQ.data.ok ? statusQ.data.data : null;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "min-h-dvh bg-bg text-fg",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { className: "vault-grid pointer-events-none fixed inset-0 opacity-40" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "relative mx-auto flex min-h-dvh max-w-7xl flex-col lg:flex-row",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
				className: "flex flex-col border-b border-border lg:w-64 lg:border-b-0 lg:border-r",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center gap-3 px-5 py-5",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "flex size-10 items-center justify-center rounded-md bg-bg-elevated shadow-[0_0_0_1px_var(--color-border)]",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Lock, {
								className: "size-4 text-accent",
								strokeWidth: 1.75
							})
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm font-medium tracking-tight",
							children: "Echo Vault"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-muted",
							children: "Credential Broker"
						})] })]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("nav", {
						className: "flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:px-3",
						children: TABS.map((item) => {
							const Icon = item.icon;
							const active = tab === item.id;
							return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								type: "button",
								onClick: () => setTab(item.id),
								className: cn("flex min-h-11 min-w-11 items-center gap-2 rounded-sm px-3 text-sm transition-colors duration-150", active ? "bg-bg-subtle text-fg" : "text-muted hover:bg-bg-subtle hover:text-fg"),
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, {
									className: "size-4 shrink-0",
									strokeWidth: 1.75
								}), item.label]
							}, item.id);
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-auto hidden px-5 py-5 lg:block",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "font-mono text-[11px] leading-relaxed text-subtle",
							children: [
								"Agents may USE credentials.",
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("br", {}),
								"Agents may NEVER READ credentials."
							]
						})
					})
				]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
				className: "flex-1 px-4 py-6 sm:px-8",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
						className: "mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "stagger-in",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mb-2 text-xs font-medium uppercase tracking-[0.18em] text-muted",
								children: "Trusted server side"
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
								className: "text-3xl font-medium tracking-tight sm:text-4xl",
								children: TABS.find((t) => t.id === tab)?.label
							})]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
							variant: "secondary",
							onClick: refresh,
							className: "self-start",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(RefreshCw, { className: "size-4" }), "Refresh"]
						})]
					}),
					tab === "overview" && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "grid gap-4",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
								className: "stagger-in rounded-xl p-5",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "text-xs font-medium uppercase tracking-[0.18em] text-muted",
										children: "Invariant"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "mt-2 max-w-2xl text-lg font-medium tracking-tight",
										children: "Agents may USE credentials. Agents may NEVER READ credentials."
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "mt-2 max-w-xl text-sm text-muted",
										children: "A vault reference is a capability handle, not a secret-retrieval mechanism. Raw PATs, API keys, and tokens never leave the broker process."
									})
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "grid gap-4 sm:grid-cols-3",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
										label: "Credentials",
										value: String(statusData?.credential_count ?? "—"),
										hint: "opaque refs only"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
										label: "Redaction",
										value: statusData?.redaction === "armed" ? "Armed" : "—",
										hint: "stdout, logs, MCP"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
										label: "Fail closed",
										value: statusData?.fail_closed ? "On" : "—",
										hint: "no anonymous fallback"
									})
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "grid gap-4 lg:grid-cols-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
									className: "p-5",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex items-center justify-between gap-3",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "GitHub identity" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Badge, {
											tone: statusTone(health?.status),
											children: health?.status ?? (healthQ.isLoading ? "checking" : "unknown")
										})]
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Safe GET /user. The PAT never appears in this response." })] }), healthQ.isLoading ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "text-sm text-muted",
										children: "Verifying credential…"
									}) : health ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
										className: "grid grid-cols-2 gap-3 text-sm",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Account",
												value: health.account ?? "—",
												mono: true
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Account ID",
												value: String(health.account_id ?? "—"),
												mono: true
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Authenticated",
												value: health.authenticated ? "true" : "false"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Ref",
												value: health.ref ?? "vault://github/echoomegaprime",
												mono: true
											})
										]
									}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "text-sm text-danger",
										children: "Credential unavailable. Broker failed closed."
									})]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
									className: "p-5",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex items-center justify-between gap-3",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Private repository" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Badge, {
											tone: repo?.private ? "accent" : "default",
											children: repo?.private ? "private" : repo ? "public" : "—"
										})]
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "echoomegaprime/echo-continuity-fabric via the vault handle." })] }), repoQ.isLoading ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "text-sm text-muted",
										children: "Reading repository metadata…"
									}) : repo ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
										className: "grid gap-3 text-sm",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Full name",
												value: repo.full_name ?? "—",
												mono: true
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Default branch",
												value: repo.default_branch ?? "—",
												mono: true
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
												label: "Description",
												value: repo.description ?? "—"
											})
										]
									}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "text-sm text-danger",
										children: "Repository lookup failed closed."
									})]
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
								className: "p-5",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Request path" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "The model only ever holds the opaque reference." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ol", {
									className: "grid gap-2 sm:grid-cols-4",
									children: [
										{
											title: "Agent",
											body: "vault://github/echoomegaprime"
										},
										{
											title: "Policy",
											body: "caller · scope · audit"
										},
										{
											title: "Vault",
											body: "raw secret stays here"
										},
										{
											title: "Provider",
											body: "api.github.com only"
										}
									].map((step, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
										className: "flex items-start gap-3 rounded-md bg-bg p-3 shadow-[0_0_0_1px_var(--color-border)]",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "font-mono text-xs text-subtle",
											children: i + 1
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
											className: "text-sm font-medium",
											children: step.title
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
											className: "mt-1 font-mono text-xs text-muted",
											children: step.body
										})] })]
									}, step.title))
								})]
							})
						]
					}),
					tab === "credentials" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "grid gap-3",
						children: credentials.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, {
							className: "p-6",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-muted",
								children: "No credentials imported. The broker fails closed until a trusted sandbox source is available."
							})
						}) : credentials.map((cred) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
							className: "p-5",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex flex-wrap items-center gap-2",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
											className: "font-mono text-sm",
											children: cred.ref
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Badge, {
											tone: statusTone(cred.status),
											children: cred.status
										})]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
										className: "mt-2 text-sm text-muted",
										children: [
											cred.provider,
											" · ",
											cred.account,
											" · ",
											cred.type
										]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
										className: "mt-1 font-mono text-xs text-subtle",
										children: [
											"source ",
											cred.source,
											cred.fingerprint ? ` · fp ${cred.fingerprint}` : "",
											cred.last_verified ? ` · verified ${cred.last_verified}` : ""
										]
									})
								] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "flex flex-wrap gap-2",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
										variant: "secondary",
										size: "sm",
										onClick: () => rotate.mutate(cred.ref),
										disabled: rotate.isPending,
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(RefreshCw, { className: "size-3.5" }), "Rotate"]
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
										variant: "ghost",
										size: "sm",
										onClick: () => revoke.mutate(cred.ref),
										disabled: revoke.isPending,
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Unplug, { className: "size-3.5" }), "Revoke"]
									})]
								})]
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(RevealSecret, { credRef: cred.ref })]
						}, cred.ref))
					}),
					tab === "tools" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolsPanel, {
						tools,
						invoke
					}),
					tab === "audit" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, {
						className: "overflow-hidden p-0",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "overflow-x-auto",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
								className: "w-full min-w-[640px] text-left text-sm",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
									className: "text-xs uppercase tracking-wide text-muted",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
										className: "border-b border-border",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Time"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Caller"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Op"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Resource"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Status"
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
												className: "px-4 py-3 font-medium",
												children: "Result"
											})
										]
									})
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", { children: audit.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-8 text-muted",
									colSpan: 6,
									children: "No audited operations yet."
								}) }) : audit.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
									className: "border-b border-border/70",
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "px-4 py-3 font-mono text-xs tabular-nums text-muted",
											children: row.timestamp.replace("T", " ").slice(0, 19)
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "px-4 py-3",
											children: row.caller
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "px-4 py-3 font-mono text-xs",
											children: row.operation
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "max-w-48 truncate px-4 py-3 font-mono text-xs",
											children: row.resource
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "px-4 py-3 tabular-nums",
											children: row.http_status ?? "—"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
											className: "px-4 py-3",
											children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Badge, {
												tone: row.result === "ok" ? "healthy" : "danger",
												children: row.result
											})
										})
									]
								}, row.id)) })]
							})
						})
					}),
					tab === "policy" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PolicyPanel, {}),
					tab === "install" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(InstallPanel, {})
				]
			})]
		})]
	});
}
function Stat({ label, value, hint }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
		className: "p-5",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-xs uppercase tracking-[0.16em] text-muted",
				children: label
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-2 text-2xl font-medium tracking-tight",
				children: value
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-1 text-xs text-subtle",
				children: hint
			})
		]
	});
}
function Field({ label, value, mono }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
		className: "text-xs text-muted",
		children: label
	}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", {
		className: cn("mt-1 break-all", mono && "font-mono text-xs"),
		children: value
	})] });
}
/**
* Human-only reveal + copy. Calls `rpcRevealSecret` (never an MCP tool — no
* agent can reach this path). The value lives only in this component's local
* state: never cached by React Query, never logged, auto-hidden after 30s or
* on unmount. Every reveal is separately audited server-side as `human_reveal`.
*/
function RevealSecret({ credRef }) {
	const [state, setState] = (0, import_react.useState)({ phase: "hidden" });
	const [copied, setCopied] = (0, import_react.useState)(false);
	(0, import_react.useEffect)(() => {
		if (state.phase !== "shown") return;
		const t = setTimeout(() => setState({ phase: "hidden" }), 3e4);
		return () => clearTimeout(t);
	}, [state.phase]);
	const reveal = async () => {
		setState({ phase: "loading" });
		try {
			const res = await rpcRevealSecret({ data: { credential_ref: credRef } });
			if (res.ok) setState({
				phase: "shown",
				value: res.secret
			});
			else setState({
				phase: "error",
				message: res.error
			});
		} catch {
			setState({
				phase: "error",
				message: "request_failed"
			});
		}
	};
	const copy = async () => {
		if (state.phase !== "shown") return;
		await navigator.clipboard.writeText(state.value);
		setCopied(true);
		setTimeout(() => setCopied(false), 2e3);
	};
	if (state.phase === "hidden" || state.phase === "loading") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
		variant: "secondary",
		size: "sm",
		onClick: reveal,
		disabled: state.phase === "loading",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(KeyRound, { className: "size-3.5" }), state.phase === "loading" ? "Revealing…" : "Reveal"]
	});
	if (state.phase === "error") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "mt-3 flex items-center gap-2 text-sm text-danger",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: ["Reveal failed: ", state.message] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Button, {
			variant: "ghost",
			size: "sm",
			onClick: () => setState({ phase: "hidden" }),
			children: "Dismiss"
		})]
	});
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "mt-3 flex flex-wrap items-center gap-2 rounded-md bg-bg p-3 shadow-[0_0_0_1px_var(--color-border)]",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
				className: "min-w-0 flex-1 select-all break-all font-mono text-xs text-fg",
				children: state.value
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Button, {
				variant: "secondary",
				size: "sm",
				onClick: copy,
				children: copied ? "Copied" : "Copy"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Button, {
				variant: "ghost",
				size: "sm",
				onClick: () => setState({ phase: "hidden" }),
				children: "Hide"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
				className: "basis-full text-[11px] text-subtle",
				children: "Auto-hides in 30s · this reveal is audited"
			})
		]
	});
}
function ToolsPanel({ tools, invoke }) {
	const [selected, setSelected] = (0, import_react.useState)("github_get_repository");
	const args = (0, import_react.useMemo)(() => ({
		vault_list: {},
		vault_status: {},
		credential_health: { credential_ref: "vault://github/echoomegaprime" },
		github_get_user: { credential_ref: "vault://github/echoomegaprime" },
		github_get_repository: {
			owner: "echoomegaprime",
			repo: "echo-continuity-fabric"
		},
		github_list_repositories: { per_page: 10 },
		provider_request: {
			credential_ref: "vault://github/echoomegaprime",
			provider: "github",
			method: "GET",
			path: "/user"
		}
	}), [])[selected] ?? {};
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
			className: "p-5",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "MCP tools" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "No get_secret. Invoke by reference only." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "grid max-h-[28rem] gap-1 overflow-auto pr-1",
				children: tools.map((tool) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
					type: "button",
					onClick: () => setSelected(tool.name),
					className: cn("flex min-h-11 w-full items-start gap-3 rounded-sm px-3 py-2 text-left transition-colors duration-150", selected === tool.name ? "bg-bg-subtle" : "hover:bg-bg-subtle/70"),
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(List, { className: "mt-0.5 size-4 shrink-0 text-muted" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "block font-mono text-xs",
						children: tool.name
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "mt-0.5 block text-xs text-muted",
						children: tool.description
					})] })]
				}) }, tool.name))
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
			className: "p-5",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, {
					className: "font-mono text-sm",
					children: selected
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Arguments are never Authorization headers." })] }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(JsonBlock, { value: args }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-4 flex gap-2",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Button, {
						onClick: () => invoke.mutate({
							name: selected,
							arguments: args
						}),
						disabled: invoke.isPending,
						children: ["Invoke", /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ArrowRight, { className: "size-4" })]
					})
				}),
				invoke.data != null && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mb-2 text-xs uppercase tracking-wide text-muted",
						children: "Result"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(JsonBlock, { value: invoke.data })]
				})
			]
		})]
	});
}
function PolicyPanel() {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Allowlists" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "HTTPS only. No caller-supplied Authorization. No redirects to untrusted hosts." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "grid gap-2 text-sm",
					children: [
						["github", "api.github.com"],
						["cloudflare", "api.cloudflare.com"],
						["openai", "api.openai.com"],
						["stripe", "api.stripe.com"],
						["xai", "api.x.ai"]
					].map(([provider, host]) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
						className: "flex items-center justify-between gap-3 rounded-md bg-bg px-3 py-3 shadow-[0_0_0_1px_var(--color-border)]",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "font-mono text-xs",
							children: provider
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "font-mono text-xs text-muted",
							children: host
						})]
					}, provider))
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(CardHeader, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardTitle, { children: "Blocked destinations" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CardDescription, { children: "Metadata services, localhost, and private networks cannot receive a resolved credential." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "flex flex-wrap gap-2",
					children: [
						"169.254.169.254",
						"localhost",
						"127.0.0.1",
						"10.0.0.0/8",
						"attacker.example"
					].map((host) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Badge, { children: host }, host))
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "flex items-start gap-3 p-5",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Radar, { className: "mt-0.5 size-4 text-accent" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm font-medium",
					children: "Canonical layer"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm text-muted",
					children: "Echo GitHub Autonomy and future provider plugins must call this broker with vault:// references. They must never read connector token files, .env, or PATs from disk."
				})] })]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Separator, {}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "flex items-center gap-2 text-xs text-subtle",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Activity, { className: "size-3.5" }), "MCP endpoint at /api/mcp — tools/list and tools/call only."]
			})
		]
	});
}
function Home() {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(VaultConsole, {});
}
//#endregion
export { Home as component };
