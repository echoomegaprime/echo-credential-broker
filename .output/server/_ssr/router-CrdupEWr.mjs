import { o as __toESM, r as __exportAll } from "../_runtime.mjs";
import { n as require_react } from "../_libs/@radix-ui/react-compose-refs+[...].mjs";
import { _ as useRouter, f as createRouter, g as createRootRoute, h as createFileRoute, l as Scripts, m as lazyRouteComponent, p as Outlet, u as HeadContent } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as require_jsx_runtime, r as QueryClientProvider } from "../_libs/react+tanstack__react-query.mjs";
import { r as TriangleAlert } from "../_libs/lucide-react.mjs";
import { t as QueryClient } from "../_libs/tanstack__query-core.mjs";
import { a as union, i as string, n as number, r as object, t as literal } from "../_libs/zod.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/router-CrdupEWr.js
var router_CrdupEWr_exports = /* @__PURE__ */ __exportAll({ getRouter: () => getRouter });
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function AppErrorComponent({ error }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
		className: "flex min-h-screen flex-col items-center justify-center gap-3 bg-bg px-6 text-center text-fg",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
				className: "text-danger",
				"aria-hidden": "true",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, {
					className: "size-10",
					strokeWidth: 2
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
				className: "text-lg font-semibold",
				children: "Something went wrong"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "max-w-md text-sm break-words text-muted",
				children: error.message || "An unexpected error occurred. Try reloading the page."
			})
		]
	});
}
/**
* App-wide client provider mounted once near the root (in `src/routes/__root.tsx`):
*
*   <AuthProvider><Outlet /></AuthProvider>
*
* Better Auth's React client (`@/lib/auth/client`) needs NO context provider —
* its `useSession()` works standalone — so this is a passthrough today. It's
* kept as the single, stable mount point for any future client-side providers
* (e.g. a toast or theme provider) without churning the root shell.
*/
function AuthProvider({ children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_jsx_runtime.Fragment, { children });
}
function isGrokEmbedderOrigin(origin) {
	try {
		const url = new URL(origin);
		if (url.protocol !== "https:" && url.protocol !== "http:") return false;
		const host = url.hostname.toLowerCase();
		if (host === "grok.com" || host.endsWith(".grok.com")) return true;
		if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") return true;
		return false;
	} catch {
		return false;
	}
}
function isSandboxPreviewGuestHost(hostname) {
	const host = hostname.toLowerCase();
	return host === "grok-sandbox.com" || host.endsWith(".grok-sandbox.com");
}
function isRemintPreviewPair(guestHost, parentHost) {
	const guest = guestHost.toLowerCase();
	const parent = parentHost.toLowerCase();
	const i = guest.indexOf(".preview.");
	if (i <= 0) return false;
	const label = guest.slice(0, i);
	const rest = guest.slice(i + 9);
	if (label.includes(".") || !rest.includes(".")) return false;
	return parent === rest || parent === `grok.${rest}`;
}
function resolveParentEmbedderOrigin(parentIsSelf, referrer, ancestorOrigin, guestHostname = "") {
	if (parentIsSelf) return null;
	for (const candidate of [referrer, ancestorOrigin ?? ""].filter(Boolean)) try {
		const url = new URL(candidate.includes("://") ? candidate : `https://${candidate}`);
		if (url.protocol !== "https:" && url.protocol !== "http:") continue;
		if (isGrokEmbedderOrigin(url.origin)) return url.origin;
		if (isSandboxPreviewGuestHost(guestHostname) || isRemintPreviewPair(guestHostname, url.hostname)) return url.origin;
	} catch {}
	return null;
}
/**
* Guest side of the grok-web ↔ sandbox preview postMessage bridge.
*
* Activates only when this page is framed by an allowlisted Grok embedder.
* Top-level runs (download/export, local `npm run dev`, deployed sites) noop.
*/
var PREVIEW_BRIDGE_CHANNEL = "grok-preview-bridge";
var EnvelopeSchema = object({
	channel: literal(PREVIEW_BRIDGE_CHANNEL),
	version: number().int().positive(),
	type: string().min(1)
});
var HelloSchema = EnvelopeSchema.extend({ type: literal("hello") });
var NavigateSchema = EnvelopeSchema.extend({
	type: literal("navigate"),
	path: string().min(1)
});
var HistorySchema = EnvelopeSchema.extend({
	type: literal("history"),
	delta: union([literal(-1), literal(1)])
});
function isSafeBridgePath(path) {
	if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) return false;
	try {
		return new URL(path, "https://preview.invalid").origin === "https://preview.invalid";
	} catch {
		return false;
	}
}
/**
* Install host↔guest messaging. Returns a dispose function.
* Noops (returns a no-op dispose) when not embedded under a Grok parent.
*/
function installPreviewHostBridge(options = {}) {
	if (typeof window === "undefined") return () => {};
	const ancestorOrigin = typeof location.ancestorOrigins !== "undefined" && location.ancestorOrigins.length > 0 ? location.ancestorOrigins[0] : null;
	const parentOrigin = resolveParentEmbedderOrigin(window.parent === window, document.referrer, ancestorOrigin, window.location.hostname);
	if (parentOrigin === null) return () => {};
	const ROOT_STATE_KEY = "__grokPreviewBridgeRoot";
	const originalPushState = window.history.pushState.bind(window.history);
	const originalReplaceState = window.history.replaceState.bind(window.history);
	const isAtHistoryRoot = () => {
		const state = window.history.state;
		return Boolean(state && typeof state === "object" && state[ROOT_STATE_KEY] === true);
	};
	try {
		const current = window.history.state;
		if (!(current !== null && typeof current === "object" && Object.prototype.hasOwnProperty.call(current, ROOT_STATE_KEY))) {
			const isRoot = window.history.length <= 1;
			originalReplaceState(current && typeof current === "object" ? {
				...current,
				[ROOT_STATE_KEY]: isRoot
			} : { [ROOT_STATE_KEY]: isRoot }, "", window.location.href);
		}
	} catch {}
	const post = (message) => {
		window.parent.postMessage(message, parentOrigin);
	};
	const reportLocation = () => {
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "location",
			path: window.location.pathname || "/",
			search: window.location.search,
			hash: window.location.hash
		});
	};
	const reportRoutes = () => {
		const paths = options.getRoutePaths?.() ?? [];
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "routes",
			paths
		});
	};
	const defaultNavigate = (path) => {
		if (!isSafeBridgePath(path)) return;
		try {
			const url = new URL(path, window.location.origin);
			if (url.origin !== window.location.origin) return;
			const next = `${url.pathname}${url.search}${url.hash}`;
			window.history.pushState(window.history.state, "", next);
			window.dispatchEvent(new PopStateEvent("popstate", { state: window.history.state }));
		} catch {}
	};
	const navigate = (path) => {
		if (!isSafeBridgePath(path)) return;
		if (options.navigate) {
			options.navigate(path);
			return;
		}
		defaultNavigate(path);
	};
	const announce = () => {
		reportLocation();
		reportRoutes();
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "ready"
		});
	};
	const onMessage = (event) => {
		if (event.source !== window.parent) return;
		if (event.origin !== parentOrigin) return;
		const envelope = EnvelopeSchema.safeParse(event.data);
		if (!envelope.success || envelope.data.version !== 1) return;
		if (envelope.data.type === "hello") {
			if (!HelloSchema.safeParse(event.data).success) return;
			announce();
			return;
		}
		if (envelope.data.type === "navigate") {
			const parsed = NavigateSchema.safeParse(event.data);
			if (!parsed.success) return;
			navigate(parsed.data.path);
			queueMicrotask(reportLocation);
			return;
		}
		if (envelope.data.type === "history") {
			const parsed = HistorySchema.safeParse(event.data);
			if (!parsed.success) return;
			if (parsed.data.delta === -1 && isAtHistoryRoot()) return;
			window.history.go(parsed.data.delta);
		}
	};
	const onPopState = () => {
		reportLocation();
	};
	const onHashChange = () => {
		reportLocation();
	};
	window.history.pushState = (data, unused, url) => {
		const next = data && typeof data === "object" ? {
			...data,
			[ROOT_STATE_KEY]: false
		} : data;
		originalPushState(next, unused, url);
		reportLocation();
	};
	window.history.replaceState = (data, unused, url) => {
		const next = isAtHistoryRoot() ? {
			...data && typeof data === "object" ? data : {},
			[ROOT_STATE_KEY]: true
		} : data;
		originalReplaceState(next, unused, url);
		reportLocation();
	};
	window.addEventListener("message", onMessage);
	window.addEventListener("popstate", onPopState);
	window.addEventListener("hashchange", onHashChange);
	announce();
	return () => {
		window.removeEventListener("message", onMessage);
		window.removeEventListener("popstate", onPopState);
		window.removeEventListener("hashchange", onHashChange);
		window.history.pushState = originalPushState;
		window.history.replaceState = originalReplaceState;
	};
}
/** Collect static path patterns from a TanStack route tree (best-effort). */
function collectRoutePathsFromTree(routeTree) {
	const paths = /* @__PURE__ */ new Set();
	const walk = (node) => {
		if (!node || typeof node !== "object") return;
		const record = node;
		const full = typeof record.fullPath === "string" ? record.fullPath : typeof record.path === "string" ? record.path : null;
		if (full !== null && full !== "") paths.add(full.startsWith("/") ? full : `/${full}`);
		else if (full === "") paths.add("/");
		const children = record.children;
		if (Array.isArray(children)) for (const child of children) walk(child);
		else if (children && typeof children === "object") for (const child of Object.values(children)) walk(child);
	};
	walk(routeTree);
	return [...paths];
}
/**
* Mount once in `__root.tsx` so the Grok preview chrome can drive navigation
* (and later receive registered routes). Noops when the app is not embedded.
*/
function PreviewHostBridge() {
	const router = useRouter();
	(0, import_react.useEffect)(() => {
		return installPreviewHostBridge({
			navigate: (path) => {
				router.history.push(path);
			},
			getRoutePaths: () => collectRoutePathsFromTree(router.routeTree)
		});
	}, [router]);
	return null;
}
var styles_default = "/assets/styles-XXib5N_C.css";
var APP_NAME = "Echo Vault";
var Route$19 = createRootRoute({
	head: () => ({
		meta: [
			{ charSet: "utf-8" },
			{
				name: "viewport",
				content: "width=device-width, initial-scale=1"
			},
			{ title: APP_NAME },
			{
				name: "theme-color",
				content: "#09090b"
			},
			{
				name: "description",
				content: "Echo Vault credential broker — agents may use credentials, never read them."
			}
		],
		links: [
			{
				rel: "icon",
				type: "image/svg+xml",
				href: "/favicon.svg"
			},
			{
				rel: "stylesheet",
				href: styles_default
			},
			{
				rel: "manifest",
				href: "/__grok/manifest.webmanifest"
			},
			{
				rel: "apple-touch-icon",
				href: "/__grok/icon-180.png"
			},
			{
				rel: "preconnect",
				href: "https://fonts.googleapis.com"
			},
			{
				rel: "preconnect",
				href: "https://fonts.gstatic.com",
				crossOrigin: "anonymous"
			},
			{
				rel: "stylesheet",
				href: "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap"
			}
		]
	}),
	component: RootDocument
});
function RootDocument() {
	const [queryClient] = (0, import_react.useState)(() => new QueryClient({ defaultOptions: { queries: {
		retry: 1,
		refetchOnWindowFocus: false
	} } }));
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("html", {
		lang: "en",
		className: "dark antialiased",
		suppressHydrationWarning: true,
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("head", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(HeadContent, {}) }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("body", {
			className: "bg-bg text-fg",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PreviewHostBridge, {}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AuthProvider, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(QueryClientProvider, {
					client: queryClient,
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Outlet, {})
				}) }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Scripts, {})
			]
		})]
	});
}
var $$splitComponentImporter = () => import("./routes-CCjRrqcm.mjs");
var Route$18 = createFileRoute("/")({ component: lazyRouteComponent($$splitComponentImporter, "component") });
/**
* RFC 8414 authorization-server metadata for ECHO Vault v2.
*
* The directory is named `[.]well-known` because TanStack's route generator
* skips any directory whose name starts with "." — the bracket escape yields
* the literal URL path `/.well-known/oauth-authorization-server`.
*/
var Route$17 = createFileRoute("/.well-known/oauth-authorization-server")({ server: { handlers: {
	GET: async ({ request }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleAuthorizationServerMetadata } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handleAuthorizationServerMetadata(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/**
* RFC 9728 protected-resource metadata for the MCP endpoint (`/api/mcp`).
* 401s from /api/mcp point here via `WWW-Authenticate: Bearer resource_metadata="…"`.
* See oauth-authorization-server.ts for why the directory is `[.]well-known`.
*/
var Route$16 = createFileRoute("/.well-known/oauth-protected-resource")({ server: { handlers: {
	GET: async ({ request }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleProtectedResourceMetadata } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handleProtectedResourceMetadata(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/**
* MCP endpoint (Streamable HTTP, JSON responses). Authentication is an OAuth
* bearer token or a workload token — see src/lib/vault/v2/http-transport.ts.
* No self-asserted header is trusted.
*/
var Route$15 = createFileRoute("/api/mcp")({ server: { handlers: {
	GET: async ({ request }) => {
		const { handleMcpGet } = await import("./http-transport-DIF0xnKu.mjs");
		return handleMcpGet(request);
	},
	POST: async ({ request }) => {
		const { handleMcpPost } = await import("./http-transport-DIF0xnKu.mjs");
		return handleMcpPost(request);
	}
} } });
/**
* Vault v2 credential card: the operator opens the single-use link from
* Telegram, types the secret, and it goes straight to the canonical vault.
* GET renders the form (never consumes the token); POST stores the secret.
* All logic — token check, CSRF, size limit, CSP, escaping — lives in
* handleCardRequest. No secret ever appears in a response.
*/
var Route$14 = createFileRoute("/card/$token")({ server: { handlers: {
	GET: async ({ request, params }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleCardRequest } = await import("./card-pages-DKhV17Ik.mjs");
		return handleCardRequest(request, params.token);
	},
	POST: async ({ request, params }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleCardRequest } = await import("./card-pages-DKhV17Ik.mjs");
		return handleCardRequest(request, params.token);
	}
} } });
/**
* Owner console overview (`/console`). All logic — configuration gate, passkey
* session, CSRF, CSP, escaping — lives in handleConsoleRequest
* (src/lib/vault/v2/owner-console-pages.ts). No secret ever appears in a response.
*/
async function handle$1(request) {
	(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
	const { handleConsoleRequest } = await import("./owner-console-pages-B_tkbaAc.mjs");
	return handleConsoleRequest(request);
}
var Route$13 = createFileRoute("/console/")({ server: { handlers: {
	GET: ({ request }) => handle$1(request),
	POST: ({ request }) => handle$1(request)
} } });
/**
* Every owner-console page and endpoint below `/console/` (login, enroll,
* clients, grants, entries, audit, digest, security and their POST actions).
* A thin wrapper: routing inside the console, the passkey session, CSRF, CSP
* and escaping all live in handleConsoleRequest
* (src/lib/vault/v2/owner-console-pages.ts). No secret ever appears in a response.
*/
async function handle(request) {
	(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
	const { handleConsoleRequest } = await import("./owner-console-pages-B_tkbaAc.mjs");
	return handleConsoleRequest(request);
}
var Route$12 = createFileRoute("/console/$")({ server: { handlers: {
	GET: ({ request }) => handle(request),
	POST: ({ request }) => handle(request)
} } });
/**
* RFC 9728 §3.1 path form: a client that knows only the resource URL
* `https://host/api/mcp` builds `/.well-known/oauth-protected-resource/api/mcp`.
* Serves the same document as the root form (which this splat route also
* matches, with an empty suffix). Any other suffix is 404: this server
* protects exactly one resource.
*/
var Route$11 = createFileRoute("/.well-known/oauth-protected-resource/$")({ server: { handlers: {
	GET: async ({ request, params }) => {
		const { ensureV2Configured } = await import("./bootstrap-DBXqHiC1.mjs");
		const { handleProtectedResourceMetadata, MCP_RESOURCE_PATH } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		ensureV2Configured();
		const suffix = `/${String(params._splat ?? "").replace(/\/+$/, "")}`;
		if (suffix !== "/" && suffix !== MCP_RESOURCE_PATH) return new Response(JSON.stringify({ error: "not_found" }), {
			status: 404,
			headers: {
				"content-type": "application/json; charset=utf-8",
				"cache-control": "no-store"
			}
		});
		return handleProtectedResourceMetadata(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/**
* Node import (begin): a fleet node pushes credentials it found on its own disks
* into the vault after the owner approves that node. Write-only — see
* src/lib/vault/v2/node-import.ts and docs/ops/credential-import.md.
*/
var Route$10 = createFileRoute("/api/import/begin")({ server: { handlers: { POST: async ({ request }) => {
	const { handleImportBegin } = await import("./node-import-Dw-_yJuw.mjs");
	return handleImportBegin(request);
} } } });
/**
* Node import (finish): a fleet node pushes credentials it found on its own disks
* into the vault after the owner approves that node. Write-only — see
* src/lib/vault/v2/node-import.ts and docs/ops/credential-import.md.
*/
var Route$9 = createFileRoute("/api/import/finish")({ server: { handlers: { POST: async ({ request }) => {
	const { handleImportFinish } = await import("./node-import-Dw-_yJuw.mjs");
	return handleImportFinish(request);
} } } });
/**
* Node import (submit): a fleet node pushes credentials it found on its own disks
* into the vault after the owner approves that node. Write-only — see
* src/lib/vault/v2/node-import.ts and docs/ops/credential-import.md.
*/
var Route$8 = createFileRoute("/api/import/submit")({ server: { handlers: { POST: async ({ request }) => {
	const { handleImportSubmit } = await import("./node-import-Dw-_yJuw.mjs");
	return handleImportSubmit(request);
} } } });
/**
* Browser injector: exchange a single-use ticket for the credential sealed to
* the injector's public key. `Authorization: Bearer ein_…` only — see
* src/lib/vault/v2/injector-http.ts and docs/ops/injector-contract.md.
*/
var Route$7 = createFileRoute("/api/injector/redeem")({ server: { handlers: { POST: async ({ request }) => {
	const { handleInjectorRedeem } = await import("./injector-http-BmgdVPdy.mjs");
	return handleInjectorRedeem(request);
} } } });
/**
* Browser injector: report the outcome of an injection ("injected" | "failed").
* `Authorization: Bearer ein_…` only — see src/lib/vault/v2/injector-http.ts.
*/
var Route$6 = createFileRoute("/api/injector/report")({ server: { handlers: { POST: async ({ request }) => {
	const { handleInjectorReport } = await import("./injector-http-BmgdVPdy.mjs");
	return handleInjectorReport(request);
} } } });
/**
* OAuth 2.1 authorization endpoint (PKCE S256 only). Renders the
* "Approve this connection on your phone" page, which polls this same route
* with `?pending=…` until the owner decides, then 302s to the client.
*/
var Route$5 = createFileRoute("/api/oauth/authorize")({ server: { handlers: { GET: async ({ request }) => {
	(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
	const { handleAuthorize } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
	return handleAuthorize(request);
} } } });
/** RFC 7591 dynamic client registration (public clients; no scopes until the owner approves). */
var Route$4 = createFileRoute("/api/oauth/register")({ server: { handlers: {
	POST: async ({ request }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleRegister } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handleRegister(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/** RFC 7009 token revocation (access tokens; refresh tokens revoke their whole family). */
var Route$3 = createFileRoute("/api/oauth/revoke")({ server: { handlers: {
	POST: async ({ request }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleRevoke } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handleRevoke(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/** OAuth 2.1 token endpoint: authorization_code (+PKCE) and rotating refresh_token grants. */
var Route$2 = createFileRoute("/api/oauth/token")({ server: { handlers: {
	POST: async ({ request }) => {
		(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
		const { handleToken } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handleToken(request);
	},
	OPTIONS: async ({ request }) => {
		const { handlePreflight } = await import("./oauth-server-BJCUNFGm.mjs").then((n) => n.l).then((n) => n.l);
		return handlePreflight(request);
	}
} } });
/**
* Stateless REST wrapper around dispatchTool() — for callers that cannot do
* the MCP JSON-RPC envelope (the ECHO SDK gate's handler_kind='http'
* dispatcher makes one bare POST with a flat JSON body).
*
* Body: {"tool": "<name>", "arguments": {...}}
* Auth: `Authorization: Bearer` — a workload token (ewk_…) or an OAuth access
* token (eva_…). Same gateway, policy, approvals and ledger as /api/mcp.
*/
var Route$1 = createFileRoute("/api/rest/tool")({ server: { handlers: { POST: async ({ request }) => {
	const { handleRestTool } = await import("./http-transport-DIF0xnKu.mjs");
	return handleRestTool(request);
} } } });
/**
* Telegram Bot API webhook for vault v2 approvals. Authenticated by the
* X-Telegram-Bot-Api-Secret-Token header (setWebhook secret_token); all logic
* — secret check, decision, answerCallbackQuery, message edit — lives in
* handleTelegramWebhook. No secret ever appears in the response.
*/
var Route = createFileRoute("/api/telegram/webhook")({ server: { handlers: { POST: async ({ request }) => {
	(await import("./bootstrap-DBXqHiC1.mjs")).ensureV2Configured();
	const { handleTelegramWebhook } = await import("./telegram-B-fJEnsh.mjs").then((n) => n.r).then((n) => n.r);
	return handleTelegramWebhook(request);
} } } });
var IndexRoute = Route$18.update({
	id: "/",
	path: "/",
	getParentRoute: () => Route$19
});
var DotwellKnownOauthAuthorizationServerRoute = Route$17.update({
	id: "/.well-known/oauth-authorization-server",
	path: "/.well-known/oauth-authorization-server",
	getParentRoute: () => Route$19
});
var DotwellKnownOauthProtectedResourceRoute = Route$16.update({
	id: "/.well-known/oauth-protected-resource",
	path: "/.well-known/oauth-protected-resource",
	getParentRoute: () => Route$19
});
var ApiMcpRoute = Route$15.update({
	id: "/api/mcp",
	path: "/api/mcp",
	getParentRoute: () => Route$19
});
var CardTokenRoute = Route$14.update({
	id: "/card/$token",
	path: "/card/$token",
	getParentRoute: () => Route$19
});
var ConsoleIndexRoute = Route$13.update({
	id: "/console/",
	path: "/console/",
	getParentRoute: () => Route$19
});
var ConsoleSplatRoute = Route$12.update({
	id: "/console/$",
	path: "/console/$",
	getParentRoute: () => Route$19
});
var DotwellKnownOauthProtectedResourceSplatRoute = Route$11.update({
	id: "/$",
	path: "/$",
	getParentRoute: () => DotwellKnownOauthProtectedResourceRoute
});
var ApiImportBeginRoute = Route$10.update({
	id: "/api/import/begin",
	path: "/api/import/begin",
	getParentRoute: () => Route$19
});
var ApiImportFinishRoute = Route$9.update({
	id: "/api/import/finish",
	path: "/api/import/finish",
	getParentRoute: () => Route$19
});
var ApiImportSubmitRoute = Route$8.update({
	id: "/api/import/submit",
	path: "/api/import/submit",
	getParentRoute: () => Route$19
});
var ApiInjectorRedeemRoute = Route$7.update({
	id: "/api/injector/redeem",
	path: "/api/injector/redeem",
	getParentRoute: () => Route$19
});
var ApiInjectorReportRoute = Route$6.update({
	id: "/api/injector/report",
	path: "/api/injector/report",
	getParentRoute: () => Route$19
});
var ApiOauthAuthorizeRoute = Route$5.update({
	id: "/api/oauth/authorize",
	path: "/api/oauth/authorize",
	getParentRoute: () => Route$19
});
var ApiOauthRegisterRoute = Route$4.update({
	id: "/api/oauth/register",
	path: "/api/oauth/register",
	getParentRoute: () => Route$19
});
var ApiOauthRevokeRoute = Route$3.update({
	id: "/api/oauth/revoke",
	path: "/api/oauth/revoke",
	getParentRoute: () => Route$19
});
var ApiOauthTokenRoute = Route$2.update({
	id: "/api/oauth/token",
	path: "/api/oauth/token",
	getParentRoute: () => Route$19
});
var ApiRestToolRoute = Route$1.update({
	id: "/api/rest/tool",
	path: "/api/rest/tool",
	getParentRoute: () => Route$19
});
var ApiTelegramWebhookRoute = Route.update({
	id: "/api/telegram/webhook",
	path: "/api/telegram/webhook",
	getParentRoute: () => Route$19
});
var DotwellKnownOauthProtectedResourceRouteChildren = { DotwellKnownOauthProtectedResourceSplatRoute };
var rootRouteChildren = {
	IndexRoute,
	DotwellKnownOauthAuthorizationServerRoute,
	DotwellKnownOauthProtectedResourceRoute: DotwellKnownOauthProtectedResourceRoute._addFileChildren(DotwellKnownOauthProtectedResourceRouteChildren),
	ApiMcpRoute,
	CardTokenRoute,
	ConsoleSplatRoute,
	ConsoleIndexRoute,
	ApiImportBeginRoute,
	ApiImportFinishRoute,
	ApiImportSubmitRoute,
	ApiInjectorRedeemRoute,
	ApiInjectorReportRoute,
	ApiOauthAuthorizeRoute,
	ApiOauthRegisterRoute,
	ApiOauthRevokeRoute,
	ApiOauthTokenRoute,
	ApiRestToolRoute,
	ApiTelegramWebhookRoute
};
var routeTree = Route$19._addFileChildren(rootRouteChildren)._addFileTypes();
function getRouter() {
	return createRouter({
		routeTree,
		defaultErrorComponent: AppErrorComponent
	});
}
//#endregion
export { getRouter, router_CrdupEWr_exports as t };
