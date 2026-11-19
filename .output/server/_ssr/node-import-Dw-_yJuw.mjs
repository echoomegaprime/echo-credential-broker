import { o as log, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { a as rateLimitKey, i as getDefaultRateLimitStore, o as withRateLimitStore } from "./rate-limit-store-D2QvwAS2.mjs";
import { a as constantTimeEqual, h as sanitizeDisplayText, i as checkApproval, o as consumeApproval, s as createApproval, t as ApprovalError } from "./approvals-vHr7W1Jg.mjs";
import { ensureV2Configured } from "./bootstrap-DBXqHiC1.mjs";
import { C as normalizeSite, S as normalizePurpose, d as entryRef, k as secretFingerprint, r as EntryError, u as entryLabel, w as openEntryVault, x as normalizeAccount } from "./cards-BG7l2-sJ.mjs";
import { createHash, randomBytes } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/node-import-Dw-_yJuw.js
/**
* Bulk import: turn a credential-scan manifest into vault entries, so the owner
* does not have to type every existing credential into a card.
*
* Two steps, both free of secret values in everything they return:
*
*   planImport(manifest)        pure. Manifest findings (references only) →
*                               one planned entry per distinct secret, plus the
*                               findings that will not be imported and why.
*   applyImport(plan, deps)     reads each secret back from its source file
*                               (through `resolveSecret`, supplied by the
*                               on-box script), stores it with the same seam
*                               rotation uses (openEntryVault: backend put →
*                               entry row → ledger) and reports a status code
*                               per entry.
*
* The secret exists only as a local variable between `resolveSecret` and
* `writeSecret`; it is registered for redaction first. Nothing here prints, logs
* or returns it. Source files are never modified.
*
* Imported entries are ordinary entries: `entry_use`, `entry_transfer`, re-entry
* cards, rotation and delete all work on them. Using one still needs the
* owner's consent exactly as for a card-entered entry.
*/
/** Providers the scanner names that are not a service an entry could be used against. */
var UNIMPORTABLE = {
	"private-key": "private_key_file",
	"echo-vault": "vault_own_token",
	jwt: "jwt_unattributed",
	"url-credentials": "url_credentials"
};
/**
* Variable-name hints for `generic_assignment` findings, first match wins.
* Only names that identify one service; anything else stays `unknown_provider`.
*/
var NAME_HINTS = [
	[/cloudflare|(^|_)cf_/i, "cloudflare.com"],
	[/twilio/i, "twilio.com"],
	[/eleven_?labs|(^|_)xi_/i, "elevenlabs.io"],
	[/anthropic|claude/i, "anthropic.com"],
	[/openrouter/i, "openrouter.ai"],
	[/openai/i, "openai.com"],
	[/(^|_)xai(_|$)|grok/i, "x.ai"],
	[/groq/i, "groq.com"],
	[/together/i, "together.ai"],
	[/deepseek/i, "deepseek.com"],
	[/mistral/i, "mistral.ai"],
	[/perplexity|(^|_)pplx/i, "perplexity.ai"],
	[/replicate/i, "replicate.com"],
	[/runpod/i, "runpod.io"],
	[/firecrawl/i, "firecrawl.dev"],
	[/tavily/i, "tavily.com"],
	[/bright_?data/i, "brightdata.com"],
	[/github|(^|_)gh_/i, "github.com"],
	[/stripe/i, "stripe.com"],
	[/sendgrid/i, "sendgrid.com"],
	[/resend/i, "resend.com"],
	[/vercel/i, "vercel.com"],
	[/supabase/i, "supabase.com"],
	[/telegram/i, "telegram.org"],
	[/hugging_?face|(^|_)hf_/i, "huggingface.co"],
	[/notion/i, "notion.so"],
	[/slack/i, "slack.com"],
	[/discord/i, "discord.com"],
	[/pinecone/i, "pinecone.io"],
	[/youtube|gemini|google/i, "google.com"],
	[/(^|_)aws(_|$)/i, "aws.amazon.com"]
];
function siteForFinding(f, opts) {
	const blocked = UNIMPORTABLE[f.provider];
	if (blocked) return { reason: blocked };
	if (f.detector === "generic_assignment" || f.provider === "unknown") {
		if (!opts.includeGeneric) return { reason: "generic_not_requested" };
		const hint = NAME_HINTS.find(([re]) => re.test(f.key_name ?? ""));
		if (!hint) return { reason: "unknown_provider" };
		return { site: hint[1] };
	}
	try {
		return { site: normalizeSite(f.provider) };
	} catch {
		return { reason: "invalid_site" };
	}
}
/** A variable name as an account label ("YOUTUBE_API_KEY" → "youtube_api_key"), or null when it cannot be one. */
function accountFromKeyName(name) {
	if (!name) return null;
	const cleaned = name.toLowerCase().replace(/[^a-z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 64);
	if (!cleaned) return null;
	try {
		return normalizeAccount(cleaned);
	} catch {
		return null;
	}
}
function purposeFor(node, file) {
	const tidy = (v) => v.replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
	const raw = `import ${tidy(node ?? "node") || "node"}/${tidy(file) || "file"}`.slice(0, 64).replace(/[-/ ]+$/, "");
	try {
		return normalizePurpose(raw);
	} catch {
		return "import";
	}
}
function basenameOf(path) {
	return path.split(/[\\/]/).pop() ?? path;
}
/**
* Manifest → plan. Pure and deterministic: the same manifest always yields the
* same entries with the same identities, so a second run finds them and skips.
*
* One entry per distinct secret (scan fingerprint). The account is the variable
* the secret was assigned to when the scanner saw one, otherwise
* `imported-<first 8 of the scan fingerprint>`; a clash inside a site gets the
* fingerprint suffix so two different keys never collapse into one entry.
*/
function planImport(manifest, opts = {}) {
	if (!manifest || !Array.isArray(manifest.findings)) throw new EntryError("invalid_input", "Not a scan manifest");
	if (manifest.contains_secret_values !== false) throw new EntryError("invalid_input", "The manifest must be a reference-only scan (contains_secret_values: false)");
	const node = typeof manifest.node === "string" && manifest.node ? manifest.node : null;
	const only = opts.onlySites ? new Set(opts.onlySites.map((s) => normalizeSite(s))) : null;
	const skipped = [];
	const bySecret = /* @__PURE__ */ new Map();
	const ordered = [...manifest.findings].sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.detector.localeCompare(b.detector));
	for (const f of ordered) {
		const skip = (reason) => skipped.push({
			path: f.path,
			line: f.line,
			detector: f.detector,
			provider: f.provider,
			key_name: f.key_name,
			reason
		});
		if (typeof f.fingerprint !== "string" || !/^[0-9a-f]{16}$/.test(f.fingerprint)) {
			skip(UNIMPORTABLE[f.provider] ?? "no_fingerprint");
			continue;
		}
		const mapped = siteForFinding(f, opts);
		if ("reason" in mapped) {
			skip(mapped.reason);
			continue;
		}
		if (only && !only.has(mapped.site)) {
			skip("provider_not_selected");
			continue;
		}
		const known = bySecret.get(f.fingerprint);
		const source = {
			path: f.path,
			line: f.line,
			detector: f.detector
		};
		if (known) {
			known.sources.push(source);
			if (!known.keyName && f.key_name) known.keyName = f.key_name;
			continue;
		}
		bySecret.set(f.fingerprint, {
			site: mapped.site,
			first: f,
			keyName: f.key_name,
			sources: [source]
		});
	}
	const taken = /* @__PURE__ */ new Set();
	const entries = [];
	for (const [fp, group] of [...bySecret.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
		const kind = "api_key";
		const fallback = `imported-${fp.slice(0, 8)}`;
		let account = accountFromKeyName(group.keyName) ?? fallback;
		if (taken.has(`${group.site}\n${account}`)) account = `${account}-${fp.slice(0, 8)}`.slice(0, 254);
		taken.add(`${group.site}\n${account}`);
		const purpose = purposeFor(node, group.first.file ?? basenameOf(group.first.path));
		entries.push({
			scan_fingerprint: fp,
			site: group.site,
			account,
			purpose,
			label: entryLabel(group.site, account, purpose),
			kind,
			sources: group.sources
		});
	}
	entries.sort((a, b) => a.site.localeCompare(b.site) || a.account.localeCompare(b.account));
	return {
		node,
		entries,
		skipped
	};
}
var STATUSES = [
	"imported",
	"would_import",
	"exists",
	"already_stored",
	"source_unreadable",
	"secret_out_of_range",
	"secret_in_metadata",
	"vault_unavailable",
	"store_unavailable",
	"identity_conflict",
	"store_failed"
];
function sha256Hex$1(value) {
	return createHash("sha256").update(value, "utf8").digest("hex");
}
/**
* Plan → entries. Safe to run twice: an identity that already holds this secret
* is `exists`, and a secret already held by another entry of the same site and
* kind is `already_stored`. An identity that holds a DIFFERENT secret does not
* swallow the credential: it is stored under the account with the scan
* fingerprint appended. One failed entry never stops the rest.
*/
async function applyImport(plan, deps) {
	const dryRun = deps.dryRun === true;
	const actor = deps.actor ?? "local:import";
	const v = openEntryVault(deps);
	const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
	const outcomes = [];
	const done = (p, status, entryId) => {
		counts[status]++;
		outcomes.push({
			site: p.site,
			account: p.account,
			label: p.label,
			kind: p.kind,
			status,
			...entryId ? { entry_id: entryId } : {},
			sources: p.sources
		});
	};
	/** True when `row` provably holds `secret`. Unreadable → false (import rather than drop). */
	const holds = async (row, secret) => {
		try {
			return constantTimeEqual(sha256Hex$1(await v.readSecret(row)), sha256Hex$1(secret));
		} catch {
			return false;
		}
	};
	for (const planned of plan.entries) {
		let p = planned;
		let secret = null;
		try {
			secret = await deps.resolveSecret(p);
		} catch {
			secret = null;
		}
		if (typeof secret !== "string" || secret.length === 0) {
			let known = null;
			try {
				known = await v.entries.findIdentity(p.site, p.account, p.kind);
			} catch {
				known = null;
			}
			if (known) done(p, "exists", known.id);
			else done(p, "source_unreadable");
			continue;
		}
		registerSecretForRedaction(secret);
		if (secret.length < 8 || secret.length > 4096) {
			done(p, "secret_out_of_range");
			continue;
		}
		if ([
			p.site,
			p.account,
			p.purpose
		].some((field) => field.includes(secret))) {
			done(p, "secret_in_metadata");
			continue;
		}
		const fp = secretFingerprint(secret);
		const suffix = `-${p.scan_fingerprint.slice(0, 8)}`;
		const accounts = p.account.endsWith(suffix) ? [p.account] : [p.account, `${p.account}${suffix}`.slice(0, 254)];
		let outcome = "conflict";
		let existingId;
		for (const account of accounts) {
			let identity;
			try {
				identity = await v.entries.findIdentity(p.site, account, p.kind);
			} catch {
				outcome = "store_down";
				break;
			}
			if (!identity) {
				if (account !== p.account) p = {
					...p,
					account,
					label: entryLabel(p.site, account, p.purpose)
				};
				outcome = "free";
				break;
			}
			if (await holds(identity, secret)) {
				outcome = "exists";
				existingId = identity.id;
				break;
			}
		}
		if (outcome !== "free") {
			secret = null;
			if (outcome === "exists") done(p, "exists", existingId);
			else done(p, outcome === "store_down" ? "store_unavailable" : "identity_conflict");
			continue;
		}
		let candidates;
		try {
			candidates = (await v.entries.list({ site: p.site })).filter((e) => e.kind === p.kind && e.fingerprint === fp);
		} catch {
			secret = null;
			done(p, "store_unavailable");
			continue;
		}
		let twin = null;
		for (const candidate of candidates) if (await holds(candidate, secret)) {
			twin = candidate;
			break;
		}
		if (twin) {
			secret = null;
			done(p, "already_stored", twin.id);
			continue;
		}
		if (dryRun) {
			secret = null;
			done(p, "would_import");
			continue;
		}
		const id = `ve_${randomBytes(16).toString("hex")}`;
		const started = Date.now();
		const ledgerRow = (result, error) => ({
			client_id: actor,
			capability: "vault.entry.import",
			resource: `entry:${p.site}/${p.account}`,
			credential_ref: entryRef(id),
			decision: "allow",
			tier: 2,
			result,
			error,
			duration_ms: Date.now() - started,
			task: "bulk import from a credential scan"
		});
		let stored = null;
		let failure = "store_failed";
		try {
			await v.writeSecret({
				id,
				site: p.site,
				account: p.account,
				purpose: p.purpose,
				kind: p.kind
			}, secret);
			try {
				stored = await v.entries.insert({
					id,
					site: p.site,
					account: p.account,
					purpose: p.purpose,
					label: p.label,
					kind: p.kind,
					fingerprint: fp,
					secret_length: secret.length,
					nowIso: v.nowIso
				});
			} catch (err) {
				await v.destroySecret({ id }).catch(() => void 0);
				throw err;
			}
		} catch (err) {
			const code = err instanceof EntryError ? err.code : "store_failed";
			failure = code === "vault_unavailable" ? "vault_unavailable" : code === "entry_exists" ? "exists" : "store_failed";
			log.warn("vault_entry_import_failed", {
				site: p.site,
				error: code
			});
		}
		secret = null;
		if (!stored) {
			if (failure !== "exists") await v.ledger(ledgerRow("error", failure), false);
			done(p, failure);
			continue;
		}
		await v.ledger(ledgerRow("ok"), false);
		log.info("vault_entry_imported", {
			entry_id: stored.id,
			site: stored.site
		});
		done(p, "imported", stored.id);
	}
	return {
		dry_run: dryRun,
		planned: plan.entries.length,
		counts,
		outcomes
	};
}
/**
* Node import: a fleet node pushes the credentials it found on its own disks
* straight into the vault, after the owner approves that node on Telegram.
*
* Why this exists: the importer (import.ts) needs the vault's database and
* backend, which live on the vault host. Copying the vault's environment to
* every node, or giving the vault host a shell on every node, would both widen
* what a single compromise reaches. This channel does neither.
*
*   POST /api/import/begin    { node, planned, session_hash, apply, include_generic }
*        → the owner gets one Telegram prompt naming the node, the count and a
*          pairing code. Nothing can be submitted until they approve.
*   POST /api/import/submit   Authorization: Bearer <session secret>
*                             { approval_id, node, planned, apply, include_generic, items: [...] }
*        → each item is planned and stored by the same code a local import uses.
*   POST /api/import/finish   Authorization: Bearer <session secret>, same fields
*        → closes the session (the approval is consumed).
*
* Properties:
*   - WRITE-ONLY. No route here returns, compares aloud or confirms a secret.
*     Responses carry labels and status codes.
*   - The session secret is generated on the node and never leaves it except
*     as the bearer of its own submissions; the vault stores only its sha256,
*     inside the approved request digest. A different node, count or mode is a
*     different digest and is refused.
*   - One owner decision per node per run, open for at most 30 minutes, capped
*     at the number of credentials the owner was shown.
*   - `begin` is the one unauthenticated call. It is globally rate limited and
*     fails closed, so it cannot be used to flood the approver.
*   - Submitted secrets are registered for redaction before anything else
*     touches them, and never logged.
*/
var IMPORT_CAPABILITY = "vault.entry.import";
var IMPORT_SESSION_TTL_MS = 18e5;
var MAX_IMPORT_BODY_BYTES = 262144;
var MAX_BEGIN_BODY_BYTES = 2048;
var HOUR_MS = 36e5;
var NODE_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
var HASH_PATTERN = /^[0-9a-f]{64}$/;
var BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]{43,128})$/;
var FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/;
var DETECTOR_PATTERN = /^[a-z0-9_]{1,40}$/;
var HEADERS = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store"
};
function json(status, body, extra = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...HEADERS,
			...extra
		}
	});
}
var refuse = (status, error, extra = {}) => json(status, {
	ok: false,
	error
}, extra);
function sha256Hex(value) {
	return createHash("sha256").update(value, "utf8").digest("hex");
}
/** The six characters shown both on the node's terminal and in the owner's prompt. */
function pairingCode(sessionHash) {
	return sessionHash.slice(0, 6).toUpperCase();
}
/** The exact request the owner approves. Any difference later is a digest mismatch. */
function importRequest(terms, sessionHash) {
	return {
		client: {
			client_id: `import:${terms.node}`,
			name: `Node ${terms.node}`,
			kind: "workload",
			scopes: []
		},
		capability: IMPORT_CAPABILITY,
		resource: `node:${terms.node}`,
		params: {
			session_hash: sessionHash,
			planned: terms.planned,
			apply: terms.apply,
			include_generic: terms.include_generic
		}
	};
}
function readTerms(body) {
	const node = typeof body.node === "string" ? body.node.toLowerCase() : "";
	const planned = body.planned;
	if (!NODE_PATTERN.test(node)) return null;
	if (typeof planned !== "number" || !Number.isInteger(planned) || planned < 1 || planned > 2e3) return null;
	if (typeof body.apply !== "boolean" || typeof body.include_generic !== "boolean") return null;
	return {
		node,
		planned,
		apply: body.apply,
		include_generic: body.include_generic
	};
}
async function readBody(request, maxBytes) {
	if (request.method.toUpperCase() !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
	const declared = Number(request.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > maxBytes) return refuse(413, "request_too_large");
	let value;
	try {
		const buf = Buffer.from(await request.arrayBuffer());
		if (buf.byteLength > maxBytes) return refuse(413, "request_too_large");
		value = JSON.parse(buf.toString("utf8"));
	} catch {
		return refuse(400, "invalid_request");
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) return refuse(400, "invalid_request");
	return value;
}
function limitsOf(deps) {
	return deps.limits ?? getDefaultRateLimitStore();
}
function nowOf(deps) {
	return (deps.now ?? deps.approvals?.now ?? Date.now)();
}
/** POST /api/import/begin */
async function handleImportBegin(request, deps = {}) {
	ensureV2Configured();
	const body = await readBody(request, MAX_BEGIN_BODY_BYTES);
	if (body instanceof Response) return body;
	const terms = readTerms(body);
	const sessionHash = typeof body.session_hash === "string" ? body.session_hash : "";
	if (!terms || !HASH_PATTERN.test(sessionHash)) return refuse(400, "invalid_request");
	try {
		if (!(await withRateLimitStore(limitsOf(deps), "hit", (s) => s.hit(rateLimitKey("import.begin", "global"), HOUR_MS, nowOf(deps), 8))).recorded) return refuse(429, "too_many_import_requests", { "retry-after": "600" });
	} catch {
		return refuse(503, "unavailable");
	}
	const mode = terms.apply ? "store them" : "preview only, nothing stored";
	const summary = `Import up to ${terms.planned} credentials found on node ${terms.node} into the vault (${mode}). Pairing code ${pairingCode(sessionHash)}. Write-only: nothing is read back to the node.`;
	try {
		const record = await createApproval(importRequest(terms, sessionHash), summary, {
			...deps.approvals,
			ttlMs: IMPORT_SESSION_TTL_MS,
			now: deps.approvals?.now ?? deps.now,
			env: deps.approvals?.env ?? deps.env
		});
		log.info("vault_node_import_requested", {
			node: terms.node,
			planned: terms.planned,
			apply: terms.apply,
			approval_id: record.id
		});
		return json(200, {
			ok: true,
			approval_id: record.id,
			expires_at: record.expires_at,
			pairing_code: pairingCode(sessionHash)
		});
	} catch (err) {
		const code = err instanceof ApprovalError ? err.code : "approval_failed";
		log.warn("vault_node_import_begin_failed", {
			node: terms.node,
			error: code
		});
		return refuse(503, /^[a-z0-9_]{1,64}$/.test(code) ? code : "approval_failed");
	}
}
var APPROVAL_HTTP = {
	not_found: [401, "invalid_session"],
	digest_mismatch: [401, "invalid_session"],
	pending: [409, "approval_pending"],
	denied: [403, "approval_denied"],
	expired: [410, "session_expired"],
	already_consumed: [410, "session_closed"]
};
/** Body, bearer, then the session terms the bearer must hash to. No approval lookup yet. */
async function readSession(request) {
	const body = await readBody(request, MAX_IMPORT_BODY_BYTES);
	if (body instanceof Response) return body;
	const bearer = BEARER_PATTERN.exec(request.headers.get("authorization") ?? "");
	if (!bearer) return refuse(401, "invalid_session");
	const terms = readTerms(body);
	const approvalId = typeof body.approval_id === "string" ? body.approval_id : "";
	if (!terms || !approvalId) return refuse(400, "invalid_request");
	return {
		terms,
		approvalId,
		request: importRequest(terms, sha256Hex(bearer[1])),
		body
	};
}
function cleanText(value, max) {
	return typeof value === "string" ? sanitizeDisplayText(value, max) : "";
}
/** One submitted item → a reference finding plus its secret. Null when malformed. */
function readItem(raw) {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const r = raw;
	if (typeof r.secret !== "string" || r.secret.length === 0 || r.secret.length > 8192) return null;
	registerSecretForRedaction(r.secret);
	if (typeof r.fingerprint !== "string" || !FINGERPRINT_PATTERN.test(r.fingerprint)) return null;
	if (typeof r.detector !== "string" || !DETECTOR_PATTERN.test(r.detector)) return null;
	if (JSON.stringify([
		r.provider,
		r.key_name,
		r.sources
	]).includes(JSON.stringify(r.secret).slice(1, -1))) return null;
	const provider = cleanText(r.provider, 80);
	if (!provider) return null;
	const keyName = r.key_name === null || r.key_name === void 0 ? null : cleanText(r.key_name, 80) || null;
	const rawSources = Array.isArray(r.sources) ? r.sources.slice(0, 5) : [];
	const sources = [];
	for (const s of rawSources) {
		if (!s || typeof s !== "object") continue;
		const path = cleanText(s.path, 400);
		const line = s.line;
		if (!path || typeof line !== "number" || !Number.isInteger(line) || line < 1) continue;
		sources.push({
			path,
			line,
			detector: r.detector
		});
	}
	if (sources.length === 0) return null;
	return {
		finding: {
			path: sources[0].path,
			file: sources[0].path.split(/[\\/]/).pop(),
			line: sources[0].line,
			detector: r.detector,
			provider,
			key_name: keyName,
			length: r.secret.length,
			fingerprint: r.fingerprint
		},
		secret: r.secret,
		sources
	};
}
/** POST /api/import/submit */
async function handleImportSubmit(request, deps = {}) {
	ensureV2Configured();
	const session = await readSession(request);
	if (session instanceof Response) return session;
	const { terms, approvalId } = session;
	const rawItems = session.body.items;
	if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 25) return refuse(400, "invalid_request");
	let state;
	try {
		state = await checkApproval(approvalId, session.request, {
			...deps.approvals,
			now: deps.approvals?.now ?? deps.now
		});
	} catch {
		return refuse(503, "unavailable");
	}
	if (state !== "ok") return refuse(...APPROVAL_HTTP[state]);
	const items = [];
	let malformed = 0;
	const seen = /* @__PURE__ */ new Set();
	for (const raw of rawItems) {
		const item = readItem(raw);
		if (!item || seen.has(item.finding.fingerprint)) {
			malformed++;
			continue;
		}
		seen.add(item.finding.fingerprint);
		items.push(item);
	}
	const accepted = [];
	let overPlan = 0;
	try {
		for (const item of items) if ((await withRateLimitStore(limitsOf(deps), "hit", (s) => s.hit(rateLimitKey("import.entries", approvalId), HOUR_MS, nowOf(deps), terms.planned))).recorded) accepted.push(item);
		else overPlan++;
	} catch {
		return refuse(503, "unavailable");
	}
	const bySecret = new Map(accepted.map((i) => [i.finding.fingerprint, i]));
	const plan = planImport({
		node: terms.node,
		contains_secret_values: false,
		findings: accepted.map((i) => i.finding)
	}, { includeGeneric: terms.include_generic });
	for (const entry of plan.entries) {
		const item = bySecret.get(entry.scan_fingerprint);
		if (item) entry.sources = item.sources;
	}
	const result = await applyImport(plan, {
		...deps,
		dryRun: !terms.apply,
		actor: `import:${terms.node}`,
		resolveSecret: async (entry) => bySecret.get(entry.scan_fingerprint)?.secret ?? null
	});
	const skipped = {};
	for (const s of plan.skipped) skipped[s.reason] = (skipped[s.reason] ?? 0) + 1;
	log.info("vault_node_import_batch", {
		node: terms.node,
		approval_id: approvalId,
		apply: terms.apply,
		submitted: rawItems.length,
		imported: result.counts.imported,
		malformed,
		over_plan: overPlan
	});
	return json(200, {
		ok: true,
		dry_run: result.dry_run,
		counts: result.counts,
		malformed,
		over_plan: overPlan,
		skipped,
		entries: result.outcomes.map((o) => ({
			label: o.label,
			status: o.status
		}))
	});
}
/** POST /api/import/finish */
async function handleImportFinish(request, deps = {}) {
	ensureV2Configured();
	const session = await readSession(request);
	if (session instanceof Response) return session;
	let state;
	try {
		state = await consumeApproval(session.approvalId, session.request, {
			...deps.approvals,
			now: deps.approvals?.now ?? deps.now
		});
	} catch {
		return refuse(503, "unavailable");
	}
	if (state !== "ok") return refuse(...APPROVAL_HTTP[state]);
	log.info("vault_node_import_closed", {
		node: session.terms.node,
		approval_id: session.approvalId
	});
	return json(200, {
		ok: true,
		closed: true
	});
}
//#endregion
export { handleImportBegin, handleImportFinish, handleImportSubmit };
