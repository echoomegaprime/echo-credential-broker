import { pendingMigrations } from "../../scripts/migration-plan.mjs";

/** Which database backend is active. */
export type DbSource = "neon" | "pglite";

// An empty/whitespace DATABASE_URL (an easy misconfig in deploy UIs) must mean
// "unset" — otherwise production would silently run on the PGLite fallback.
const rawDatabaseUrl =
  typeof process !== "undefined" ? process.env.DATABASE_URL : undefined;
const databaseUrl =
  rawDatabaseUrl && rawDatabaseUrl.trim() ? rawDatabaseUrl : undefined;

/**
 * Active backend: real **Neon** when `DATABASE_URL` is set (deployed / configured
 * sandbox), otherwise a local embedded **PGLite** (Postgres compiled to WASM) so
 * the app has a working database even with nothing configured — the live preview
 * included. Swap in Neon later by just setting `DATABASE_URL`; no code changes.
 */
export const dbSource: DbSource = databaseUrl ? "neon" : "pglite";

/**
 * Minimal shared SQL surface, satisfied by both Neon and PGLite. Both the
 * tagged-template and `.query()` forms resolve to an array of row objects:
 *
 *   const sql = await getSql();
 *   const rows = await sql`select * from todos where id = ${id}`; // parameterized
 *   const rows2 = await sql.query("select * from todos where id = $1", [id]);
 */
export interface Sql {
  <T = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]>;
  query<T = Record<string, unknown>>(
    text: string,
    params?: unknown[],
  ): Promise<T[]>;
}

/**
 * Init state lives on globalThis as promises: dev HMR creates new instances of
 * this module, and two instances racing module-level state would open a second
 * pool or run two concurrent PGLite migration passes (whose duplicate
 * `_migrations` insert rejects — and would get memoized, poisoning every later
 * `getSql()`). A failed init clears its slot so the next call retries.
 */
const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __pgliteInstance__?: Promise<import("@electric-sql/pglite").PGlite>;
  __pgliteMigrateChain__?: Promise<void>;
};

/**
 * Result-type parity: Postgres sends every value as text plus a type OID — the
 * JS value is the DRIVER's parsing choice, and pg and PGLite disagree (pg:
 * int8 -> string, date -> local-midnight Date; PGLite: int8 -> BigInt, which
 * JSON.stringify rejects, date -> UTC Date). Normalize both so preview and
 * production return identical, JSON-safe shapes:
 *   int8/bigint (incl. count(*)) -> number (past 2^53 loses precision — cast
 *                                   `::text` if you ever need huge integers)
 *   date                         -> 'YYYY-MM-DD' string
 *   interval                     -> Postgres interval text
 * numeric already comes back as a string on both (arbitrary precision).
 */
const OID_INT8 = 20;
const OID_DATE = 1082;
const OID_INTERVAL = 1186;
const identity = (v: string) => v;

type Run = <T>(text: string, params: unknown[]) => Promise<T[]>;

/** Wrap a query runner in the tagged-template + `.query()` `Sql` surface. */
function toSql(run: Run): Sql {
  const sql = (async <T = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]> => {
    // Rebuild with $1, $2, … placeholders so values stay parameterized.
    let text = strings[0];
    for (let i = 0; i < values.length; i += 1) text += `$${i + 1}${strings[i + 1]}`;
    return run<T>(text, values);
  }) as unknown as Sql;
  sql.query = <T = Record<string, unknown>>(text: string, params: unknown[] = []) =>
    run<T>(text, params);
  return sql;
}

function createNeonSql(): Promise<Sql> {
  globalRef.__pgSqlPromise__ ??= (async () => {
    // Regular Postgres driver: node-postgres (`pg`) — works directly with Neon's
    // pooled endpoint. One pool per process; warm serverless instances reuse it.
    const { Pool, types } = await import("pg");
    types.setTypeParser(OID_INT8, Number);
    types.setTypeParser(OID_DATE, identity);
    types.setTypeParser(OID_INTERVAL, identity);
    const pool = new Pool({ connectionString: databaseUrl });
    return toSql(async <T>(text: string, params: unknown[]) => {
      const res = await pool.query(text, params);
      return res.rows as T[];
    });
  })().catch((err) => {
    globalRef.__pgSqlPromise__ = undefined;
    throw err;
  });
  return globalRef.__pgSqlPromise__;
}

/**
 * True when this module was transformed by Vite (dev server or a build).
 * Vite defines `import.meta.env` and rewrites `import.meta.glob(...)` calls at
 * transform time; under plain `node` (the stdio MCP transport, `node --test`)
 * neither exists, so migrations are read from disk instead.
 */
const underVite = typeof import.meta.env !== "undefined";

/**
 * Where the embedded PGLite keeps its files, or null for an in-memory database.
 *   - `ECHO_VAULT_DATA_DIR` set  → `<that dir>/pglite` (any runtime).
 *   - plain node, unset          → `<repo>/.vault-data/pglite` (gitignored), so
 *     the stdio transport's ledger, approvals, entries and grants survive
 *     restarts. Resolved from this file, not the cwd an MCP client spawned us in.
 *   - Vite dev/preview, unset    → in-memory (the template's preview contract).
 *   - `node --test`, unset       → in-memory, so a test can never write into the
 *     operator's real data directory.
 */
async function pgliteDataDir(): Promise<string | null> {
  const configured = process.env.ECHO_VAULT_DATA_DIR?.trim();
  if (!configured && (underVite || process.env.NODE_TEST_CONTEXT)) return null;
  const { resolve, join, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const base = configured
    ? resolve(configured)
    : join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".vault-data");
  return join(base, "pglite");
}

/**
 * PGLite is single-process: two processes opening one data directory corrupt
 * it. Take a pid lock next to the directory; a lock left by a dead process is
 * replaced. A second live process fails with a clear, catchable error.
 */
async function lockDataDir(dir: string): Promise<void> {
  const { mkdirSync, openSync, writeSync, closeSync, readFileSync, rmSync } = await import("node:fs");
  const { dirname } = await import("node:path");
  mkdirSync(dirname(dir), { recursive: true, mode: 0o700 });
  const lockPath = `${dir}.lock`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      process.once("exit", () => {
        try {
          rmSync(lockPath, { force: true });
        } catch {
          // best effort
        }
      });
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      let owner = Number.NaN;
      try {
        owner = Number(readFileSync(lockPath, "utf8").trim());
      } catch {
        // unreadable lock: treat as stale
      }
      let alive = false;
      if (Number.isInteger(owner) && owner > 0 && owner !== process.pid) {
        try {
          process.kill(owner, 0);
          alive = true;
        } catch (probe) {
          alive = (probe as NodeJS.ErrnoException).code === "EPERM";
        }
      }
      if (alive) {
        throw Object.assign(
          new Error(
            `vault_data_dir_in_use: ${dir} is open in process ${owner}. Run one local vault process at a time, ` +
              "or set DATABASE_URL so several processes share one Postgres database.",
          ),
          { code: "vault_data_dir_in_use" },
        );
      }
      rmSync(lockPath, { force: true });
    }
  }
  throw Object.assign(new Error("vault_data_dir_lock_failed"), { code: "vault_data_dir_lock_failed" });
}

/** `migrations/*.sql` (top level only), keyed by path. */
async function loadMigrations(): Promise<Record<string, string>> {
  if (underVite) {
    // Inlined by the bundler (no runtime fs). The glob does not descend, so the
    // opt-in auth schema under migrations/auth/ stays out.
    return import.meta.glob("/migrations/*.sql", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
  }
  // Plain node: read the same directory, same non-recursive scope.
  const { readdir, readFile } = await import("node:fs/promises");
  const { join, dirname, resolve } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const configured = process.env.ECHO_VAULT_MIGRATIONS_DIR?.trim();
  const dir = configured
    ? resolve(configured)
    : join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations");
  const out: Record<string, string> = {};
  for (const name of await readdir(dir)) {
    if (!name.endsWith(".sql")) continue;
    out[`/migrations/${name}`] = await readFile(join(dir, name), "utf8");
  }
  return out;
}

async function createPgliteSql(): Promise<Sql> {
  // Embedded Postgres, imported on demand so it never loads on the Neon path.
  // One instance per process, shared across HMR module instances, so data
  // survives source edits. In-memory under Vite; on disk under plain node or
  // whenever ECHO_VAULT_DATA_DIR is set (see pgliteDataDir).
  globalRef.__pgliteInstance__ ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const dataDir = await pgliteDataDir();
    if (dataDir) await lockDataDir(dataDir);
    const options = {
      parsers: {
        [OID_INT8]: Number,
        [OID_DATE]: identity,
        [OID_INTERVAL]: identity,
      },
    };
    const pg = dataDir ? new PGlite(dataDir, options) : new PGlite(options);
    await pg.waitReady;
    await pg.exec(
      "create table if not exists _migrations (name text primary key, applied_at timestamptz not null default now())",
    );
    return pg;
  })().catch((err) => {
    globalRef.__pgliteInstance__ = undefined;
    throw err;
  });
  const pg = await globalRef.__pgliteInstance__;

  // Apply migrations/ (the single schema source) so preview matches production.
  // Applied files are tracked in _migrations. Runs once per module instance
  // — so an HMR reload after adding a migration file applies it live — with
  // passes serialized on a global chain so concurrent callers never
  // double-apply.
  const migrate = async (): Promise<void> => {
    const migrations = await loadMigrations();
    const doneRows = await pg.query<{ name: string }>(
      "select name from _migrations",
    );
    const done = doneRows.rows.map((r) => r.name);
    for (const { name, path } of pendingMigrations(Object.keys(migrations), done)) {
      // Apply + record atomically (parity with scripts/migrate.mjs) so a failed
      // statement can't leave a file half-applied but untracked.
      await pg.transaction(async (tx) => {
        await tx.exec(migrations[path]);
        await tx.query("insert into _migrations (name) values ($1)", [name]);
      });
    }
  };
  const pass = (globalRef.__pgliteMigrateChain__ ?? Promise.resolve())
    .catch(() => undefined) // an earlier failed pass must not wedge the chain
    .then(migrate);
  globalRef.__pgliteMigrateChain__ = pass;
  await pass;

  return toSql(async <T>(text: string, params: unknown[]) => {
    const result = await pg.query<T>(text, params);
    return result.rows;
  });
}

let sqlPromise: Promise<Sql> | null = null;

async function createSql(): Promise<Sql> {
  if (typeof window !== "undefined") {
    throw new Error(
      "@/lib/db is server-only — call getSql() from a createServerFn handler " +
        "or a server route loader, never from client code.",
    );
  }
  return dbSource === "neon" ? createNeonSql() : createPgliteSql();
}

/**
 * Get the shared, **server-only** SQL client. Neon when `DATABASE_URL` is set,
 * otherwise the local PGLite fallback. Memoized — safe to call per request.
 *
 * Schema comes from `migrations/*.sql`, auto-applied before the first query on
 * both backends — define tables there, never inline in server functions.
 */
export function getSql(): Promise<Sql> {
  sqlPromise ??= createSql().catch((err) => {
    sqlPromise = null; // don't memoize failures — let the next call retry
    throw err;
  });
  return sqlPromise;
}

/**
 * The shared PGLite instance (preview only), with `migrations/*.sql` applied.
 * Lets Better Auth persist to the SAME embedded DB as app data in preview (via a
 * Kysely dialect). Throws when `DATABASE_URL` is set (that path uses Neon).
 */
export async function getPglite(): Promise<import("@electric-sql/pglite").PGlite> {
  if (dbSource !== "pglite") {
    throw new Error("getPglite() is only available on the PGLite fallback (no DATABASE_URL)");
  }
  await getSql();
  const pg = await globalRef.__pgliteInstance__;
  if (!pg) throw new Error("PGLite instance failed to initialize");
  return pg;
}

/**
 * Close the embedded PGLite (flushes its files). No-op on the Neon path or when
 * nothing was opened. Call before a plain-node process exits.
 */
export async function closeDb(): Promise<void> {
  const pending = globalRef.__pgliteInstance__;
  if (!pending) return;
  globalRef.__pgliteInstance__ = undefined;
  globalRef.__pgliteMigrateChain__ = undefined;
  sqlPromise = null;
  try {
    await (await pending).close();
  } catch {
    // already closed or never opened
  }
}

/**
 * Finish DB bootstrap before the server handles traffic.
 *
 * - **PGLite** (preview / no `DATABASE_URL`): open the embedded DB and apply
 *   `migrations/*.sql`. Idempotent — concurrent callers share one promise.
 * - **Neon**: no-op (pool is created lazily on first query).
 *
 * Vite `configureServer` awaits this at dev startup; production imports of this
 * module under Vite kick it off immediately (see bottom of file).
 */
export function ensureDbReady(): Promise<void> {
  if (dbSource !== "pglite") return Promise.resolve();
  return getSql().then(() => undefined);
}

// Server-only eager start: under Vite (dev server / built server bundle), kick
// PGLite bootstrap as soon as this module loads. Client bundles never hit this
// path (`getSql` throws in the browser). Under plain `node` nothing starts at
// import time: the first `getSql()` opens the database, and its failure reaches
// the caller that asked for it.
//
// The stored promise never rejects: a failed bootstrap is logged here and the
// next `getSql()` retries and surfaces the error itself. Rethrowing from this
// un-awaited promise would be an unhandled rejection, which kills the process.
const globalBoot = globalThis as typeof globalThis & {
  __pgBootstrapPromise__?: Promise<void>;
};
if (typeof window === "undefined" && dbSource === "pglite" && underVite) {
  globalBoot.__pgBootstrapPromise__ ??= ensureDbReady().catch((err) => {
    globalBoot.__pgBootstrapPromise__ = undefined;
    console.error("[db] PGLite bootstrap failed:", err);
  });
}
