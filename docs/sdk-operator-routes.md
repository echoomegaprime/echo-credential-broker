# Private SDK action-review and factor-use routes

Status: implemented source; **disabled and not installed/admitted**. These are
private-process routes, not new public REST/MCP tools and not a second vault.
Existing GS343/Sentinel observation-only adapters and Steward charter are unchanged.

## Entry points

`scripts/sdk-operator.ts review <job-uuid>` verifies a root-owned, owner-signed
job and returns admission metadata only. It does not resolve a credential,
claim a job, execute commands or assert fresh state/approval.

`scripts/sdk-operator.ts execute <job-uuid>` consumes the same exact job once,
uses the configured actor's SDK credential inside the process, verifies the
signed fresh-state precondition, signs through the installed SOL wire contract,
and sends one mutation to the SDK gate. It never returns an upstream body.

Implementation: `src/lib/vault/sdk-operator.ts`. Tests:
`src/lib/vault/sdk-operator.test.ts`. The public dispatcher explicitly forbids
`sdk_action_review` and `sdk_operator_execute`; an approved caller-name header
is not authentication for these operations. Public provider policies, private-IP
SSRF guards and generic credential-use behavior are not relaxed.

## Bounded action catalog

| Action | Behavior |
|---|---|
| `gs343.fixture.execute` | One fixed parameterized INSERT into `arcanum_sdk.gs343_diagnoses`, real `source_node=quench`, reserved QA marker in both error text and source path. No fix execution. |
| `gs343.fixture.cleanup` | One fixed DELETE bound to exact BIGINT ID, signature, QUENCH and both QA markers. No blanket cleanup. |
| `certforge.submit` | One request bound to exact SHA and canonical `echoomegaprime/echo-omnipresence-runtime.git@SHA` acquisition identity. |
| `gs343.acceptance.install` / `rollback` | Review-only target/file/preimage manifest. Cannot execute installation, rollback or any shell command. |

Fixture SQL uses the live table's actual `source_node` column (not `node`) and
positive decimal BIGINT IDs, preserving values beyond JavaScript's safe integer
range. No live fixture or cleanup has been performed by this source build.

The fixture state probe checks the current SDK capability contract, **not** the
table's contents, fixture existence, mod installation or error quiet window.
Certification checks a digest of fresh service-status readback, not a certificate.
Installation review does not establish that target state has been observed.

## Admission and existing gates

Reuse of `jose` Ed25519 verification follows this repository's existing identity
verifier pattern. The Echo job has its own explicit owner-pinned issuer, audience
`echo-sdk-operator/v1`, key ID and `echo-sdk-job+jwt` purpose. No Grok login key,
header identity or self-generated key is accepted as authority.

The signed job binds actor, existing mission, exact configured SDK credential
SHA-256, candidate SHA, action, capability, full parameters, fresh-state probe
and expected digest, risk-review fields, idempotency key, UUID jti, iat and exp.
Lifetime is at most 90 seconds. Request JSON is deliberately restricted to the
ASCII / safe-integer subset that exactly matches the installed Python SDK's
sorted compact serialization; unsupported Unicode/floats fail closed.

The issuer's mission admission is an assertion by that configured authority,
not a direct validation against QUENCH's SOL database. Actual server-side SDK
key scope remains enforced on every call. There is no fallback to the broker's
general API key as the mutation principal. Its vault transport credential is
used only by the existing approved `GateVaultBackend`.

TOTP is located by the existing exact service `echo-sdk-tier3-totp`, username
`sovereign`, and used only in-process. Seed format must be RFC6238 Base32;
unexpected format fails closed. HMAC resolution uses the same exact-key scoped
read and signing form as installed `sol_sdk.py`. Neither code nor seed nor HMAC
is accepted in argv, returned, printed, or saved to a job/claim/log.

**This admission does not replace the Commander's existing RiskGate policy or
the SDK server's separate exact-parameter human approval.** No legacy config,
confirmation token, new trust key, scope or approval has been manufactured.
Owner admission of this new route and its trust root is still required.

## One-use and evidence semantics

Before any vault resolution, two issuer-bound exclusive-create tombstones are
written and fsynced: jti and idempotency key. Concurrent workers and fresh
processes cannot reuse them. Root owns the store; the ordinary agent/forge UID
cannot erase tombstones. Partial/ambiguous claim failures return `consumed:null`,
not a false claim of reusability. Tombstones are never automatically deleted.
This is one-use for this route, not universal exactly-once SQL execution.

There is exactly one mutation POST. Redirects are errors, response reads and
deadlines are bounded. Failure, missing approval, timeout or ambiguous outcome
does not trigger a retry. A real approval refusal consumes this job: inspect
authoritative pending approval read-only, obtain the real owner decision, then
have the issuer create a newly admitted job if appropriate. Do not reset claims.

Results contain typed status/HTTP/run UUID metadata, `execution_verified:false`,
body-withheld and audit status. Read back actual rows/certification through
normal scoped read routes before reporting success. Audit failure is visible
and makes the CLI fail without retrying the mutation. Python/JavaScript strings
and runtime memory cannot be guaranteed zeroized; no such claim is made.

## Protected host deployment boundary

The CLI deliberately refuses Windows, non-root execution, caller-supplied config
paths, and source checkouts outside `/opt/echo-credential-broker-operator/<SHA>`.
It has no setuid launcher, public listener, sudo grant, or newly granted SDK cap.

The operator-controlled fixed paths are:

- `/etc/echo/credential-broker/sdk-operator.json`: root-owned, not group/world writable.
- `/etc/echo/credential-broker/sdk-operator-jobs/<uuid>.jwt`: same controls; signed job is a protected admission credential, not model input.
- `/var/lib/echo-credential-broker/sdk-operator/claims`: root-owned 0700; parents root-owned and not group/world writable.

`sdk-operator-config.DISABLED.json` is a non-authorizing template. Required actual
issuer/key and scoped principal credential coordinates are intentionally absent.
Do not copy a general-purpose sovereign key into this mapping or generate a key
and call it owner admission. Do not request factors or private signing keys in chat.

`echo-sdk-operator@.service.template` is staged only. Owner deployment must bind
the independently certified exact broker SHA, verify root ownership/integrity
of **the entire code/dependency tree and Node executable**, sanitize preload/
proxy environment, and preserve a known-good previous unit/artifact. It must
not delegate arbitrary Node/shell execution. The unit pins vault and mutation
transport to FORGE loopback. No unit, credential environment file, configuration,
job issuer or service-control allowlist has been installed by this build.

After actual owner admission, the existing governed service-control SDK may
start the exact template job only if that unit is already explicitly allowlisted
and current mission scope permits it. An absent allowlist is not permission to
route around it. This source does not register or grant that operation.

Activation still requires exact-SHA release evidence and the real owner trust/
principal configuration. QA4–6 and installed-mod QA7 remain separate live tests.
No Steward training is started and no proposed fix becomes outcome-verified
because a private route, mocked test or command exit was successful.
