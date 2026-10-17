# Private operator certification scope

`.echo/apps.json` opts this exact repository candidate into Certification Forge.
`.echo/certification.json` runs `scripts/certforge_operator_journey.py` with a
bounded Python entrypoint. The existing runtime repository's full journey is
unchanged. This candidate is new: earlier broker SHA4c91 is not certified by it.

This journey proves only the private SDK-operator unit/security contract: 44
synthetic-credential route tests and one bounded YAML security regression. It
checks disabled deployment defaults and the private-operation public-dispatch
prohibition, as well as the lock and installed dependency versions. It does not
certify the unrelated UI, production host, signer, vault, real SQL/approval/TOTP,
installed mods, QA4-7 or rollback. No live credentials or production CLI are used.

The owner-admitted offline image must include Node22.12+ and the reviewed locked
`jose`6.2.9, `js-yaml`4.3.2 and `argparse`2.0.1 dependency bundle. No npm, migration,
download, Docker socket, network or install command runs in the journey. The local
Node-enabled QUENCH source environment passes44+1; that is not a hosted certificate.
The default owner runner source is Python3.12 Alpine only with network disabled.
It must honestly fail `node_runtime_missing` until a Node-enabled image/profile is
admitted and its new environment/image identity is pinned. A package version check
does not prove the integrity or release custody of an offline dependency bundle.

Live CertForge projects discovered for exact binding:

- Broker: `prj_141a0c3a7a62270c469c65c7`.
- Runtime/ledger: `prj_e96e342f7b8c95635ce43490`.
- Organization: `org-echo-sovereign`.

The current Certification Forge GitHub App uses a global project setting; its
public health/diagnostics do not establish the configured tenant/project/policy/
environment. An authenticated metadata-only owner readback and correct per-repo
project resolution are still needed. Do not dump its environment, submit against
a guessed project, create a fake signature or use a predicted run ID as a receipt.

The actual SAB owner request `apr_ba8939632cfc407a` was pending on creation; the
notification result was dry-run/not delivered. That baseline request names4c91
and8b1; source changes require refreshed exact-candidate binding before execution.
It is not an approval, grant or deployment authorization. Private config remains
DISABLED, and exact-request SDK approval/TOTP remains enforced independently.
