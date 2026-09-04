# Troubleshooting

## `/readyz` returns 503

Readiness checks the database, migration version, active configuration, the
reserved quota-completion pool, master/signing-key availability, and the worker
heartbeat when the selected process role requires one. A
`quota_completion_pool: unavailable` result means the distinct terminal-write
pool could not accept its bounded probe; inspect PostgreSQL connectivity and
settlement pressure before adding traffic. Run:

```bash
latchway doctor
latchway migrate status
docker compose logs --no-log-prefix latchway
```

Do not paste logs containing deployment secrets into an issue. Latchway's
normal logging path redacts known credential fields, but surrounding platform
logs may not.

## The first-owner form is closed

Bootstrap is intentionally one-time. After any owner exists, leaving
`LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` in the environment cannot reopen it. An active
owner can create another administrator or reset a local password through the
Admin API/CLI. If every owner credential is lost, use the documented
operator-controlled recovery procedure and database backup; do not modify rows
ad hoc.

## A configuration revision will not activate

Run validation and plan against the exact draft and strong ETag:

```bash
latchway config validate rev_...
latchway config plan rev_...
latchway config diff rev_...
```

Typical failures are a stale ETag, missing reference, unsupported
protocol/model capability, impossible input-accounting context, overlapping
private destination policy, secret tombstone, or an active user override that
the new revision would strand. Fix the draft or create a new one; never edit an
activated revision.

## `attestation_invalid` or `attestation_required`

Confirm that the SDK application resource ID, environment, public gateway
origin, platform, bundle/package identifier, signing identity, and cloud
project match the active server policy. App Attest requires a physical Apple
device and entitlement. Its exact validation category must match the signed
executable (`3` development, `2` TestFlight, `4` App Store, or `5` ad
hoc/enterprise), and its bundle-version allowlist must contain the exact
`CFBundleVersion`/`CURRENT_PROJECT_VERSION`, not the marketing version.
Production Play Integrity requires the exact signed app installed from the
configured Play track. A simulator, emulator, or sideloaded APK cannot satisfy
those release policies.

Check the redaction-safe installation, attestation-failure, and audit views.
Raw evidence is intentionally unavailable after verification.
For App Attest, use `latchway_app_attest_verifier_failures_total` to separate
bounded verifier phases such as `assertion_object`, `assertion_scope`,
`assertion_counter`, `assertion_signature`, and `key_store`. The client still
receives only the generic problem code; the metric never contains evidence,
credential or installation identifiers, counters, bundle metadata, or error
text.

## `dpop_invalid`, `dpop_replayed`, or `dpop_nonce_required`

Do not construct DPoP manually in application code. Use the platform SDK and
ensure redirects are disabled. A proof is single-use and bound to one exact
method, public URL, access-token hash, and optional server nonce. SDKs retry at
most once only for a canonical pre-dispatch problem and never replay a streamed
or non-replayable body.

## `quota_exceeded` or `output_limit_exceeded`

Inspect the quota snapshot and exact route simulation:

```bash
latchway usage summary --environment env_...
latchway routes simulate rev_... --feature FEATURE \
  --platform react_native_ios --trust-level app_verified \
  --claims-file claims.json
```

The client cannot override a limit or trusted server input bound. For structured
protocols, unsupported rich input fails closed when hard input/total or
input-priced cost enforcement needs a conservative proof. Unknown provider
usage is charged conservatively rather than refunded.

## `upstream_unavailable` or `upstream_timeout`

Run the server-side self-test, then inspect ordered request attempts:

```bash
latchway verify upstream --server-owned \
  --environment env_... --upstream UPSTREAM --model MODEL
latchway requests inspect req_...
```

Check protected DNS/address policy, credential metadata, provider capability,
route fallback conditions, request bounds, and the distinct connect,
response-header, first-byte, idle, and total timeouts. Latchway does not follow
upstream redirects and does not retry after response commitment.

## A secret cannot be rotated or deleted

Secret IDs are version-specific. Refresh metadata before rotating. Deletion is
permanent, tombstones the logical name, and is rejected while any active or
rollback-eligible revision references the secret. A lost database commit
acknowledgement returns `operation_indeterminate`; reconcile its operation ID
in the audit log before repeating a non-idempotent mutation.

## A deployment or release check says `unavailable`

`unavailable` is a deliberate failed evidence gate, not a warning that can be
overridden. Supply the exact candidate's protected live-provider, physical
device, cloud, resilience, supply-chain, tag, or registry receipt and rerun the
fixed workflow. Local tests cannot manufacture external release evidence.

## Upgrade or restore fails

Stop promotion, preserve the database and evidence, and follow
`docs/operations/upgrades.md` or `docs/operations/backup-restore.md`. Migrations
are forward-only. Restore into an isolated database, validate the master key,
run `doctor`, and verify the previous released image before changing production
traffic.
