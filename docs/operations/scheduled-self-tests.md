# Scheduled self-tests

Scheduled self-tests run the same bounded credential-aware upstream or
OpenRouter diagnostics as the Admin API without turning a browser session into
background authority. They are intended for low-frequency production canaries,
not traffic generation.

## Create and review

Create an active, revocable Admin API token owned by the operator who will own
the schedule and scope it to `run_self_tests`. Then use either the CLI or the
console Self-tests page. The CLI reads the token from the selected environment
variable. The console accepts it in a password input for one bearer request,
omits the browser cookie, and clears the input immediately. Neither interface
puts token plaintext in the JSON document.

```bash
export LATCHWAY_ADMIN_API_TOKEN='value-from-a-secret-manager'
latchway verify schedule create \
  --environment env_... --kind upstream \
  --upstream primary --model canary \
  --interval-seconds 3600 \
  --max-cost-nano-usd 10000000 \
  --daily-cost-limit-nano-usd 240000000
latchway verify schedule list --environment env_...
latchway verify schedule get sts_...
```

Review the returned schedule ID, environment/application IDs, pinned
configuration revision, authorization credential ID, target, cadence, and both
cost ceilings. Provider secret values are never returned. Creation is rejected
unless the configured trusted-input profile and pricing prove the diagnostic's
worst-case cost before any dispatch.

## Frequency and cost controls

- Cadence is 3,600–2,592,000 seconds (one hour through 30 days).
- The per-run ceiling is 1–1,000,000,000 nano-USD.
- The UTC-day ceiling is at most 10,000,000,000 nano-USD and must cover every
  theoretical run at the configured cadence and per-run maximum.
- An organization may have at most 32 active schedules and one active schedule
  per environment/kind/upstream/model tuple.
- Overdue periods coalesce into one job. The scheduler does not create a
  catch-up burst after downtime.
- PostgreSQL row locks serialize per-schedule daily reservations across worker
  replicas. A rejected or failed dispatch retains its conservative reservation.

## Fail-closed bindings and recovery

Creation binds the exact active configuration revision, every current provider
secret record ID/version, and the authenticating durable API-token ID and
administrator. Before every run the worker revalidates the organization,
application, environment, active membership and role, token scope/expiry/
revocation, active revision, and secret versions. It never silently substitutes
a new token, revision, key, target, or tenant scope.

Authorization loss, configuration replacement, and secret rotation create a
redaction-safe failed self-test and automatically disable future runs with
reason `authorization`, `active_configuration`, or `credential_binding`.
Exhausted daily budget records `budget` but leaves the schedule active for the
next UTC day. Operators can permanently soft-disable a schedule while keeping
its audit/run history:

```bash
latchway verify schedule disable sts_...
```

Each job commits a durable `dispatching` marker before provider access. If a
worker is recovered after that point, Latchway records `execution_recovery`
and does not repeat the ambiguous provider request. A completed job can be
claimed again safely without another dispatch.

## Operations and observability

Run at least one worker replica and keep worker heartbeat readiness healthy.
The normal worker job duration/count telemetry includes
`run_scheduled_self_test`; `latchway_scheduled_self_tests_total` reports the
bounded outcomes `passed`, `failed`, `rejected`, and `recovered` by application
and environment. Audit events use system actors for automatic runs/disables and
the authenticated administrator or API-token actor for create/disable
mutations. Results contain fixed check names and stable safe details only—no
token, secret, prompt, provider response, provider URL, or raw error body.
