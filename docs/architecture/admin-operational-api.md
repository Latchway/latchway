# Administrative operational views

The canonical Admin API exposes tenant-scoped operational state without
returning provider credentials, identity subjects, bearer or refresh tokens,
DPoP proofs, attestation evidence, or request bodies. The embedded console and
CLI must consume these HTTP resources rather than querying PostgreSQL.

## Authorization and tenancy

- User, installation, request, usage, and audit reads require the
  `inspect_users` capability. A scoped API token must include it even when the
  administrator's membership role would otherwise allow the read.
- User block/unblock and installation revocation require
  `revoke_installations`. Blocking suspends future sessions and revokes current
  grants and refresh tokens; unblocking never restores revoked credentials.
- Local and credential-aware self-tests require `run_self_tests`. Creating a
  persistent schedule additionally requires bearer authentication by the
  exact durable API token that will authorize later runs; a browser session
  cannot create or substitute that authority.
- Every lookup derives the organization from the authenticated principal.
  Supplied organization filters must exactly match that organization, and
  cross-tenant identifiers are reported as not found or denied.

Cookie-authenticated mutations retain the Admin API's strict Origin and CSRF
checks. Successful user status changes, installation revocations, and
self-tests write a value-free audit summary in the same transaction. An
ambiguous commit returns `operation_indeterminate` with the operation ID used
by the potentially committed audit event.

## Bounded query behavior

The users, installations, requests, and audit collections use opaque keyset
cursors and return at most 200 records. Duplicate or unknown query parameters
are rejected. User claims are limited to 64 top-level fields and 64 KiB of
encoded JSON; at most 64 distinct identity-provider identifiers are returned.
Each request contains at most the schema-enforced 32 upstream attempts, and
at most 256 immutable decision stages; usage rows are aggregated in PostgreSQL
before their bounded result is decoded. Request lists support exact status,
feature, user, platform, component kind, trust source, route, upstream, model,
public error code, request ID, half-open time range, latency, token, and integer
nano-USD cost filters. Start time has deterministic ascending or descending
keyset order. Empty, duplicate, unregistered, reversed, or negative filter
values fail closed rather than silently broadening a query.

Usage summary ranges are half-open (`start <= recorded_at < end`) and limited
to 366 days. Timeseries data uses UTC hour or UTC day buckets and rejects a
range that would emit more than 10,000 points. Token and cost values come from
the immutable usage ledger; multi-attempt usage is summed while the logical
request record remains single-counted. The request explorer returns metadata
and the exact configuration revision, selected limit plan, first selected
route/upstream/model tuple, terminal public failure code, and contiguous
decision stages ordered by `number` (1–256). A logical row is created only
after both access-token and request-bound DPoP authorization succeed, but before
client-context validation, configuration loading, request inspection, policy,
routing, or quota reservation. Consequently every post-auth denial remains
durable even if quota was never reserved. Stage provenance is restricted to
closed stage/outcome names, stable problem codes, bounded policy and quota-rule
keys, integer limit values, selected route identifiers, the immutable revision,
and start/completion timing. It has no arbitrary detail or payload field and is
append-only while the request is retained; deleting the parent through a future
retention policy deletes its stages atomically. The minute-scheduled,
multi-replica-safe `recover_stale_authenticated_requests` job locks bounded
batches whose pre-reservation lifecycle has remained `authenticated` for 24
hours, appends a terminal `lifecycle_recovered` / `internal_error` stage, and
marks the logical request failed. This closes rows abandoned by a transient
stage-persistence failure without guessing which dependency operation ran.

Physical attempts remain ordered by `attempt_number` (1–32). Each
attempt includes its canonical route and upstream, physical model,
start/optional-first-byte/optional-first-token/optional-completion times,
optional upstream HTTP status, public lifecycle status, normalized usage, and
separate token-usage and cost provenance. The read path rejects gaps,
impossible lifecycle combinations, and timestamps outside
`started_at <= first_byte_at <= first_token_at <= completed_at` when a token was
observed. `first_token_at` remains absent for lifecycle-only, opaque, and
historical attempts; it is never inferred from `first_byte_at`. The API does
not partially return a corrupt request.

Logical and decision-stage failures expose registered problem codes, collapsing
unrecognized durable values to `unknown`. Attempt failures use the closed public
vocabulary `canceled`, `gateway_error`,
`protocol_error`, `timeout`, `unavailable`, `upstream_rejected`, and `unknown`.
Known internal lifecycle codes map into those categories; every unrecognized or
legacy internal value collapses to `unknown`. Raw provider bodies, provider
error text, internal errors, request/response bodies, and identity subjects are
never returned. Provider-reported cost exposes the fixed bounded source
`openrouter_usage_cost`; the attempt's configured catalog binding remains
distinct for reservation replay.

The rich summary limits each feature, physical-model, and selected-limit-plan
breakdown to an operator-selected 1–200 rows and reports truncation. It returns
active-user and logical-request counts, exact rational requests/cost per active
user, integer-millisecond p50/p95/p99 request latency and time to first token,
and integer parts-per-million failure, quota-denial, attestation-failure, and
fallback rates. Estimated, calculated, provider-reported, and unknown ledgers
remain separate. A provenance breakdown that contains provider-reported cost
also names its fixed report source. No user identifier is emitted as a
time-series or breakdown label. Historical requests whose plan predates persisted selection are labeled
`legacy_unknown`; the migration never guesses a past CEL result.

Audit lists accept exact actor kind/ID, action, resource type/ID, environment,
descriptive source, stable reason code, outcome, and half-open occurrence-time
filters. The detail endpoint returns the same tenant-scoped immutable event.
Events expose actor and target opaque IDs plus ordered field, operation,
classification, and redaction markers. They do not expose before/after values
or free-form mutation reasons. Console source is derived from authenticated
session transport and system source is server-owned. CLI versus API is a
bounded claim by an authenticated API token; it is descriptive and never an
authorization, authentication, or trust input.

## Self-tests and system status

`POST /admin/v1/self-tests` executes three durable diagnostics. `local` checks
PostgreSQL transaction availability, migration compatibility, and presence of
an active compiled environment configuration. `upstream` and `openrouter`
resolve one upstream and model from that active immutable snapshot. They accept
only configured identifiers, never an arbitrary URL or credential.

Credential-aware runs require a supported Responses, Chat, Embeddings, or
Anthropic Messages capability, an exact model-bound trusted-input profile, an
active configured USD price, and a positive operator cost ceiling. Responses,
Chat, and Anthropic rewrite one streaming and one non-streaming request to a
one-token output maximum. Anthropic also installs and forwards the adapter-owned
canonical version header. Embeddings rewrites exactly one non-streaming request
with a zero generated-output bound; its streaming and output-clamp checks are
recorded as skipped. The runner computes the complete protocol-specific price
before target acquisition and refuses dispatch when it cannot prove the ceiling.
Each request re-enters the encrypted secret callback and shared protected target
cache. Reported input/output/total usage, applicable final SSE usage and output
clamp, and configured cost are checked against the pre-dispatch bounds. The
OpenRouter variant remains Chat-only and additionally validates the canonical
HTTPS target, key information and available access. Every protocol runs a
malformed-request probe whose body is consumed but never exposed.

Completed redaction-safe results are stored in the jobs ledger and can be
retrieved after a restart. The result contains only fixed check names and safe
details: no provider credential, prompt, response, URL, raw dependency error,
or provider error body. A completed diagnostic has terminal `passed` or
`failed` state; a failed check is never presented as a successful verification.

Credential-aware runs can also be scheduled through
`/admin/v1/self-test-schedules`. Creation pins the exact active configuration
revision, current provider-secret record IDs and versions, tenant target,
per-run and UTC-day cost ceilings, cadence, administrator, and authenticating
Admin API-token ID. Token plaintext and provider secret material are never
persisted. The server rejects browser-session creation even if a token ID is
supplied; the console's create form sends a transient bearer with cookies
omitted and clears its password field immediately. List, detail, and disable
remain capability-gated redaction-safe operations.

The worker revalidates the token, active membership, tenant resources, pinned
configuration, and every secret version before each run. Revocation, revision
replacement, or secret rotation fails closed and disables the schedule rather
than rebinding. Cadences range from one hour through 30 days, missed intervals
coalesce to one run, and row locks plus a daily reservation ledger prevent
replicas from exceeding the cost ceiling. A durable marker is committed before
provider dispatch; recovery after that marker records the fixed
`execution_recovery` failure and never repeats an ambiguous provider request.
See [Scheduled self-tests](../operations/scheduled-self-tests.md).

`GET /admin/v1/system` reports build version, contract and protocol versions,
the configured process role, current migration version, and a readiness bit.
Dependency errors are reduced to `ready: false`; endpoint output does not
include database addresses or error text.

`GET /admin/v1/system/doctor` returns the canonical structured report also used
by `latchway doctor` and the Console Health center. Fixed checks cover database
and migration state, active configuration, key availability and rotation,
master-key consistency, external JWKS state, worker replicas, durable jobs,
scheduled connection checks, quota cleanup, clock skew, storage visibility,
pool saturation, and SDK contract metadata. Dependency errors collapse into
fixed summaries and remediation text.

`GET /admin/v1/system/support-bundle` wraps that report in a versioned,
structurally allowlisted JSON document. It does not traverse arbitrary runtime
objects or database rows and therefore has no supported field for credentials,
tokens, cookies, authorization headers, DPoP proofs, the master key, provider
secrets, attestation evidence, or request/response content.
