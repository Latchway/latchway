# ADR 0018: Use deterministic route plans and per-attempt accounting

## Context

One client action is one logical request even when Latchway dispatches more
than one upstream attempt. Priority, weighted, and sticky route selection must
remain deterministic, while fallback and same-route retry may incur real
provider token and cost charges. The existing single-attempt lifecycle cannot
safely add retries: it finalizes the logical reservation with attempt one,
assumes every `Attempt` has number one, and has no durable allocation or
settlement record for later attempts.

HTTP request bodies are consumable streams, credentials are attempt-scoped,
and a response cannot be replaced after headers or bytes are committed to the
client. A transport failure may also be ambiguous: the provider can have
processed a request even when Latchway received no response.

## Decision

Latchway separates one immutable logical request from a bounded ordered route
plan and its contiguous upstream attempts.

### Route plan

- Evaluate access and route `when` expressions once against the sealed request
  facts and active configuration revision.
- Group matching routes by ascending numeric priority.
- Within each priority group, derive a deterministic weighted order without
  replacement. The seed is the feature plus the configured sticky key: logical
  request ID for `none`, internal application-user ID for `user`, and internal
  installation ID for `installation`. Route IDs provide the stable tie-break.
- The first entry is the primary route. Later entries are candidates only when
  the current route's configured `fallbackOn` set permits the typed outcome.
- A route may retry itself only under an explicit bounded retry policy. Same-
  route retries are exhausted before fallback when an outcome is configured
  for both. The total logical-request attempt count has a server-owned hard
  maximum independent of configuration.
- Route simulation and production dispatch use the same planner and expose the
  ordered candidates, conditions, models, accounting profiles, and warnings.

Selection inputs never include a client-supplied upstream, physical model,
price, route override, user ID, installation ID, or plan.

### Immutable request preparation

Each structured protocol adapter parses one bounded client body into an owned
immutable preparation. Rendering a route produces a fresh provider request
body with the server-selected physical model, output clamp, protocol headers,
and any trusted input-accounting proof. Every attempt receives a new reader
over those immutable bytes, a newly resolved protected destination, and newly
injected credentials. A consumed `http.Request.Body`, authorization header, or
provider request object is never reused.

Opaque HTTP bodies are replayable only when the configured route explicitly
permits buffering within its body bound. Unsafe opaque methods additionally
require an explicit idempotency policy; otherwise retry and fallback are
disabled for them.

### Attempt lifecycle and quotas

- Reserve the logical-request count and logical concurrency leases once.
- Before each dispatch, atomically create the next contiguous attempt and
  reserve that attempt's trusted token and maximum cost allocations against
  the same logical reservation.
- Record the attempt before provider dispatch. Mark the exact attempt as
  dispatched immediately before the transport can write upstream bytes.
- Settle each attempt independently from provider-reported, gateway-derived,
  or unknown usage. Unknown or ambiguous post-dispatch usage charges that
  attempt's conservative allocation.
- Keep logical concurrency leases open across the bounded attempt sequence and
  release them only when the logical request reaches a terminal state.
- Charge `logical_requests` once, `upstream_attempts` once per dispatch, and
  organization/user token and cost budgets for every actual or conservative
  billed attempt. Never reuse unused allocation from a different physical
  model without a new trusted preflight and reservation.
- If capacity for another attempt cannot be reserved, do not dispatch it. The
  logical request terminates with a safe quota or upstream error while all
  earlier attempt charges remain durable.

Reservation, attempt creation, attempt settlement, and logical finalization
are independently idempotent. Attempt numbers are contiguous and bounded; a
caller cannot skip, replace, reopen, or settle another attempt.

### Typed outcomes and response commitment

Fallback/retry conditions are evaluated from a closed internal outcome set,
not provider text. Initially this includes connect failure, timeout before
headers, HTTP 429, and explicitly configured 5xx statuses. Client cancellation,
policy or quota denial, malformed input, credential/configuration failure, and
protocol-observer failure are not retryable by default.

No retry or fallback occurs after client response commitment. Commitment means
Latchway has written response headers or any response-body byte. For a
configured retryable HTTP status, Latchway decides before relaying headers,
closes the prior response with bounded cleanup, settles the attempt, and only
then reserves the next attempt. Once a successful streaming response is
committed, later stream errors terminate that response and are never hidden by
another attempt.

Backoff is bounded, context-cancellable, and uses deterministic request-derived
jitter so tests are reproducible and replicas do not require shared timer
state. Each process also derives bounded `stale`, `closed`, `open`, and
`half_open` observations from dispatched attempt outcomes for telemetry. These
observations do not reorder candidates, suppress or admit a dispatch, reserve a
probe, or otherwise affect the deterministic plan in version 1. An
admission-affecting breaker would require an explicit configuration and
replica-consistency contract rather than being inferred from local telemetry.

## Alternatives

- Finalize one reservation and insert extra attempt rows afterward: permits
  token and cost overspend and loses atomic denial before retry dispatch.
- Charge every attempt as a new logical request: breaks user-facing request
  quotas and makes one action nondeterministically consume request allowance.
- Reuse the original `http.Request`: reuses consumed bodies and can leak stale
  attempt credentials or model rewrites.
- Retry after a partial stream: cannot restore HTTP semantics and can duplicate
  provider output or application side effects.
- Let each replica choose random weighted fallbacks: makes simulation, audit,
  replay, and incident reconstruction disagree.

## Consequences

The quota schema retains the immutable first-attempt reservation and adds a
per-attempt token/cost allocation ledger. Protocol adapters must expose
immutable preparation/rendering before heterogeneous-model fallback is safe.
The request explorer and usage views can distinguish one logical request from
all physical attempts and their individual usage confidence.

Circuit observations are process-local and can differ briefly between
replicas. They describe the state seen when an attempt acquired dispatch
ownership; they are not evidence that a route was blocked.

Fallback can legitimately stop because a second conservative reservation is
denied. Ambiguous post-dispatch failures may charge a failed attempt and a
successful fallback; this reflects potential infrastructure cost rather than
double-counting the logical request.

## Security implications

The design prevents replay after client commitment, body-reader reuse, stale
credential reuse, attempt-number substitution, unreserved retry cost, and
random replica-dependent routing. Protected destinations and header filtering
are re-applied for every attempt. Provider payloads never control retry class,
route identity, accounting bounds, or circuit keys. Bounded attempts, body
sizes, response cleanup, and backoff prevent retry amplification. Circuit
observation keys, cache size, failure counters, and time windows are separately
bounded to prevent telemetry state from causing unbounded memory growth.

## Migration implications

The first implementation adds a forward-only database migration for immutable
initial reservation units and per-attempt quota entries. Existing schema-11
requests have exactly one attempt and can be backfilled without changing their
settled totals or provenance. An upgrade fails rather than guessing if legacy
data contains an impossible multi-attempt logical request.

Adding retry-policy configuration, immutable adapter preparation, and route-
simulation output changes the operator contract and requires a later contract
bundle version. Client DPoP/session wire protocol can remain version `1` because
the data-plane endpoint and authorization shape do not change.

## Status

Accepted on 2026-08-28 and implemented and locally validated for contract
`0.5.1` and wire protocol `1` on 2026-08-29. Priority, deterministic weighted
and sticky selection, bounded same-route retry, configured fallback,
per-attempt accounting, immutable request rendering, and response-commitment
guards are executable only through the closed policies described above. The
per-process circuit observation lifecycle is telemetry-only and does not alter
those routing decisions. Their
normal, adversarial, PostgreSQL, race, and conformance tests pass, and the
complete corrected-target local load suite passed at source checkpoint
`00197f916cd50803093a5e73bbac725e97c394e3`. Live-provider and
exact-release-image observations remain separate release evidence and are not
implied by this ADR status.
