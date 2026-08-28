# ADR 0017: Require trusted preflight bounds for input-token budgets

## Context

Hard input- and total-token limits must reserve enough capacity before an
upstream request is dispatched. A request-body byte heuristic is not a
conservative token bound: physical-model selection and provider request
rewriting happen later, tokenization varies by model, and remote files,
images, audio, tools, or provider extensions can add billable input that is
not bounded by the JSON body size. Provider-reported usage arrives after
dispatch and therefore cannot prevent concurrent overspend.

The quota database and usage schema are already metric-generic. They can
durably reserve, settle, release, recover, and project calendar buckets for
new token metrics without making an unsafe adapter estimate authoritative.

## Decision

Production activation of hard `input_tokens` and `total_tokens` limits
requires a server-trusted, conservative input-token bound tied to the exact
rewritten provider request and selected physical model. The bound must be
produced after route and model resolution and before dispatch. Client model
names, client counters, request-body heuristics, and post-dispatch provider
usage are not trusted preflight bounds.

For a request with trusted input bound `I` and exact server-applied output cap
`O`:

- every applicable `input_tokens` rule reserves the same `I`;
- every applicable `total_tokens` rule reserves the same checked sum `I + O`;
- both values are bound into the trusted request fingerprint;
- known successful provider usage refunds only the unused reservation;
- failed, cancelled, timed-out, unknown, and dispatched-expiry outcomes retain
  the full reservation;
- a pre-dispatch release or undispatched expiry refunds the full reservation;
- normalized known usage is accepted only when the overflow-safe invariant
  `total_tokens = input_tokens + output_tokens` holds.

The initial storage slice registers only hard UTC-calendar lifecycle and
snapshot behavior for these metrics. Configuration compilation and the data
plane continue to reject them until an adapter supplies the required trusted
preflight result. Input/total token buckets and per-request limits remain
unsupported until their capacity, impossible-request, and recovery semantics
are specified and implemented.

## Alternatives

- Reserve the existing JSON-byte estimate: permits overspend for model-specific
  tokenization, rewritten requests, and externally referenced multimodal
  content.
- Charge only provider-reported usage after dispatch: permits concurrent hard
  limit overspend and weakens disconnect abuse handling.
- Reserve an arbitrary global multiplier: has no proven upper bound across
  configured providers and models.
- Reject all future input/total accounting work until tokenizer support exists:
  unnecessarily couples generic durable quota lifecycle work to one adapter.

## Consequences

Quota lifecycle and snapshot primitives can be tested independently while the
production capability gate remains fail closed. A future adapter capability
must distinguish a proven preflight bound from an estimate and identify the
selected model/accounting profile that justifies it. Activating such a
capability may require a versioned configuration contract for tokenizer or
provider-counting declarations.

## Security implications

Bounds and `I + O` use checked non-negative integer arithmetic. Reservation
values are server-owned, uniform across rules of one metric, fingerprinted,
and recovered from durable state. Unknown post-dispatch usage is charged
conservatively, so disconnects cannot create a quota bypass. Configuration
must consider every plan reachable through administrator-owned user overrides
when validating adapter support.

## Migration implications

No database migration or client wire change is required for dormant calendar
lifecycle support because existing bucket, reservation-entry, usage, and
snapshot representations are metric-generic. A future public tokenizer,
accounting-profile, or restricted-request-subset configuration requires an
explicit contract-version decision. Input/total per-request support may need a
schema change so entryless reservations retain enough information for crash
recovery.

## Status

Accepted for version 1 on 2026-08-28.
