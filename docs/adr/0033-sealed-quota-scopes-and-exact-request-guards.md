# ADR 0033: Seal quota scope facts and measure request-local guards exactly

> Renumbering note: this decision was originally ADR 0021. It was renumbered
> without changing its scope when the Installation Family addendum reserved
> ADRs 0017 through 0028.

## Context

Quota scope identity is security-sensitive. A client-controlled platform, plan,
or claim value could move an otherwise identical request into a fresh bucket.
Likewise, request-byte, image, and tool-call limits cannot be hard limits when
their units are estimated, counted before server rewrites, or accepted from a
header or administrative simulation.

The selected limit-plan identifier already participates implicitly in every
rule and logical-request fingerprint. Exposing it again as an optional scope
dimension would create two representations of the same policy decision and
make accidental omission possible.

## Decision

Configuration contract `0.5.1` has one canonical quota-scope vocabulary:

```text
organization, application, environment, user, installation, feature,
route, upstream, model, platform, normalized_claim:<name>
```

Fixed dimensions appear in that order and at most one explicit normalized
claim selector may appear, last. `limit_plan` is intentionally not a scope
dimension: the server-selected plan remains an implicit, mandatory part of
bucket and request identity.

Production `platform` comes only from the validated session authorization.
For a configured `normalized_claim:<name>` selector, policy reads only that
top-level value from the sealed, bounded normalized-claim map. Missing is a
real value, not an inapplicable rule: it receives a distinct
domain-separated digest. Present values use the identity grammar (valid UTF-8,
NUL-free bounded strings; booleans; narrowly canonical bounded decimal
`json.Number` values; or a bounded array of those scalars). Canonical numbers
exclude exponent notation, leading integer zeroes, trailing fractional zeroes,
and negative zero, so semantically equal spellings cannot split a quota scope.
Maps, nested arrays, null, native floating point/integer values, and invalid
encodings fail closed.

Only the selector name and an opaque SHA-256-derived identity cross from
policy to quota. Raw normalized claim values never enter bucket keys, request
fingerprints, attempts, snapshots, usage, or quota API results. PostgreSQL
independently enforces the same canonical dimension order.

Hard `request_bytes`, `image_units`, and `tool_calls` limits use only the
`per_request` algorithm. They are evaluated atomically with all other
applicable hard rules but create no durable quota bucket or reservation entry.
Every attempt persists a versioned proof containing the SHA-256 and byte
length of the exact post-rewrite body plus the exact structured counts. Retry,
replay, and recovery require the same proof. The body is read, owned, rebound,
and hashed after feature/model/output rewriting and again immediately before
attempt ownership and target acquisition; same-length substitution fails
before dispatch.

The structured v1 adapters count:

- OpenAI Chat: `image_url` content parts and assistant `tool_calls` entries
  (or one legacy `function_call`);
- Anthropic Messages: image blocks, including images inside `tool_result`
  content, and assistant `tool_use` blocks;
- OpenAI Responses: its executable grammar has zero images and counts local
  `function_call` and `custom_tool_call` input items;
- OpenAI Embeddings: exact zero images and tool calls;
- opaque HTTP: exact request bytes only. Image and tool counts are unknowable,
  so either structured guard makes the selected route ineligible.

The administrative route simulator accepts bounded hypothetical byte/image/
tool facts and passes them through the production projection helpers. Those
facts affect only the displayed reservation; they do not alter CEL and never
create state.

## Alternatives

- Accept a client byte count or content digest: permits under-reporting and
  body substitution.
- Count the body before server rewrites: does not bind what is dispatched.
- Treat a missing claim as a non-applicable rule: permits quota bypass by
  omitting a normalized claim.
- Store raw normalized claims in quota keys: leaks sensitive identity data and
  expands operational views beyond their purpose.
- Interpret opaque request bodies heuristically: converts an unknown
  structured count into a bypassable estimate.

## Consequences

Per-request guards deny above-bound requests without creating a bucket,
reservation, or attempt. Within-bound and exact-zero requests retain the
durable logical request/attempt lifecycle needed for idempotency, audit,
retry, and recovery. Scope identities remain stable across replicas and do not
reveal selected claim values.

Adding a new structured request grammar or changing the meaning of an image or
tool-call unit requires a versioned protocol/contract decision and matching
adapter, replay, PostgreSQL, simulator, and adversarial evidence.

## Security implications

Sealed platform and normalized-claim inputs prevent clients from selecting a
fresh quota namespace. Domain-separated claim digests keep raw identity facts
out of operational records while distinguishing missing from present values.
Post-rewrite hashing and exact structured measurements prevent same-length body
substitution, pre-rewrite undercounting, and fabricated request-local units;
unsupported opaque measurements fail closed instead of becoming estimates.

## Migration implications

Database schema `18` extends the closed scope vocabulary and adds the versioned
attempt request-measurement binding. Existing buckets and schema-17 attempt
rows are not rewritten. New attempts use decision-binding version `2`; legacy
version `1` rows remain readable with measurement-binding version `0`.

## Status

Accepted for configuration contract `0.5.1` and wire version `1` on
2026-08-29.

The decision was renumbered from ADR 0021 to ADR 0033 on 2026-08-30. Its
implementation and historical evidence remain unchanged; the component-aware
scope extension is a separate pending contract decision.
