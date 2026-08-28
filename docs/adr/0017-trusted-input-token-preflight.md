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

Contract `0.4.0` activates one deliberately narrow method,
`utf8_byte_bpe_declared_framing_v1`, for OpenAI Chat. It is valid only when all
of the following conditions hold:

- the operator declares an immutable profile for the exact `openai_chat`
  protocol and exact physical model, including non-negative maximum framing
  tokens per request and per message and a positive context window;
- every route that can reach an input/total-token limit or nonzero input-token
  price selects a model bound to that exact profile;
- activation proves that the exact smallest legal rewritten body plus one
  message, declared framing, and the feature's absolute output maximum can fit
  the context window without overflowing integer accounting;
- after server-owned model rewriting and output clamping, the adapter accepts
  only a bounded, text-only request containing `model`, a non-empty array of
  at most 4,096 `{role, content}` messages, optional `stream`, the required
  streaming usage option, optional `n = 1`, and exactly one output-token
  maximum; tools, media, files, arbitrary extensions, multiple choices, and
  every other root or message field fail closed when trusted accounting is
  required;
- the conservative input bound is the exact canonical rewritten UTF-8 JSON
  byte length plus the declared request and per-message framing maxima. This
  relies on the configured provider model using a byte-level BPE in which the
  number of content tokens cannot exceed the encoded bytes; operator framing
  maxima cover provider tokens not represented by those bytes;
- the adapter returns the protocol, method, physical model, profile digest,
  rewritten-body SHA-256, byte length, message count, input bound, applied
  output bound, and checked total bound. The data plane independently
  recomputes the framing formula, checks the context limit, and reads, hashes,
  owns, and rebinds the exact body both before reservation and immediately
  before target acquisition;
- the quota layer defensively binds protocol, method, model, profile/body
  digests, and all three bounds into the logical-request fingerprint and
  requires every input/output/total reservation to equal its bound.

With that proof, production configuration permits hard UTC-calendar
`input_tokens` and `total_tokens` rules and may reserve a hard cost limit using
a nonzero configured input-token price. Known provider usage above any trusted
bound is treated as an upstream protocol anomaly: usage becomes unknown and
the full conservative reservation is retained. Input/total token buckets and
per-request rules remain unsupported until their capacity,
impossible-request, and recovery semantics are specified and implemented.

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

The restricted Chat subset gains enforceable production input, total, and
input-priced cost budgets. Rich Chat requests continue to work only on routes
whose reachable policies and prices do not require a trusted input proof; they
are never silently estimated for a hard budget. Adding another tokenizer,
provider counting rule, protocol, request shape, or proof method requires an
explicit versioned contract decision and matching adapter, activation, replay,
and settlement evidence.

## Security implications

Bounds, framing multiplication, and `I + O` use checked non-negative integer
arithmetic. Reservation values are server-owned, uniform across rules of one
metric, fingerprinted, and recovered from durable state. Profile and body
digests prevent replay under a substituted model, accounting declaration, or
rewritten request. The quota layer revalidates the proof rather than trusting
the adapter's claimed bound. Unknown or anomalous post-dispatch usage is
charged conservatively, so disconnects and provider misreporting cannot create
a quota bypass. Configuration considers every plan reachable through
administrator-owned user overrides when validating adapter support.

## Migration implications

No database migration or client wire change is required because existing
bucket, reservation-entry, usage, and snapshot representations are
metric-generic. The new operator-facing accounting profile and model reference
are a contract-`0.4.0` configuration change; wire protocol `1` and database
schema `11` remain unchanged. Input/total per-request support may need a schema
change so entryless reservations retain enough information for crash
recovery.

## Status

Accepted for wire version 1 on 2026-08-28; restricted OpenAI Chat activation
implemented for draft contract `0.4.0` on 2026-08-28.
