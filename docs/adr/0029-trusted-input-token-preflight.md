# ADR 0029: Require trusted preflight bounds for input-token budgets

> Renumbering note: this decision was originally ADR 0017. It was renumbered
> without changing its scope when the Installation Family addendum reserved
> ADRs 0017 through 0028.

## Context

Hard input- and total-token limits must reserve enough capacity before an
upstream request is dispatched. A request-body byte heuristic is not a
conservative token bound: physical-model selection and provider request
rewriting happen later, tokenization varies by model, and remote files,
images, audio, tools, or provider extensions can add billable input that is
not bounded by the JSON body size. Provider-reported usage arrives after
dispatch and therefore cannot prevent concurrent overspend.

The quota database and usage schema are metric-generic. They can durably
reserve, settle, release, recover, and project calendar buckets for token
metrics without making an unsafe adapter estimate authoritative.

## Decision

Production enforcement of hard `input_tokens` and `total_tokens` limits
requires a server-trusted, conservative input-token bound tied to the exact
rewritten provider request and selected physical model. The bound is produced
after route and model resolution and before reservation or dispatch. Client
model names, client counters, request-body heuristics, and post-dispatch
provider usage are not trusted preflight bounds.

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

Configuration contract `0.5.0` activates one deliberately narrow method,
`utf8_byte_bpe_declared_framing_v1`, for OpenAI Responses, OpenAI Chat, OpenAI
Embeddings, and Anthropic Messages. Opaque HTTP has no trusted input proof.
The method is valid only when all of the following conditions hold:

- the operator declares an immutable profile for the exact structured
  protocol and exact physical model, including non-negative maximum framing
  tokens per request and per message or item and a positive context window;
- the selected feature, route, model capability, and profile protocol match,
  and the selected model's physical model exactly matches the profile;
- after server-owned model rewriting and output clamping, the adapter accepts
  only its bounded text-only proof surface: Chat messages; Responses local
  text or text-message items and optional text instructions; Embeddings local
  text or a bounded text batch; or Anthropic text system/message content;
- remote or embedded files, images, audio, binary/token-ID inputs, tools,
  schemas, provider-hosted state, and arbitrary extensions fail closed when
  the selected plan or nonzero input price requires trusted accounting;
- the conservative input bound is the exact rewritten UTF-8 JSON byte length
  plus the declared request framing and the declared per-message/item framing
  multiplied by the bounded framing-unit count. This relies on the configured
  physical model using a byte-level BPE in which token count cannot exceed
  encoded bytes; operator framing maxima cover provider tokens not represented
  by those bytes;
- Responses, Chat, and Anthropic require and preserve a positive
  server-applied output maximum. Embeddings has no generated-token maximum,
  so its output bound is exactly zero and its total bound equals its input
  bound;
- the adapter returns the protocol, method, physical model, profile digest,
  rewritten-body SHA-256, byte length, framing-unit count, input bound,
  applied output bound, and checked total bound. The data plane independently
  recomputes the framing formula, checks the context limit, and reads, hashes,
  owns, and rebinds the exact body both before reservation and immediately
  before target acquisition;
- the quota layer defensively binds protocol, method, model, profile/body
  digests, and all three bounds into the logical-request fingerprint and
  requires every input/output/total reservation to equal its bound.

Configuration validation proves each declared profile is internally possible
and that exact model references are coherent. It does not reject an otherwise
valid mixed-protocol environment merely because some unrelated route cannot
produce a trusted proof. The data plane fails closed before reservation,
secret access, target acquisition, or dispatch only when the route and plan
selected for the current request require proof and cannot produce it. The
same selected-route rule applies to a hard cost limit with a nonzero input
token price; hard-cost pricing catalog completeness remains an activation
requirement.

With a valid proof, production configuration permits hard UTC-calendar,
rolling token-bucket, and per-request `input_tokens` and `total_tokens` rules
and may reserve a hard cost limit using a nonzero configured input-token
price. Known provider usage above any trusted bound is an upstream protocol
anomaly: usage becomes unknown and the full conservative reservation is
retained. A request whose trusted bound is above a token-bucket capacity or
per-request maximum is denied without creating a bucket, reservation, or
attempt and remains stable under exact replay.

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

The restricted text subsets of all four structured protocols gain enforceable
production input, total, and input-priced cost budgets. Rich structured
requests continue to work on routes whose selected policies and prices do not
require a trusted input proof; they are never silently estimated for a hard
budget. Adding another tokenizer, provider counting rule, protocol, request
shape, or proof method requires an explicit versioned contract decision and
matching adapter, activation, replay, and settlement evidence.

## Security implications

Bounds, framing multiplication, and `I + O` use checked non-negative integer
arithmetic. Reservation values are server-owned, uniform across rules of one
metric, fingerprinted, and recovered from durable state. Profile and body
digests prevent replay under a substituted model, accounting declaration, or
rewritten request. The quota layer revalidates the proof rather than trusting
the adapter's claimed bound. Unknown or anomalous post-dispatch usage is
charged conservatively, so disconnects and provider misreporting cannot create
a quota bypass. Configuration preserves pricing safety for plans reachable
through administrator-owned user overrides, while proof availability is
enforced for the concrete selected route and plan at request time.

## Migration implications

Bucket, reservation-entry, usage, and snapshot representations remain
metric-generic, and no client wire change is required. Database schema `16`
widens the durable attempt proof constraint to admit the protocol-valid
Embeddings output bound of zero; application validation still requires a
positive output bound for every generative structured protocol. The
operator-facing profile protocol expansion is a configuration-contract
`0.5.0` change; wire protocol remains `1`. Per-request-only reservations remain
entryless, while their trusted bounds are request-local gates.

## Status

Accepted for wire version 1 on 2026-08-28; restricted OpenAI Chat activation
implemented for draft contract `0.4.0` on 2026-08-28. Hard input/total
token-bucket and per-request algorithms were implemented behind the same proof
on 2026-08-29. Responses, Embeddings, and Anthropic text-only proof surfaces,
mixed-protocol selection, and schema `16` zero-output persistence were accepted
for configuration contract `0.5.0` on 2026-08-29.

The decision was renumbered from ADR 0017 to ADR 0029 on 2026-08-30. Its
implementation and historical evidence remain unchanged.
