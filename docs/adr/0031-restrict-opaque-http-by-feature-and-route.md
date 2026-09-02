# ADR 0031: Restrict opaque HTTP by feature and route

> Renumbering note: this decision was originally ADR 0019. It was renumbered
> without changing its scope when the Installation Family addendum reserved
> ADRs 0017 through 0028.

## Context

Some applications need a protected HTTP capability that is not one of
Latchway's structured AI protocols. Treating that capability as a conventional
forward proxy would let an untrusted client choose an authority, leak provider
credentials, bypass model/route policy, or amplify an ambiguous unsafe request
through retry. Unlike a structured adapter, a generic adapter also cannot
derive trustworthy token usage from an arbitrary provider payload.

The draft contract already reserved `/proxy/` and a feature-level
`opaqueHttp` request policy, but the endpoint was deliberately non-executable.
An executable design needs independently bounded request, response, streaming,
header, destination, and replay behavior.

## Decision

Latchway exposes opaque HTTP only at the canonical public shape
`/proxy/{feature}/{remainingPath...}`. The path feature must exactly equal the
signed `X-Latchway-Feature` declaration. Queries, fragments, encoded path
aliases, dot segments, and repeated empty segments are rejected before
dispatch. Client-selected upstream authorities and absolute destinations are
never accepted as routing inputs.

The selected feature owns a closed request policy:

- `allowedMethods` is a nonempty subset of `GET`, `POST`, `PUT`, `PATCH`, and
  `DELETE`;
- `pathTemplates` contains canonical exact-depth provider-relative templates;
  a capture such as `{resource_id}` occupies exactly one segment, capture names
  are unique within a template, and the configured set must be pairwise
  disjoint;
- compatibility-only `pathPrefixes` retains the v1 segment-bound behavior when
  `pathTemplates` is absent; the two modes cannot be combined;
- `maxBodyBytes` bounds the buffered request body, including chunked input;
- `allowedRequestHeaders` is the only client-header forwarding allowlist.

The existing protected target still selects the exact configured base URL,
requires the upstream family `generic`, applies DNS and private-network
controls, strips credentials and hop-by-hop/Latchway/forwarding headers, and
injects provider credentials only inside the secret callback. The opaque
adapter cannot set or replace any destination.

Each route additionally requires `maxResponseBytes`. The effective response
bound is the smaller of that value and the server-wide limit.
`streamingAllowed` defaults to false and must be true before a successful
`text/event-stream` response can be relayed. Provider error bodies remain
suppressed and cannot influence retry classification.

Request buffering makes a fresh attempt technically possible, but transport
replay remains a separate policy decision. `GET` may use configured retry or
fallback. Every other supported method is treated as unsafe and receives no
retry or fallback unless that route explicitly sets `retryUnsafeMethods: true`,
which is the administrator's declaration that executions on that route are
idempotent. A fallback route must independently permit unsafe replay. No
attempt is made after response commitment.

Opaque responses always settle with unknown provider usage. Logical request,
attempt, concurrency, and conservative configured cost accounting still use
the normal reserve/execute/settle lifecycle; the adapter never fabricates
tokens or provider cost.

## Alternatives

- Accept a destination URL from the client: rejected because it creates an
  authenticated SSRF and credential-exfiltration primitive.
- Forward every non-hop-by-hop header: rejected because provider credentials
  and tenant-routing metadata evolve faster than a denylist.
- Infer idempotence from `PUT` or `DELETE`: rejected because opaque provider
  semantics and bodies are outside Latchway's control.
- Treat every chunked response as an event stream: rejected because ordinary
  bounded JSON and binary responses may use chunked HTTP transport.
- Parse arbitrary payloads for usage: rejected because it would turn
  provider-controlled, unversioned data into trusted accounting.

## Consequences

Opaque HTTP is intentionally less feature-rich than a forward proxy. It cannot
carry query parameters, use arbitrary destinations, forward compressed request
bodies, expose provider error bodies, or report measured token usage. Operators
must create explicit features and routes for each capability and choose body,
response, header, streaming, and unsafe-replay boundaries.

The request body is buffered within the configured bound so retries receive
fresh readers. Successful SSE remains incremental and is not buffered in full.
Unknown usage conservatively retains applicable post-dispatch reservations.

## Security implications

Exact feature equality prevents a path/header confused deputy. Segment-bound
legacy matching prevents `/safe` from authorizing `/safeevil`. Exact-depth
templates reject traversal, encoded separators, partial or repeated captures,
catch-alls, and pairwise overlap; one request can therefore match at most one
template without declaration-order behavior. Captures are not substitutions.
Protected target resolution and generic-upstream validation prevent destination
escape. The positive route response cap limits untrusted output, and the
explicit SSE gate prevents an administrator from accidentally activating an
unbounded long-lived stream. Unsafe replay is off unless every executed route
opts in.

## Developer-experience implications

Operators must declare the allowed methods, canonical path policy, client
headers, request and response bounds, streaming permission and unsafe replay
decision for each opaque feature and route. Clients call the canonical
feature path with an exactly matching feature declaration; arbitrary
destinations, query strings and undeclared headers are intentionally
unavailable. Structured protocol integrations are unaffected by this escape
hatch's narrower ergonomics.

## Migration implications

Existing generic-upstream configurations with `pathPrefixes` remain valid and
retain byte-for-byte segment-bound behavior: a prefix matches itself and its
descendants, `/safe` does not match `/safeevil`, a trailing slash matches only
its slash-bearing spelling and descendants rather than `/safe`, and the legacy
root prefix `/` continues to match every canonical non-root provider path. This
compatibility mode is not silently translated to
templates. New configurations should use `pathTemplates`; switching modes is
an explicit revision, and the fields cannot coexist. Routes that assumed query
forwarding, arbitrary headers, or retry of mutating methods must still use
canonical provider paths, positive header allowlists, and an explicit
unsafe-replay decision. Structured OpenAI and Anthropic routes are unaffected.

## Documentation implications

Opaque HTTP guides must present it as a bounded configured capability, never a
forward proxy. They must include exact-depth template examples, the legacy
segment-bound prefix rules, canonical-path rejections, positive header
allowlisting, response/SSE caps and the explicit unsafe-method replay opt-in.
Usage material must state that provider token usage remains unknown rather
than inferred from arbitrary payloads.

## Status

Accepted and implemented for draft contract `0.5.0` and wire protocol `1` on
2026-08-29. Exact-depth templates and the explicit v1 prefix compatibility mode
were implemented on 2026-08-31. This local implementation decision is not
release, publication, or live-provider evidence.

The decision was renumbered from ADR 0019 to ADR 0031 on 2026-08-30. Its
implementation and historical evidence remain unchanged.
