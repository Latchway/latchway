# ADR 0018: Use feature-bound authenticated transports

## Context

Clients ask for application features while server configuration selects routes,
models, prices, and providers. A generic authenticated client that accepts a
feature or destination on every call makes confused-deputy mistakes and
credential attachment to the wrong host easier.

## Decision

SDKs expose transports bound at construction to one configured feature and one
Latchway origin policy. Each outgoing request obtains a current component
session, creates a fresh RFC 9449 DPoP proof for the exact method and URI, and
adds protocol, SDK, and optional framework metadata. Provider placeholders may
be replaced locally but are never sent upstream. Destination changes,
redirects, retries, and refreshes are re-authorized before transmission.

## Alternatives

- Accept the feature only as a mutable per-request header: rejected because it
  makes accidental privilege crossover easy.
- Give applications provider credentials: rejected by the product boundary.

## Security implications

Binding narrows credential scope and makes redirects and retries explicit.
Authorization values are computed at request time; no cached static header is
treated as proof of possession. The component private key stays in platform
key storage.

## Developer-experience implications

Applications create one reusable transport per feature and inject it into raw
HTTP or a supported framework. Session bootstrap and safe refresh remain SDK
responsibilities rather than application callback choreography.

## Migration implications

Existing SDK request helpers can delegate to the feature-bound primitive.
Adopting framework headers and component sessions requires the future protocol
and SDK contract update; this ADR does not change wire protocol 1 by itself.

## Documentation implications

Quickstarts must show where the feature is bound, which destinations are
eligible, how retries obtain fresh proofs, and how unavailable or revoked
features surface to the framework.

## Status

Accepted as the target architecture on 2026-08-30. The current SDKs implement
legacy installation-bound authorization; component-aware transport remains
pending.
