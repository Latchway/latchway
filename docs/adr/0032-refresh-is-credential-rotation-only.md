# ADR 0032: Keep legacy session refresh limited to credential rotation

> Renumbering note: this decision was originally ADR 0020. It was renumbered
> when the Installation Family addendum reserved ADRs 0017 through 0028. ADR
> 0024 supersedes its terminal-reuse behavior for component session families;
> this file remains the record of contract 0.5.1 and the current legacy runtime.

## Context

The draft client OpenAPI document allowed `identity_token` and `attestation`
inside a session-refresh request. The server never accepted either field, and
refresh has no session-challenge nonce or attestation binding to which fresh
identity or device evidence could be bound. The JavaScript client nevertheless
sent both values, so its nominal refresh path could not interoperate with the
server. Sending a single-use App Attest, Play Integrity, App Check, or Turnstile
token without a new server challenge would also weaken replay and freshness
semantics.

## Decision

`POST /client/v1/sessions/refresh` accepts one exact JSON field:
`refresh_token`. The endpoint remains protected by a fresh DPoP proof and
rotates the refresh-token family according to the existing protocol.

Identity reauthentication, attestation renewal, attestation step-up, and stale
attestation never add evidence to refresh. When the server returns the
canonical condition for one of those actions, an SDK discards the old session
and performs a new session-challenge and exchange flow. The new exchange binds
identity and attestation evidence to the new challenge, DPoP key, application,
environment, platform, and principal.

Unknown refresh fields are rejected before coordinator work. SDKs must not
retain a fallback that injects identity or attestation fields into refresh.
Refresh-token reuse, revocation, and terminal expiry remain terminal according
to the existing session policy.

## Alternatives

- Add an identity token to every refresh: rejected because it was never
  accepted by the server and has no new challenge binding.
- Add provider evidence to refresh: rejected because provider tokens can be
  single-use and the refresh request does not carry the challenge state needed
  for exact attestation binding.
- Extend refresh with a nested challenge protocol: rejected because the
  existing challenge and exchange endpoints already provide the required
  binding and lifecycle without a second protocol.

## Consequences

Refresh stays a small credential-rotation operation. Reauthentication and
step-up require one extra challenge/exchange round trip, but their evidence is
fresh, unambiguous, and covered by the same verification path as initial
session establishment. SDK session generations must remain monotonic when a
fresh exchange replaces an expired or stepped-up session.

The OpenAPI correction removes fields that no released server accepted. It is
a draft-contract interoperability and security correction, not a supported
wire-behavior removal. Draft contract `0.5.0` and wire protocol `1` remain
appropriate; no released compatibility pair is claimed.

## Security implications

An identity or attestation token cannot be replayed through an endpoint that
lacks the server challenge used to create it. Fresh device evidence is bound to
the exact new session exchange, while DPoP continues to bind refresh-token
rotation to the installation key. Strict body parsing prevents accidental or
malicious field smuggling.

## Migration implications

SDKs and applications must stop sending identity or attestation fields to the
refresh endpoint. When identity renewal or attestation step-up is required,
clients must discard the old session and run the existing challenge/exchange
flow. Refresh-token storage, rotation, DPoP key handling, and the wire protocol
version otherwise remain unchanged.

## Status

Accepted and implemented for draft contract `0.5.0` and wire protocol `1` on
2026-08-29. Publication, cross-SDK live conformance, and physical-device proof
remain separate release gates.

Renumbered from ADR 0020 to ADR 0032 on 2026-08-30 and superseded by ADR 0024
for the Installation Family contract. The legacy implementation remains in
source until the Phase 3 migration lands and must not be described as the
target refresh design.
