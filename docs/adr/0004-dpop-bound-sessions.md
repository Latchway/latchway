# ADR 0004: RFC 9449 DPoP-bound sessions

## Context

Bearer tokens stolen from an untrusted client can otherwise be replayed from another machine. Platform key stores can hold P-256 keys while exposing only a public key.

## Decision

Every installation creates a P-256 key, computes its RFC 7638 JWK thumbprint and uses RFC 9449 DPoP for challenge, session, refresh and protected requests. Access tokens carry `cnf.jkt`; refresh tokens are opaque, hashed, rotating, revocable and bound to the same installation/thumbprint. PostgreSQL stores a hash of proof `jti` per session with uniqueness before upstream dispatch.

## Alternatives

- Bearer JWT sessions: simpler but replayable after theft.
- Mutual TLS: strong possession but impractical for public mobile/browser application integration.
- Proprietary signed headers: avoids standards complexity but increases interoperability and review risk.

## Consequences

SDKs need secure key persistence, URI canonicalization, clock-skew handling, single-flight refresh and proof generation for arbitrary requests. Servers need nonce support, replay pruning and signing-key rotation.

## Security implications

Reject private JWK members, remote key URLs, symmetric/unknown algorithms, stale `iat`, duplicate `jti`, wrong `htm`/`htu`, invalid `ath`, and thumbprint mismatch. DPoP reduces token replay; it does not protect a compromised process that can invoke the legitimate key.

## Developer-experience implications

SDKs must hide routine key persistence, proof construction, nonce handling and single-flight refresh while surfacing recoverable clock, nonce and session errors. Raw HTTP implementers need shared vectors for JWK thumbprints, URI canonicalization and `ath`; access tokens cannot be treated as ordinary bearer tokens.

## Migration implications

A proof-format or algorithm change requires a wire-version decision and shared vector update. Active sessions remain valid across server signing-key rotation through overlapping public keys.

## Documentation implications

Client guides must trace the challenge, exchange, protected-request and refresh proofs, including required claims and error recovery. Platform key-storage guidance, clock-skew troubleshooting and the limits of proof-of-possession must be explicit, and no example may label a bound access token as bearer authentication.

## Status

Accepted for wire protocol 1 on 2026-08-27.
