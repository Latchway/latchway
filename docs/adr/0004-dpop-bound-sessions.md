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

## Migration implications

A proof-format or algorithm change requires a wire-version decision and shared vector update. Active sessions remain valid across server signing-key rotation through overlapping public keys.

## Status

Accepted for wire protocol 1 on 2026-08-27.
