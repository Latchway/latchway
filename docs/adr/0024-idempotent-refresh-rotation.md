# ADR 0024: Make component refresh rotation briefly idempotent

## Context

Extensions and background tasks can race while refreshing one component
session. Treating the first duplicate of an otherwise identical request as
credential theft can revoke a legitimate component, while permitting arbitrary
reuse weakens rotation and replay detection.

## Decision

The first successful rotation stores an encrypted response keyed by old refresh
hash, component ID, DPoP JWK thumbprint, and result for a 30-second grace
window. An identical duplicate tuple returns the same result without issuing a
second chain. A different component, key, payload, or result binding and any
reuse after the grace window are suspicious and follow the configured
component/family revocation and audit policy. Rotation-result storage is
bounded, expires promptly, and never exposes token plaintext to operators.

## Alternatives

- Revoke on every reuse: rejected because expected component concurrency can
  cause self-revocation.
- Accept duplicates indefinitely: rejected because it creates a replay oracle
  and extends stolen-token usefulness.

## Security implications

Idempotency is exact-tuple and time bounded. Stored responses require envelope
encryption, access separation, deletion, replay telemetry, and tests for key,
component, payload, expiry, multi-replica, and transaction races.

## Developer-experience implications

SDKs can coalesce refresh locally but remain correct if two tasks race. The
same access/refresh result is returned, so callers do not need conflict-specific
state repair during the grace window.

## Migration implications

This decision supersedes ADR 0032's terminal reuse behavior for component
session families. Legacy wire-1 behavior remains accurately documented until
the new tables, contract, policies, and SDK locks migrate together.

## Documentation implications

Security and SDK guides must explain the narrow grace semantics, distinguish an
idempotent duplicate from suspicious reuse, and document audit/recovery behavior
without exposing token material.

## Status

Accepted as the target refresh design on 2026-08-30. The current runtime still
implements ADR 0032 and therefore does not satisfy this decision.
