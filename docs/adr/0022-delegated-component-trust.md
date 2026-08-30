# ADR 0022: Delegate component trust explicitly and narrowly

## Context

Some extensions cannot obtain direct platform attestation, but a directly
attested containing application can prepare them. Treating every sibling as
directly attested overstates assurance; treating every extension as unrelated
identity-only trust loses useful, bounded provenance.

## Decision

A configured root component may issue a single-use, signed, parent-bound
delegation for an allowed component definition. Delegation is limited to
configured features and lifetime, binds the child component key, parent
component and attestation, and records issue, verification, expiry, and
consumption. Provenance is explicit: `direct_attested`,
`delegated_from_attested_root`, `delegated_identity_only`, `identity_only`,
`web_risk_verified`, or `debug`. Effective trust is the minimum allowed by
root trust, delegation, current evidence, policy, and family state.

## Alternatives

- Copy the root attestation result to children: rejected because it fabricates
  direct evidence.
- Permit unconfigured arbitrary delegation: rejected because it lets a client
  define its own privilege surface.

## Security implications

Delegations are feature-scoped, time-bounded, non-replayable, key-bound, and
invalid after parent trust, component, or family revocation. Direct attestation
requirements cannot be satisfied by delegation.

## Developer-experience implications

Operators declare component definitions; the containing app prepares the child
and receives actionable errors for missing configuration, expired parent trust,
or unsupported direct attestation.

## Migration implications

Legacy roots receive no synthetic delegation records. Delegated components are
created only after the new configuration and provisioning contracts activate.

## Documentation implications

Guides and Admin views must distinguish direct evidence from delegated
provenance, show the trust chain and expiry, and avoid describing a delegated
component as directly attested.

## Status

Accepted on 2026-08-30. Delegation contracts, persistence, policy context, and
security tests remain unimplemented.
