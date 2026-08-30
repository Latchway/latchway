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
`web_risk_verified`, or `debug`. When an eligible delegated Apple component
later supplies its own valid App Attest evidence, the composite source becomes
`delegated_direct_attested`; the parent and delegation identifiers remain
present. Effective trust is the minimum allowed by root trust, delegation,
component evidence, policy, and family state.

## Alternatives

- Copy the root attestation result to children: rejected because it fabricates
  direct evidence.
- Permit unconfigured arbitrary delegation: rejected because it lets a client
  define its own privilege surface.

## Security implications

Delegations are feature-scoped, time-bounded, non-replayable, key-bound, and
invalid after parent trust, component, or family revocation. Delegation alone
cannot satisfy a direct-attestation requirement. Direct step-up uses a separate
one-use challenge, binds the component's own App Attest key and DPoP key, and
rotates only that component's session after successful verification.

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

## Consequences

Delegated components can operate without fabricated direct-attestation claims,
but policy must account for provenance, parent state, expiry, and the weakest
trust input. Platforms that cannot produce component-owned evidence remain
delegated-only; an optional direct step-up strengthens only the eligible child
that supplied it.

## Status

Accepted on 2026-08-30 and implemented in draft contract `1.0.0`, database
schema 23, the server policy/session runtime, Admin trust views, and SDK source.
The generic direct-step-up protocol preserves delegation ancestry under
`delegated_direct_attested` when a supported platform can produce the required
component-owned evidence. Apple rejects App Attest key generation in iOS app
extensions, so iOS Widget, Share, Action, and SSO clients remain delegated-only;
the containing app must not attest for them. Final cross-repository coordinate
convergence and protected root-app App Attest, isolation, and exact-image
evidence remain open.
