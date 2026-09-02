# ADR 0005: Separate authentication from attestation

## Context

Identity tokens answer who authenticated with the application. Platform attestation answers different questions about app identity, device signals or web risk. Conflating them creates misleading trust and vendor coupling.

## Decision

Identity verifiers and attestation verifiers are separate interfaces and configuration objects. Identity produces a normalized principal. Attestation consumes a canonical challenge binding and produces stable normalized signals and trust levels. Policies combine those inputs explicitly. Firebase Authentication and Firebase App Check remain independent even when both are configured.

## Alternatives

- One provider-specific login exchange: simpler per vendor but locks identity to attestation and obscures failure semantics.
- Treat attestation as identity: cannot establish the application's user.
- Treat authentication as application integrity: permits modified clients with valid user tokens.

## Consequences

Session exchange has distinct error codes, freshness and step-up behavior. Providers can evolve without changing policy inputs when normalized semantics remain stable.

## Security implications

Attestation never upgrades an unverified identity, and identity never implies trusted app/device state. Raw provider payloads are size-bounded, minimally retained and absent from ordinary API/log output.

## Developer-experience implications

Integrators configure identity and attestation independently and receive distinct failures for each stage. Provider adapters can change behind stable normalized principal and trust signals, so application policy need not parse provider-specific payloads.

## Migration implications

New providers map to existing stable signals or require a deliberate trust-model and contract revision. Existing policies continue using normalized fields rather than provider JSON.

## Documentation implications

Setup and troubleshooting material must keep authentication and attestation flows separate, then show explicitly how policy combines their normalized outputs. Provider guides must define what each signal establishes and must not claim that identity proves application integrity or that attestation identifies a user.

## Status

Accepted for version 1 on 2026-08-27.
