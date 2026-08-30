# ADR 0012: No prompt or response storage by default

## Context

Prompts and model responses can contain personal, proprietary, regulated or credential-like data. Routine storage expands breach impact and retention obligations.

## Decision

Do not persist or log prompt or response bodies by default. Record bounded metadata, hashes only where justified, usage, timing, route, status and redacted diagnostics. Any body capture requires an explicit environment policy, documented purpose, strict authorization, encryption, size and retention limits, audit access and visible warnings.

## Alternatives

- Store bodies for observability: easier debugging but unacceptable default exposure.
- Store irreversible hashes universally: still creates correlation risk and limited debugging value.
- Never permit capture: strongest privacy but can block explicitly governed debugging needs.

## Consequences

Operational tools rely on request IDs, traces, usage and deterministic test fixtures. Support procedures ask users for sanitized reproductions rather than database extraction.

## Security implications

Redaction applies before logging and audit serialization, including errors from identity, attestation and upstream providers. Optional capture cannot include credentials or security proofs and requires separate viewer capability.

## Migration implications

Enabling capture changes the deployment privacy posture and must be recorded in configuration revision and audit. Disabling it triggers documented retention deletion rather than merely stopping new writes.

## Status

Accepted for version 1 on 2026-08-27.
