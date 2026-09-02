# ADR 0006: Feature-first client routing

## Context

Physical models, vendors, prices and availability change independently from application semantics. Allowing clients to select them bypasses centralized authorization and makes migrations client releases.

## Decision

The primary client abstraction is a stable application feature such as `habit-assistant`. The client sends `X-Latchway-Feature`; active server configuration maps the feature to access policy, attestation policy, limit plan, output clamps and ordered routes. Server-selected models may rewrite the client model field.

## Alternatives

- Trust a client model name: leaks infrastructure choices and permits unauthorized spend.
- Expose only route IDs: couples clients to operational topology.
- One application-wide upstream: simple but prevents policy and cost differentiation.

## Consequences

Operators can change providers and models without app releases. Route simulation and configuration reference validation are necessary. Clients must handle a stable `feature_not_found` or `feature_not_allowed` error.

## Security implications

Features are resolved within the authenticated application/environment; route/model/price inputs from clients are ignored or rejected. Policy evaluation uses normalized server-owned context and safe CEL.

## Developer-experience implications

Application code names a stable feature and can keep the same request integration while operators change routes or physical models. Operator tooling needs reference validation and route simulation, and client libraries must expose stable feature-not-found and feature-not-allowed failures.

## Migration implications

Renaming or removing a feature is an application contract change and should use an overlap/deprecation period. Backend model changes are configuration revisions, not wire changes.

## Documentation implications

Examples and API guides must lead with feature selection rather than client-selected providers or models. Operator documentation must explain feature-to-policy/route mapping, simulation and safe rename/deprecation, while SDK guides show how to set a feature and handle its stable errors.

## Status

Accepted for version 1 on 2026-08-27.
