# ADR 0011: SDKs authorize HTTP transports, not AI semantics

## Context

Applications already use URLSession, OkHttp, fetch and provider-specific AI libraries. Requiring a new AI abstraction would duplicate fast-changing provider APIs and impede adoption.

## Decision

SDKs manage installation keys, attestation, sessions, DPoP authorization, refresh, revocation and diagnostics, then integrate with ordinary platform HTTP transports. Public APIs are handwritten and idiomatic. They accept an application identity-token provider but never an upstream provider secret.

## Alternatives

- Full prompt/model client: convenient demos but proprietary framework scope and constant protocol lag.
- Expose only raw token endpoints: makes each application reimplement critical DPoP and refresh safety.
- Generate public APIs from OpenAPI: produces non-idiomatic and unstable surfaces.

## Consequences

SDKs need careful arbitrary-body, streaming, cancellation and non-replayable request behavior. Existing AI request and response types remain usable.

## Security implications

SDKs must not transparently replay a request that may have reached an upstream. Secure storage, single-flight refresh, redacted diagnostics and feature header injection are security-critical responsibilities.

## Developer-experience implications

Application developers keep their platform HTTP client and provider request/response types, adding an authorized transport rather than adopting a Latchway prompt API. SDKs hide session mechanics but must preserve streaming, cancellation and non-replayable-body behavior in idiomatic platform APIs.

## Migration implications

Wire DTOs may be regenerated internally from contract bundles, while public SDK migrations remain deliberate semantic-versioned changes. Applications can adopt Latchway without rewriting payload construction.

## Documentation implications

Quickstarts must wrap ordinary platform or provider HTTP clients and focus on identity-token callbacks, feature selection and transport installation. Platform guides must describe streaming, cancellation and ambiguous-send errors without presenting a proprietary AI object model or encouraging manual DPoP/session handling.

## Status

Accepted for version 1 on 2026-08-27.
