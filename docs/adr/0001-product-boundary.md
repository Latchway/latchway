# ADR 0001: Product boundary

## Context

Mobile and browser applications cannot safely hold AI provider credentials. Existing gateways commonly authenticate a virtual key but do not establish the application's user, installation, attestation state, or feature-level policy.

## Decision

Latchway is the boundary between an untrusted application and trusted AI infrastructure. It verifies the application's existing identity credential, platform-appropriate attestation and an installation-held DPoP key; issues a short session; authorizes a named application feature; reserves limits; selects a server-owned route/model; injects upstream credentials; proxies the existing HTTP shape; and records usage. Clients never assert trusted user, plan, route, price, usage, or provider credentials.

## Alternatives

- Embed provider keys in clients: operationally simple but inherently extractable.
- Give each client a conventional gateway virtual key: does not establish user or installation trust.
- Build a full AI application framework: expands scope and prevents drop-in HTTP compatibility.

## Consequences

Latchway must operate both a security-sensitive session plane and a protocol-compatible proxy. Feature and policy configuration become first-class product concepts.

## Security implications

Every client field is untrusted until derived from verified server state. Compromise of Latchway or its master/signing keys is high impact and requires hardened operations, redaction, rotation and audit.

## Developer-experience implications

Application developers keep their existing identity provider and HTTP payloads while the SDK handles proofs and short sessions; their durable integration choice is the named feature. Operators, rather than client code, own routes, models, prices and provider credentials, so diagnostics must identify which boundary rejected a request without exposing those values.

## Migration implications

Applications retain their identity provider and request payloads but add SDK authorization and feature selection. Existing provider keys move to encrypted server-side secrets.

## Documentation implications

Public architecture and quickstart material must show the complete untrusted-client-to-upstream boundary and separate application-developer duties from operator duties. Examples must never place provider credentials in a client or imply that a client may choose trusted plan, route, model, price or usage facts.

## Status

Accepted for version 1 on 2026-08-27.
