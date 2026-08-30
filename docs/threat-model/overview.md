# Threat model overview

## Scope

This model covers Latchway's client session endpoints, AI-compatible proxy, Admin API, dashboard, CLI, PostgreSQL state, workers, deployment boundary, configured identity and attestation providers, and AI upstreams. Client applications, public networks, identity tokens, attestation evidence, and upstream responses are untrusted until verified at the relevant boundary.

## Security objectives

- Upstream provider credentials remain server-side, encrypted at rest, redacted, and unavailable through read APIs.
- A request is attributed only to an identity verified for the configured application and environment.
- A session is usable only with its installation's P-256 private key and remains short-lived, refreshable through rotation, and revocable.
- Attestation claims are bound to a one-time server challenge and normalized without overstating platform assurance.
- Configuration and administrative mutation require authorization, optimistic concurrency, immutable history, and audit records.
- Quotas cannot be bypassed through concurrency, fallback, failure, retries, clock boundaries, or arithmetic overflow.
- Proxy routing cannot reach arbitrary or private infrastructure, smuggle headers, expose secrets, or silently retry a request after response bytes are visible.
- Usage and observability are useful without persisting prompts, secrets, raw identity credentials, or raw attestation evidence by default.

## Adversaries

- a malicious or reverse-engineered client with full control of HTTP requests and application storage;
- a legitimate user attempting to exceed plan or feature limits;
- a stolen access or refresh token without, or with, a compromised device key;
- a web attacker controlling script execution or browser storage;
- a tenant administrator attempting cross-tenant access or unsafe upstream configuration;
- a compromised identity, attestation, DNS, or AI upstream service;
- an internet attacker probing parsers, timeouts, redirects, streaming, and resource exhaustion;
- an operator or database reader with access not intended to reveal plaintext secrets or raw subjects;
- a failed or duplicated server/worker process causing replay, reservation, or settlement races.

## Trust assumptions

TLS termination, PostgreSQL, the configured master key source, gateway signing keys, deployment identity, and approved identity/attestation trust roots must be protected by the operator. Latchway does not make a rooted device trustworthy, make web code non-extractable, validate the semantic truth of model output, or protect an upstream after intentionally sending it a request.

## Risk treatment

Controls are designed to fail closed for identity, DPoP, revocation, hard quotas, pricing required for a cost cap, configuration activation, and destination safety. Availability may degrade when those authoritative checks are unavailable. Accepted residual risks must be explicit in an ADR or release security statement; high and critical unresolved risks block release.

Related details: `assets.md`, `trust-boundaries.md`, `mobile.md`, `web.md`, `upstream-proxy.md`, `quota-bypass.md`, and `administration.md`.
