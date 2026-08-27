# Latchway repository instructions

This repository is the source of truth for the Latchway wire protocol, configuration schema, Go server, CLI, dashboard, database migrations, deployment assets, and cross-SDK conformance fixtures.

## Non-negotiable product boundaries

- Latchway authenticates an application's existing users; it does not replace the application's identity system.
- Untrusted clients never receive or supply upstream provider credentials, trusted user identifiers, prices, plans, routes, or usage totals.
- Sessions use P-256 proof-of-possession keys and RFC 9449 DPoP. Do not introduce a proprietary proof format.
- Authentication and application/device attestation remain separate inputs to policy.
- PostgreSQL 15 or newer is the only required external service for version 1.
- Clients request application features. Server-owned configuration selects physical providers and models.
- Quotas use reserve, execute, and settle. Never hold a database transaction open while an upstream request is running.
- Production prompt and response bodies are not stored by default.
- The dashboard and CLI must use the canonical Admin API; neither may bypass it with direct database access.

## Contract ownership

The normative contract sources are under `api/`. Any wire-breaking change requires:

1. an explicit protocol-version decision;
2. updated OpenAPI, schemas, error registry, examples, and test vectors;
3. an ADR when the change alters a recorded architectural decision;
4. updated `docs/implementation/COMPATIBILITY.md` and `STATUS.md`;
5. regenerated contract bundle checksums;
6. conformance results from every affected SDK before release.

Generated wire DTOs may be internal. Public SDK APIs must remain handwritten and idiomatic.

## Engineering rules

- Preserve valid existing work and keep changes reviewable and bisectable.
- Do not add production-path `TODO`, `FIXME`, unimplemented panic, empty handler, fake response, or hard-coded success.
- Never commit secrets, signing material, identity tokens, attestation evidence, provider payloads, or local environment files.
- Keep monetary values as integer nano-USD and timestamps unambiguous.
- Reject unsafe defaults: debug attestation in production, permissive JWT algorithms, arbitrary proxy destinations, private-network upstreams, and secret-returning APIs.
- Use structured redaction-safe errors and stable codes from `api/error-codes.yaml`.
- Update `docs/implementation/STATUS.md` after every meaningful phase or changed blocker.

## Validation expectations

Run the narrowest relevant tests after each change and the complete documented validation set before handoff. Do not disable failing tests or suppress security findings without documenting the exact reason. Contract-only changes must at minimum validate JSON, YAML, OpenAPI references, schema examples, test-vector cryptography, and deterministic bundle generation.

## Agent skill tooling

The tracked `.agents/skills`, `agent/skills`, `.claude/skills`, and `skills-lock.json` content is third-party development tooling, not Latchway production source or normative project policy. Preserve its provenance and license metadata. This file and the versioned product contracts take precedence when an advisory skill conflicts with a recorded Latchway decision.
