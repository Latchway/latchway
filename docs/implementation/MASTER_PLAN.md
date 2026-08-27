# Latchway implementation master plan

The authoritative execution contract defines twenty sequential phases. Work should be delivered as reviewable vertical slices; a later phase may proceed only where it does not depend on an unmet earlier gate. Missing external credentials do not block independent work.

| Phase | Objective | Current state | Gate summary |
| --- | --- | --- | --- |
| 0 | Audit all repositories and classify existing work | Complete; governance baselines committed | Baseline complete and trees clean |
| 1 | Governance, protocol contracts, threat model, ADRs | Draft contract locked across all repositories and reproducibly validated | Schemas validate and all repositories identify contract `0.1.0` |
| 2 | Go, PostgreSQL, CLI, dashboard and image foundation | Runnable foundation and prior Compose gate pass; current-image rebuild remains | Compose starts; `/healthz` and `/readyz` pass |
| 3 | Database and one-time administrative bootstrap | Canonical Admin API, CLI and embedded owner setup/login committed; schema version 3 | Exactly one owner can bootstrap; all mutations audited |
| 4 | Immutable configuration revisions | Not started | Concurrency-safe activation, validation, diff and rollback |
| 5 | Identity verification and normalized principals | Standalone verifier/JWKS/privacy/user-store implementation and adversarial gates pass; active-config wiring pending | Strict JWT presets and adversarial identity tests pass |
| 6 | RFC 9449 DPoP and session vertical slice | P-256 proof/JWK primitives implemented; challenge, tokens, replay and refresh pending | Challenge, exchange, protected request, refresh and replay tests pass |
| 7 | First end-to-end proxy | OpenAI Chat adapter and deterministic mock upstream implemented; authenticated composition pending | Authenticated debug-attested request streams through mock upstream |
| 8 | Quota, pricing and usage settlement | Not started | Contention cannot overspend; reservations recover |
| 9 | Protocol adapters and routing | Not started | OpenAI, Anthropic and restricted opaque routes conform |
| 10 | Apple App Attest and Swift SDK | Implementation and local generic-build validation in progress; physical proof externally blocked | Fixtures and physical-device validation pass |
| 11 | Play Integrity and Android SDK | SDK committed; static/JVM tests pass; Android SDK licenses and Play-track proof remain | Fixtures and Play-distributed validation pass |
| 12 | Browser/Node JavaScript SDK | Core SDK committed; local browser/Node/package gates pass | Browser and Node conformance pass |
| 13 | React Native bridge SDK | Implementation in progress | Native dependency and example-app conformance pass |
| 14 | Complete Admin API, CLI and dashboard | Bootstrap/auth/tenant/API-token slice committed; remaining resources/views pending | All control planes use one API and audit every mutation |
| 15 | Observability and PostgreSQL jobs | Not started | Metrics, traces, health and crash recovery pass |
| 16 | Deployment assets | Not started | Compose and documented cloud smoke tests pass |
| 17 | Cross-repository conformance | Not started | Shared vectors and real proxied requests pass for every SDK |
| 18 | Security, race, fuzz, load and upgrade hardening | Not started | Security and reliability targets have recorded evidence |
| 19 | Documentation and version 1.0 release | Not started | Every Definition of Done item links to post-build evidence |

## Immediate execution sequence

1. Complete and commit local iOS and React Native SDK gates without claiming externally blocked device evidence.
2. Implement immutable configuration revisions, conflict-safe activation, validation, rollback, and compiled snapshots.
3. Connect identity and RFC 9449 primitives through challenge, attestation, access/refresh session, replay, and revocation persistence.
4. Deliver the first authenticated debug-attested proxy request through the deterministic mock upstream.
5. Add quota reserve/execute/settle and then broaden providers, protocols, control-plane resources, and deployment proof.
6. Update `STATUS.md` after each material change and keep `COMPLETION_REPORT.md` evidence-only.

## Release slices

- `v0.1.0`: PostgreSQL, debug attestation, custom JWT, DPoP session, OpenAI Chat proxy, request limits, OpenRouter self-test, JavaScript fetch client, Compose.
- `v0.2.0`: identity presets, native attestation, refresh rotation, revocation, Swift and Android alpha.
- `v0.3.0`: remaining protocols, routing, fallback, token/cost reservation, pricing and provenance.
- `v0.4.0`: Admin API, CLI, dashboard, revision management, simulation, audit and usage views.
- `v0.5.0`: all SDK betas and compatibility automation.
- `v0.9.0`: deployments, hardening, upgrade tests and release automation.
- `v1.0.0`: only after the entire Definition of Done passes with published artifacts.
