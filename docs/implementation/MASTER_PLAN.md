# Latchway implementation master plan

The authoritative execution contract defines twenty sequential phases. Work should be delivered as reviewable vertical slices; a later phase may proceed only where it does not depend on an unmet earlier gate. Missing external credentials do not block independent work.

| Phase | Objective | Current state | Gate summary |
| --- | --- | --- | --- |
| 0 | Audit all repositories and classify existing work | Complete; governance baselines committed | Baseline complete and tracked trees clean at recorded passing revisions |
| 1 | Governance, protocol contracts, threat model, ADRs | Draft contract `0.1.0`/protocol `1` is reproducibly validated and a prior core/bundle baseline is locked across all SDK repositories | Core schemas, deterministic bundle, and baseline lock equality validate; no release or compatibility promise |
| 2 | Go, PostgreSQL, CLI, dashboard and image foundation | Runnable foundation, prior Compose gate, and current local non-root OCI build pass; current Compose smoke and registry digest remain open | Local runtime/image gates pass; release image evidence is absent |
| 3 | Database and one-time administrative bootstrap | Canonical Admin API, CLI, embedded owner setup/login, and schema version 9 committed | Exactly one owner can bootstrap; implemented mutations are audited |
| 4 | Immutable configuration revisions | Revision creation, validation, planning, conflict-safe activation, rollback, and compiled snapshots committed and locally tested | Local immutable-revision and concurrency gates pass |
| 5 | Identity verification and normalized principals | Strict verifier/JWKS/privacy/user store is wired into active configuration and session exchange | Local identity, rotation, mapping, policy, and adversarial gates pass |
| 6 | RFC 9449 DPoP and session vertical slice | Local debug-attested challenge/exchange, access/refresh issuance, replay, JWKS, protected authorization, reuse detection, and current-installation revocation committed | Full local Phase 6 and public protected-revoke gates pass; production native trust is outside this phase evidence |
| 7 | First end-to-end proxy | Local authenticated debug-attested OpenAI Chat vertical passes through deterministic mock upstream; local-verifier CLI and live canary remain | Local authenticated request, relay, settlement and replay-without-redispatch gate passes |
| 8 | Quota, pricing and usage settlement | Hard UTC-calendar request-count plus UTC-calendar and per-request output-token rules have atomic durable reserve/execute/settle, exact applied-cap reservations, provider-usage release, conservative unknown charging, provenance-bearing usage, entryless per-request lifecycle, contention, bounded stateful recovery, capability-gated activation, and authenticated PostgreSQL proof; full engine remains | Configured nano-USD pricing attribution, concurrency, token-bucket, hard-cost, snapshot, and override gates remain open |
| 9 | Protocol adapters and routing | Initial OpenAI Chat adapter exists; routing, fallback, Anthropic, and restricted opaque routes remain | OpenAI, Anthropic and restricted opaque routes conform |
| 10 | Apple App Attest and Swift SDK | Swift SDK, local fixture sources, and synchronized-baseline lock committed; latest-core conformance, server trust-root verification and physical proof remain | Fixtures and physical-device validation pass |
| 11 | Play Integrity and Android SDK | Android SDK and synchronized-baseline lock committed with local static/JVM gates; latest-core conformance, server verification, Android SDK/`ANDROID_HOME`, license-bound build, and Play-track proof remain | Fixtures and Play-distributed validation pass |
| 12 | Browser/Node JavaScript SDK | SDK and synchronized-baseline lock committed; local browser/Node/package gates pass; latest-core live conformance remains | Browser and Node conformance pass against the selected core |
| 13 | React Native bridge SDK | Native-backed SDK and synchronized-baseline lock committed with local source gates; latest-core conformance, CocoaPods/native-consumer, published native dependencies, and device conformance remain | Native dependency and example-app conformance pass |
| 14 | Complete Admin API, CLI and dashboard | Bootstrap/auth/tenant/config/API-token slices committed; remaining resources and views pending | All control planes use one API and audit every mutation |
| 15 | Observability and PostgreSQL jobs | Initial bounded quota-expiry and DPoP-replay cleanup runtime is role-aware; broader telemetry/jobs remain | Metrics, traces, health and complete crash recovery remain open |
| 16 | Deployment assets | Foundation exists; current image, cloud smoke, and operational deployment evidence remain | Compose and documented cloud smoke tests pass |
| 17 | Cross-repository conformance | Prior baseline core/bundle locks are synchronized; latest-core live matrix is not run | Shared vectors and real proxied requests pass for every SDK |
| 18 | Security, race, fuzz, load and upgrade hardening | Full core race suite, six fuzz smoke targets, focused PostgreSQL race, and revocation contention pass; load/soak/upgrade and remaining audits are open | Security and reliability targets have recorded evidence |
| 19 | Documentation and version 1.0 release | Evidence ledgers are maintained; no release artifacts, tags, or publications exist | Every Definition of Done item links to post-build evidence |

Schema version 9 has a bounded recovery limitation for Phase 8: an expired per-request-only entryless attempt cannot reconstruct its applied cap or add an unknown-output usage row. That shape has no durable capacity to recover; normal known settlement persists provider usage.

## Immediate execution sequence

1. Add configured integer nano-USD pricing attribution and provenance without activating hard cost limits.
2. Add concurrency leases, token buckets and quota snapshots, then broaden routing and protocol adapters.
3. Add production App Attest and Play Integrity server verification and run the cross-repository conformance matrix at the synchronized locks without claiming externally blocked physical evidence early.
4. Complete control-plane resources, observability/jobs, deployment smoke tests, and operational recovery gates.
5. Finish load/soak/upgrade/security hardening and produce signed, published release artifacts only after every release gate passes.
6. Update `STATUS.md` after each material change and keep `COMPLETION_REPORT.md` evidence-only.

## Release slices

- `v0.1.0`: PostgreSQL, debug attestation, custom JWT, DPoP session, OpenAI Chat proxy, request limits, OpenRouter self-test, JavaScript fetch client, Compose.
- `v0.2.0`: identity presets, native attestation, refresh rotation, revocation, Swift and Android alpha.
- `v0.3.0`: remaining protocols, routing, fallback, token/cost reservation, pricing and provenance.
- `v0.4.0`: Admin API, CLI, dashboard, revision management, simulation, audit and usage views.
- `v0.5.0`: all SDK betas and compatibility automation.
- `v0.9.0`: deployments, hardening, upgrade tests and release automation.
- `v1.0.0`: only after the entire Definition of Done passes with published artifacts.
