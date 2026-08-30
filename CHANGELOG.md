# Changelog

All notable project changes will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows Semantic Versioning once distributable artifacts exist.

## [Unreleased]

### Added

- Add bounded per-process `stale`, `closed`, `open`, and `half_open` circuit
  observations for upstream-attempt telemetry without changing deterministic
  route selection or dispatch admission.
- Add a real OTLP/HTTP export and shutdown-flush regression and run the
  credential-free release/evidence tooling in ordinary pull-request CI.

### Fixed

- Make the embedded console's browser proof fail closed if any same-origin
  mutation leaves the canonical Admin API.
- Expire stale circuit failure history before recording a new outcome so old
  failures cannot reopen an observation window.

## [1.0.0-rc.1] - 2026-08-30

### Changed

- Establish the canonical retained release-candidate checkpoint required by
  the protected previous-candidate upgrade and application-rollback gate. The
  checkpoint does not create a public tag or alter the frozen API contract.
- Advance contract 0.5.1 for closed, provider-specific Apple App
  Attest and Google Play Integrity configuration while retaining wire protocol
  version 1; contract 0.5.0 remains the preceding sealed local checkpoint.
- Advance the draft contract to 0.4.0 for physical-model-bound input
  accounting profiles and a restricted, conservative OpenAI Chat preflight
  that enables hard calendar input/total quotas and input-priced cost
  reservation, while retaining wire protocol version 1.

### Added

- Canonical administrator lifecycle across PostgreSQL, Admin API, CLI, and the
  embedded console: bounded listing, local-account creation, role changes,
  disable/re-enable, owner password reset, last-active-owner protection, scoped
  credential revocation, tenant isolation, and value-free audit records.
- Add calendar week windows and optional server-owned IANA timezones to quota
  configuration and route-simulation output; an omitted timezone canonicalizes
  to UTC and no client-supplied timezone participates in enforcement.
- Restricted generic HTTP execution at `/proxy/{feature}/{path...}` with exact
  feature binding, generic protected destinations, method/path/body/header
  allowlists, per-route response and SSE bounds, unknown-usage settlement, and
  explicit opt-in before unsafe-method retry or fallback.
- Canonical encrypted secret creation, listing, rotation, and reference-aware
  deletion across the PostgreSQL domain layer, Admin API, and CLI, including
  tenant authorization, audit redaction, stale-write protection, clock-skew and
  concurrency tests, safe commit recovery, and runtime wiring.
- Exact rewritten-body and accounting-profile proof binding across the Chat
  adapter, policy/configuration activation, durable quota replay, conservative
  settlement, and authenticated PostgreSQL dispatch gates.
- Phase 0 repository baseline and implementation status records.
- Phase 1 governance, architecture, threat-model, and decision records.
- Draft protocol contract 0.1.0 with wire protocol version 1.
- Draft client and Admin OpenAPI 3.1 contracts, configuration schema, stable error registry, and cross-language security vectors.
- Initial Go/PostgreSQL runtime, migration, CLI, embedded console, Compose, and single-image foundation in the working tree.

Publication remains a separate, evidence-gated operation; this source release
entry does not itself claim a registry artifact, deployed image, or physical-
device attestation result.
