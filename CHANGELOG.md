# Changelog

All notable project changes will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows Semantic Versioning once distributable artifacts exist.

## [Unreleased]

### Changed

- Advance the draft contract to 0.3.0 for normative secret UTF-8 byte bounds
  and current-version mutation semantics, plus explicit correlated handling of
  indeterminate database commits, while retaining wire protocol version 1.

### Added

- Canonical encrypted secret creation, listing, rotation, and reference-aware
  deletion across the PostgreSQL domain layer, Admin API, and CLI, including
  tenant authorization, audit redaction, stale-write protection, clock-skew and
  concurrency tests, safe commit recovery, and runtime wiring.
- Phase 0 repository baseline and implementation status records.
- Phase 1 governance, architecture, threat-model, and decision records.
- Draft protocol contract 0.1.0 with wire protocol version 1.
- Draft client and Admin OpenAPI 3.1 contracts, configuration schema, stable error registry, and cross-language security vectors.
- Initial Go/PostgreSQL runtime, migration, CLI, embedded console, Compose, and single-image foundation in the working tree.

The local authenticated debug/mock gateway vertical is functional. No public
package, published image, hardware-attested production proof, or production
release exists yet.
