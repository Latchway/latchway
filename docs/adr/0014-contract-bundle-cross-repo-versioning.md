# ADR 0014: Versioned cross-repository contract bundles

## Context

Five repositories implement one security protocol. Copying examples manually permits silent drift and incompatible SDK releases.

## Decision

Each core release publishes `latchway-contract-<version>.tar.gz` containing client/Admin OpenAPI, configuration schema, error registry, protocol manifest, test vectors and `SHA256SUMS`. Generation is deterministic. Every SDK pins contract version, core release, bundle hash and server compatibility range in `contract.lock`; CI verifies drift and conformance.

## Alternatives

- Git submodules: couple checkout workflows and do not identify release compatibility.
- Fetch default-branch files in CI: mutable and non-reproducible.
- Duplicate contracts manually: guaranteed divergence.

## Consequences

Core contract changes precede SDK updates. Release automation publishes the bundle and dispatches SDK update work. Internal DTO generation is reproducible from the pinned bundle.

## Security implications

Hashes and immutable release artifacts prevent accidental or supply-chain substitution. Fixtures contain test-only keys clearly isolated from production secrets. Signature/provenance verification can be added without changing bundle contents.

## Migration implications

Wire-breaking changes increment protocol metadata and compatibility declarations. SDKs can test old/new bundles during a migration window; React Native waits for compatible native and JavaScript packages.

## Status

Accepted beginning with contract 0.1.0 on 2026-08-27.
