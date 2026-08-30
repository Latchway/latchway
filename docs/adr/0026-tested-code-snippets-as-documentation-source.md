# ADR 0026: Generate documentation snippets from tested source

## Context

Hand-copied quickstart and framework snippets drift from SDK APIs, package
versions, entitlements, and error handling. A syntactically plausible snippet
can still teach insecure key handling or fail in a clean consumer.

## Decision

SDK repositories own compilable examples and publish versioned documentation
bundles. The core docs build extracts marked snippets, verifies their source
coordinate and digest, compiles or runs the owning example, and fails when the
rendered MDX differs. Manually maintained executable copies are forbidden.

## Alternatives

- Copy snippets during release review: rejected because review cannot reliably
  detect semantic drift across languages.
- Generate examples from OpenAPI alone: rejected because public SDK APIs are
  handwritten and platform-specific setup is not represented by OpenAPI.

## Security implications

Tests and extraction rules prevent examples from normalizing static tokens,
exported keys, provider secrets, debug attestation in production, or stale DPoP
proof reuse. Example fixtures use non-secret placeholders.

## Developer-experience implications

Readers can paste examples that match the documented package version.
Contributors update executable source once and receive a deterministic docs
diff.

## Migration implications

Existing snippets must be mapped to an owning repository source region or
rewritten as explicitly non-executable pseudocode. SDK documentation bundles
need a versioned manifest before public publication.

## Documentation implications

Generated pages identify supported package versions and source links. Docs CI
checks extraction drift, compilation, bundle integrity, missing sources, and
unreferenced generated output.

## Consequences

Executable examples cannot be edited only in MDX; their owning SDK source and
tests must change first. This adds bundle and synchronization work to releases,
but makes a displayed snippet traceable to a tested source coordinate and
prevents silent API or security drift.

## Status

Accepted on 2026-08-30 and implemented through repository-owned documentation
bundles, fixture synchronization, clean package consumers, snippet/link drift
validation, and cross-repository source conformance. Published-package
quickstarts remain a post-publication verification gate.
