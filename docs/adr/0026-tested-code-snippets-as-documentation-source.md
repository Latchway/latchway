# ADR 0026: Generate documentation snippets from tested source

## Context

Hand-copied quickstart and framework snippets drift from SDK APIs, package
versions, entitlements, and error handling. A syntactically plausible snippet
can still teach insecure key handling or fail in a clean consumer.

## Decision

SDK repositories own compilable examples and publish versioned documentation
bundles. Owning SDK CI compiles or runs the example before producing its bundle.
The core docs build verifies the archive, manifest, checksums, source coordinate,
and digest, then fails when the generated public output differs. Manually
maintained executable copies are forbidden.

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

Generated pages identify tested package versions and exact source coordinates.
Docs CI checks extraction drift, bundle integrity, missing sources, and
unreferenced generated output. SDK and cross-repository release gates own
compilation and clean-consumer evidence.

## Consequences

Executable examples cannot be edited only in MDX; their owning SDK source and
tests must change first. This adds bundle and synchronization work to releases,
but makes a displayed snippet traceable to a tested source coordinate and
prevents silent API or security drift.

## Status

Accepted on 2026-08-30 and implemented for the version `1.0.0` SDK source
candidates on 2026-08-31. Each owning SDK builds a deterministic, checksummed,
source-provenanced documentation bundle. The core importer strictly verifies
and locks those four archives, regenerates public snippets, catalogs, and
release-bound reference pages, and fails CI on archive, provenance, lock, or
rendered-output drift. Owning SDK CI compiles or runs the source examples from
which the bundle regions are extracted. Published-package quickstarts and clean
release-produced archives remain protected post-publication verification gates;
the checked-in local-candidate locks record `source_tree_clean: false` rather
than claiming that external release evidence already exists.
