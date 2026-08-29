# Immutable product and evidence releases

Latchway publishes two immutable GitHub releases for each stable version. They
have different purposes and neither is mutated after publication.

- `vX.Y.Z` is the product release. Promotion creates it as a draft, uploads the
  candidate, contract, SBOM, security, and promotion-evidence assets, and then
  publishes it once. SDK publication and public conformance observe this tag.
- `evidence/vX.Y.Z` is the final-evidence release. Its annotated tag targets the
  same exact core candidate commit. The finalizer creates or reconciles a draft
  only after every release-scope evidence domain has passed, uploads the
  authoritative completion report, checksum manifest, attestations, public
  state, and durable raw-evidence archive, and then publishes it once.

Both workflows first require the repository immutable-release setting through
the versioned GitHub API. After publication they require the release API to
report `immutable: true`, verify the automatically generated GitHub release
attestation, and verify every local asset against that attestation. Existing
drafts may be resumed only when every existing asset has the expected digest;
existing immutable releases are accepted only when the complete fixed asset set
matches byte for byte.

The evidence release exists only after those post-publication checks succeed.
The completion report therefore names `evidence/vX.Y.Z` as its publication
target without asserting that the evidence release already existed when the
pre-publication report bytes were rendered.

The durable `latchway-release-evidence-v1.tar.gz` asset contains the exact
secret-scanned security inputs and the exact physical-device receipt/proof bytes
used by the release gates, plus their manifests and attestations. This makes the
release revalidatable after GitHub Actions transport artifacts expire.
