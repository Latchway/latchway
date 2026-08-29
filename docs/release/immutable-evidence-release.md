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

Both workflows make the immutable-release setting check their first remote
preflight. The protected release environment must provide
`LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN`, a fine-grained read-only token with
`Administration: read` for all five Latchway release repositories and no
contents, Actions, packages, or administration-write permission. The workflow
accepts only the exact versioned API response shape
`{"enabled":true,"enforced_by_owner":<boolean>}`. The ordinary workflow token
and cross-repository dispatch token are never used for this administration
read.

Every workflow or standalone finalizer that invokes GitHub release or
attestation verification first requires GitHub CLI 2.97.0 or newer. Earlier
versions are rejected because they include known release-verification token
disclosure and signer-workflow identity-matching flaws. The retained release
attestation evidence is a canonical projection of the validated signed bundle;
CLI transport URLs and time-varying diagnostic fields are not hashed into the
immutable record.

Promotion creates the product tag, recoverable draft, and complete fixed asset
set before changing any stable OCI alias. Immediately before publication it
re-fetches the protected annotated tag target, release ID and metadata, exact
asset names, and every digest. The finalizer performs the same last-moment
closure for the evidence tag and draft. After publication both workflows
require the release API to report `immutable: true`, retain and structurally
verify the automatically generated GitHub release attestation against the exact
repository, tag-ref object, release ID, and complete asset set, and run
`gh release verify-asset` for every local fixed asset. Existing drafts may be
resumed only when every existing asset has the expected digest; existing
immutable releases are verification-only and accepted only when the complete
fixed asset set matches byte for byte.

The product title and body are deterministic. The body binds the exact
candidate commit and the SHA-256 of the source-attested promotion report; the
finalizer checks that value against both the downloaded report bytes and its
immutable product-release asset digest. The exact version OCI tag is
verify-or-create and never overwritten. The `X.Y`, `X`, and `latest` aliases
may advance only through an authenticated, semver-monotonic transition; a rerun
of an older release cannot move an alias backward. Promotion and final evidence
both bind every intended alias to the expected index digest.

GitHub's Update Release endpoint does not document an atomic `If-Match`
precondition for the publish PATCH. The workflows therefore capture the exact
validated draft representation and ETag, require a supported conditional GET
to return `304 Not Modified` immediately before the sole publish PATCH, and
serialize promotion/finalization. This closes detectable draft changes but is
not a server-side compare-and-swap on the unsafe request. Repository policy
must give the protected release environment and dedicated release workflow
exclusive write authority over drafts during finalization; another release
writer in the remaining micro-window could otherwise cause an irreversible
failure that post-publication verification can detect but not repair.

The evidence release exists only after those post-publication checks succeed.
The completion report therefore names `evidence/vX.Y.Z` as its publication
target without asserting that the evidence release already existed when the
pre-publication report bytes were rendered.

The durable `latchway-release-evidence-v1.tar.gz` asset contains the exact
secret-scanned security inputs and the exact physical-device receipt/proof bytes
used by the release gates, plus their manifests and attestations. This makes the
release revalidatable after GitHub Actions transport artifacts expire.
