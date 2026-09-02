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

Release-candidate image production uses two additional protected boundaries.
The candidate checkout builds, smokes, scans, and exports both platform images
without registry or OIDC credentials. A fresh no-checkout
`release-image-publishing` job validates the exact closed image handoff, loads
it into an empty Docker credential store, and receives only `packages: write`
while pushing the platform children and assembling the candidate index. A
separate fresh no-checkout `release-evidence-signing` job validates the
unsigned evidence and registry state before receiving OIDC to sign and attest
it. Both registry-bearing jobs always log out; neither executes candidate
source or repository scripts. Configure required reviewers on both
environments and do not place reusable secrets in either one.

Bootstrap and continuously verify those environments, their unique fail-closed
sentinels, the protected `main` and immutable version-tag rulesets, and npm
trusted publishers with the [GitHub and npm release controls](github-release-controls.md)
desired-state reconciler. A privileged workflow job must assert its exact
environment sentinel before any credential, OIDC, or mutation-capable token is
used.

## First GHCR package bootstrap

The first GitHub Container Registry publish creates
`ghcr.io/latchway/latchway` as a private package even when it is produced by a
public repository. Land the preview workflow on `main`, dispatch it with that
exact current `main` SHA, and expect the first credential-free public-verifier
job to fail after the source-free publisher creates the package. A package
administrator must then open the `Latchway/latchway` container package
settings, verify that it is linked to the `Latchway/latchway` repository, and
change its visibility to **Public**. That visibility change is irreversible.
Rerun only the failed workflow jobs; the anonymous digest, child-layer, and
signature checks plus the authenticated provenance/SBOM checks must all pass.
Do not call the package published or usable before that rerun is green.

After visibility bootstrap, remove inherited human package-write access where
the organization permits it and retain the protected workflows as the only
writers. Public GHCR packages can be pulled anonymously; the release verifier
depends on that behavior and deliberately starts with an empty Docker
credential store.

Promotion separates candidate execution from every public mutation. A
zero-repository-permission candidate job (`permissions: {}` with no explicit
secret or token environment) recomputes the candidate, security, and promotion
validators. After that gate passes, a fresh source-free read-only planner uses
fixed workflow commands to produce a one-run handoff containing only fixed
release assets, canonical promotion coordinates, and a strict SHA-256 manifest
with an exact file closure. Fresh no-checkout jobs independently require that
closure, every hash, the candidate artifact hashes, and the candidate, security,
and promotion attestations before they can mutate anything. The handoff contains
neither the candidate source archive nor candidate-owned scripts.

The first write job has only `contents: write`; it creates or verifies the
annotated product tag, creates or resumes the recoverable draft, and closes the
complete fixed asset set. A second fresh job has `packages: write` but not
`contents: write`; it revalidates the source-free handoff, protected tag, draft,
and asset digests before registry authentication. That job uses a newly created
empty `DOCKER_CONFIG`, installs an unconditional exit trap before login, and
always attempts `docker logout ghcr.io`. It executes only fixed workflow
commands while verifying or advancing OCI coordinates. A third fresh job has
only `contents: write`, no registry credential, and no candidate source; it
revalidates the handoff and every intended OCI coordinate before the sole
release-publication PATCH. SDK dispatch runs only after both the OCI mutation
and immutable GitHub publication jobs succeed, and downloads the source-free
handoff rather than the candidate-source artifact.

Finalization applies the same credential boundary to public-state
reconciliation. A no-checkout read-only authority receives an evidence-only
handoff whose exact file closure, per-file size, aggregate size, and SHA-256
values were sealed before transport. It authenticates the product tag,
immutable release, fixed assets, OCI aliases, signatures, attestations, and npm
metadata using fixed workflow commands; it never receives or extracts the
candidate source archive and never runs repository scripts. Its nine-file
source-free result is closed by a second size-and-hash manifest. A fresh
`permissions: {}` runner validates that complete handoff before extracting the
candidate and runs candidate-owned verification tooling offline with no GitHub
read/admin token, release secret, registry credential, or OIDC request
credential. Candidate tooling may prepare data-only publication state, a
registry-proof proposal, and a durable archive, but it does not render the
authoritative completion report.

The fresh no-checkout signer/publisher downloads the original authenticated
evidence-only handoff as data, rechecks its strict manifest and aggregate file
closure, and independently reconstructs the five-entry public-registry proof
from the authenticated aggregate. The prepared proof must match that canonical
reconstruction byte for byte. Fixed inline finalizer logic then opens the
durable archive without extracting it, rejects links, devices, duplicate or
unsafe paths, and requires the exact directory set, file set, owner, group,
mode, timestamp, size, and SHA-256 for every retained candidate, security,
independent-review, promotion, and external-evidence byte. Only after those
checks does fixed no-checkout workflow logic create the canonical completion
report. No checked-out candidate source, candidate helper, or candidate-rendered
status/report is a trust root in the credentialed or OIDC-bearing job.

Immediately before publication the final write job re-fetches the protected
annotated tag target, release ID and metadata, exact asset names, and every
digest. The finalizer performs the same last-moment closure for the evidence tag
and draft. After publication both workflows require the release API to report
`immutable: true`, verify the automatically generated GitHub release
attestation, and run `gh release verify-asset` for every local fixed asset.
Existing drafts may be resumed only when every existing asset has the expected
digest; existing immutable releases are verification-only and accepted only
when the complete fixed asset set matches byte for byte.

The product title and body are deterministic. The body binds the exact
candidate commit and the SHA-256 of the source-attested promotion report; the
finalizer checks that value against both the downloaded report bytes and its
immutable product-release asset digest. The exact version OCI tag is
verify-or-create and never overwritten. The `X.Y`, `X`, and `latest` aliases
may advance only through an authenticated, semver-monotonic transition; a rerun
of an older release cannot move an alias backward. Promotion and final evidence
both bind every intended alias to the expected index digest.

GHCR does not provide a server-side compare-and-swap or immutable-tag control
for these transitions. Organization and package policy must therefore make the
protected release workflows the exclusive writers of stable image tags and
moving aliases. Remove inherited human package-write access where feasible,
do not issue long-lived package-write tokens, and keep preview/public-verifier
credentials unable to write stable coordinates. The workflows re-read and
verify every digest before and after each transition and fail closed on
interference, but an independent writer could still race the registry's
inspect-then-create or inspect-then-retag window. That residual non-atomic
window is an external release risk, not an immutability guarantee. Unique
preview tags avoid ordinary collisions but share the same exclusive-writer and
non-atomic registry limitation; they do not remove the stable-alias requirement.

Promotion and finalization share one repository-wide stable-release chronology
group. Before a promotion changes any moving alias, it preflights all three
aliases and requires the exact immutable `evidence/vX.Y.Z` tag, deterministic
release metadata, complete nine-asset set, and GitHub release attestation for
every earlier stable product tag and every superseded alias version. Enumerating
product tags also catches a failed promotion that created its exact immutable
tag/version coordinate but stopped before moving an alias. It then verifies
each earlier version's completion report against the retained bundle and the
exact finalizer workflow/source
identity, downloads all nine assets, matches every byte to the GitHub release
digests and `SHA256SUMS`, and matches every durable asset to the hash table in
the signed report. Only after every predecessor has final evidence does a
second phase re-close all alias states and advance them. Consequently a newer
promotion may fail safely and be retried while the preceding finalizer is
unfinished, but it cannot advance aliases and make that finalizer permanently
unrecoverable.

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
