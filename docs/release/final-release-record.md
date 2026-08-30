# Final release record

`finalize-release-record.yml` is the last, post-publication v1 release gate. It
does not publish the product candidate or an SDK package. It runs only on
protected `main` in the `release` environment after those operations and after
release-scope cross-repository conformance has passed. It does create or resume
the separate annotated `evidence/vX.Y.Z` tag and draft, attach the complete
fixed evidence set, and publish that evidence release immutably.

## Required inputs

Dispatch the workflow with the exact stable core tag and candidate commit, plus
the run ID and run attempt for each of these successful protected-main runs:

- the immutable candidate producer (`release.yml`);
- the candidate security producer (`security.yml`); and
- release-scope cross-repository conformance
  (`cross-repository-conformance.yml`, scope `release`).

Run attempts are part of the authority. A rerun changes the attempt number, so
an operator cannot silently substitute artifacts under an already approved run
ID. The finalizer checks each run's event, conclusion, head branch, head SHA,
attempt, and active workflow path before downloading its fixed-name artifact.

## Fail-closed proof chain

The finalizer verifies the retained Sigstore bundles for the candidate,
security report, and release-scope conformance report. Every verification is
bound to the exact candidate source digest, signer digest, `refs/heads/main`,
repository, and expected producer workflow, and rejects self-hosted signers.
It then recomputes the candidate and security validators against the clean
candidate checkout.

The release-scope report is not a user assertion. Its attested `release_ready`
verdict transitively covers the authenticated raw observations for all required
domains, including public tags and registries. In particular, those producers
compare the exact npm registry tarballs to the reviewed release bytes and
retain the raw registry view, provenance, signatures, Sigstore material, and
any authenticated adoption record. They also verify the CocoaPods proof, Swift
release assets, every signed Maven Central module plus its deployment records,
and the signed/provenanced OCI index digest.
The finalizer additionally performs fresh checks for:

- the annotated core tag object and exact candidate target;
- the existing non-draft, non-prerelease GitHub release;
- the immutable OCI index plus the exact version, `X.Y`, `X`, and `latest` tag
  digests;
- the OCI Cosign identity and GitHub provenance; and
- both npm package versions, SHA-512 integrity, registry signatures, trusted
  publisher identity, and source-bound SLSA provenance. npm does not inject
  `gitHead` into these reviewed prebuilt tarballs, so commit identity comes
  from the authenticated provenance and retained registry/adoption evidence.

Finalization shares the promotion workflow's repository-wide chronology group.
A later promotion must authenticate this release's immutable final-evidence tag,
complete fixed asset set, and GitHub release attestation before it may advance
any `X.Y`, `X`, or `latest` alias. It also verifies the retained completion
report attestation against this exact finalizer workflow and candidate commit,
then closes every downloaded asset against the release API digest,
`SHA256SUMS`, and the signed report's durable-asset hash table. The promotion
performs those checks for every superseded alias before its separate mutation
phase, so overlapping release runs fail closed without making an older
finalizer impossible to resume.

Registry coordinates accepted by the finalizer are derived from the five exact
repository coordinates in the attested conformance report. They are not
workflow inputs. The finalizer independently reconstructs the public-registry
proof's exact five paths and hashes from the authenticated aggregate and
requires the unprivileged prepared proof to be byte-identical. The canonical
report binds the resulting proof and durable archive hashes, so the immutable
record identifies the retained package metadata, integrity/checksum,
signature, and OCI proof bytes rather than recording only a boolean claim.

## Output and resumability

The unprivileged preparation job may run the repository validators, including
`verify-public-registry-proof.py`, but neither that helper's status nor any
candidate-rendered Markdown is accepted by the publisher. A fresh no-checkout
finalizer validates the original evidence-only authority manifest, reopens the
durable tar archive without extracting it, compares its exact entry closure and
every file hash to the authenticated inputs, and only then generates the
deterministic `COMPLETION_REPORT.md` with fixed inline workflow logic. The
report contains the five repository commits, versions, and annotated tags;
contract and OCI identity; exact public package coordinates; every required
release evidence domain; and the SHA-256 of each durable release asset.

The workflow attests that exact Markdown file and publishes it with
`COMPLETION_REPORT.attestation.sigstore.json`. It creates or resumes the draft,
uploads every fixed asset, re-fetches the protected tag target and exact draft
asset set immediately before publication, proves the exact validated ETag is
still current with a conditional GET, then verifies the immutable release and
every asset. GitHub does not document atomic `If-Match` support for this PATCH,
so the protected release environment must remain the exclusive draft writer.
Reconciliation is verify-or-add while the release is a draft:

- an absent asset may be uploaded;
- one existing report must have exactly the newly rendered SHA-256 and bytes;
- one existing bundle must verify that report under this workflow's exact
  candidate identity;
- duplicate assets, unavailable digests, a bundle without its report, or any
  byte mismatch fail; and
- no asset is overwritten or deleted.

Because a fresh Sigstore bundle is not byte-deterministic, an exact rerun reuses
and re-verifies the existing bundle instead of creating a different one. If an
earlier run stopped after uploading only the report, the rerun may create and
add the missing valid bundle while the draft remains mutable. Once published,
reruns perform verification only; no post-publication upload is permitted. The
final report, bundle, and verified public state are also retained as a 90-day
workflow artifact.

The checked-in `docs/implementation/COMPLETION_REPORT.md` remains source
documentation. It must not claim dynamic publication facts. The release asset
produced here is the authoritative immutable record for a specific public tag.
