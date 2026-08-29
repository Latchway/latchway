# Final release record

`finalize-release-record.yml` is the last, post-publication v1 release gate. It
does not publish a candidate, create a tag, create a GitHub release, or publish
an SDK package. It runs only on protected `main` in the `release` environment
after those operations and after release-scope cross-repository conformance has
passed.

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
verify the exact npm package versions and `gitHead`, CocoaPods release, Swift
tag, every Maven Central module, and the signed/provenanced OCI index digest.
The finalizer additionally performs fresh checks for:

- the annotated core tag object and exact candidate target;
- the existing non-draft, non-prerelease GitHub release;
- the immutable OCI index and stable version tag digest;
- the OCI Cosign identity and GitHub provenance; and
- both npm package versions, commits, and SHA-512 integrity metadata.

Registry coordinates accepted by the renderer are derived from the five exact
repository coordinates in the attested conformance report. They are not
workflow inputs. The rendered domain table preserves the public-registry
document hash and every hash-bound raw proof artifact, so the record identifies
the observed package metadata, integrity/checksum, signature, and OCI proof
bytes rather than recording only a boolean claim.

## Output and resumability

`render-completion-report.py` validates the proof chain offline and renders a
deterministic `COMPLETION_REPORT.md` release asset. It contains the exact five
repository commits, versions, and annotated tags; OCI index and platform
digests; contract, wire protocol, bundle hash, and database schema; package
coordinates; all release evidence domains; automated security checks;
operational/mobile proof; candidate artifact hashes; and hashes of its four
input documents.

The workflow attests that exact Markdown file and publishes it with
`COMPLETION_REPORT.attestation.sigstore.json`. Publication is verify-or-add:

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
add the missing valid bundle. The final report, bundle, and verified public
state are also retained as a 90-day workflow artifact.

The checked-in `docs/implementation/COMPLETION_REPORT.md` remains source
documentation. It must not claim dynamic publication facts. The release asset
produced here is the authoritative immutable record for a specific public tag.
