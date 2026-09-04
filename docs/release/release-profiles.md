# Version 1 release profiles

Latchway distinguishes public package publication from the stronger
`release-qualified` assurance claim. This keeps a small-maintainer launch from
turning absent external evidence into a pass.

The machine-readable policy is
[`../../.github/release-profiles.json`](../../.github/release-profiles.json).
`scripts/release-profile.py` validates that policy and projects one canonical
release-scope cross-repository report through a named profile. The default is
`strict_full`; selecting the narrower profile is always explicit.

## `strict_full`

This is the unchanged full-assurance profile. It requires all three local
domains and every claim in all eight external domains. It still requires an
independent human review in the protected promotion/finalization process.
The additive evaluator reports only the state of the cross-repository gate; it
does not replace the protected security workflow or independently qualify a
release.

## `single_maintainer_v1`

This profile permits a public `v1.0.0` launch with an explicitly lower
assurance label. It requires:

- passed source, promotion-precondition, and local postpublication tag checks;
- public annotated tags and GitHub releases;
- the GHCR image, all JavaScript and React Native npm packages, the SwiftPM
  tag, CocoaPods, and Maven Central publication;
- Docker Compose and Google Cloud Run evidence for the exact immutable image;
  and
- the multi-architecture image, vulnerability and license scans, SBOM,
  signature, and provenance.

It does not require an independent human reviewer. The following remain
`unverified` and are printed in every passing profile report:

- independent human review;
- live SDK, provider, physical-device, Apple distribution/extension, Play
  Integrity, Firebase App Check, and Turnstile evidence;
- AWS, Fly.io, and Cloudflare Containers evidence;
- load, failure, replica, restore, and upgrade/rollback evidence; and
- Mintlify production publication evidence.

A structurally passing local result may be described only as
`v1_profile_projection_passed_with_deferred_assurance`. It must not be
described as publication-ready, `release_qualified`, `fully_evidence_gated`,
or `independently_reviewed`. The evaluator always emits
`authentication_status: not_performed`, `publication_ready: false`, and
`release_qualified: false`; a protected workflow must authenticate the
producer runs and attestations before issuing any launch decision.

After every required publication has completed, the protected
`.github/workflows/finalize-single-maintainer-profile.yml` workflow is the only
profile-wide path that may issue
`v1_profile_publication_ready_with_deferred_assurance`. It authenticates the
exact source, candidate, core-publication, public-tag, selected-registry, and
supply-chain runs and attempts; reuses only the signed Compose and Cloud Run
captures embedded in the closed core handoff; checks out the six exact public
repository commits to prove source, promotion preconditions, and annotated
release tags; preserves the canonical strict report with its expected failed
all-domain evidence-window gate; derives a separately named profile-local
input by changing only the `local_promotion` domain projection; and gives a
fresh no-checkout signer the final decision. That signer independently
reconstructs the one-field projection and exact gates from the retained inputs.
The reclassification is permitted only because the unchanged strict report's
exact `promotion.local_preconditions` check passed: its separate
`promotion.evidence_window` check remains failed solely because it includes
strict domains this profile explicitly defers.
The decision keeps
`release_qualified`, `fully_evidence_gated`, and `independently_reviewed`
false and retains every deferred item as `unverified`.

## Evaluate an exact candidate

First produce and retain the canonical strict cross-repository report. Its
strict verdict and `local_promotion` domain are expected to remain failed when
the all-domain evidence window includes profile-deferred domains; its separate
`promotion.local_preconditions` check, local source domain, and local release
domain must pass. Retain the exact source report, the four required external
documents, and all hash-referenced artifacts in one evidence directory:

```text
external-evidence/
├── public_tags.json
├── public_registries.json
├── cloud_deployments.json
├── supply_chain.json
└── artifacts/
```

Run:

```bash
python3 scripts/release-profile.py validate-policy

python3 scripts/finalize-release-profile.py derive-profile-report \
  --strict-release-report /path/to/latchway-cross-repository-release-strict.json \
  --source-report /path/to/latchway-cross-repository-source.json \
  --external-evidence-dir /path/to/external-evidence \
  --output /tmp/latchway-single-maintainer-v1-profile-input.json

python3 scripts/release-profile.py evaluate \
  --profile single_maintainer_v1 \
  --release-report /tmp/latchway-single-maintainer-v1-profile-input.json \
  --external-evidence-dir /path/to/external-evidence \
  --output /tmp/latchway-single-maintainer-v1.json
```

The derivation preserves the unchanged failed strict report and produces the
separately named, one-field profile-local input. The evaluator revalidates
candidate coordinates, required claim closure,
timestamps, immutable image digest, artifact paths, artifact hashes, and the
seven-day evidence window. Missing evidence is `unverified`; malformed,
substituted, or tampered evidence is `failed`.

This local command does not authenticate a GitHub Actions run or Sigstore
bundle. A handwritten JSON document is not platform evidence, even when the
structural projection passes. The output deliberately cannot claim publication
readiness. Authenticate every input with its producer and attestation in a
protected workflow before making a launch decision. The strict protected
workflows and their `strict_full` semantics remain unchanged.

## Collect and finalize the selected public registries

Run `.github/workflows/release-domain-observations.yml` for
`public_registries` with `release_profile` set to `single_maintainer_v1` and
leave both documentation-production run inputs empty. Pass that observation
run to `.github/workflows/release-domain-evidence.yml`, again with
`release_profile` set to `single_maintainer_v1`. The signed document has the
exact six selected claims: GHCR, JavaScript npm, React Native npm, SwiftPM,
CocoaPods, and Maven Central. It cannot contain or imply the deferred Mintlify
claim. Omitting the profile input preserves the original strict seven-claim
behavior.

After the core and all SDK publications are successful, collect `public_tags`,
the profile-scoped `public_registries`, and `supply_chain`, then dispatch
`.github/workflows/finalize-single-maintainer-profile.yml` at the unchanged
candidate commit. Supply the exact run ID and attempt for:

- source conformance;
- the immutable candidate;
- the successful single-maintainer core release;
- public tags;
- profile-scoped public registries; and
- supply chain.

The workflow intentionally has no AWS, Fly.io, Cloudflare Containers,
Mintlify, device, provider, resilience, or reviewer inputs. It fails if main
has moved from the candidate, any producer path/run/attempt or attestation is
substituted, a selected registry claim is absent, a deferred claim is promoted,
or the regenerated strict report unexpectedly claims release readiness. Its
90-day artifact contains the authenticated profile decision, the structural
projection, the unchanged failed strict release report, the separately named
profile-local input, the sealed authority manifest, all four selected external
documents, checksums, and the final Sigstore bundle.

## Additive v1 core publication workflow

`.github/workflows/single-maintainer-release.yml` is the protected, additive
core publication path for this profile. It is intentionally fixed to
`v1.0.0`. It accepts only:

- one exact successful `.github/workflows/release.yml` candidate run and
  attempt;
- one exact successful Compose deployment-evidence run and attempt; and
- one exact successful Cloud Run deployment-evidence run and attempt.

Before its first mutation it authenticates all three producer runs, verifies
their GitHub attestations, revalidates the closed candidate and deployment
archives, reruns local release-tooling and Go gates, and verifies the candidate
index digest, both architectures, zero-high/critical vulnerability and license
reports, SPDX SBOM attestations, keyless signature, and SLSA provenance. A
fresh credentialed job may then create or adopt only the exact annotated
`v1.0.0` tag, stage a recoverable draft, promote the candidate digest to
`1.0.0`, `1.0`, `1`, and `latest`, and publish the exact asset set. Existing
coordinates are adopted only when they match; divergent tags, releases,
assets, or OCI aliases fail closed. The workflow never deletes, force-pushes,
or overwrites a divergent coordinate.

Candidate tests, deterministic handoff construction, semantic handoff
verification, registry verification, and handoff attestation run on separate
GitHub-hosted runners. Candidate code never executes on the runner that holds a
registry credential or requests the publication attestation. The final
no-checkout attestor independently closes the exact file set, manifest hashes,
scan and SPDX semantics, complete deferred list, release-policy record, and
producer attestations before requesting OIDC.

The release title, body, and retained
`latchway-single-maintainer-v1.json` record identify
`single_maintainer_v1`, keep `profile_status` equal to `incomplete`, and set
all three forbidden assurance claims to `false`. Core publication does not by
itself establish authenticated profile-wide publication readiness; the other
required public packages, postpublication checks, and producer-attestation
authentication must still pass.

The workflow reuses the existing `release-image-publishing` and
`release-evidence-signing` environments but distinguishes this lower-assurance
mode from the strict control sentinel. Add the environment-only variable
`LATCHWAY_RELEASE_PROFILE_POLICY_ID` with these exact values:

```text
release-image-publishing
  latchway-release-profile-v1:latchway:single_maintainer_v1:release-image-publishing
release-evidence-signing
  latchway-release-profile-v1:latchway:single_maintainer_v1:release-evidence-signing
```

The attested release record repeats both IDs, states that an independent
reviewer was not required, and fixes `strict_full_controls_satisfied` to
`false`. A strict-policy sentinel must never be used as evidence that reviewer
protection existed during this profile.

Its candidate and deployment producers additionally require these existing
environments and sentinels:

```text
deployment-evidence-authentication
  latchway-release-controls-v1:latchway:deployment-evidence-authentication
deployment-evidence-compose
  latchway-release-controls-v1:latchway:deployment-evidence-compose
deployment-evidence-cloud_run
  latchway-release-controls-v1:latchway:deployment-evidence-cloud_run
deployment-evidence-signing
  latchway-release-controls-v1:latchway:deployment-evidence-signing
```

Cloud Run collection also uses the existing environment secrets
`GCP_SERVICE_ACCOUNT` and `GCP_WORKLOAD_IDENTITY_PROVIDER`. The additive
publisher needs no custom secret; it uses the run-scoped GitHub token with
job-specific permissions.

The canonical `.github/release-controls.json` remains the unchanged strict
desired state and still requires an independent reviewer. If an operator
explicitly removes required reviewers to execute the single-maintainer
profile, strict control reconciliation must remain failed/unverified until the
reviewer protection is restored. That deliberate lower-assurance state must
not be represented as strict-policy compliance.

Restoring strict mode also requires removing
`LATCHWAY_RELEASE_PROFILE_POLICY_ID` from both reused environments. The strict
reconciler intentionally treats either profile-only variable as configuration
drift; leaving it in place must keep strict reconciliation failed.

After deferred observations are available, rerun the existing strict promotion
and finalization path. Do not rewrite the earlier profile report or retroactively
mark deferred entries as passed.
