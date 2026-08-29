# Protected release-domain evidence

`scripts/release-domain-evidence.py` is the producer/finalizer for the five
cross-repository domains that previously had only an envelope validator:

- `live_sdk_conformance`;
- `live_provider`;
- `supply_chain`;
- `public_tags`; and
- `public_registries`.

It does not run in normal CI, publish anything, or manufacture evidence when an
external account, registry, provider, device, or release does not exist. The
manually dispatched `.github/workflows/release-domain-observations.yml`
producer and `.github/workflows/release-domain-evidence.yml` finalizer are both
restricted to the `release-evidence` GitHub environment and
`refs/heads/main`. Configure that environment with required reviewers and
prevent unreviewed deployments before using either workflow for a release.
Four domains have executable protected observation plans. The live-SDK domain
has the same strict result/finalization contract but is intentionally blocked
until the existing self-hosted SDK receipts and a real JavaScript live harness
can be authenticated and merged without treating hosted fixtures as devices.

## Trust and identity model

The observation workflow checks out the exact five repository commits and
requires both the dispatch SHA and core `HEAD` to equal the candidate. It
downloads two immutable GitHub artifacts by explicit run ID and fixed name:

1. a passing source-scope cross-repository report;
2. the immutable OCI candidate manifest and its hash-bound artifacts.

It then executes the selected, source-controlled observation plan itself.
There is no uploaded-results input and no generic command input. Exact Admin
self-test, Docker/Trivy/Syft/Cosign/GitHub, tag/release API,
npm, Swift, CocoaPods, and Maven commands are selected by
`scripts/release-domain-observer.py`. The workflow seals their output in a
machine-results manifest and attests that manifest with GitHub OIDC.

The observer independently compares all five checkout `HEAD` values with the
repository commits inside the verified source identity and requires every
checkout to be clean both before and after observation. Dispatch commit inputs
cannot substitute a different SDK checkout. It also rehashes the source and
candidate documents after every command. Observation subprocesses receive an
explicit allowlisted environment; unrelated runner credentials and secret
variables are not inherited, and tool-version probes are not run implicitly.

The producer revalidates the source report and candidate manifest using the
same strict validators as the operational-resilience finalizer. Consequently
every result must bind the exact five repository commits, package tags and
versions, contract version, bundle SHA-256, core release, and immutable OCI
index digest.

The finalizer accepts only the artifact name derived from the domain and
candidate commit. It queries the GitHub Actions API and requires the supplied
run to be a completed successful `workflow_dispatch` run of
`.github/workflows/release-domain-observations.yml` on `main` at the exact
candidate SHA. An arbitrary workflow run or user-selected artifact name cannot
enter the finalizer.

Before emitting a domain document, the finalizer verifies all three retained
Sigstore bundles with `gh attestation verify`:

- source report: `Latchway/latchway/.github/workflows/cross-repository-conformance.yml`;
- candidate manifest: `Latchway/latchway/.github/workflows/release.yml`; and
- machine-results manifest: `Latchway/latchway/.github/workflows/release-domain-observations.yml`.

Every verification pins `refs/heads/main`, the exact source digest, the exact
signer workflow digest, the repository, and the signer workflow, and denies
self-hosted runners. A manifest created locally, by another repository,
workflow, ref, source commit, or runner class is therefore not release
evidence. Source and candidate workflows retain their own attestation bundles
inside their artifacts; an absent bundle is a hard failure, not an implicit
online-trust fallback.

The finalizer also attests the completed domain document and retains that
fourth bundle as `<domain>.attestation.sigstore.json`. Promotion and release
conformance verify this bundle against the exact finalizer workflow, candidate
source and signer digests, `main`, the core repository, and a hosted runner
before parsing any protected-domain claims. The bundle is deliberately outside
the domain document's artifact list because a document cannot hash its own
future attestation.

## Machine-result contract

The observation workflow's raw directory has an exact file set. It contains one result
file for every fixed observation required by the selected domain and only the
raw artifacts referenced by those files. Unknown files, symlinks, traversal,
duplicate JSON keys, non-UTF-8 data, stale timestamps, oversized files, hash
substitution, and changes during validation or copying are rejected.

Each result is named by replacing dots in its observation ID with hyphens and
adding `.json`. For example,
`provider.openrouter.non-streaming` is
`provider-openrouter-non-streaming.json`:

```json
{
  "schema_version": 1,
  "kind": "latchway_release_machine_result",
  "domain": "live_provider",
  "observation": "provider.openrouter.non-streaming",
  "started_at": "2026-08-29T10:10:00Z",
  "finished_at": "2026-08-29T10:11:00Z",
  "candidate": {
    "core_commit": "<exact 40-character commit>",
    "core_release": "v1.0.0",
    "contract_version": "0.5.1",
    "bundle_sha256": "<exact 64-character SHA-256>",
    "oci_image_digest": "ghcr.io/latchway/latchway@sha256:<exact digest>",
    "repositories": {
      "core": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
      "javascript": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
      "ios": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
      "android": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
      "react_native": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"}
    }
  },
  "tool": {
    "name": "latchway-admin-self-test",
    "version": "1.0.0",
    "invocation_sha256": "<SHA-256 of the fixed, secret-free invocation descriptor>"
  },
  "exit_code": 0,
  "artifacts": [
    {
      "path": "artifacts/provider-openrouter-non-streaming/self-test.json",
      "sha256": "<SHA-256 of the retained redacted response>"
    }
  ]
}
```

The result schema intentionally has no `claims`, `claim`, `passed`, `success`,
or `verdict` field. Those fields are rejected rather than copied. A successful
machine exit plus its retained, non-empty raw output is an observation; only
the attested finalizer maps the complete fixed observation set to the public
claim names. A missing or nonzero result leaves the domain unproducible.

Raw artifacts must be redacted at the producer boundary. The finalizer also
rejects common authorization, cookie, password, API-key, GitHub-token,
OpenAI-style key, and AWS-access-key shapes. Never place environment dumps,
HTTP authorization headers, provider request or response bodies, prompts,
identity credentials, attestation payloads, device identifiers, or plaintext
secrets in the artifact. The live-provider producer should retain the
canonical redacted Admin self-test result, not upstream traffic.

## Fixed observations

The exact observation-to-claim mapping and expected tool identities are code,
not workflow input. They are defined by `CLAIM_REQUIREMENTS` and
`OBSERVATION_TOOLS` in `scripts/release-domain-evidence.py`.

- Live SDK evidence requires five release-image platform runs and explicit
  DPoP-vector, error-mapping, refresh, revocation, streaming, quota-snapshot,
  and protocol-version-rejection results. The fixed tool is
  `latchway-live-sdk-harness`. The generic hosted producer currently refuses
  this domain; see the explicit prerequisite below.
- Live provider evidence first verifies the HTTPS gateway `/healthz` build
  commit, package version, contract version, and wire protocol against the
  candidate identity, then requires the five bounded OpenRouter Admin
  self-test observations. The bounded token is present only in the child
  process environment selected by `--api-token-env`, never in argv or output.
- Supply-chain evidence requires the OCI index, both exact platform children,
  both vulnerability scans, both license scans, both SPDX SBOMs, keyless cosign
  verification, and GitHub provenance verification. Tool identities are fixed
  to Docker/Buildx, the source-controlled validators for the attested candidate
  Trivy/SPDX reports, Cosign, and GitHub attestation verification.
- Public-tag evidence requires an annotated tag and GitHub release observation
  for every one of the five repositories.
- Public-registry evidence requires the exact GHCR digest, both npm packages,
  Swift package resolution, CocoaPods resolution, and Maven Central resolution.

The fixed producer runs the real command or harness and writes its actual exit
code and redacted output. An operator-authored `status: passed` document is not
an accepted input, and the finalizer has no artifact-name escape hatch for one.

## Protected finalization

First dispatch `Protected release-domain observations` after the relevant
external operation exists, supplying the exact five repository commits and the
source/candidate run IDs. Then dispatch `Protected release-domain evidence`
with that successful observation run ID. Artifact names are derived, not user
supplied. Neither job runs in ordinary CI. The bounded live-provider token is
read only from the protected environment and must never be copied into raw
output.

The retained output contains:

- the external domain JSON consumed by `cross-repo-conformance.py`;
- the domain JSON's separately retained GitHub Sigstore bundle;
- the exact source report, candidate manifest, machine-results manifest, and
  all three Sigstore bundles;
- redacted machine result envelopes and their raw outputs; and
- JSON results of all three GitHub attestation verifications.

The finalizer writes into an empty absolute directory through an atomic staging
directory. It never overwrites an existing evidence set. Every retained file is
mode `0600`. Finalizer inputs and raw results are named in the domain document
and hash-bound by SHA-256; the subsequently created document-attestation bundle
is authenticated by Sigstore and verified directly downstream.

## External blockers remain evidence, not implementation shortcuts

This tooling makes absent proof fail closed; it does not make external proof
appear. Before version 1 release evidence can pass, the responsible protected
producers must still execute against the exact candidate:

- all five live SDK/platform paths. Core does not run native/RN fixture scripts
  on a generic hosted macOS runner. A remaining producer tranche must consume
  the exact attested artifacts from iOS
  `.github/workflows/physical-app-attest.yml`, Android
  `.github/workflows/physical-play-integrity.yml`, and React Native
  `.github/workflows/physical-device-evidence.yml`, pinning each SDK workflow,
  source and signer digest to the source identity without rejecting their
  intentional self-hosted runners. It must combine those receipts with a real
  JavaScript live harness and cover error mapping, refresh, installation
  revocation, and protocol-version rejection. Until then the protected hosted
  producer exits with `live_sdk_external_receipts_required` and no machine
  manifest can be attested for this domain;
- a bounded live OpenRouter self-test using an operator-owned credential;
- image signature/provenance and scan tools against the published candidate;
  and
- public tag, GitHub release, GHCR, npm, Swift, CocoaPods, and Maven resolution
  after publication.

No placeholder result, local unit test, debug attestation, registry fixture, or
synthetic provider response satisfies those gates.

## Local tests

Normal CI exercises only fixture-based rejection and workflow-policy tests:

```bash
python3 -m unittest -v \
  scripts/test_release_domain_observer.py \
  scripts/test_release_domain_evidence.py \
  scripts/test_release_workflows.py
```

They require no network access or credentials.
