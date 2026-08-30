# Protected release-domain evidence

`scripts/release-domain-evidence.py` is the producer/finalizer for six
cross-repository domains that previously had only an envelope validator:

- `live_sdk_conformance`;
- `physical_devices`;
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
All six domains have executable protected observation plans. Live-SDK and
physical-device evidence consume authenticated outputs from the existing
self-hosted device workflows; the hosted core workflow never represents a
simulator or fixture as a physical-device run.

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

For `live_sdk_conformance` and `physical_devices`, dispatch also supplies exact
run IDs and run attempts for iOS App Attest, Android Play Integrity, and the
two-job React Native physical workflow. A protected
`LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN` must have only Actions read
access to the three SDK repositories. The producer queries the Actions API and
requires the exact repository, workflow path, `workflow_dispatch` event,
`main` branch, successful conclusion, source commit, run ID, and attempt. It
also requires the completed workflow and device timestamps to fall after the
candidate was created, inside the bounded evidence window. It then downloads
only these derived artifact names:

- `app-attest-physical-<run>-<attempt>`;
- `play-integrity-physical-<run>-<attempt>`;
- `react-native-ios-physical-<run>-<attempt>`; and
- `react-native-android-physical-<run>-<attempt>`.

Every receipt has an exact file set and an attested `SHA256SUMS`. The observer
verifies the profile, evidence, and checksum subjects against the retained
Sigstore bundle, pinning the exact SDK repository, protected physical workflow,
`refs/heads/main`, and both source and signer digest to the SDK commit. These
physical producers intentionally use protected self-hosted runners, so this
verification does not apply the hosted-runner rejection used for core source,
candidate, machine-result, and final evidence attestations. The checked-out
SDK's `device-evidence.py verify` is rerun, and the receipt is rehashed after
the verifier exits. The checked-out SDK's gateway-deployment verifier is also
rerun against the retained signed statement, pinned P-256 public key, client
policy, configuration hash, image digest, core/contract identity, and gateway
origin; its canonical output must byte-match the retained verification result.

Profiles and evidence bind the exact core/SDK commits, package and contract
versions, contract bundle, OCI index digest, gateway origin and configuration,
production distribution, hardware-backed provider, and physical-device state.
React Native's linked native profile/evidence bytes must exactly equal the
independently authenticated iOS or Android receipt and its native hash/version
pins. The live-SDK domain additionally builds the exact JavaScript checkout
and runs `scripts/live-conformance.mjs` against the same HTTPS gateway. Its
protected credentials appear only in the allowlisted child environment, never
in argv or retained output.

The producer revalidates the source report and candidate manifest using the
same strict validators as the operational-resilience finalizer. Consequently
every result must bind the exact five repository commits, package tags and
versions, contract version, bundle SHA-256, core release, and immutable OCI
index digest.

Private sibling checkouts use the protected
`LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN` secret. It must be a fine-grained
Contents: read credential scoped only to the four SDK repositories. The token
is not persisted by checkout and is unnecessary when those repositories are
public.

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
  `latchway-live-sdk-harness`. Native and React Native observations come only
  from authenticated physical receipts; JavaScript comes only from the real
  live harness.
- Physical-device evidence reuses the four authenticated native/React Native
  platform observations and derives only the canonical physical-device
  claims. It is finalized and attested independently as
  `physical_devices.json`; the live-SDK document is not a substitute.
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
  The Maven observation replays verification with the exact v2 upload intent,
  deployment record, and terminal deployment status. It requires the canonical
  15-field proof, six-field embedded deployment, 144-entry public manifest,
  nine-field artifact rows, five-field checksum rows, and six-field GnuPG
  status; Portal state remains null where adoption state is inapplicable, while
  an adoption record must bind the exact verified public-manifest digest.

The fixed producer runs the real command or harness and writes its actual exit
code and redacted output. An operator-authored `status: passed` document is not
an accepted input, and the finalizer has no artifact-name escape hatch for one.

## Protected finalization

First dispatch `Protected release-domain observations` after the relevant
external operation exists, supplying the exact five repository commits and the
source/candidate run IDs. For live SDK or physical-device evidence, also supply
the three physical run IDs and exact attempts. Then dispatch `Protected release-domain evidence`
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

- all five live SDK/platform paths. The producer is implemented, but real
  evidence still requires protected physical iOS/Android runners and devices,
  production-signed or Play-distributed apps, configured App Attest and Play
  Integrity services, exact retained native receipts for React Native linkage,
  the cross-repository Actions-read token, a deployed candidate gateway, and
  protected JavaScript identity and attestation credentials;
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
