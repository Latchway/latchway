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
producer and `.github/workflows/release-domain-evidence.yml` finalizer are
restricted to protected GitHub environments and `refs/heads/main`. Configure
`release-evidence`, `release-evidence-live-provider`,
`release-evidence-github-read`, `release-evidence-physical`,
`release-evidence-firebase-app-check`, `release-evidence-turnstile`, and
`release-evidence-signing` with required reviewers and prevent unreviewed
deployments before using either workflow for a release.
All six domains have executable protected observation plans. Live-SDK and
physical-device evidence consume authenticated outputs from the existing
self-hosted device workflows; the hosted core workflow never represents a
simulator or fixture as a physical-device run.

## Trust and identity model

The observation workflow authenticates and downloads two immutable GitHub
artifacts by explicit run ID and fixed name on a fresh hosted job that never
checks out or executes candidate code:

1. a passing source-scope cross-repository report;
2. the immutable OCI candidate manifest and its hash-bound artifacts.

Source retrieval is a separate protected job. It checks out the exact five
repository commits with non-persisted credentials, verifies every `HEAD`,
archives the clean worktrees, and ends without executing repository code. The
selected source-controlled observation plan consumes only those archives.
There is no uploaded-results input and no generic command input. Two additional
fresh no-checkout jobs perform the privileged observations using fixed inline
commands: one can call only the HTTPS health and Admin self-test endpoints, and
one can perform only the fixed GitHub API, release, asset, Actions-run, and
attestation reads for the selected domain. Each job emits a bounded, exact-file
manifest containing the complete candidate identity, source and candidate
hashes, per-file hashes and byte counts, and start/finish times. The
source-controlled observer consumes those captures offline; it never receives
the Admin or GitHub-read token and never invokes the Admin CLI or GitHub CLI for
those observations. Docker/Trivy/Syft/Cosign, npm, Swift, CocoaPods, and Maven
commands that need no protected credential remain selected by
`scripts/release-domain-observer.py`. Candidate-controlled validation and
manifest production run later on a fresh job without provider, sibling,
GitHub-read, or physical-artifact credentials. A final no-checkout signer job
alone receives GitHub OIDC permission and attests the validated manifest.
No job that builds or executes a candidate SDK, CLI, observer, or validator has
`id-token: write`, attestation, or artifact-metadata permission; workflow
boundary tests enforce that invariant.

The observer independently compares all five checkout `HEAD` values with the
repository commits inside the verified source identity and requires every
checkout to be clean both before and after observation. Dispatch commit inputs
cannot substitute a different SDK checkout. It also rehashes the source and
candidate documents after every command. Observation subprocesses receive an
explicit allowlisted environment; unrelated runner credentials and secret
variables are not inherited, and tool-version probes are not run implicitly.
Both candidate execution jobs additionally refuse to start if `GH_TOKEN`,
`GITHUB_TOKEN`, `LATCHWAY_ADMIN_API_TOKEN`, or either GitHub OIDC request
variable is present.

The `release-evidence-live-provider` environment runs only on a newly
provisioned, repository-scoped, single-job JIT collector named for the exact
run and attempt. It must expose a freshly issued
`LATCHWAY_ONE_TIME_LIVE_PROVIDER_GRANT`, never a reusable Admin token. The
grant is bound to repository, candidate commit, run, attempt, audience,
`run_self_tests` scope, the exact OpenRouter request, a unique JTI, and a
maximum five-minute lifetime. Its SHA-256 and the same bindings are sealed into
a root-owned externally signed collector lease. The runner declares no
long-lived, organization, administration, registry, or OIDC credential and is
restricted to DNS-pinned, TLS-verified gateway egress.

The fixed capture sends the ephemeral Admin credential only to
`POST /admin/v1/self-tests` through a mode-`0600` Curl configuration and
separately calls unauthenticated `GET /healthz`. It rejects either the exact
grant or any Admin-token shape in a response. A root-owned independent
supervisor then proves exactly one consumption, revokes and zeroizes the grant,
deregisters the runner, and arms an out-of-band destruction watchdog. The
capture retains the signed lease, consumption receipt, teardown, signatures,
and public trust root alongside the two bounded JSON responses and a hash-bound
manifest. Missing external JIT provisioning, issuer, supervisor, signature, or
destruction infrastructure makes the live-provider gate fail closed.

The `release-evidence-github-read` environment must expose
`LATCHWAY_RELEASE_EVIDENCE_GITHUB_READ_TOKEN`, a read-only token scoped only to
the five product repositories, `Latchway/latchway-docs`, and their released
packages. It must have no
repository, package, workflow, or organization write capability.
The fixed no-checkout capture uses it only for the selected domain: OCI
provenance for `supply_chain`; annotated-tag, immutable-release, and release
attestation records for `public_tags`; or immutable release metadata, exact
assets, asset attestations, and bound Actions-run records for
`public_registries`. The offline observer rejects a missing, extra, symlinked,
oversized, stale, hash-changed, coordinate-changed, or unused capture file.

For `public_registries`, dispatch additionally requires the exact successful
Mintlify production-evidence run ID and attempt; those inputs must be empty for
every other domain. The authority job authenticates the exact
`Latchway/latchway-docs` run, deployment-status or reviewed dispatch event,
`main` ref, source commit, workflow path, and one bounded artifact named
`latchway-mintlify-production-<docs-commit>-<deployment>-<run>-<attempt>`. It
accepts exactly the evidence JSON, its one-line checksum, and its Sigstore
bundle, then verifies the evidence subject against the docs production workflow
with both signer and source digest pinned to the documentation commit. The
credential-free core observer independently revalidates the source checkpoint,
production deployment, 24-hour freshness window, fixed claims, page/link/
redirect/AI observations, and every canonical result-set digest before retaining
the raw authority closure and normalized proof.

For `live_sdk_conformance` and `physical_devices`, dispatch also supplies exact
run IDs and run attempts for iOS App Attest, Android Play Integrity, and the
two-job React Native physical workflow. A protected
`LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN` must have only Actions read
access to the three SDK repositories. A fresh no-checkout physical-authority
job queries the Actions API and
requires the exact repository, workflow path, `workflow_dispatch` event,
`main` branch, successful conclusion, source commit, run ID, and attempt. It
also requires the completed workflow and device timestamps to fall after the
candidate was created, inside the bounded evidence window. It then downloads
only these derived artifact names:

- `app-attest-physical-<run>-<attempt>`;
- `play-integrity-physical-<run>-<attempt>`;
- `react-native-ios-physical-<run>-<attempt>`; and
- `react-native-android-physical-<run>-<attempt>`.

Every receipt has an exact file set and an attested `SHA256SUMS`. The isolated
physical-authority job verifies the profile, evidence, and checksum subjects
against the retained
Sigstore bundle, pinning the exact SDK repository, protected physical workflow,
`refs/heads/main`, and both source and signer digest to the SDK commit, then
retains bounded verification records beside the receipts. The secret-free
observer revalidates the exact authority file set, run metadata, artifact
metadata, receipts, and verification records. These
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
pins. The live-SDK domain builds the exact JavaScript checkout on a
credential-free hosted runner. Firebase App Check and Turnstile then execute in
different protected environments on provider-specific, ephemeral JIT runners.
Each runner is registered for one job, starts from a fresh image and workspace,
has gateway-only egress, and carries no long-lived, organization,
administration, registry, or OIDC credential. A root-owned external supervisor
that is not part of the candidate checkout verifies a signed collector lease,
accepts only the exact run/attempt, core and JavaScript commits, provider,
audience, harness hashes, candidate hashes, gateway, and request hash, and
invokes the candidate with a single-use grant whose lifetime is at most five
minutes. The grant is consumed exactly once and then zeroed and revoked.

This external supervisor is a release gate, not workflow-created trust. Before
dispatch, operators must provision the fresh JIT runner, signed lease,
root-owned run/finalize hooks, isolated signing key, gateway receipt verifier,
restricted network policy, and automatic runner destruction. The workflow
fails if the runner name or freshness contract is wrong, either hook is
writable by the job user, the lease or gateway receipt signature is invalid,
the grant is reused, teardown does not deregister and schedule destruction, or
the gateway does not issue a one-consumption receipt. The candidate cannot
self-report those properties.

The secret-free aggregation job verifies the signatures again before executing
observer code. The observer then requires both provider captures, rejects the
former reusable identity/attestation-token environment path, revalidates the
exact capture and isolation schemas, checksum closure, identity, run, provider,
gateway, harness, one-use, receipt, and teardown bindings, and retains the
capture plus every isolation file as hash-bound machine-result inputs. The two
providers must share the exact harness and gateway verification key but have
different grants, JTIs, runner identities, and protected environments.
Credentials never appear in argv or retained output.

The producer revalidates the source report and candidate manifest using the
same strict validators as the operational-resilience finalizer. Consequently
every result must bind the exact five repository commits, package tags and
versions, contract version, bundle SHA-256, core release, and immutable OCI
index digest.

Private sibling retrieval uses the protected
`LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN` secret. It must be a fine-grained
Contents: read credential scoped only to the four SDK repositories. The token
is not persisted by checkout, no repository code executes in that job, and the
token is unnecessary when those repositories are public.

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
    "contract_version": "1.0.0",
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

- Live SDK evidence requires six release-image platform runs: one JavaScript
  run with Firebase App Check, one JavaScript run with Cloudflare Turnstile,
  and the four native/React Native physical paths. It also requires explicit
  DPoP-vector, error-mapping, refresh, revocation, streaming, quota-snapshot,
  and protocol-version-rejection results. The fixed tool is
  `latchway-live-sdk-harness`. Native and React Native observations come only
  from authenticated physical receipts; JavaScript comes only from two real
  live-harness executions. The JavaScript observations bind the non-secret
  `attestation_provider` value to `firebase_app_check` or `turnstile`, and the
  public JavaScript release-image claim requires both observations.
- Physical-device evidence reuses the four authenticated native/React Native
  platform observations and derives only the canonical physical-device
  claims. It is finalized and attested independently as
  `physical_devices.json`; the live-SDK document is not a substitute.
- Live provider evidence consumes the sealed HTTPS capture, first verifies the
  `/healthz` build commit, package version, contract version, and wire protocol
  against the candidate identity, then requires the five bounded OpenRouter
  Admin self-test observations. No candidate CLI or validator process receives
  the `run_self_tests` token; it is never present in argv or retained output.
- Supply-chain evidence requires the OCI index, both exact platform children,
  both vulnerability scans, both license scans, both SPDX SBOMs, keyless cosign
  verification, and GitHub provenance verification. Tool identities are fixed
  to Docker/Buildx, the source-controlled validators for the attested candidate
  Trivy/SPDX reports, Cosign, and GitHub attestation verification.
- Public-tag evidence requires an annotated tag, immutable GitHub release, and
  authenticated release-verification observation for every one of the five
  repositories, all consumed from the sealed GitHub authority capture.
- Public-registry evidence requires the exact GHCR digest, the ordered
  four-package JavaScript npm release set, the React Native npm package, Swift
  package resolution, CocoaPods resolution, Maven Central resolution, and the
  verified production documentation deployment. The JavaScript proof requires
  exactly 31 fixed release assets plus at least one authenticated adoption
  record for each of `client`, `openai`, `vercel-ai`, and `langchain`; it
  independently validates the aggregate package, candidate, publish-input, and
  post-publish schemas at versions 2, 2, 2, and 3 respectively. It also
  requires a passing pinned offline OSV scan, exact annotated-tag evidence,
  the source checkout's contract lock and complete fixture hashes, exact
  four-tarball `SHA256SUMS`, and recomputed SHA-1/SHA-256/SHA-512/integrity.
  Every npm archive must be an exact regular-file closure whose entries,
  unpacked bytes, package manifest, translated workspace peers, client
  contract lock, and `dist` bytes match the reviewed evidence.
  The JavaScript observation also retains the four exact released npm
  tarballs as separate raw artifacts (at most 10 MiB each). They add exactly
  four aggregate/finalizer authority rows; the final credentialed verifier
  reopens those bytes and recomputes every ordered `dist` row and the aggregate
  instead of trusting a rebound normalized observer assertion.
  The final public-registry verifier revalidates the retained source-conformance
  document and uses its contract version, locked core checkpoint, bundle hash,
  wire version, and generated-fixture closure as independent contract authority.
  The core authority source archive is deliberately a clean Git checkout: it
  contains neither `node_modules` nor generated `dist`, so this credential-free
  core job does not install dependencies or claim a second source rebuild. It
  instead recomputes the ordered reproducibility aggregate from the four
  released archive `dist` closures. The separately required React Native
  release gate performs the independent clean `pnpm` build from the same
  locked JavaScript commit before accepting these dependencies.
  GitHub release assets, immutable-asset verification, source attestations, and
  npm provenance/adoption workflow runs are consumed only from the sealed
  GitHub authority capture; public registry resolution itself remains live and
  credential-free.
  Source-attestation capture is an exact union with those production
  verifier loops: all JavaScript and Android release assets; every React
  Native asset except its derived `.tgz.sha256`; and every iOS asset except its
  derived source-archive `.sha256`. This includes both iOS and React Native
  `docs-bundle-<version>.tar.gz` subjects.
  At GitHub's 64-asset release bound the exact capture-manifest maximum is
  `230 + 245 + 21 + 31 + 7 = 534` rows: JavaScript, React Native, iOS,
  Android, and documentation respectively. The uploaded authority artifact
  therefore permits 535 files including `manifest.json`; max and max-plus-one
  production-path regressions keep that boundary closed. The four retained
  JavaScript tarballs are already among those captured release-asset bytes, so
  they do not increase the 534-row GitHub capture maximum; they add four files
  only when the observer carries the same bytes into the authenticated
  aggregate/finalizer handoff.
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
supplied. Neither job runs in ordinary CI. The Firebase App Check and
Turnstile environments each receive a separately minted, run-bound one-use
grant containing only that provider's identity and attestation capability; a
reusable identity token, generic attestation token, or static per-provider
token is rejected by the observer path. The grant is exposed only to the
root-owned collector hook for its selected provider and is destroyed during
unconditional teardown. The
physical Actions-read token is confined to its no-checkout authentication job.
The `run_self_tests` Admin token and GitHub-read token are confined to their
respective fixed no-checkout capture jobs. Candidate observation, aggregation,
and signing run on fresh runners without those credentials. None of these
tokens may be copied into raw output.

The retained output contains:

- the external domain JSON consumed by `cross-repo-conformance.py`;
- the domain JSON's separately retained GitHub Sigstore bundle;
- the exact source report, candidate manifest, machine-results manifest, and
  all three Sigstore bundles;
- redacted machine result envelopes and their raw outputs; and
- for each JavaScript provider, the exact capture plus `ISOLATION_SHA256SUMS`,
  signed lease and teardown, execution record, signed gateway-consumption
  receipt, gateway verification key, harness manifest, and redacted report;
  and
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

- all six live SDK/platform paths. The producer is implemented, but real
  evidence still requires protected physical iOS/Android runners and devices,
  production-signed or Play-distributed apps, configured App Attest and Play
  Integrity services, exact retained native receipts for React Native linkage,
  the cross-repository Actions-read token, a deployed candidate gateway, and
  separately minted Firebase App Check and Turnstile one-use grants, two fresh
  provider-specific JIT runners, the external signed-lease supervisor and
  isolated keys, gateway receipt signing, restricted network policy, and
  externally enforced teardown/destruction;
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
