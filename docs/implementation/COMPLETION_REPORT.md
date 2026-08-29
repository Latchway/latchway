# Version 1 candidate evidence ledger

Status: **source complete; public version 1 release not finalized**.

This file is the truthful pre-release ledger for the current source candidate.
It is not the immutable post-publication completion report required by section
39 of the A-to-Z contract. The protected finalizer renders that report only
after every release domain has authenticated evidence for one exact candidate.

## Release artifacts

| Artifact | Candidate coordinate | Current evidence |
| --- | --- | --- |
| Core | `v1.0.0`; normative checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` | Contract frozen; no public annotated product tag or GitHub release claimed |
| JavaScript | `@latchway/client@1.0.0`; source `b1738804a9519d9adb39fb31da01258224b955ea` | Local reproducible package/consumer gates pass; npm publication not claimed |
| Swift/iOS | `Latchway` / `Latchway/AppAttest` `1.0.0`; source `dc409a5d95efcc9c9b7d8d023d1155653bb680cb` | Local Swift Package, consumer, CocoaPods, and fixture gates pass; public tag/package and physical proof not claimed |
| Android | `dev.latchway:latchway-*` `1.0.0`; source `96371f1340a4fb835429290360a344d66a79454d` | Local Gradle, Maven-layout, and consumer gates pass; Maven Central and Play-distributed proof not claimed |
| React Native | `@latchway/react-native@1.0.0`; source `afc3383427830950623425f04dcba7025faff37b` | Local JavaScript, native bridge, example, package, and evidence-export gates pass; npm and physical-device proof not claimed |
| Contract bundle | `latchway-contract-0.5.1.tar.gz` | Two local builds are byte-identical at SHA-256 `52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754`; no public release asset claimed |
| OCI image | Intended `ghcr.io/latchway/latchway:v1.0.0` | Supplemental local image ID `sha256:d0b3ede4d520bb2a5443c8c9fe69c50e8614a2a20e05c81a6d8c3427562e87f7`; no registry `RepoDigest` claimed |
| Database | Schema `19` | Migration sources and local migration/runtime tests present; exact cloud/released-image migration receipts pending |

Contract `0.5.1` is marked `released` at `2026-08-29T07:14:27Z`
with wire protocol `1`. That state freezes normative source; it does not assert
that the product or packages have been publicly released.

## Test evidence

### Core and control plane

- Go unit/integration/race/vet, PostgreSQL migration/data-plane/admin/job,
  contract validation, deterministic bundle, fuzz-smoke, console lint/type/test,
  and fixture-backed browser flows were exercised throughout the version 1
  source pass.
- Trusted exact-model input/total-token preflight, atomic quota reservation and
  settlement, retry/attempt accounting, conservative unknown usage, routing,
  protocol adapters, session/DPoP, identity, attestation verifiers, Admin API,
  CLI, dashboard, telemetry, jobs, and release-evidence validators have focused
  normal, adversarial, and race coverage.
- The normative contract checkpoint is immutable. Descendant release and
  documentation changes are compatible only while `api/` remains byte-identical
  to `2f5e5e67c824e270431f1232cc6dc2824848e380`.

### SDKs and packages

| Repository | Local evidence |
| --- | --- |
| JavaScript | 36 Vitest and 11 Node tests plus lint, typecheck, build, examples, exports, contract, package closure, clean consumer, and reproducibility; tarball SHA-256 `902877f7a57377eb737ce725d77abda6e7d59dab6823df77af9764ae9c2dfb7f` |
| Swift/iOS | 64 Swift tests, release build, consumer, CocoaPods lint, contract archive, fixture, and device-evidence schema tests; one environment-dependent test skip was recorded |
| Android | 670 Gradle tasks for test/assemble/lint, release/adversarial and device-evidence suites, local Maven publication, and offline consumers pass at the synchronized source |
| React Native | 33 Vitest, 12 Node, 13 Python device-evidence, and 7 physical-evidence-export tests plus lint, typecheck, codegen, build, example/native consumers, podspec, package closure, and reproducibility; tarball SHA-256 `1713186dbda968310d923e8e903274eefb3c345e189d30a9d464773a4e56473e` |

Repository-local results demonstrate source and package integrity. They do not
replace the protected all-SDK suite against the exact released image.

### Supplemental runtime, security, and failure evidence

- A local production image started with PostgreSQL, migrated to schema 19,
  passed health/readiness/doctor/version, ran as `65532:65532` with a read-only
  root filesystem and dropped capabilities, and stopped gracefully.
- A local OCI layout contained both `linux/amd64` and `linux/arm64`; archive
  SHA-256 was `926ada1aeba3887384ac9d4b010a94b2899b83134094d833ba4bff2a30ff4743`.
- `govulncheck` found zero reachable vulnerabilities in the local binary. Trivy
  found zero `HIGH` or `CRITICAL` findings in the exported local image.
- The local SPDX 2.3 SBOM contained 52 packages and 52 relationships and had
  SHA-256 `44e96ff77d9264079906f964e76cf4920230ee37a7130d8ee69d8a0c08e325ff`.
- Nine automated failure-matrix groups passed. Six destructive/protected
  scenarios were correctly left `external_required` instead of being
  represented by synthetic success.

All five items are supplemental local observations. The release workflow must
repeat the applicable work for the exact per-architecture published digest and
produce authenticated receipts.

## Compatibility matrix

| Server | Protocol | JavaScript | Swift/iOS | Android | React Native |
| --- | --- | --- | --- | --- | --- |
| `1.0.0` (`1.0.x` maximum tested series) | Contract `0.5.1`, wire `1` | `1.0.0`, Node 24.19+ / browser | `1.0.0`, iOS 15+ | `1.0.0`, API 23+ | `1.0.0`, RN 0.82.x, iOS 15+, Android API 24+ |

Every SDK lock pins core
`2f5e5e67c824e270431f1232cc6dc2824848e380` and contract bundle
`52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754`.
The React Native manifest also pins the exact JavaScript, Swift, and Android
source commits shown under Release artifacts.

## Security statement

- Prompt and response body logging is disabled by default. Normal request,
  usage, audit, telemetry, and release evidence exclude prompt bodies,
  provider credentials, identity tokens, attestation evidence, and DPoP proofs.
- Upstream and identity-provider secrets are write-only, reference-bound,
  envelope-encrypted at rest, redacted from control-plane responses, and never
  supplied by clients. Provider destinations and forwarded headers are bounded
  and SSRF-protected.
- Access tokens are short-lived and P-256 DPoP-bound. Refresh tokens rotate;
  replay/reuse and user/application/environment/installation revocation fail
  closed across replicas. Signing-key rotation retains the necessary overlap
  for valid active sessions.
- Native App Attest and Play Integrity source paths validate configured
  application identity and challenge binding. They do not prove human identity,
  and no production physical-device claim exists until the protected device
  suite passes.
- Web App Check and Turnstile verdicts are intentionally weaker risk signals
  than native hardware-backed attestation and are composed with identity,
  origin/action/hostname checks, DPoP, replay controls, and quotas.
- A configured upstream may retain request content under its own account and
  data policy after Latchway dispatches an authorized request.
- Supplemental local scans found no reachable Go vulnerability and no high or
  critical local-image vulnerability. The exact release image still requires
  protected per-architecture vulnerability and license results, SBOMs,
  signatures, and provenance.

## Operational proof

| Operation | Source/local evidence | Release evidence required |
| --- | --- | --- |
| Clean Compose startup | Local production image/PostgreSQL smoke passed | Protected exact-image Compose receipt |
| Fresh migration | Local schema-19 migration passed | Exact-image cloud/platform migration receipts |
| Configuration activation/rollback | Canonical Admin API and local concurrency/browser tests pass | Exact-candidate deployment observation under load |
| Backup/restore | Isolated drill tooling, validation, and documentation are implemented | Protected backup/restore drill receipt |
| Upgrade/application rollback | Previous-candidate discovery, authentication, and drill tooling are implemented | Successful distinct-ancestor candidate drill |
| Graceful shutdown | Local container stop passed | Exact-candidate shutdown under protected load |
| Worker recovery/multi-replica | Jobs, heartbeats, shared replay/quota state, and failure producers are implemented | Destructive protected multi-replica/failure receipts |
| Cloud deployments | Compose, Cloud Run, AWS, Fly.io, and Cloudflare assets validate locally | Provider-issued exact-image smoke receipts for all claimed platforms |

## External-required version 1 gates

The following are unfinished release evidence, not post-1.0 enhancements:

- exact-release-image conformance for JavaScript, Swift, Android, React Native
  iOS, and React Native Android;
- real production App Attest on a physical Apple device and Play Integrity from
  a Play-distributed Android build;
- live OpenRouter non-streaming/streaming, usage, clamp, and error canaries;
- exact-image Compose, Cloud Run, AWS, Fly.io, and Cloudflare Containers smokes;
- protected load, destructive failure, multi-replica, backup/restore, and
  previous-candidate upgrade/rollback drills;
- exact per-architecture scans, license results, SBOMs, image signing, and
  provenance;
- annotated tags, GitHub releases, OCI/npm/Swift/CocoaPods/Maven publication,
  raw-asset verification, and clean post-publication consumers.

No valid GitHub/registry publication session, production cloud/provider
credential set, or connected physical device was available during this source
pass. These gates cannot be truthfully converted into passing evidence by local
fixtures or source inspection.

When every item above passes for the same immutable candidate, the finalizer
will produce the authoritative completion report. Until then, this ledger must
not be cited as proof that public `v1.0.0` is ready or released.
