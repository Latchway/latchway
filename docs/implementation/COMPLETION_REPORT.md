# Version 1 candidate evidence ledger

Status: **source complete; public version 1 release not finalized**.

This file is the truthful pre-release ledger for the current source candidate.
It is not the immutable post-publication completion report required by section
39 of the A-to-Z contract. The protected finalizer renders that report only
after every release domain has authenticated evidence for one exact candidate.

## Release artifacts

| Artifact | Candidate coordinate | Current evidence |
| --- | --- | --- |
| Core | Intended `v1.0.0`; locally passing RC implementation/release-tooling checkpoint `ca26b74b6588b9c81935c5e50843a0be98fbd135`; exact protected RC candidate pending; passing local source/load checkpoint `73743b1633e4521aeda7ba1228cd18b78ef3a185`; normative contract checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` | Contract frozen and unchanged; coherent `1.0.0-rc.1` source including protected client diagnostics is prepared; non-root corrected-target load, local multi-architecture supply-chain, Compose, failure-matrix, and recovery drills passed at their named checkpoints; protected RC/stable candidate runs, exact-image evidence, public annotated product tag, and GitHub release are not claimed |
| JavaScript | `@latchway/client@1.0.0`; source `afab50dcdb577be8a9ca6e94c054a7717a857f6d` | Local reproducible package/consumer and release-workflow gates pass; npm publication not claimed |
| Swift/iOS | `Latchway` / `Latchway/AppAttest` `1.0.0`; source `f7e3e3585c233ddff88bebb4f39402cd6398a1f2` | Local Swift Package, consumer, CocoaPods, fixture, unsupported-device fail-closed, and release-workflow gates pass; public tag/package and physical proof not claimed |
| Android | `dev.latchway:latchway-*` `1.0.0`; source `a41c0a5fd648365258695b2fe0abda44b618b9d6` | Local Gradle, stable API 37.0 installer, Maven-layout, consumer, explicit emulator-rejection, and release-workflow gates pass; Maven Central and Play-distributed proof not claimed |
| React Native | `@latchway/react-native@1.0.0`; source `4a7e6cebf1c4bae7672dfe21ddc01f554e3fa80c` | Local JavaScript, synchronized exact native pins, bridge, New Architecture examples, package, and evidence-export gates pass; npm and physical-device proof not claimed |
| Contract bundle | `latchway-contract-0.5.1.tar.gz` | Two local builds are byte-identical at SHA-256 `52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754`; no public release asset claimed |
| OCI image | Intended `ghcr.io/latchway/latchway:v1.0.0` | Supplemental local multi-architecture index `sha256:09bb1ae785197251342fc88bc370d7d7f2a0e13bd8df948418c7803d9dc9587b`; no registry `RepoDigest` claimed |
| Database | Schema `20` | Migration sources, bounded diagnostics index, and local migration/runtime tests present; exact cloud/released-image migration receipts pending |

Contract `0.5.1` is marked `released` at `2026-08-29T07:14:27Z`
with wire protocol `1`. That state freezes normative source; it does not assert
that the product or packages have been publicly released.

The checkpoint and candidate are separate by design: SDK locks consume the
byte-frozen contract at the checkpoint, while the implementation candidate is
the server/CLI/dashboard and corrected performance-contract snapshot. The
source/load checkpoint is the clean documentation descendant that passed the
unchanged complete local suite. Documentation-only descendants do not rewrite
those historical coordinates. Any later code change requires a new candidate
and new affected evidence.

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
| JavaScript | 36 Vitest and 12 Node tests plus lint, typecheck, build, examples, exports, contract, package closure, clean consumer, and reproducibility; current tarball SHA-256 `dd1e797bcf14523d996ed4b510deab2ce27e2259de94cf435fe049d78faa422e` |
| Swift/iOS | 65 Swift tests, release build, consumer, CocoaPods lint, contract archive, fixture, unsupported-device fail-closed, and device-evidence schema tests pass |
| Android | 670 Gradle tasks for test/assemble/lint, release/adversarial and device-evidence suites, local Maven publication, and offline consumers pass at the synchronized source |
| React Native | 33 Vitest, 21 Node, and the device-finalization/export/gateway suites plus lint, typecheck, codegen, build, New Architecture examples, native consumers, podspec, package closure, and reproducibility; current tarball at `4a7e6cebf1c4bae7672dfe21ddc01f554e3fa80c` has SHA-256 `32c22817a73b44b42f31ef14c6b7bebfce5bca98f89ca2794019c33a40439037` |

Repository-local results demonstrate source and package integrity. They do not
replace the protected all-SDK suite against the exact released image.

### Supplemental runtime, security, and failure evidence

- A local production image at the named historical checkpoint started with
  PostgreSQL, migrated to schema 19,
  passed health/readiness/doctor/version, ran as `65532:65532` with a read-only
  root filesystem and dropped capabilities, and stopped gracefully.
- The exact local candidate OCI layout contained both `linux/amd64` and
  `linux/arm64`; archive SHA-256 was
  `35dab580a652d7c930975b52ca5a97379606a3fec54b68046eddffeb0ac0f031`
  and index digest was
  `sha256:09bb1ae785197251342fc88bc370d7d7f2a0e13bd8df948418c7803d9dc9587b`.
- Pinned `govulncheck v1.1.4` binary mode found zero called-symbol findings in
  the exact-source Go 1.27 binary. Pinned Trivy `0.74.0` found zero blocked
  `HIGH` or `CRITICAL` vulnerability, policy, or license findings in either
  architecture or the source tree.
- Both platforms have subject-bound embedded SPDX and SLSA statements.
  Standalone SPDX 2.3 SBOMs contain 52 packages; amd64 SHA-256 is
  `61346f0a2aaca142e040d34613077418c352707615b6317f259cc94c8eee565a`
  and arm64 SHA-256 is
  `113bde74dd53a7cb213748a7ba9c5b2414bd2786c2a8513b149992916a9bd7da`.
- At core checkpoint `73743b1633e4521aeda7ba1228cd18b78ef3a185`, nine
  automated failure-matrix groups passed. Six destructive/protected scenarios
  were correctly left `external_required` instead of being represented by
  synthetic success. A local backup, fresh restore with an identical state
  fingerprint, current upgrade, and distinct-ancestor application rollback
  also passed; its receipt SHA-256 is
  `40b43fecde7f111575ba9b1d8a23bb49860ef9048b3acdabf80d111a732b99c3`.
- A now-historical unchanged self-contained v1 load suite completed at core
  `1f6f45b17961f8788cf8d9d71b846e88fd82c751` in the original 2-vCPU/2-GiB
  environment. Idle memory, 100 non-streaming requests/second, 500 concurrent
  SSE streams, and exact zero-overspend contention passed. Gateway overhead was
  `13.077/16.728/23.605 ms` at P50/P95/P99 against the original initial
  `<5/<15/<30 ms` targets, so P50 and P95 failed and
  that report correctly retains `load_targets_passed: false`. The complete
  local receipt is
  `/private/tmp/latchway-v1-final-load-1f6f45b.XUv01M/load-v1.json`, SHA-256
  `dfa49463558f96fe3a953bd3d6d3565398517f58d1bf04759840bb7744533187`.
- ADR 0022 and the current release-tooling candidate
  `73743b1633e4521aeda7ba1228cd18b78ef3a185`
  adopt the plan-authorized strict `<15/<20/<30 ms` P50/P95/P99 correction
  while preserving P99 and every functional, correctness, throughput, stream,
  memory, contention, and failure gate.
- The exact non-root complete local suite passed at clean source/load
  checkpoint `73743b1633e4521aeda7ba1228cd18b78ef3a185` from
  `2026-08-29T11:15:44Z` through `2026-08-29T11:18:10Z` with
  `complete_suite: true` and `load_targets_passed: true`. P50/P95/P99 overhead
  was `10.908333/15.156082/18.917875 ms` over 1,000 samples. Idle RSS was
  `170.84765625 MiB`. The 100-RPS gate completed 6,000/6,000 requests with
  exact terminal quota. The 500-stream gate held for 60 seconds with
  `70.875 MiB` growth, `119.68359375 MiB` peak RSS,
  `-0.09072579646475752 MiB/min` slope, no premature completion, and exact
  terminal quota. Contention was exactly 64 accepted, 64 denied, zero
  unexpected, 64 used, and zero reserved.
  The local receipt is
  `/private/tmp/latchway-load-nonroot-73743b-repeat/load-v1.json`,
  SHA-256
  `3e6acfb06053d7a3dab3b336a419b2a9a24710a45443917b80a47f8bb416c34a`.
- One exact-checkpoint diagnostic, SHA-256
  `7af0b4206ef2477a49b77d31bd672e0e833de270ad9597a2e00d9684ce0d5ce6`,
  passed P50/P95 plus every functional, quota, stream, memory, throughput, and
  contention check, but was correctly rejected because a single host-scheduler
  P99 outlier reached `59.861333 ms` against the unchanged `30 ms` bound. It is
  not counted as passing evidence.

The passing suite is supplemental local evidence. Protected execution against
the exact published per-architecture image remains required and no public
release-readiness claim follows from the local result.

These items are supplemental local observations. The release workflow must
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
| Fresh migration | Historical local schema-19 image migration passed; additive schema-20 migration and integration tests pass at current source | Exact-current-image cloud/platform migration receipts |
| Configuration activation/rollback | Canonical Admin API and local concurrency/browser tests pass | Exact-candidate deployment observation under load |
| Backup/restore | Isolated backup into a fresh database restored an identical state fingerprint and passed doctor/health/readiness | Protected exact-image backup/restore drill receipt |
| Upgrade/application rollback | Current schema upgrade and distinct-ancestor application rollback passed locally | Released previous/current digest- and attestation-bound drill |
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

No protected registry-publication identity, production cloud/provider
credential set, or device visible to the release tooling was available during
this source pass. GitHub CLI access and an intermittently connected iPhone are
now available, but these gates still cannot be truthfully converted into
passing evidence by local fixtures or source inspection.

When every item above passes for the same immutable candidate, the finalizer
will produce the authoritative completion report. Until then, this ledger must
not be cited as proof that public `v1.0.0` is ready or released.
