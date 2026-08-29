# Implementation status

Status date: 2026-08-30

Latchway is a **source-complete version 1 candidate**, optimized first for
React Native applications using the native iOS and Android SDKs. It is suitable
for local integration and release-candidate evaluation. It is **not yet a
published or supported production release**. The exact candidate still needs
live provider, physical-device, cloud, destructive-resilience, protected
supply-chain, public-tag, and public-registry evidence before `v1.0.0` may be
promoted.

## Required execution snapshot

| Required field | Current value |
| --- | --- |
| Current phase | Phase 19 canonical prior-candidate checkpoint prepared; protected RC run and stable descendant pending |
| Current objective | Land the coherent `1.0.0-rc.1` checkpoint alone on protected `main`, retain its successful candidate run, then land and revalidate the `1.0.0` descendant before external evidence, promotion, and publication |
| Last passing commit in each repository | Core RC implementation/release-tooling checkpoint `4a89b9a88c3dd6cde1c97e945fdbf37b8865e56c` (exact protected candidate pending; the complete local load remains bound to `73743b1633e4521aeda7ba1228cd18b78ef3a185`); JavaScript `afab50dcdb577be8a9ca6e94c054a7717a857f6d`; Swift/iOS `f7e3e3585c233ddff88bebb4f39402cd6398a1f2`; Android `a41c0a5fd648365258695b2fe0abda44b618b9d6`; React Native `4a7e6cebf1c4bae7672dfe21ddc01f554e3fa80c` |
| Protocol contract version | Contract `0.5.1`, wire protocol `1`, frozen normative checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Database schema version | `19` |
| Last full test time | `2026-08-29T22:42:36Z`, successful RC source/release validation (all Go tests, vet, 196 Python tests, console build, frozen API) plus synchronized SDK package checks; the last complete non-root local v1 load remains the `2026-08-29T11:18:10Z` run at `73743b1633e4521aeda7ba1228cd18b78ef3a185` |
| Passing test commands | The repository commands recorded immediately below pass at the named source commits; the complete local load command also passes at the source/load checkpoint |
| Open blockers | Local implementation/load/deployment/recovery blockers: none. Release blockers: protected `main` has not retained the required canonical RC candidate run or its stable descendant run, and exact-image live SDK/provider/device/cloud/destructive-resilience/signing/publication evidence remains unavailable |
| External credentials still required | Protected GitHub repository settings, runners, and registry publication/signing identities; Apple Distribution signing and production App Attest configuration (a physical iPhone is connected); a physical Android device plus Play Console, Google Cloud, Play Integrity, and a Play-distributed build; OpenRouter credentials; and credentials for every claimed cloud deployment |
| Next executable task | Advance protected `main` only to the signed `1.0.0-rc.1` checkpoint and wait for its `release.yml` run to pass; only then advance to the signed stable descendant and begin exact-candidate source and release evidence |

Passing repository commands at the recorded heads include:

```sh
# latchway
go test ./...
go vet ./...
go test -count=1 ./internal/quota ./internal/dataplane
python3 scripts/test_render_completion_report.py
# Run only with a new empty absolute evidence directory.
./scripts/run-local-load-gates.sh -acknowledge-load -evidence-dir /absolute/empty/evidence-dir

# latchway-js
mise exec -- pnpm check
mise exec -- pnpm verify:reproducible
mise exec -- pnpm pack:check

# latchway-ios-sdk
swift test
swift build -c release

# latchway-android (with ANDROID_HOME configured)
./gradlew test --no-daemon
./scripts/verify-local-publication.sh

# latchway-react-native-sdk
mise exec -- pnpm check
mise exec -- pnpm verify:reproducible
mise exec -- pnpm pack:check
```

## Frozen contract and release coordinates

| Field | Value |
| --- | --- |
| Intended server release | `v1.0.0` |
| Required retained prior candidate | Canonical `v1.0.0-rc.1` source checkpoint and successful protected-main `release.yml` run; no public RC tag |
| Contract version | `0.5.1` |
| Contract status | `released` (normative source freeze; not a public product-release claim) |
| Contract release time | `2026-08-29T07:14:27Z` |
| Wire protocol | `1` |
| Normative core checkpoint | `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Passing RC implementation and release-tooling checkpoint | `4a89b9a88c3dd6cde1c97e945fdbf37b8865e56c` (`1.0.0-rc.1`); exact protected candidate pending |
| Passing local source/load checkpoint | `73743b1633e4521aeda7ba1228cd18b78ef3a185` |
| Contract archive | `latchway-contract-0.5.1.tar.gz` |
| Contract archive SHA-256 | `52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754` |
| Database schema | `19` |
| Declared compatible server range | `1.0.0` through `1.0.x` |

The archive was reproduced byte-for-byte in two independent local output
directories. All four SDK locks point to the normative checkpoint above.
Release-hardening and documentation commits may descend from that checkpoint,
but must not alter `api/`; any later API drift invalidates the locks.
The current implementation candidate adopts ADR 0022's plan-authorized strict
`<15/<20/<30 ms` P50/P95/P99 correction without weakening P99, correctness,
throughput, streaming, memory, contention, or failure gates. The unchanged
complete local load suite passes at the source/load checkpoint above. A later
documentation-only repository head is not implicitly a different
implementation candidate, and any later code change requires the affected
gates to be rerun.

## Mobile-first SDK coordinates

| Component | Version | Source commit | Local status |
| --- | --- | --- | --- |
| JavaScript `@latchway/client` | `1.0.0` | `afab50dcdb577be8a9ca6e94c054a7717a857f6d` | Source, tests, examples, exports, package closure, reproducibility, clean-consumer, workflow-owned tag, and private-core evidence gates pass |
| Swift package / `Latchway` pod | `1.0.0` | `f7e3e3585c233ddff88bebb4f39402cd6398a1f2` | 65 Swift tests, release build, package consumer, CocoaPods lint, fixture, contract, unsupported-device fail-closed, and private-core evidence gates pass |
| Android `dev.latchway:latchway-*` | `1.0.0` | `a41c0a5fd648365258695b2fe0abda44b618b9d6` | 76 JVM tests, 670 Gradle task gate, stable API 37.0 installer, device-evidence fixtures, assemble/lint/local Maven/offline-consumer, and private-core evidence gates pass |
| React Native `@latchway/react-native` | `1.0.0` | `4a7e6cebf1c4bae7672dfe21ddc01f554e3fa80c` | JavaScript, codegen, synchronized exact native pins, bridge, New Architecture examples, package closure, reproducibility, podspec, workflow-owned tag, and private-sibling checkout gates pass |

The React Native compatibility manifest pins the exact JavaScript, Swift, and
Android source commits above. The native Android SDK supports API 23 or newer;
the React Native Android bridge uses API 24 or newer. Swift supports iOS 15 or
newer. Publication and physical-device claims remain separate from these local
source results.

## Implemented version 1 surface

The following work is implemented in source and covered by repository-local
tests or deterministic fixtures:

- Trusted, exact-model input preflight and hard input, output, total-token,
  request-count, cost, and concurrency enforcement using atomic
  reserve-execute-settle accounting. Calendar, rolling token-bucket,
  per-request, recovery, refund, conservative unknown-usage, retry-cost, and
  multi-scope behavior fail closed.
- OpenAI Chat Completions, Responses, and Embeddings; Anthropic Messages;
  restricted opaque HTTP; non-streaming and SSE relay; server-owned model
  rewrite; protocol capabilities; priority, weighted, deterministic sticky,
  fallback, and retry plans; attempt accounting; timeout policy; circuit-state
  observations; header filtering; and SSRF protection.
- The canonical Admin API, CLI, and embedded dashboard, including one-time
  owner bootstrap, administrator and API-token lifecycle, applications and
  environments, write-only secrets, immutable configuration revisions,
  validation/plan/activation/rollback, identity and attestation configuration,
  features/routes/upstreams/models/pricing/limits/access/abuse policy, user and
  installation operations, route simulation, requests, usage, audit,
  self-tests, health, and the first-run configuration workflow.
- Generic JWT/OIDC and Firebase, Supabase, Clerk, static asymmetric, and
  explicitly enabled symmetric identity verification; pseudonymous external
  subjects; RFC 9449 P-256 DPoP sessions; rotating refresh families; replay and
  revocation controls; and gateway signing-key rotation.
- Server and SDK implementations for Apple App Attest and Google Play
  Integrity, plus Firebase App Check and Cloudflare Turnstile risk signals.
  Debug attestation is development-only and fails closed in production unless
  explicitly allowed by policy.
- Structured redaction-safe logging, OpenTelemetry metrics/traces, analytics,
  worker heartbeats, retention and reconciliation jobs, scheduled self-tests,
  JWKS refresh, signing-key rotation, and multi-role `all`, `api`, and `worker`
  operation.
- PostgreSQL migrations through schema 19; Compose and cloud deployment assets
  for Cloud Run, AWS, Fly.io, and Cloudflare Containers; backup, restore,
  upgrade, rollback, load, failure-injection, and multi-replica evidence
  producers; and release workflows for deterministic artifacts, scans, SBOMs,
  signatures, provenance, tags, packages, containers, and post-publication
  verification.

This list describes implemented behavior and validation machinery. It does not
substitute for the external observations required by the release contract.

## Supplemental local evidence

These observations were produced locally on 2026-08-29. They support the
candidate but are not immutable protected-run release evidence.

| Area | Local result |
| --- | --- |
| Runtime image | Exact core checkout `73743b1633e4521aeda7ba1228cd18b78ef3a185` built and ran as version `1.0.0`, configured user `65532:65532` |
| Container smoke | Fresh schema-19 migration, health, readiness, doctor, read-only root filesystem, dropped capabilities, SIGTERM restart, and isolated cleanup passed; receipt SHA-256 `1db12c4f130547a75d7599b13c93ee81f714355a6aa9a366e6365e9263a9e162` |
| Multi-architecture build | Exact local OCI layout at `73743b1633e4521aeda7ba1228cd18b78ef3a185` contains `linux/amd64` and `linux/arm64`; archive SHA-256 `35dab580a652d7c930975b52ca5a97379606a3fec54b68046eddffeb0ac0f031`, index `sha256:09bb1ae785197251342fc88bc370d7d7f2a0e13bd8df948418c7803d9dc9587b` |
| Failure matrix | At exact core checkpoint `73743b1633e4521aeda7ba1228cd18b78ef3a185`, nine automated semantic groups passed; six destructive or protected-infrastructure scenarios were correctly classified `external_required` |
| Local recovery drill | Backup, fresh restore with identical state fingerprint, current upgrade, and distinct-ancestor application rollback passed; receipt SHA-256 `40b43fecde7f111575ba9b1d8a23bb49860ef9048b3acdabf80d111a732b99c3` |
| Go vulnerability scan | Exact-source `CGO_ENABLED=0`, `-trimpath` binary scan with pinned `govulncheck v1.1.4` reported zero called-symbol findings; result SHA-256 `172a57db4d2b0d373e3d2dbdac765ec52d2e2c0e5301731ec10422bbdde1e6b6` |
| Container/source vulnerability and license scans | Pinned Trivy `0.74.0` reported zero blocked `HIGH` or `CRITICAL` findings for both architectures and source policy/license gates |
| Local SBOM/provenance | Each platform has a subject-bound embedded SPDX statement and SLSA predicate; standalone SPDX 2.3 files contain 52 packages with amd64 SHA-256 `61346f0a2aaca142e040d34613077418c352707615b6317f259cc94c8eee565a` and arm64 SHA-256 `113bde74dd53a7cb213748a7ba9c5b2414bd2786c2a8513b149992916a9bd7da` |
| JavaScript package | Reproducible tarball SHA-256 `902877f7a57377eb737ce725d77abda6e7d59dab6823df77af9764ae9c2dfb7f` |
| React Native package | Reproducible exact-native-pin tarball SHA-256 `cd7c63d5047e2ab3ce413365fd81b08996a6c31643512f7568942d5a49db461b` |
| Mobile source/package evidence | Swift, Android, React Native, New Architecture examples, clean consumers, fail-closed simulator/emulator paths, and exact source pins passed; local prepublication receipt SHA-256 `763c94234e7585bd18799276b681ec9484ae0f8cd434e0143582894fdf9c9c33` explicitly retains `release_eligible: false` until physical proofs exist |
| Historical local v1 load suite | Complete at core `1f6f45b17961f8788cf8d9d71b846e88fd82c751`; idle memory, 100 RPS, 500 concurrent SSE streams, and zero-overspend contention pass, but the original initial overhead gate fails at P50/P95 with `13.077/16.728/23.605 ms` against `<5/<15/<30 ms`; that historical report correctly retains `load_targets_passed: false` |
| Corrected-target non-root local v1 load suite | Passed at clean source/load checkpoint `73743b1633e4521aeda7ba1228cd18b78ef3a185`: `complete_suite: true`, `load_targets_passed: true`, overhead `10.908333/15.156082/18.917875 ms` against strict `<15/<20/<30 ms`, 6,000/6,000 non-streaming requests with exact terminal quota, 500 SSE streams for 60 seconds with `70.875 MiB` growth and no premature completion, and exact 64 accepted/64 denied/0 unexpected contention |

The release workflow must repeat image, per-architecture scan, SBOM, load, and
resilience work against the exact published digest on protected runners. Local
artifact names and hashes are deliberately not presented as registry or
Sigstore claims.

The historical complete local load document is
`/private/tmp/latchway-v1-final-load-1f6f45b.XUv01M/load-v1.json`, SHA-256
`dfa49463558f96fe3a953bd3d6d3565398517f58d1bf04759840bb7744533187`.
It records the original 2-vCPU/2-GiB environment and all six required gates
under the superseded initial threshold. It is diagnostic history, not a pass
under the current contract or a durable release asset.

The current passing corrected-target receipt is
`/private/tmp/latchway-load-nonroot-73743b-repeat/load-v1.json`, SHA-256
`3e6acfb06053d7a3dab3b336a419b2a9a24710a45443917b80a47f8bb416c34a`.
It ran from `2026-08-29T11:15:44Z` through `2026-08-29T11:18:10Z`, recorded
idle RSS `170.84765625 MiB`, peak stream RSS `119.68359375 MiB`, stream plateau
slope `-0.09072579646475752 MiB/min`, and exact terminal quotas. It is still a
local receipt, not protected exact-image release evidence.

One exact-checkpoint diagnostic is retained transparently with JSON SHA-256
`7af0b4206ef2477a49b77d31bd672e0e833de270ad9597a2e00d9684ce0d5ce6`.
It passed P50/P95, request outcomes, terminal quotas, streams, memory, and
contention, but was correctly rejected because a single host-scheduler P99
outlier reached `59.861333 ms` against the unchanged `30 ms` bound. It is not
counted as a pass.

## External-required release gates

No connected physical Apple or Android device, valid GitHub/registry
publication session, production provider credentials, or claimed cloud account
was available for this source pass. The following gates therefore remain open:

1. Run every SDK against the exact immutable release image, including DPoP,
   error mapping, refresh, revocation, streaming, quota snapshots, and protocol
   rejection.
2. Complete a production App Attest request on a physical Apple device, a Play
   Integrity request from a Play-distributed Android build, and the equivalent
   React Native iOS and Android requests.
3. Complete OpenRouter streaming and non-streaming canaries with usage, output
   clamp, and normalized-error checks.
4. Smoke the exact image on Compose, Cloud Run, AWS, Fly.io, and Cloudflare
   Containers with provider-issued deployment evidence.
5. Run protected load, destructive failure, multi-replica, backup/restore, and
   previous-candidate upgrade/rollback drills.
6. Build the exact multi-architecture registry image; perform per-architecture
   vulnerability and license scans; create SBOMs; sign the digest; and verify
   provenance.
7. Create and verify annotated public tags and GitHub releases in all five
   repositories, then publish and post-install-test the OCI image, both npm
   packages, Swift Package/CocoaPods release, and Maven Central artifacts.

## Readiness decision

The codebase is ready for React Native/iOS/Android integration and for an
operator-controlled release-candidate run. It is not yet ready to be described
as publicly released, production-supported, physically attested, cloud-proven,
or registry-verified. The protected finalizer is the only path that may turn
this source-complete candidate into the public `v1.0.0` release.
