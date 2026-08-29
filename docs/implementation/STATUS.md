# Implementation status

Status date: 2026-08-29

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
| Current phase | Phase 19 final local source validation before protected release finalization |
| Current objective | Revalidate cross-repository source conformance at the passing load checkpoint, then freeze one exact candidate for the protected external release finalizer |
| Last passing commit in each repository | Core local source/load checkpoint `00197f916cd50803093a5e73bbac725e97c394e3` (implementation/performance candidate `859dae84aa5dbd42c415ca10b67725fef131874b`); JavaScript `b1738804a9519d9adb39fb31da01258224b955ea`; Swift/iOS `dc409a5d95efcc9c9b7d8d023d1155653bb680cb`; Android `e2a0e0c288f0d0b9b6d8104c48f08f764f06c029`; React Native `945e45f8df6f1f2bd7bdceb3d89903988f0b8aad` |
| Protocol contract version | Contract `0.5.1`, wire protocol `1`, frozen normative checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Database schema version | `19` |
| Last full test time | `2026-08-29T10:44:09Z`, successful completion of the unchanged self-contained local v1 load suite at `00197f916cd50803093a5e73bbac725e97c394e3` |
| Passing test commands | The repository commands recorded immediately below pass at the named source commits; the complete local load command also passes at the source/load checkpoint |
| Open blockers | Local implementation/load blockers: none. Release blockers: exact-image live SDK/provider/device/cloud/resilience/supply-chain/publication evidence remains unavailable |
| External credentials still required | Protected GitHub and registry publication/signing identities; Apple signing/App Attest configuration and a physical device; Play Console, Google Cloud/Play Integrity configuration and a Play-distributed device build; OpenRouter credentials; and credentials for every claimed cloud deployment |
| Next executable task | Run final cross-repository source conformance and clean/DCO checks at the documentation descendant, then execute the protected external release finalizer sequence |

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
| Contract version | `0.5.1` |
| Contract status | `released` (normative source freeze; not a public product-release claim) |
| Contract release time | `2026-08-29T07:14:27Z` |
| Wire protocol | `1` |
| Normative core checkpoint | `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Current implementation candidate | `859dae84aa5dbd42c415ca10b67725fef131874b` |
| Passing local source/load checkpoint | `00197f916cd50803093a5e73bbac725e97c394e3` |
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
| JavaScript `@latchway/client` | `1.0.0` | `b1738804a9519d9adb39fb31da01258224b955ea` | Source, tests, examples, exports, package closure, reproducibility, and clean-consumer gates pass |
| Swift package / `Latchway` pod | `1.0.0` | `dc409a5d95efcc9c9b7d8d023d1155653bb680cb` | Swift tests, release build, package consumer, CocoaPods lint, fixture, and contract gates pass |
| Android `dev.latchway:latchway-*` | `1.0.0` | `e2a0e0c288f0d0b9b6d8104c48f08f764f06c029` | Unit, device-evidence fixture, assemble, lint, local Maven, and offline-consumer gates pass |
| React Native `@latchway/react-native` | `1.0.0` | `945e45f8df6f1f2bd7bdceb3d89903988f0b8aad` | JavaScript, codegen, native bridge, example, package closure, reproducibility, podspec, and evidence-export gates pass |

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
| Runtime image | `latchway:v1-local-source`, image ID `sha256:d0b3ede4d520bb2a5443c8c9fe69c50e8614a2a20e05c81a6d8c3427562e87f7`, configured user `65532:65532` |
| Container smoke | PostgreSQL start/migrate, health, readiness, doctor, version, read-only root filesystem, dropped capabilities, and graceful stop passed |
| Multi-architecture build | Local OCI layout contains `linux/amd64` and `linux/arm64`; archive SHA-256 `926ada1aeba3887384ac9d4b010a94b2899b83134094d833ba4bff2a30ff4743` |
| Failure matrix | Nine automated semantic groups passed; six destructive or protected-infrastructure scenarios were correctly classified `external_required` |
| Go vulnerability scan | `govulncheck` reported zero reachable vulnerabilities in the locally built binary |
| Container vulnerability scan | Trivy reported zero `HIGH` or `CRITICAL` findings in the exported local image |
| Local SBOM | SPDX 2.3, 52 packages and 52 relationships; SHA-256 `44e96ff77d9264079906f964e76cf4920230ee37a7130d8ee69d8a0c08e325ff` |
| JavaScript package | Reproducible tarball SHA-256 `902877f7a57377eb737ce725d77abda6e7d59dab6823df77af9764ae9c2dfb7f` |
| React Native package | Reproducible tarball SHA-256 `4630ba1902efc755b5d3d5595200f4dc39189aa9c5963c72ae1e9d4adcb78fff` |
| Historical local v1 load suite | Complete at core `1f6f45b17961f8788cf8d9d71b846e88fd82c751`; idle memory, 100 RPS, 500 concurrent SSE streams, and zero-overspend contention pass, but the original initial overhead gate fails at P50/P95 with `13.077/16.728/23.605 ms` against `<5/<15/<30 ms`; that historical report correctly retains `load_targets_passed: false` |
| Corrected-target local v1 load suite | Passed at clean source/load checkpoint `00197f916cd50803093a5e73bbac725e97c394e3`: `complete_suite: true`, `load_targets_passed: true`, overhead `10.313125/16.879209/22.149626 ms` against strict `<15/<20/<30 ms`, 6,000/6,000 non-streaming requests with `5.858971 ms` maximum scheduler lag, `5.876054 ms` maximum start lag, and exact terminal quota, 500 SSE streams for 60 seconds with `65.75 MiB` growth and no premature completion, and exact 64 accepted/64 denied/0 unexpected contention |

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

The passing corrected-target receipt is
`/private/tmp/latchway-v1-final-load-00197f9-repeat.fh68aD/load-v1.json`,
SHA-256
`40fd96c97ef2dbfcb661b5dc38a086c72b47a149dac1899dbe465306ecd76f1c`.
It ran from `2026-08-29T10:41:44Z` through `2026-08-29T10:44:09Z`, recorded
idle RSS `170.38671875 MiB`, peak stream RSS `121.75390625 MiB`, stream plateau
slope `-2.6650677806911576 MiB/min`, and exact terminal quotas. It is still a
local receipt, not protected exact-image release evidence.

One prior same-commit corrected-target run is retained transparently at
`/private/tmp/latchway-v1-final-load-00197f9.jHpkKX/load-v1.json`, SHA-256
`d297ca178dc611437aa0d828671551250c9e549f1d2b243eb4bf59f4f4688b79`.
It passed corrected latency (`10.295/14.632/21.593 ms`), request outcomes,
terminal quotas, streams, memory, and contention, but was correctly rejected
because one host scheduler/start pause reached `199.7 ms` against the unchanged
`25 ms` bound. It is not counted as a pass.

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
