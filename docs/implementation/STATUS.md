# Implementation status

Status date: 2026-08-29

Latchway is a **source-complete version 1 candidate**, optimized first for
React Native applications using the native iOS and Android SDKs. It is suitable
for local integration and release-candidate evaluation. It is **not yet a
published or supported production release**. The exact candidate still needs
live provider, physical-device, cloud, destructive-resilience, protected
supply-chain, public-tag, and public-registry evidence before `v1.0.0` may be
promoted.

## Frozen contract and release coordinates

| Field | Value |
| --- | --- |
| Intended server release | `v1.0.0` |
| Contract version | `0.5.1` |
| Contract status | `released` (normative source freeze; not a public product-release claim) |
| Contract release time | `2026-08-29T07:14:27Z` |
| Wire protocol | `1` |
| Normative core checkpoint | `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Contract archive | `latchway-contract-0.5.1.tar.gz` |
| Contract archive SHA-256 | `52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754` |
| Database schema | `19` |
| Declared compatible server range | `1.0.0` through `1.0.x` |

The archive was reproduced byte-for-byte in two independent local output
directories. All four SDK locks point to the normative checkpoint above.
Release-hardening and documentation commits may descend from that checkpoint,
but must not alter `api/`; any later API drift invalidates the locks.

## Mobile-first SDK coordinates

| Component | Version | Source commit | Local status |
| --- | --- | --- | --- |
| JavaScript `@latchway/client` | `1.0.0` | `b1738804a9519d9adb39fb31da01258224b955ea` | Source, tests, examples, exports, package closure, reproducibility, and clean-consumer gates pass |
| Swift package / `Latchway` pod | `1.0.0` | `dc409a5d95efcc9c9b7d8d023d1155653bb680cb` | Swift tests, release build, package consumer, CocoaPods lint, fixture, and contract gates pass |
| Android `dev.latchway:latchway-*` | `1.0.0` | `96371f1340a4fb835429290360a344d66a79454d` | Unit, device-evidence fixture, assemble, lint, local Maven, and offline-consumer gates pass |
| React Native `@latchway/react-native` | `1.0.0` | `c8716b99ac70bc12f8a8fe40fd678e83301f9317` | JavaScript, codegen, native bridge, example, package closure, reproducibility, podspec, and evidence-export gates pass |

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
| React Native package | Reproducible tarball SHA-256 `205c471a443f4175d145ebac21da800611a7ef23311ca665579afdbdbd2be7f9` |

The release workflow must repeat image, per-architecture scan, SBOM, load, and
resilience work against the exact published digest on protected runners. Local
artifact names and hashes are deliberately not presented as registry or
Sigstore claims.

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
