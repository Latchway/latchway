# Latchway version 1 master plan

The original A-to-Z contract defines twenty phases. The implementation phase
is complete in source. Promotion remains evidence-gated: source completion does
not authorize claims about physical devices, providers, clouds, public tags, or
registries that were not observed for the exact immutable candidate.

## Phase ledger

| Phase | Objective | Source status | Release evidence status |
| --- | --- | --- | --- |
| 0 | Repository audit | Complete across all five repositories | Baseline and source histories recorded |
| 1 | Governance, contracts, threat model, ADRs | Complete; contract `0.5.1`, wire `1`, checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` | Deterministic frozen bundle and SDK locks pass locally; public bundle asset pending |
| 2 | Go/PostgreSQL/CLI/dashboard/image foundation | Complete; single binary and embedded dashboard support `all`, `api`, and `worker` | Local non-root image and PostgreSQL smoke pass; exact public digest pending |
| 3 | Database and administrative bootstrap | Complete through schema 20 | Local normal, race, authorization, bounded diagnostics-index, and migration tests pass |
| 4 | Immutable configuration store | Complete, including validation, plan, ETags, activation, rollback, cache, and reconciliation | Local concurrency and rollback gates pass |
| 5 | Identity verification | Complete for generic OIDC/JWT, Firebase, Supabase, Clerk, static asymmetric, and explicitly enabled symmetric JWT | Local mock/fixture and adversarial gates pass; production issuer/provider observations remain release inputs |
| 6 | RFC 9449 DPoP and sessions | Complete for challenge/exchange, refresh rotation, replay, revocation, signing keys, and JWKS | Local normal/race/fuzz/conformance gates pass |
| 7 | First end-to-end proxy | Complete with deterministic mock, CLI verification, streaming, settlement, and replay safety | Local end-to-end passes; live OpenRouter canary pending |
| 8 | Quota, pricing, and usage | Complete for trusted token preflight, multi-scope hard quotas, pricing, reserve/settle/recover, retries, provenance, snapshots, and overrides | Local PostgreSQL contention, recovery, overflow, race, and fuzz gates pass; protected load/resilience run pending |
| 9 | Protocols and routing | Complete for OpenAI Chat/Responses/Embeddings, Anthropic Messages, restricted opaque HTTP, weighted/sticky/priority routing, fallback/retry, timeout, attempt accounting, and circuit observations | Local adapter, malformed-stream, policy, SSRF, and routing gates pass; live provider matrix pending |
| 10 | Apple App Attest and Swift SDK | Server verifier and Swift source/package are complete | Fixture/package gates pass; physical production App Attest and RN-iOS proof pending |
| 11 | Play Integrity and Android SDK | Server verifier and Android source/publication layout are complete | Fixture/Gradle/local-Maven gates pass; Play-distributed device and RN-Android proof pending |
| 12 | JavaScript SDK | Browser and Node implementations, examples, package closure, and release tooling complete | Local source/package/reproducibility gates pass; npm publication pending |
| 13 | React Native SDK | TurboModule, native bridges, identity callback, fetch integration, diagnostics, example, and exact native pins complete | Local JavaScript/native/package gates pass; physical devices and npm publication pending |
| 14 | Admin API, CLI, and dashboard | Complete canonical control plane, including wizard, configuration, secrets, administrators/tokens, users/installations, simulation, request/usage/audit views, self-tests, and health | Local Go, PostgreSQL, console, and Playwright gates pass |
| 15 | Observability and operational jobs | Complete logging, OpenTelemetry, analytics, reconciliation, retention, scheduled self-tests, key rotation, JWKS refresh, and heartbeats | Local redaction/job/race gates pass; protected multi-replica/worker recovery evidence pending |
| 16 | Deployment assets | Complete for Compose, Cloud Run, AWS, Fly.io, and Cloudflare Containers, with migration/secret/health/backup/restore/upgrade guidance | Local image/Compose smoke passes; exact-image cloud smokes pending |
| 17 | Cross-repository conformance | Complete tooling, shared vectors, contract locks, release-image suites, and compatibility manifest | Source/fixture/package gates pass; protected live exact-image and public-bundle scopes pending |
| 18 | Hardening | Complete source fuzz/race/adversarial/review, load/failure producers, scanners, SBOM/signing/provenance automation, and release validation | Supplemental local image scan/SBOM/failure results pass; protected exact-image load, destructive failure, per-arch scans, signing, and provenance pending |
| 19 | Documentation and version 1 release | Documentation and fail-closed promotion/finalization machinery complete in source | Final report, tags, GitHub releases, packages, image, and post-publication verification pending |

## Remaining execution sequence

Only externally observed release work remains. It must run in this order for one
immutable candidate:

1. Produce and attest the exact multi-architecture candidate image and SDK
   artifacts on protected runners.
2. Run live all-SDK conformance, OpenRouter canaries, physical App Attest/Play
   Integrity tests, cloud smoke tests, and operational resilience drills against
   those exact artifacts.
3. Run per-architecture vulnerability/license scans, SBOM validation, signing,
   provenance verification, load, failure injection, backup/restore, and
   previous-candidate upgrade/rollback.
4. Aggregate only authenticated, candidate-bound, unexpired evidence. Any
   mismatch, skip, stale receipt, or missing domain blocks promotion.
5. Create annotated tags and GitHub releases, publish the OCI/npm/Swift/
   CocoaPods/Maven artifacts, and verify raw registry bytes and clean-consumer
   installation.
6. Render and attest the immutable completion report only after every public
   coordinate and post-publication result agrees.

## Promotion rule

`v1.0.0` is complete only when every Definition of Done item has exact release
evidence and all five public repositories and registries agree. Until then the
correct state is **source-complete candidate**, never “production ready” or
“released.” External credentials and hardware do not justify weakening,
skipping, or fabricating a gate.
