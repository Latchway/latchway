# Completion report

Status: **incomplete — the local authenticated debug/mock proxy, atomic mixed request-count/output-token quota slice, durable request/stream concurrency leases, and configured integer pricing attribution pass, but the remaining quota and pricing capabilities, native attestation, operations, deployment, compatibility, and release are unfinished**.

This is the evidence ledger required for eventual version 1.0. “Not produced” is an explicit failing release gate.

## Release artifacts

| Artifact | Evidence |
| --- | --- |
| Core commit and tag | Passing implementation commit `e1173cfcf7dfc0c96d6f1d730c1cdee8067072ab`; no release tag |
| iOS commit and tag | Clean lock-sync commit `fd670a04004787901bb19b3ab762f4d2dc050a07` over local implementation `2972f99c59b652722a586510a9c943ac57a69a5c`; no release tag or physical App Attest proof |
| Android commit and tag | Clean lock-sync commit `cd96781426831f464fc1e5350094aab91ca11dd2` over local implementation `0042a916580d14295bd944104aae6deb2ac136c5`; no release tag or registry publication |
| JavaScript commit and tag | Clean lock-sync commit `8df68931730bad05ef110fe53e09d857b5bd61f8` over local implementation `273925d73a5a959f95664b1b1d838505dcce5f6c`; no release tag or registry publication |
| React Native commit and tag | Clean lock-sync commit `bf1d5e9319c859edc215677e6c02b7d0f91cc811` over local implementation `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0`; no release tag or registry publication |
| OCI image evidence | Local image `latchway:phase6-0a03d93` built successfully at image ID `sha256:c0dcae33d48658d41557fbf6a7886beec53a0c4a14f2322d77da179e303a32e0`; configured runtime user `65532`; no registry RepoDigest or publication |
| Contract bundle hash | Draft `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`; byte reproducible, not published |
| Database schema version | `9`, validated from fresh local PostgreSQL schemas; unreleased |

## Test evidence

At core commit `e1173cfcf7dfc0c96d6f1d730c1cdee8067072ab`, the full PostgreSQL-enabled normal and race Go suites, full vet, contract validation, and four relevant fuzz smokes pass. The concurrency quota suite passed five consecutive runs and under the race detector; the authenticated configured-pricing/concurrency PostgreSQL E2E passed with count `3` and under the race detector. Two contract-bundle builds are byte-identical at the unchanged SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`, and both `api` and migrations have zero diff. The authenticated PostgreSQL proof covers the real custom-JWT/debug-attestation/DPoP/policy/mixed-quota/protected-upstream/settlement vertical: the adapter applies and reserves an output cap of 64, each success settles 7 provider-reported output tokens and releases 57, and the shared output bucket reaches 14 used after two successes. Each success records five usage rows with exact provenance, including a dedicated `65,236` nano-USD row calculated as `request fee + ceil(input tokens * input rate / 1,000,000) + ceil(output tokens * output rate / 1,000,000)` with separate token-class ceilings. The attempt and cost row persist the catalog ID, USD, exact configuration revision, and calculated confidence; the cost row additionally carries `configured_flat_rate:<attempt-id>` provenance, and the provider-supplied cost extension is ignored. A held authenticated stream also proves denial before target acquisition/dispatch, non-stream bypass without stream state, exact denial replay, release, immediate reuse, zero `used_units`, retained lease audit rows, and no concurrency usage record. Focused quota tests add exact contention bounds, request/stream applicability, stable accepted and denied replays after release, calendar-denial precedence, all terminal outcomes, both expiry modes, tamper rejection, and settle-versus-expiry serialization. Exact opaque reservation and terminal settlement replays leave state unchanged, DPoP replay does not redispatch, and atomic daily request denial does not mutate the non-exceeded output bucket.

The JavaScript, iOS, Android, and React Native repositories have locally passing source revisions and clean lock-sync commits recorded above. Their `contract.lock` files identify the synchronized baseline core revision and bundle, not the latest implementation; lock equality is not runtime compatibility evidence.

Current-image Compose startup/smoke and registry digest capture, official Android SDK/Gradle tests, React Native CocoaPods/native-consumer validation, native server attestation fixture suites, physical-device attestation, remaining quota/pricing primitives, live upstream canary, load/soak, released-version upgrade, SBOM, license, dependency, and container security evidence remain incomplete. The local authenticated mock vertical and earlier OCI/fuzz/full-race evidence do not satisfy all Phase 18 hardening gates.

## Compatibility matrix

The draft contract is `0.1.0` and wire protocol is `1`. The current core implementation passes at `e1173cfcf7dfc0c96d6f1d730c1cdee8067072ab`; the most recently reproduced synchronized bundle baseline remains `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`, with SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.

Every SDK lock now pins core revision `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` and bundle `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`. Synchronization is complete, but each affected shared-vector and live server conformance gate must still pass before a compatibility promise or minimum released SDK/server version can be recorded.

## Security statement

- Administrative bootstrap/session/token boundaries, immutable active configuration, strict provider JWT verification, rotating fixed-endpoint key retrieval, external-subject pseudonymization, envelope encryption, protected outbound destinations, header filtering, and no-body-storage architecture are implemented and tested locally.
- The debug-attested client session plane implements identity-to-challenge/exchange, short-lived DPoP-bound access tokens, rotating refresh families, transactional replay enforcement, refresh-reuse revocation, JWKS publication, protected authorization, and current-installation revocation.
- Current-installation revocation transactionally validates the access principal and request-bound proof, consumes replay state, and revokes the installation, grants, refresh tokens, and accepted attestation keys. Adversarial, idempotency, clock-regression, race, and contention gates pass.
- Raw identity credentials, external subjects, upstream secrets, prompt bodies, attestation evidence, and proofs are excluded from normal persistence/logging boundaries by API design and tests where implemented.
- The local authenticated proxy and atomic mixed request-count/output-token reserve/settle path are implemented. Hard calendar and per-request output-token rules reserve the exact adapter-applied cap; known provider usage releases the difference, while unknown post-dispatch results, failures, and stateful reservation expiry conservatively charge the full reservation. Durable request/stream concurrency leases count only active occupancy in `reserved_units`, keep `used_units` at zero, release on settlement/pre-dispatch failure/expiry, retain audit rows, and create no usage records; trusted non-stream requests do not materialize stream capacity. Usage records preserve calculated, reported, or unknown provenance, and per-request-only/non-applicable-stream policies retain an entryless durable lifecycle. Immutable configured USD pricing uses exact separately rounded integer math and exact `effectiveAt` activation, persists catalog/revision attribution for successful and failed known usage, records explicit zero, and retains unknown selection metadata without a false cost row. Provider-reported prices are not trusted. Production native attestation trust-root verification, token buckets, hard cost limits, upstream-reported pricing, retries, the rest of the quota engine, complete operational jobs, and production deployment remain incomplete. Debug attestation is not evidence of hardware-backed trust.
- Web trust remains explicitly weaker than hardware-backed native trust.
- No unresolved issue may be interpreted as accepted merely because this report lists it.

## Operational proof

An earlier revision demonstrated clean single-image Compose startup, migration, health/readiness, and embedded-console serving. Fresh-schema PostgreSQL migrations now reach schema version 9. The latest local OCI build evidence remains the older `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` image and declares non-root user `65532`.

Current-image Compose startup, a registry RepoDigest, released-version upgrade, configuration rollback under deployment load, backup/restore, graceful shutdown under load, worker recovery, multi-role operation, and cloud-platform smoke tests have not been demonstrated.

## Remaining work

Phase 6 has a passing local debug-attested session and protected revocation gate, and the local Phase 7 authenticated mock proxy gate now passes. The refresh step-up request shape still needs an explicit contract/version decision because the safe server recovery path is a new challenge. Phase 7 still lacks its verifier CLI/live canary. Phase 8 now includes hard calendar request-count, calendar and per-request output-token enforcement, durable request/stream concurrency leases, and configured integer nano-USD attribution, but token buckets, hard cost limits, quota snapshots, overrides, upstream-reported pricing, retries, and the rest of its engine remain. The next implementation objective is token buckets followed by quota snapshots. Schema version 9 also has a bounded recovery limitation: an expired per-request-only entryless attempt cannot reconstruct its applied cap or add an unknown-output usage row; that shape has no durable capacity to recover, while normal known settlement persists provider usage. Phases 8–19 retain further open gates including native attestation, broader adapters/routing, complete administration and operations, deployment, cross-repository conformance, hardening, and release artifacts. Consequently this report does not satisfy the version-1.0 completion rule.
