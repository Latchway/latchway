# Completion report

Status: **incomplete — the local core session plane passes, but the authenticated proxy, quotas, native attestation, operations, and release are unfinished**.

This is the evidence ledger required for eventual version 1.0. “Not produced” is an explicit failing release gate.

## Release artifacts

| Artifact | Evidence |
| --- | --- |
| Core commit and tag | Passing implementation commit `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`; no release tag |
| iOS commit and tag | Clean lock-sync commit `fd670a04004787901bb19b3ab762f4d2dc050a07` over local implementation `2972f99c59b652722a586510a9c943ac57a69a5c`; no release tag or physical App Attest proof |
| Android commit and tag | Clean lock-sync commit `cd96781426831f464fc1e5350094aab91ca11dd2` over local implementation `0042a916580d14295bd944104aae6deb2ac136c5`; no release tag or registry publication |
| JavaScript commit and tag | Clean lock-sync commit `8df68931730bad05ef110fe53e09d857b5bd61f8` over local implementation `273925d73a5a959f95664b1b1d838505dcce5f6c`; no release tag or registry publication |
| React Native commit and tag | Clean lock-sync commit `bf1d5e9319c859edc215677e6c02b7d0f91cc811` over local implementation `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0`; no release tag or registry publication |
| OCI image evidence | Local image `latchway:phase6-0a03d93` built successfully at image ID `sha256:c0dcae33d48658d41557fbf6a7886beec53a0c4a14f2322d77da179e303a32e0`; configured runtime user `65532`; no registry RepoDigest or publication |
| Contract bundle hash | Draft `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`; byte reproducible, not published |
| Database schema version | `7`, validated from fresh local PostgreSQL schemas; unreleased |

## Test evidence

At core commit `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`, the full normal and race Go suites, full PostgreSQL integration set, focused PostgreSQL session race gate, 20 repeated revocation-contention runs, vet, contract validation, deterministic bundle proof, all six security-sensitive fuzz smoke targets, and the complete `make check` gate pass. The latter also covers formatting, reproducible sqlc generation, frozen console dependencies, console lint/typecheck/tests, build, and embedded-asset checks.

The JavaScript, iOS, Android, and React Native repositories have locally passing source revisions and clean lock-sync commits recorded above. Their `contract.lock` files identify the current core revision and bundle, but lock equality is not evidence of runtime compatibility with the current core.

Current-image Compose startup/smoke and registry digest capture, official Android SDK/Gradle tests, React Native CocoaPods/native-consumer validation, native server attestation fixture suites, physical-device attestation, authenticated end-to-end proxying, quota contention, live upstream canary, load/soak, released-version upgrade, SBOM, license, dependency, and container security evidence remain incomplete. The local OCI build, six current fuzz targets, and full core race suite are passing evidence, but they do not satisfy all Phase 18 hardening gates.

## Compatibility matrix

The draft contract is `0.1.0` and wire protocol is `1`. The current core implementation and deterministic bundle were validated at `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`, with bundle SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.

Every SDK lock now pins core revision `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` and bundle `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`. Synchronization is complete, but each affected shared-vector and live server conformance gate must still pass before a compatibility promise or minimum released SDK/server version can be recorded.

## Security statement

- Administrative bootstrap/session/token boundaries, immutable active configuration, strict provider JWT verification, rotating fixed-endpoint key retrieval, external-subject pseudonymization, envelope encryption, protected outbound destinations, header filtering, and no-body-storage architecture are implemented and tested locally.
- The debug-attested client session plane implements identity-to-challenge/exchange, short-lived DPoP-bound access tokens, rotating refresh families, transactional replay enforcement, refresh-reuse revocation, JWKS publication, protected authorization, and current-installation revocation.
- Current-installation revocation transactionally validates the access principal and request-bound proof, consumes replay state, and revokes the installation, grants, refresh tokens, and accepted attestation keys. Adversarial, idempotency, clock-regression, race, and contention gates pass.
- Raw identity credentials, external subjects, upstream secrets, prompt bodies, attestation evidence, and proofs are excluded from normal persistence/logging boundaries by API design and tests where implemented.
- Production native attestation trust-root verification, quotas, authenticated proxy composition, complete operational jobs, and production deployment remain incomplete. Debug attestation is not evidence of hardware-backed trust.
- Web trust remains explicitly weaker than hardware-backed native trust.
- No unresolved issue may be interpreted as accepted merely because this report lists it.

## Operational proof

An earlier revision demonstrated clean single-image Compose startup, migration, health/readiness, and embedded-console serving. Fresh-schema PostgreSQL migrations through schema version 7 and all current core normal/race/integration gates pass at `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`. A fresh local OCI build for that revision completed and declares non-root user `65532`.

Current-image Compose startup, a registry RepoDigest, released-version upgrade, configuration rollback under deployment load, backup/restore, graceful shutdown under load, worker recovery, multi-role operation, and cloud-platform smoke tests have not been demonstrated.

## Remaining work

Phase 6 has a passing local debug-attested session and protected revocation gate. The refresh step-up request shape still needs an explicit contract/version decision because the safe server recovery path is a new challenge. Phases 7–19 also contain open gates, including authenticated proxying, quotas, native attestation, broader adapters/routing, complete administration and operations, deployment, cross-repository conformance, hardening, and release artifacts. Consequently this report does not satisfy the version-1.0 completion rule. Version 1.0 must not be declared until every required artifact and post-build proof is present.
