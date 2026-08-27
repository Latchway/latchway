# Completion report

Status: **incomplete — substantial local implementation, not an end-to-end gateway or release**.

This is the evidence ledger required for eventual version 1.0. “Not produced” is an explicit failing release gate.

## Release artifacts

| Artifact | Evidence |
| --- | --- |
| Core commit and tag | Passing implementation commit `c83703e3eb226451ca3928b91982dfb376f35b4a`; no release tag |
| iOS commit and tag | Implementation in progress; no passing implementation commit or tag |
| Android commit and tag | Passing local implementation commit `0042a916580d14295bd944104aae6deb2ac136c5`; no release tag or registry publication |
| JavaScript commit and tag | Passing implementation commit `273925d73a5a959f95664b1b1d838505dcce5f6c`; no release tag or registry publication |
| React Native commit and tag | Implementation in progress; no passing implementation commit or tag |
| OCI image digest | Not produced for the current revision |
| Contract bundle hash | Draft `1228820f87744334ec8091b9ebbe737500016daa844175bd1ad64fd0095d1afd`; byte reproducible, not published |
| Database schema version | `3`, validated from fresh local PostgreSQL schemas; unreleased |

## Test evidence

The core full Go suite passes against isolated PostgreSQL schemas, including the Admin API/bootstrap and identity-store integration gates. Core vet, contract validation, identity race tests, console lint/typecheck/16 tests/build/reproducibility, JavaScript SDK lint/typecheck/22 tests/build/examples/package/reproducibility, and Android independent Kotlin/JVM compilation plus 34 static tests also pass.

Cross-repository conformance, current-image Compose rebuild, official Android Gradle tests, native server fixture suites, physical-device attestation, authenticated end-to-end proxying, quota contention, fuzzing, full race coverage, live upstream canary, load/soak, upgrade, SBOM, license, dependency and container security evidence is not yet complete.

## Compatibility matrix

The draft contract is `0.1.0`, wire protocol `1`, at core revision `5c98dc4d656d8140e0b4af90f42ea6d884f0d60a`. Every SDK lock identifies that revision and bundle checksum. JavaScript and Android have committed locally passing implementations, but no compatibility promise or minimum released SDK/server version exists yet; see `COMPATIBILITY.md`.

## Security statement

- Administrative bootstrap/session/token boundaries, strict provider JWT verification, rotating fixed-endpoint key retrieval, external-subject pseudonymization, P-256 DPoP primitives, envelope encryption, protected outbound destinations, header filtering, and no-body-storage architecture are implemented and tested locally.
- Raw identity credentials, external subjects, upstream secrets, prompt bodies, attestation evidence, and proofs are excluded from normal persistence/logging boundaries by API design and tests where implemented.
- Attestation trust-root verification, access/refresh session issuance and rotation, replay persistence, revocation, quotas, signed active configuration, authenticated proxy composition, operational jobs, and production deployment remain incomplete.
- Web trust remains explicitly weaker than hardware-backed native trust.
- No unresolved issue may be interpreted as accepted merely because this report lists it.

## Operational proof

An earlier revision demonstrated clean single-image Compose startup, migration, health/readiness, and embedded-console serving. Fresh-schema PostgreSQL migrations and all current core integration tests pass at `c83703e`. A current OCI rebuild, released-version upgrade, configuration rollback, backup/restore, graceful shutdown under load, worker recovery, multi-role operation, and cloud-platform smoke tests have not been demonstrated.

## Remaining work

Phases 4 and 6–19 still contain open gates, and Phase 5 is not wired into an active session endpoint. Consequently this report does not satisfy the version-1.0 completion rule. Version 1.0 must not be declared until every required artifact and post-build proof is present.
