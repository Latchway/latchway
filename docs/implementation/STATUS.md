# Implementation status

## Current phase

The core-repository portion of Phase 1 — Governance, Contracts, and Threat Model — is implemented and validated in the working tree. The phase-wide gate remains open until review, commit, and SDK contract-lock propagation. The runnable Phase 2 foundation passes its Compose health gate, while remaining Phase 2 checklist work and independent Phase 3 database/bootstrap work continue.

## Current objective

Review and lock protocol contract `0.1.0` / wire protocol `1`, complete the remaining development-foundation checklist, and finish the auditable one-time administrative bootstrap slice.

## Last passing commit in each repository

“Passing” here means the last immutable baseline known not to contain a failing product test; blank repositories have no executable product tests.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `2da60f89f3bb0afc38ed7ab1ecdb8bf60797bbb8` | Clean baseline containing development-agent skills only; the passing product work below is uncommitted |
| `latchway-ios-sdk` | None; unborn `main` | No product manifest or tests |
| `latchway-android` | None; unborn `main` | No product manifest or tests |
| `latchway-js` | None; unborn `main` | No product manifest or tests |
| `latchway-react-native-sdk` | None; unborn `main` | No product manifest or tests |

## Protocol contract version

Contract `0.1.0`; wire protocol `1`; status `draft`.

## Database schema version

`2`. The running PostgreSQL 18.6 development service reported `current: 2`, `available: 2`, and `up_to_date: true`.

## Last full test time

2026-08-27T17:25:09+07:00 for the contract checks and live foundation verification in the shared, uncommitted working tree. This is not a cross-repository release test.

## Passing test commands

- `python3 scripts/validate-contracts.py` — parsed JSON/YAML, resolved OpenAPI and schema references, checked OpenAPI structure and operation IDs, matched problem codes to the registry, validated examples/vectors, recomputed canonical attestation hashes, and verified DPoP ES256 signatures and expected semantics.
- Two independent `python3 scripts/build-contract-bundle.py --output-directory <temporary-directory>` runs followed by `cmp -s` — byte-identical `latchway-contract-0.1.0.tar.gz` archives, SHA-256 `71ab98ae70a54f00d7d116d96b0561f4a36248a08bd7fb815decd1da6fd2b17d`.
- `shasum -a 256 -c SHA256SUMS` in each extracted archive — every bundled file verified.
- `docker compose up -d --build` — console lint/typecheck, seven frontend tests, frontend build, all Go package tests, image build, PostgreSQL startup, and Latchway startup passed in the shared working tree.
- `docker compose ps` — both `postgres:18.6-alpine` and `latchway` reported healthy.
- `docker compose exec -T latchway /latchway migrate status --output json` — schema `current=available=2`.
- `curl --fail --silent --show-error http://127.0.0.1:8080/healthz`, `/readyz`, and `/` — build/protocol metadata, database/schema readiness, and the embedded console returned successfully.

The deterministic archive is validation evidence only; it has not been published as a release asset.

## Reproducible toolchain pins

- Go `1.27.0`.
- PostgreSQL image `18.6-alpine`.
- Node `24.19.0`, `@types/node` `24.13.3`, and pnpm `10.15.0`.

Node `24.19.0` is an intentional operational pin: the official image used by the build publishes that LTS patch, while the initially considered `24.20.0` tag is not currently available. The pin must be advanced only with a successful image build and console test run.

## Open blockers

- The Phase 1 contract is not yet reviewed, committed, published, or consumed by SDK `contract.lock` files; the locally built archive is draft evidence.
- The root private security contact or GitHub private-reporting configuration must be verified before public release.
- The runnable foundation is not a functional gateway: identity, attestation, DPoP sessions, policy, proxying, quota settlement, secrets, and public SDK flows remain unimplemented.
- Baseline GitHub Actions, the intended `sqlc` workflow, SDKs, a conformance server, and production deployment assets remain outstanding at this snapshot.
- Host tools `sqlc`, `golangci-lint`, `govulncheck`, and `psql` were absent at baseline; the reproducible development workflow must provision or containerize every tool it requires.

## External credentials still required

- Apple Developer team, App Attest identifiers/environment, and a physical supported device.
- Google Cloud/Play Integrity project, Play-distributed package/signing digest, and a suitable device.
- OpenRouter key and pinned inexpensive validation model.
- Container/package registry ownership and release signing credentials.
- Cloud deployment accounts and managed PostgreSQL instances for platform smoke tests.

None of these credentials blocks Phase 2 or fixture-based security and conformance work.

## Next executable task

Review the validated Phase 1 bundle and propagate exact lock metadata to SDK repositories; finish the remaining Phase 2 checklist; then complete and test the Phase 3 administrative bootstrap and audit invariants against schema version 2.
