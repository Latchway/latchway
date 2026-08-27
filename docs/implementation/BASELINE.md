# Repository baseline

Audit date: 2026-08-27 (Asia/Ho_Chi_Minh)

This document records the pre-implementation state required by Phase 0. The audit was read-only. Repository state can change after the recorded snapshot; `STATUS.md` is the current execution ledger.

## Workspace inventory

| Repository | Default branch and revision | Remote | Working tree at audit | Existing product implementation |
| --- | --- | --- | --- | --- |
| `latchway` | `main` at `2da60f89f3bb0afc38ed7ab1ecdb8bf60797bbb8`; sole commit `Added Go skill`; no tags | `https://github.com/Latchway/latchway.git` | Clean and synchronized with `origin/main` | None |
| `latchway-ios-sdk` | Unborn `main`; zero objects, refs, commits, or tags; live remote advertised no refs | `https://github.com/Latchway/latchway-ios-sdk.git` | Untracked agent-skill material | None |
| `latchway-android` | Unborn `main`; zero objects, refs, commits, or tags; live remote advertised no refs | `https://github.com/Latchway/latchway-android.git` | Empty and clean | None |
| `latchway-js` | Unborn `main`; zero objects, refs, commits, or tags; live remote advertised no refs | `https://github.com/Latchway/latchway-js.git` | Empty and clean | None |
| `latchway-react-native-sdk` | Unborn `main`; zero objects, refs, commits, or tags; live remote advertised no refs | `https://github.com/Latchway/latchway-react-native-sdk.git` | Empty and clean | None |

## Core repository classification

The initial core commit contains 633 tracked entries and 111,598 inserted lines. Every tracked path belongs to one of:

- `.agents/skills/` — 293 source skill files;
- `agent/skills/` — 293 adapted copies;
- `.claude/skills/` — 46 symlinks to `.agents/skills`;
- `skills-lock.json` — hashes and GitHub provenance for 46 `samber/cc-skills-golang` skills.

The 24 tracked Go files are duplicated Cobra CLI examples inside those skill assets. They are not Latchway packages. The skill metadata declares MIT licensing. This tooling is preserved and attributed in `NOTICE`; it must not be shipped as runtime source unless a later decision explicitly requires it.

At baseline the core repository had no:

- repository-wide agent instructions;
- product license, security policy, governance, contribution guide, README, or changelog;
- Go module, application packages, database migrations, queries, or generated code;
- OpenAPI, configuration schema, error registry, protocol manifest, or test vectors;
- dashboard, JavaScript manifest, or frontend build;
- Makefile, toolchain pin, Dockerfile, Compose file, deployment asset, or CI workflow;
- product tests, fixtures, executables, package identity, release, or tags.

No product placeholder, hard-coded success path, generated product content, local absolute workspace path, credential, signing key, service-account file, or environment file was present. There was also no product architecture to preserve or reject.

## SDK repository classification

- The iOS repository's untracked material consists only of MIT-licensed Swift concurrency and Swift Testing agent skills. It is not SDK source. Swift 6.4 and Xcode 27.0 were locally available, but no `Package.swift` existed.
- Android contained no non-Git files. Java 23.0.2 was available; Gradle and a wrapper were absent.
- JavaScript and React Native contained no non-Git files. Their future package identities are `@latchway/client` and `@latchway/react-native`, but no manifests existed.

## Build and test baseline

Core commands failed for structural reasons:

```text
go env GOMOD                 -> /dev/null
go build ./...               -> no Go module
go test ./...                -> no Go module
make test                    -> no target
docker compose config        -> no Compose configuration
```

Local core tools observed: Go 1.24.1, Node 22.18.0, pnpm 10.1.0, Docker 29.7.2, and Docker Compose 5.4.0. `psql`, `sqlc`, `goose`, `golangci-lint`, and `govulncheck` were not installed on the host.

## Baseline risks and constraints

1. All product implementation starts from an empty baseline, so compile success cannot be mistaken for feature completion.
2. The protocol must be stabilized in the core repository before SDKs invent wire behavior independently.
3. Toolchain versions must be explicitly pinned; unusually new local Apple and Java toolchains must not become accidental minimum requirements.
4. The vendored agent-skill material needs continuing license attribution and exclusion from production images.
5. Real App Attest, Play Integrity, OpenRouter, registry, and cloud validation require external accounts or credentials, but do not block fixture-based or unrelated work.

## Phase 0 gate

- All five repositories were inspected and existing content was classified.
- No existing product work was deleted or replaced.
- This baseline captures branches, remotes, commits, tags, worktrees, licenses, CI, package identities, placeholders, and architectural choices.
- The clean-tree portion of the gate is not satisfied while this uncommitted Phase 0/1 foundation is under construction. It must be rechecked after review and commit.
