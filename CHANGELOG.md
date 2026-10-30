# Changelog

All notable project changes will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows Semantic Versioning once distributable artifacts exist.

## [Unreleased]

## [1.2.0] - 2026-10-30

### Added

- Administrator account self-service (ADR 0040, Admin bundle edition 1.1.3,
  `admin_account_self_service`): change your own password, list and sign out
  your own console sessions, switch organization without signing in again,
  and see why a console session ended. Owners can list every administrator's
  API tokens with their last use, and session lists show a coarse device
  summary. `GET /admin/v1/auth/info` reports what the sign-in screen needs.
- Two-factor sign-in for administrators (ADR 0041, `admin_two_factor`): TOTP
  authenticator apps with single-use recovery codes, a `202` second-factor step
  at sign-in, an organization setting that requires it, and owner resets
  (also `latchway admin accounts reset-two-factor`).
- Passkeys for administrators (ADR 0042, `admin_passkeys`): sign in with a
  passkey alone, or use one as the second step after a password. Passkeys
  count toward an organization's two-factor requirement; adding or removing one
  needs the current password.
- Single sign-on for administrators with OpenID Connect (ADR 0043, `admin_sso`):
  one identity provider per organization, linking by verified email, optional
  account creation with a chosen role, and an option to require it for members
  other than owners. Team member lists and `latchway admin accounts list` show
  who signs in with SSO.
- Member invitations (ADR 0044, `admin_invitations`): owners send one-time
  links, optionally by email through a configured SMTP relay
  (`LATCHWAY_SMTP_*`); new people choose their own password, and existing
  accounts accept after signing in.
- Application roles (ADR 0045, `admin_application_roles`): owners can make a
  member Admin or Operator in one application without changing their role
  elsewhere, and can preview the console as another role.
- User and installation insights (ADR 0046, `admin_user_insights`): filters,
  sorts and capped totals for users and installations, server-side
  installation signals, per-user usage, impact previews for installation and
  component actions, and batched user actions that skip anyone who changed
  since the preview. `latchway` family lists show signals.
- Request search (ADR 0047, `admin_request_search`): requests show their
  platform and client request ID, can be found by client request ID, report
  a capped total, and `GET /requests/facets` counts the values behind each
  filter. `latchway requests list` takes every filter and `--total`, and
  `latchway requests facets` prints the counts.
- Configuration draft lifecycle (ADR 0048, `admin_configuration_drafts`,
  schema 40): drafts stay editable after validation until activated, can be
  discarded (kept in history), record who changed which paths, take a publish
  note, can be brought up to date with a reviewed three-way merge, and can be
  started from another environment's live configuration.
  `latchway config history|discard|promote` and `config apply --note`.
- Policy insights and simulation (ADR 0049, `admin_policy_insights`,
  schema 41): per-user usage distributions against a limit, an override list,
  plan share by feature, current limit usage for a user, failure simulation
  with the data plane's retry and fallback rules, batch simulation and saved
  scenarios. `latchway routes simulate --fail`.
- Operations history (ADR 0050, `admin_operations_history`, schema 42): a
  worker samples the server self-check every five minutes (kept 30 days),
  per-connection health from recorded attempts, a list of self-test runs, and
  display-name renames for organizations, applications and environments.
  `latchway status history`, `usage connections`, `verify runs`, and
  `applications rename` / `environments rename`.
- Analytics (ADR 0051): a month-to-date card with a straight-line month-end
  projection, per-AI-connection breakdowns, errors by code, a warning when
  usage totals are still settling, and a header attention indicator.
- The redesigned admin console, including a stepped Setup wizard.
- A pull-request CI workflow covering contracts, Go with PostgreSQL, the
  console and the live first-run test.

### Changed

- Database schema 42 (forward-only migrations 34 to 42) and Admin contract
  bundle edition 1.1.3. A 1.1.x server can't start on schema 42; rolling back
  means restoring the pre-upgrade backup. Client contract 1.1.0, wire 1/2/3 and
  the SDKs are unchanged.
- Upgrade the CLI together with the server: 1.1.x CLIs reject the response
  fields 1.2.0 adds to configuration revisions, the session check, and
  requests that recorded a platform or client request ID.
- Analytics moved to `/usage`, `/cost`, `/performance` and `/reliability`;
  links to `/latency`, `/errors` and `/attestation-failures` still redirect.
- The CLI's session check accepts the `two_factor_enrollment_required`,
  `sign_in_method` and `application_roles` fields the server sends.
- An owner's password reset now also works for accounts created by single
  sign-on, which have no password until then.
- Removing the authenticator app (`POST /auth/two-factor/disable`) keeps any
  passkeys, and recovery codes can be replaced with the password when there's
  no authenticator app. An owner's two-factor reset also removes passkeys.
- Passwords set by an owner (administrator creation or reset) must be changed
  at the administrator's next sign-in before anything else works.
- A sign-in that names no organization uses the administrator's last one.

### Fixed

- Environment lists include `active_revision_id`, which the Admin contract
  declared but the server never sent; the console showed every environment as
  unconfigured on Overview and in Settings.
- Reloading an Analytics page in the embedded console rendered a blank page;
  Analytics now lives at `/usage`, `/cost`, `/performance` and `/reliability`.
- The embedded console required Admin contract 1.0.0 while 1.1.x servers
  advertise 1.1.0, leaving it in read-only safe mode.
- A configuration draft that had been validated couldn't be edited again, so
  the console's second save on a draft failed as "out of date". Servers now
  keep never-activated drafts editable, and the console carries the draft into
  a new one on older servers.

## [1.1.7] - 2026-09-23

### Added

- Emit one redaction-safe `Client API problem` event for every Client API
  problem response, including closed endpoint, SDK/caller, failure stage,
  canonical error code, status and correlation identifiers. Raw paths, headers,
  tokens, proofs, bodies, user/install identifiers and dependency text remain
  excluded.
- Persist and log closed operational-retention failure stages so intermittent
  cleanup failures identify the affected relation or transaction boundary
  without retaining PostgreSQL error text.

### Security

- Document a Caddy runtime-log filter that deletes the entire request-header
  map and masks client addresses while preserving streaming diagnostics.

## [1.1.3] - 2026-09-10

### Added

- Accept Apple development, production, or any App Attest environments per
  server policy. Persist the actual verified key environment, never `any`;
  require explicit acknowledgment for development acceptance in Production.
- Separate accepted Apple environments from signing/distribution categories in
  Console setup. New Development setups support local signing and TestFlight;
  existing environment documents are not changed automatically.

### Fixed

- Honor explicit Development-only Play Integrity testing responses through
  session exchange, refresh, and feature access without promoting `debug` to
  device trust. Keep real verdict checks and global trust ordering unchanged.
- Require fresh App Attest or Play Integrity evidence after configuration
  revision changes; do not refresh older provider evidence into a narrowed
  policy. Preserve direct-component provider signals alongside delegation data.

### Changed

- Delegate Google service-account JWT assertions/OAuth exchange and metadata
  requests to Google's maintained Go libraries. Keep fixed endpoints/scopes,
  bounded duplicate-safe responses, cancellable refresh and secret-safe errors.
- Replace the security JSON decoder's handwritten recursive value assembly with
  Go 1.27's standard JSON decoder. Preserve exact numbers, UTF-8 policy, duplicate
  rejection, and depth/node/byte limits without changing JSON serialization.
- Share strict P-256 public-coordinate decoding between DPoP and stored signing
  keys; use the existing JWT library for ES256 signature verification. No new
  JOSE dependency, wire/schema version, key format or replay-policy change.

## [1.1.2] - 2026-09-08

### Fixed

- Release token/cost quota reservations for explicitly confirmed OpenRouter
  pre-generation request rejections. Requests and attempts still count. Unknown
  errors, timeouts and interrupted generations retain conservative settlement.
- Version failed-attempt accounting so validated reported usage can settle a new
  failed attempt without reinterpreting historical quota charges during replay.
- Read bounded, allowlisted provider error diagnostics without retaining or
  relaying raw provider messages, prompts, response bodies or credentials.
- Return valid Admin request/effective-configuration views for quota-denied
  requests; align Console and CLI validation and meaningful rejection codes.

### Added

- Add optional usage evidence separating recorded, reported and unknown units,
  including explicit missing-versus-zero input/output/cost values.
- Schema 32 records content-free input-bound components; route simulation
  includes expanded schema bytes. The conservative token calculation is unchanged.
- Schema 33 records versioned settlement evidence and safe provider diagnostics.
  Existing SDKs retain client contract 1.1.0 and wire 3; the additive Admin/bundle
  edition is 1.1.1. No historical quota corrections or prompt logging are enabled.

## [1.1.1] - 2026-09-08

### Fixed

- Schema 31 permits same-account identity verification after original session
  issuance. Schema 30's issuance-only timestamp constraint caused legitimate
  supplied-token renewal to fail with `internal_error` once the clock advanced.
  Credential issuance/expiry, required attestation, identity expiry, possession
  and replay checks remain unchanged. Contract 1.1.0 and wire 3 are unchanged.
- Add advancing-clock HTTP coverage, preserved-lifetime assertions, migration
  rollback/upgrade catalog checks and retained identity-expiry validation.

## [1.1.0] - 2026-09-08

### Added

- Contract 1.1.0 and wire protocol 3 for a native-owned app session shared
  by Swift/Kotlin and React Native, with explicit `sharedNativeCallers` host
  policy and truthful per-request caller attribution. Legacy declarations remain.
- Independent same-host delegated component sessions may use the new declaration;
  runtime denial precedes grant consumption, refresh rotation and proof acceptance.
  Root credentials, remote watch definitions and legacy runtime-specific policies
  are not adopted or merged.
- Schema 30 records nullable logical-request caller attribution for the Admin API,
  CLI and console without changing user/feature quota ownership.
- Capability-negotiated identity verification authenticates a developer-supplied
  token using existing refresh possession. Same-account recovery preserves
  installation/session keys, credentials, attestation and quota; invalid or
  different-account tokens cannot extend identity freshness. Core, native and
  React Native integration requires no authentication-provider SDK dependency.

### Changed

- Add schema 29 as a function-body-only consolidation of deferred
  terminal-attempt validation reads, preserving validation outcomes, error
  precedence, legacy settlement repair, trigger timing, and locking. Wire 2,
  the frozen schema-28 contract bundle, and SDK locks are unchanged.
- Document the exact-schema readiness boundary: schema-28 binaries are not
  application-rollback targets after migration 29. Use a verified compatible
  schema-29 release-candidate/stable pair for application rollback, or restore
  a pre-29 backup/PITR point into a fresh database for schema recovery. This
  change does not claim a passing release or load gate.

## [1.0.0] - 2026-09-01

### Added

- Add a fail-closed, separately controlled independent security-review gate
  that binds eight required reviews and every accepted lower-severity risk to
  the exact candidate source, contract, and multi-architecture image.
- Require exact-image browser conformance evidence from both Firebase App
  Check and Turnstile on provider-separated ephemeral JIT collectors, using
  five-minute single-use grants, gateway-only egress, signed lease/consumption/
  teardown receipts, unconditional grant zeroization, and runner destruction.
- Separate release-evidence authentication, candidate-controlled validation,
  and OIDC attestation across fresh runners so candidate code cannot execute
  with external-review credentials or signing authority.
- Split candidate image construction, registry publication, promotion,
  provider observation, final-record preparation, and signing into strict
  source-free credential boundaries with closed, hash-bound handoffs.
- Add bounded per-process `stale`, `closed`, `open`, and `half_open` circuit
  observations for upstream-attempt telemetry without changing deterministic
  route selection or dispatch admission.
- Add a real OTLP/HTTP export and shutdown-flush regression and run the
  credential-free release/evidence tooling in ordinary pull-request CI.

### Fixed

- Bind the default container version label to the source release-candidate
  version and reject mismatched Docker build defaults during conformance.
- Pin every PostgreSQL CI and deployment image by OCI digest and use the
  PostgreSQL 18 major-version-aware `/var/lib/postgresql` volume layout.
- Lock the complete Wrangler 4.127.1 transitive npm closure, reject non-registry
  or integrity-less entries, and reverify the predeclared closure before any
  Cloudflare credential can execute it.
- Make the embedded console's browser proof fail closed if any same-origin
  mutation leaves the canonical Admin API.
- Expire stale circuit failure history before recording a new outcome so old
  failures cannot reopen an observation window.

## [1.0.0-rc.1] - 2026-08-30

### Changed

- Establish the canonical retained release-candidate checkpoint required by
  the protected previous-candidate upgrade and application-rollback gate. The
  checkpoint does not create a public tag or alter the frozen API contract.
- Advance contract 0.5.1 for closed, provider-specific Apple App
  Attest and Google Play Integrity configuration while retaining wire protocol
  version 1; contract 0.5.0 remains the preceding sealed local checkpoint.
- Advance the draft contract to 0.4.0 for physical-model-bound input
  accounting profiles and a restricted, conservative OpenAI Chat preflight
  that enables hard calendar input/total quotas and input-priced cost
  reservation, while retaining wire protocol version 1.

### Added

- Canonical administrator lifecycle across PostgreSQL, Admin API, CLI, and the
  embedded console: bounded listing, local-account creation, role changes,
  disable/re-enable, owner password reset, last-active-owner protection, scoped
  credential revocation, tenant isolation, and value-free audit records.
- Add calendar week windows and optional server-owned IANA timezones to quota
  configuration and route-simulation output; an omitted timezone canonicalizes
  to UTC and no client-supplied timezone participates in enforcement.
- Restricted generic HTTP execution at `/proxy/{feature}/{path...}` with exact
  feature binding, generic protected destinations, method/path/body/header
  allowlists, per-route response and SSE bounds, unknown-usage settlement, and
  explicit opt-in before unsafe-method retry or fallback.
- Canonical encrypted secret creation, listing, rotation, and reference-aware
  deletion across the PostgreSQL domain layer, Admin API, and CLI, including
  tenant authorization, audit redaction, stale-write protection, clock-skew and
  concurrency tests, safe commit recovery, and runtime wiring.
- Exact rewritten-body and accounting-profile proof binding across the Chat
  adapter, policy/configuration activation, durable quota replay, conservative
  settlement, and authenticated PostgreSQL dispatch gates.
- Phase 0 repository baseline and implementation status records.
- Phase 1 governance, architecture, threat-model, and decision records.
- Draft protocol contract 0.1.0 with wire protocol version 1.
- Draft client and Admin OpenAPI 3.1 contracts, configuration schema, stable error registry, and cross-language security vectors.
- Initial Go/PostgreSQL runtime, migration, CLI, embedded console, Compose, and single-image foundation in the working tree.

Publication remains a separate, evidence-gated operation; this source release
entry does not itself claim a registry artifact, deployed image, or physical-
device attestation result.
