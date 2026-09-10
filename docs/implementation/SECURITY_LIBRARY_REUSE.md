# Security library reuse

Source implementation, 8 September 2026; included in published server 1.1.3
on 10 September 2026. This batch implements the
high-priority maintenance audit without changing wire/schema versions, identity
derivation, persisted keys, ciphertext, quota settlement, or replay transactions.
Publication and deployment receipts are separate from this implementation report.

## Google credentials

`cloud.google.com/go/auth` v0.23.2 now owns service-account JWT assertions and OAuth
exchange through its explicit `New2LOTokenProvider`. Google's metadata client
v0.9.0 owns metadata request mechanics. `gax-go/v2` v2.23.0 is an indirect module.
These Google modules are Apache-2.0 licensed. The generated Play Integrity REST
client and Firebase Admin SDK are not added.

The retained shared adapter enforces:

- Only validated service-account credentials, fixed token endpoint and Play
  Integrity scope. No ambient ADC files, executable credentials or impersonation.
- Metadata requests pinned to the complete metadata URL even if environment
  variables suggest a different host. The default metadata transport has no proxy.
- No redirects; bounded response reads, expected JSON media type, strict duplicate
  rejection and validated integer lifetime. Extra ID-token fields cannot change
  access-token processing.
- Cancellable cache waiting and request deadlines, the existing refresh/lifetime
  policy, and expiry anchored to request start rather than HTTP completion.
- Redacted error/formatting surfaces and an explicitly discarded Google logger,
  including when environment settings would otherwise enable HTTP debug logs.

The high-level Google credential/cache APIs are not used because they change
refresh and cancellation semantics. `Options.Now` governs cache policy/returned
expiry; assertion timestamps now use Google's wall clock and default ten-second
skew allowance. Google reparses the private key during refresh; this is a
refresh-frequency cost, not a per-proxy-request operation.

Production source across the two old files and new shared adapter is 481 → 475
lines. The main benefit is transferring standard protocol implementation to its
maintainer, not a large deletion count. Security policy is intentionally retained.

Sources: [Google auth API](https://pkg.go.dev/cloud.google.com/go/auth#New2LOTokenProvider),
[metadata client](https://pkg.go.dev/cloud.google.com/go/compute/metadata).

## Public keys and DPoP

`internal/jwk.ParseP256` consolidates the strict coordinate decoder formerly
duplicated by DPoP and persisted signing keys. It retains fixed-width/canonical
base64url, zero-coordinate rejection and Go's point validation. Callers retain
their own member/algorithm allowlists and error mapping. Existing
`jwt.SigningMethodES256.Verify` replaces manual compact-signature hashing/splitting.

The proposed `go-jose/v4` dependency is deliberately absent. A v4.1.5 prototype
accepted newline-containing coordinate input and serialized an off-curve key
where Latchway rejects them. These are differences in validation responsibilities,
not a finding that go-jose is vulnerable. Retaining our required checks around it
would add JSON conversions with little ownership reduction. Existing identity
JWKS/RSA parsing and distributed cache/replay behavior are unchanged.

The shared helper yields five net production lines removed, but removes a duplicate
validation implementation without another runtime dependency.

## Strict JSON

`internal/jsonsafe` uses Go 1.27 `encoding/json/v2` / `jsontext` for grammar,
duplicate names and value construction. A typed unmarshaler hook counts value
slots, enforces depth 64 / 100,000 nodes, and preserves exact `json.Number`
lexemes. All other values delegate to the standard decoder. Reader byte limits
remain, including overflow-safe validation of the configured limit.

Raw invalid UTF-8 remains rejected. A compatibility option preserves v1's handling
of escaped unpaired surrogates as U+FFFD, including duplicate-name collisions.
Malformed-input errors no longer include supplied member names. Marshaling and
public/signed/persisted JSON serialization are unchanged.

The previous decoder exists only as a test oracle. Differential fuzzing compares
acceptance and exact values; explicit tests cover integer precision, escaped
duplicate names, trailing values, malformed Unicode, depth/node boundaries,
reader errors and redaction.

The first dual-pass prototype was replaced with a simpler single-pass hook. On
the local M4 Pro's small identity-document microbenchmark, the final candidate
measured approximately 1.99 μs / 1,831 bytes / 44 allocations, versus the previous
1.00 μs / 1,928 bytes / 50 allocations. This trades about one microsecond of CPU
for standard value construction and fewer allocations; it is not a throughput or
production latency claim. Keep the benchmark when updating Go's decoder.

Source: [Go 1.27 JSON release notes](https://go.dev/doc/go1.27).

## Android

The companion Android change uses platform Base64 and JsonWriter with strict
canonical input guards and ordered JWK output. It removes 26 production lines,
adds no runtime dependency, and keeps minSDK 23 / compileSDK 34. Pinned test-only
Android framework classes verify the real platform implementations on API 23 and
34; generated Maven metadata contains no test framework dependency.

The standard full test/build/lint run passes (194 tests passed, one opt-in live
test skipped). A separate live local-server check passes session establishment,
signed mock requests, quota reads and refresh, then fails diagnostics contract
validation. Pristine Android HEAD `22602393d215eee9f08927bd079171acaba98d47`
reproduces the same failure: legacy wire 2 uses Android's current default contract
1.1.0, while the server correctly negotiates diagnostics contract 1.0.0. This is
a pre-existing Android configuration mismatch, not a codec regression. It is not
silently weakened or fixed in this batch. No physical Play Integrity is claimed.

## Verification and remaining work

- Complete PostgreSQL-15-backed Go tests, affected package race tests, static
  analysis and normal focused tests passed, including the final JSON hook.
- P-256 old/new differential fuzz: 3,587,060 executions passed. Existing DPoP
  proof fuzz: 2,487,952 executions passed.
- Final single-pass JSON differential fuzz passed its retained corpus and 14,935
  additional executions in a bounded 20-second run under concurrent integration
  load. The earlier dual-pass prototype independently passed 1,220,625 executions.
- Google tests cover ambient credential overrides, malformed/oversized responses,
  ID-token injection, redirects, clock/lifetime boundaries, failed refresh retry,
  cancellation and secret-safe errors/logging.
- Existing Go source had one unrelated indentation error in quota argument
  continuation; it was corrected without changing behavior so the formatting
  stage can run.

Migration/Goose and River adoption, browser dependencies, broader Android incoming
JSON consistency, and the separate Android legacy diagnostics contract mismatch
remain outside this batch. Existing iOS/RN work is preserved. No removed release
CI is restored and no historical failing release-tooling test is hidden.

### Completion receipt

The final `make check` rerun passed formatting, deterministic SQL generation,
workflow lint, Go vet and all Go packages against the isolated PostgreSQL 15
database. It then stopped at the historical Python release-tooling suite:
569 tests, 18 failures and 133 errors—the same counts recorded before this batch,
primarily expectations for previously removed release workflows. Those tests were
not disabled and the removed workflows were not restored. The Console stage was
not reached by this command; its source did not change in this batch.

The final affected JSON/attestation/identity/session/clientapi/server race rerun
passed. The unchanged final DPoP/shared-key code also passed its focused race
suite. Contract validation, module checksum verification, tidy reproducibility
and both repository diff checks passed.

`govulncheck` v1.7.0, built with Go 1.27.0, scanned 58 root packages / 51 modules
and reported **zero reachable vulnerable symbols**. It additionally reported four
advisories in imported chi middleware and three in the required x/crypto module.
This is not a claim that the dependency graph has no advisories:

- Chi v5.2.3: GO-2026-5777 / 5775 / 5774 cover unused RealIP middleware; the
  reported fix is v5.3.0. GO-2026-4316 covers unused RedirectSlashes, fixed in
  v5.2.4. These existing modules are unchanged by this refactor. Review a separate
  chi update without enabling those middleware helpers.
- x/crypto v0.55.0: GO-2026-6355 / 6354 concern SSH, fixed in v0.56.0;
  GO-2026-5932 concerns the unmaintained OpenPGP package and has no fixed version.
  Neither package is imported by Latchway. Keep them out of the runtime and
  evaluate the next x/crypto patch separately; Argon2 is not the flagged package.

The scanner's reachability finding was corroborated by checking source references;
it is static-analysis evidence, not a guarantee against all vulnerabilities.
See [chi advisory](https://pkg.go.dev/vuln/GO-2026-5777),
[SSH advisory](https://pkg.go.dev/vuln/GO-2026-6355), and
[OpenPGP advisory](https://pkg.go.dev/vuln/GO-2026-5932).

The temporary localhost gateway was stopped. The task-owned PostgreSQL container
and its synthetic databases/schemas were removed after verification; no existing
stack or production resource was touched. Final changes remain local and
unreleased.
