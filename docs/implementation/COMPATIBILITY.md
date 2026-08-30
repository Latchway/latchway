# Compatibility policy and current matrix

This document separates the historical legacy baseline from the draft version
1 contract. It is a source compatibility ledger, not proof of public
packages, live providers, physical devices, or production support.

## Contract boundary

| Field | Legacy compatibility | Draft current contract |
| --- | --- | --- |
| Contract | Historical `0.5.1`, status `released` | `1.0.0`, status `draft`, `released_at: null` |
| Wire | `1`, retained for compatible legacy routes | `2` current; Installation Family and Client Component operations require it |
| Database | Historical schema `20` | Schema `23`, including family/component state, component-scoped quota state, and direct component-attestation linkage |
| Client parent | Legacy installation (`ins_`) | Installation Family (`fam_`) and Client Component (`cmp_`) |
| Sessions | One installation key/session family | Independent component keys/session families |
| Refresh reuse | Terminal legacy reuse under ADR 0032 | 30-second exact-tuple idempotency under ADR 0024 |
| Framework metadata | Optional declarations accepted on retained routes | Framework name/version headers in the contract and audit/request views |
| Framework support | None claimed | Registry-driven, version-pinned conformance required |

The released `0.5.1` bundle and SDK locks remain byte-frozen historical
coordinates at their normative commits. The current source emits a distinct,
deterministic draft `1.0.0` bundle; it must not overwrite or silently amend the
historical coordinate. The component-attestation additions invalidated earlier
intermediate draft hashes. The current SDK locks now converge on core checkpoint
`a62b0f6aa2328604101c1073c56f5ecb3bed3618` and bundle SHA-256
`36aa3c4786e60f2cdbbc3d0cd2f65bffe894a099479517b2e1faa01361c74b00`.

## Framework registry

The canonical source is
[`compatibility/frameworks.yaml`](../../compatibility/frameworks.yaml),
validated against
[`compatibility/frameworks.schema.json`](../../compatibility/frameworks.schema.json).
The public compatibility page is generated at
[`docs/public/reference/compatibility.mdx`](../public/reference/compatibility.mdx).

Six entries are `experimental` at exact locally tested versions: OkHttp 5.3.0,
`@langchain/openai` 1.5.10, OpenAI JavaScript 7.8.0, React Native 0.82.0,
SwiftOpenAI 4.6.0, and Vercel AI SDK 7.0.85. Foundation Models remains
`planned` because its runtime tests were skipped on the older host OS.
MacPaw/OpenAI 0.5.1 is `unsupported` because its public seams cannot preserve
fresh asynchronous DPoP and streaming dispatch. No entry is `supported`.

Support states mean:

- `planned`: target integration; no tested-version claim;
- `experimental`: pinned minimum/latest versions and conformance exist, but the
  compatibility surface is not stable;
- `supported`: pinned versions, common conformance, release evidence, public
  documentation, and limitations satisfy the release policy;
- `unsupported`: the required safe request-time seam is unavailable or the
  integration is intentionally excluded.

Static headers, dependency resolution, compilation, or one successful request
cannot elevate a framework to `experimental` or `supported`.

## Compatibility generation and validation

Run:

```sh
python3 scripts/framework_compatibility.py --check-generated
python3 -m unittest scripts/test_framework_compatibility.py
python3 scripts/validate-contracts.py
```

The validator rejects duplicate YAML keys/IDs, unknown fields, unsorted IDs,
invalid capability/security states, unpinned support claims, reversed version
ranges, schema drift, and stale generated Markdown. Public documentation must
consume generated registry output rather than maintain a second table.

The registry and its strict schema are deterministic members of the draft
`1.0.0` contract bundle under `compatibility/`. Contract validation checks the
schema, semantic policy, generated Markdown, archive closure, and checksums.
The final bundle, exact contract checkpoint, bundle hash, wire-2 constants,
component-attestation vector, and other generated fixtures are synchronized
across all four SDK locks. The clean local source-conformance gate passes.

## Current SDK source checkpoints

These coordinates record the source-converged version 1 implementations. They
are not package-publication or production-support claims.

| SDK | Version 1 source checkpoint | Minimum runtime | Source status |
| --- | --- | --- | --- |
| JavaScript `@latchway/client` | `87a46eab3853633e23a65525e451f1bdaf3ee0c3` | Node 24.19 or standards-based browser WebCrypto/fetch | Transport, component sessions, adapters, and composite-trust decoding implemented and locked |
| Swift `Latchway` | `4cafe61faabfb4b8273af8833592c69ff2db7cfa` | iOS 15+, macOS 12+ supported surfaces | Extension/component transport and Action/SSO direct App Attest step-up implemented and locked; physical proof pending |
| Android `dev.latchway:latchway-*` | `46cb6597430bc0f3c401757770420102894a5378` | Android API 23+, Java 17 | Component/OkHttp transport and composite-trust decoding implemented and locked; direct component step-up unsupported by design |
| React Native `@latchway/react-native` | `b05060dfaec8897ca0374449f26a03658ff249e8` | RN 0.82.x, iOS 15+, Android API 24+ | Native-backed transport, iOS extension-process Action/SSO direct step-up, and fail-closed native physical-proof linkage implemented and source-pinned; physical execution pending |

The historical wire-1 locks remain recoverable from their immutable repository
history. Current locks all point to the draft version 1 checkpoint named above.

## Header compatibility

Compatible legacy wire-1 clients declare:

```http
X-Latchway-SDK: ios|android|javascript|react-native
X-Latchway-SDK-Version: <sdk-version>
X-Latchway-Protocol-Version: 1
X-Latchway-Feature: <configured-feature>
X-Latchway-Request-ID: <optional-correlation-hint>
```

Wire 2 is current, uses `X-Latchway-Protocol-Version: 2`, and can additionally
declare the paired `X-Latchway-Framework` and
`X-Latchway-Framework-Version` headers. Installation Family and Client
Component operations require wire 2. Discovery and diagnostics always
advertise current wire 2 while discovery reports the supported range `[1, 2]`.

## Direct component-attestation compatibility

Wire 2 includes component-attestation binding version 2 and separate
component challenge/exchange operations. Successful proof augments a delegated
component to `delegated_direct_attested`; it does not erase its parent or
delegation identifiers. Access tokens bind the attestation provider for
component-aware sessions, while retained legacy tokens intentionally have no
provider claim.

The server source permits App Attest step-up only for configured delegated
Action, SSO, and watch component kinds on Apple platforms with an exact bundle
identifier and a component-only `preferred` policy. The current Swift and
React Native iOS client surfaces implement Action/SSO extension-process proof;
they do not claim watch client support. The containing React Native process
cannot attest an extension bundle on the extension's behalf. JavaScript and
Android decode the composite trust source for contract compatibility, but
Android direct component step-up remains unsupported in version 1.

These statements describe source and wire compatibility only. Physical App
Attest/Play Integrity, entitlement isolation, lifecycle, live-provider,
exact-image, and clean published-consumer observations remain required before
any tuple can become `supported`.

## Support evidence policy

A supported server/SDK/framework tuple requires all of:

1. one immutable prerelease/final contract bundle and matching SDK locks;
2. minimum and latest framework version jobs plus scheduled newest-compatible
   observation without automatic range widening;
3. common authentication, request, framework, security, streaming,
   cancellation, refresh, revocation, and component conformance;
4. platform-specific key isolation and physical attestation where applicable;
5. exact-image live and clean-public-consumer evidence;
6. generated public compatibility and accurate limitations/release notes.

Until then this ledger records plans and historical baselines, not support.
