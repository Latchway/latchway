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
`72a52d7b42e6ea159e8222c5dd0346be286fb39a` and bundle SHA-256
`ad7afe992181553996eba39e44d4aeb498e8159e2b52671756b5c93ab68eb765`.

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
| JavaScript `@latchway/client` | `8e36364419783b07acdd8fae82e457885f1c5447` | Node 24.19 or standards-based browser WebCrypto/fetch | Transport, component sessions, adapters, framework-version conformance, and composite-trust decoding implemented and locked |
| Swift `Latchway` | `0074f532d639b83c27966f8c75ffe37ed8df6cc8` | iOS 15+, macOS 12+ supported surfaces | Root-app App Attest, bounded invalid-input recovery, private root-Keychain isolation, explicit legacy shared-group migration detection, and delegated-only iOS extension/component transport implemented and locked; a development-signed physical root-app registration and same-key assertion passed, while protected distribution evidence remains required |
| Android `dev.latchway:latchway-*` | `c05a74e735da3589f907eb0a788a2970245c0cc8` | Android API 23+, Java 17 | Component/OkHttp transport, Retrofit/OpenAI Kotlin/LangChain4j fixtures, and composite-trust decoding implemented and locked; direct component step-up is unsupported by design and physical Play evidence remains required |
| React Native `@latchway/react-native` | `11bfaef12f373a8a81e0b08a0f2ef0ef313e13dc` | RN 0.82.x, iOS 15+, Android API 24+ | Native-backed transport, framework compatibility, root-app App Attest, private root-Keychain propagation, delegated-only iOS extensions, and fail-closed native physical-proof linkage implemented and source-pinned; a development-signed physical iOS run passed, while protected Apple distribution, extension-runtime, and physical Android evidence remain required |

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

The server source restricts the generic App Attest step-up route to configured
delegated Action, SSO, and watch component kinds on Apple platforms with an
exact bundle identifier and a component-only `preferred` policy. That wire
capability does not imply a usable iOS producer: Apple rejects App Attest key
generation in iOS app extensions. Swift and React Native iOS therefore keep
Action and SSO delegated-only, and a containing process cannot attest an
extension bundle on its behalf. Apple documents an extension exception for
eligible watchOS apps, but the current Swift package does not claim a watch
client surface. JavaScript and Android decode the composite trust source for
contract compatibility; neither provides direct component step-up in version
1.

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
