# Compatibility policy and current matrix

This document separates the historical legacy baseline from the draft version
1 contract. It is a source compatibility ledger, not proof of public
packages, live providers, physical devices, or production support.

## Contract boundary

| Field | Legacy compatibility | Draft current contract |
| --- | --- | --- |
| Contract | Historical `0.5.1`, status `released` | `1.0.0`, status `draft`, `released_at: null` |
| Wire | `1`, retained for compatible legacy routes | `2` current; Installation Family and Client Component operations require it |
| Database | Historical schema `20` | Schema `27`, including family/component state, component-scoped quota state, direct component-attestation linkage, protocol-aware first-token timing, hardened challenge Origin binding, logical-request decision stages, and bounded audit attribution/browse indexes |
| Client parent | Legacy installation (`ins_`) | Installation Family (`fam_`) and Client Component (`cmp_`) |
| Sessions | One installation key/session family | Independent component keys/session families |
| Refresh reuse | Terminal legacy reuse under ADR 0032 | 30-second exact-tuple idempotency under ADR 0024 |
| Framework metadata | Optional declarations accepted on retained routes | Framework name/version headers in the contract and audit/request views |
| Framework support | None claimed | Registry-driven, version-pinned conformance required |

The released `0.5.1` bundle and SDK locks remain byte-frozen historical
coordinates at their normative commits. The current source emits a distinct,
deterministic draft `1.0.0` bundle; it must not overwrite or silently amend the
historical coordinate. The component-attestation additions invalidated earlier
intermediate draft hashes. The current SDK locks now converge on contract source
checkpoint `a59a2c1c807aec50093ae6346492a05148c72899` and bundle SHA-256
`3a88fb69b911724da849229f34f735608e829bcfb0658087313c8d31441e9927`.
The clean core implementation checkpoint is
`82c9d3663a0532210d6a99ebecaa179f05797115`. Its canonical SDK-bundle and
public-documentation checkpoint is
`7bdf9cb6da312ea5f4282ae2caf686bcc1122fa3`, synchronized to the branch-source
Mintlify mirror at `ce4ea1e1cf56404da7146b98ca2744b194050fd5`; none of these
coordinates is a released package or production documentation deployment.

## Framework registry

The canonical source is
[`compatibility/frameworks.yaml`](../../compatibility/frameworks.yaml),
validated against
[`compatibility/frameworks.schema.json`](../../compatibility/frameworks.schema.json).
The public compatibility page is generated at
[`docs/public/reference/compatibility.mdx`](../public/reference/compatibility.mdx).

Eight entries are `experimental` at exact locally tested versions: OkHttp
4.9.2/5.3.0, Koog 1.1.1, Foundation Models 27.0.0,
`@langchain/openai` 1.5.10, OpenAI JavaScript 7.8.0, React Native 0.82.0,
SwiftOpenAI 4.6.0, and Vercel AI SDK 7.0.85. MacPaw/OpenAI 0.5.1 is
`unsupported` because its published public seams cannot preserve fresh
asynchronous DPoP and streaming dispatch; the passing repository upstream
patch is not an accepted release. No entry is `supported`.

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
are pushed branch source candidates, not package-publication,
production-support, or released-coordinate claims.

| SDK | Version 1 source checkpoint | Minimum runtime | Source status |
| --- | --- | --- | --- |
| JavaScript `@latchway/client` | `6b0c08ded377011044462d1ba6aa46cb34d7ee8f` | Node 24.19 or standards-based browser WebCrypto/fetch | Transport, component sessions, adapters, framework-version conformance, composite-trust decoding, three-browser conformance, bundler consumers, and tested vanilla-Web documentation sources implemented and locked |
| Swift `Latchway` | `af87b4454e4b6a159b9da7bd50550865c74684a2` | iOS 15+, macOS 12+ supported surfaces | Root-app App Attest, delegated-only extension transport, a compiled Firebase/App Attest golden journey, and the narrow Foundation Models 27 adapter are implemented; simulator gates and a development-signed physical root-app App Attest run pass, while protected distribution and physical Foundation Models evidence remain required |
| Android `dev.latchway:latchway-*` | `9d83a635fc0e5f1a79582c73f0fb61acc9e24471` | Android API 23+, Java 17 | Component/OkHttp transport plus a compiled Firebase/Play golden journey, Retrofit, Aallam OpenAI Kotlin, LangChain4j, and exact Koog 1.1.1 fixtures are implemented; Koog full streaming is limited to the tested OkHttp 5.3.0 tuple, and physical Play evidence remains required |
| React Native `@latchway/react-native` | `111e7841f81e87ab471c18d381fed18ec8335760` | RN 0.82.x, iOS 15+, Android API 24+ | Native-backed transport, framework compatibility, root-owned component descriptor lifecycle, private root-Keychain propagation, delegated-only iOS extensions, and a Debug-only native App Intent delegated-request path are implemented, fully checked, and source-pinned. The Release App Intent fixture has no Latchway request path and fails closed. Predecessor `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` passed a development-signed iPad root-app App Attest/Firebase/real-upstream run; the current Debug App Intent still requires physical invocation, and protected Apple distribution/extension-matrix plus physical Android evidence remain required. |

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
