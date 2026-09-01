# Compatibility policy and current matrix

This document separates the historical legacy baseline from the released
version 1 contract manifest. It is a source compatibility ledger, not proof of
public packages, live providers, physical devices, or production support.

## Contract boundary

| Field | Legacy compatibility | Current contract |
| --- | --- | --- |
| Contract | Historical `0.5.1`, status `released` | `1.0.0`, status `released`, `released_at: 2026-09-01T20:25:00Z` |
| Wire | `1`, retained for compatible legacy routes | `2` current; Installation Family and Client Component operations require it |
| Database | Historical schema `20` | Schema `28` at contract/source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` and its contract-preserving descendants, including family/component state, component-scoped quota state, direct component-attestation linkage, protocol-aware first-token timing, hardened challenge Origin binding, logical-request decision stages, bounded audit attribution/browse indexes, durable cost retry treatment, and physical-attempt quota ledger support; schema `27` remains at historical checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` |
| Client parent | Legacy installation (`ins_`) | Installation Family (`fam_`) and Client Component (`cmp_`) |
| Sessions | One installation key/session family | Independent component keys/session families |
| Refresh reuse | Terminal legacy reuse under ADR 0032 | 30-second exact-tuple idempotency under ADR 0024 |
| Framework metadata | Optional declarations accepted on retained routes | Framework name/version headers in the contract and audit/request views |
| Framework support | None claimed | Registry-driven, version-pinned conformance required |

The released `0.5.1` bundle and SDK locks remain byte-frozen historical
coordinates at their normative commits. Version 1 emits a distinct,
deterministic released `1.0.0` bundle; it does not overwrite or silently amend
the historical coordinate. All four SDK successor locks converge on contract
source `437708fb56d45196720b5769f2f59b0ee51f521d` and bundle SHA-256
`14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6`.
Checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` previously removed two
request-lifecycle PostgreSQL network turns without changing the contract or its
separate durable forensic transaction boundary. Contract/source checkpoint
`437708fb56d45196720b5769f2f59b0ee51f521d` descends from it and contains the
version 1 runtime, schema 28, Admin-session inventory/revoke, configuration
import/export, stable server-capability negotiation, authenticated Admin SSE
refresh hints, exact JSON/YAML numeric preservation, and explicit
`READ COMMITTED` application→environment lifecycle locking. The final
canonical-documentation commit is an API-preserving descendant and its
generated Mintlify mirror is bound by clean source conformance. None of these
coordinates proves a merge, tag, GitHub release, package or container
publication, cloud deployment, or production documentation deployment.

Contract/source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d`
also adds enforceable calendar, token-bucket, and aggregate per-request
`upstream_attempts` limits plus configurable cost retry treatment.
`actual_attempts` remains the default. A user-scoped `initial_attempt_only`
rule is valid only when the same plan retains an organization-scoped, non-user
`actual_attempts` rule, so product forgiveness cannot remove the durable
infrastructure-cost bound. The deterministic
`14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6`
bundle and all four SDK successor locks already bind that schema-28 contract.

## Admin capability negotiation

The current local server source advertises a stable ordered
`server_capabilities` list containing `app_attest`, `play_integrity`,
`firebase_app_check`, `turnstile`, `component_delegation`, `cost_limits`,
`openai_responses`, `openai_chat`, `openai_embeddings`,
`anthropic_messages`, `opaque_http`, `configuration_import_export`,
`admin_session_management`, and `admin_event_stream`. The Console Settings
surface requires protocol 2 and every listed capability except
`admin_event_stream` before enabling mutations. Missing protocol or required
capabilities activates read-only safe mode. `admin_event_stream` is optional:
older servers retain polling and manual refresh instead of being treated as
mutation-incompatible.

These are current local source facts covered by the complete core
implementation gate, race detector, bounded fuzz corpus, real PostgreSQL
suites, and clean source conformance; they are not published-package or
deployed-server claims.

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

The registry and its strict schema are deterministic members of the released
`1.0.0` contract bundle under `compatibility/`. Contract validation checks the
schema, semantic policy, generated Markdown, archive closure, and checksums.
The bundle, exact contract checkpoint, bundle hash, wire-2 constants,
component-attestation vector, and other generated fixtures are synchronized
across all four SDK locks, and the clean local source-conformance gate passes.

## Current SDK source checkpoints

These coordinates record the current clean, locally source-converged version 1
implementations. They are source checkpoints, not package-publication,
production-support, or public-version claims. No exact current head is
claimed as pushed until the authorized final fetch/audit/push completes.

| SDK | Version 1 source checkpoint | Minimum runtime | Source status |
| --- | --- | --- | --- |
| JavaScript `@latchway/client` | `ddd04d3a34be7ccbc7f30efc600c77b8594edd5d` | Node 24.19 or standards-based browser WebCrypto/fetch | Transport, component sessions, adapters, framework-version conformance, composite-trust decoding, three-browser conformance, bundler consumers, reproducible package checks, and tested vanilla-Web documentation sources implemented and locked to released contract `1.0.0` |
| Swift `Latchway` | `910e692278f05a56a5d007a18e6b82dcd2fab56b` | iOS 15+, macOS 12+ supported surfaces | Root-app App Attest, delegated-only extension transport, a compiled Firebase/App Attest golden journey, and the narrow Foundation Models 27 adapter are implemented; SwiftPM, CocoaPods, consumer, reproducibility, and simulator gates pass, while protected distribution and physical Foundation Models evidence remain required |
| Android `dev.latchway:latchway-*` | `275b876e1beadeff4cf3e024c0207b73e7270a96` | Android API 23+, Java 17 | Component/OkHttp transport plus a compiled Firebase/Play golden journey, Retrofit, Aallam OpenAI Kotlin, LangChain4j, exact Koog 1.1.1 fixtures, all five local Maven publications, and offline consumers pass; Koog full streaming is limited to the tested OkHttp 5.3.0 tuple, and physical Play evidence remains required |
| React Native `@latchway/react-native` | `fe35e04b714a38bc0df840f75bdbc37dbf8716a2` | RN 0.82.x, iOS 15+, Android API 24+ | Native-backed transport, framework compatibility, root-owned component descriptor lifecycle, private root-Keychain propagation, delegated-only iOS extensions, and a Debug-only native App Intent delegated-request path are implemented and source/check gates pass. The released lock and final changelog satisfy the metadata portion of stable preflight; tags and protected evidence remain required. Predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict Apple Development root/extension signing, provisioning/entitlement, registered-device install, and launch checks without new App Attest or App Intent execution. The physical path was not rerun at current successor `fe35e04b714a38bc0df840f75bdbc37dbf8716a2`. The Release App Intent fixture has no Latchway request path and fails closed. App Intent/extension invocation and physical Android evidence are operator-deferred release gates. Protected Apple distribution proof remains open and is not claimed as deferred. |

The historical wire-1 locks remain recoverable from their immutable repository
history. The checked-in SDK successor locks point to the clean released version
1 checkpoint named above and bind the complete Admin API delta.

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
