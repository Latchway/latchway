# Protocol compatibility

## Current contract

| Field | Value |
| --- | --- |
| Contract version | `0.1.0` |
| Wire protocol version | `1` |
| Status | Draft and unreleased; no compatibility promise |
| Latest passing core implementation | `925dc94a05374cf233b2836f9429d6ffa71dcf02` |
| Synchronized bundle baseline core | `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` |
| Deterministic bundle SHA-256 | `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12` |
| Minimum released server | None |
| Previous wire version supported | None; version 1 is the initial draft |

At the latest passing core commit, the server also composes a local authenticated OpenAI Chat vertical with policy, atomic multi-rule request-count reservation, protected upstream dispatch, usage settlement, exact quota-store reservation replay, DPoP replay rejection, atomic denial, and distinct `api`/`worker`/`all` process responsibilities. This is debug/mock evidence; the full quota/pricing engine, native attestation, complete control plane, operations, deployment, and release gates are not implemented.

All four SDK repositories still pin the synchronized baseline core and bundle hash above, not the latest passing implementation. That synchronization proves only that the repositories identify the same draft contract artifact. It does not prove behavioral compatibility. A fresh lock decision, shared vectors, current-core live server conformance, published dependency resolution where applicable, and the externally blocked device gates must pass before compatibility is reported.

## Required client declaration

SDKs send:

```http
X-Latchway-SDK: ios|android|javascript|react-native
X-Latchway-SDK-Version: <semantic-version>
X-Latchway-Protocol-Version: 1
X-Latchway-Feature: <configured-feature>
```

The optional `X-Latchway-Request-ID` is a client correlation hint, not an authorization input. The server preserves a safe hint and generates a safe request identifier when it is absent, ambiguous, or invalid.

## Compatibility policy

- Contract versions use Semantic Versioning for the bundle as a whole.
- Wire protocol changes are explicit in `api/protocol-version.json`; file-only clarifications do not automatically change the wire version.
- Before 1.0, coordinated breaking changes are allowed only with a new contract and explicit compatibility record.
- At server 1.0, the current wire version and at least the previous minor protocol version must be supported during the documented migration window.
- An incompatible client receives an RFC 9457 problem with `protocol_version_unsupported`, the request ID, supported versions, and safe upgrade guidance.
- Generated wire DTOs may change with the contract. Handwritten public SDK APIs remain idiomatic and must not be replaced by generated surfaces.
- A matching `contract.lock` is necessary but insufficient evidence. Compatibility also requires the affected shared-vector, fixture, live-server, packaging, and platform gates.

## Repository matrix

| Component | Intended package | Current implementation evidence | Synchronized lock commit | Remaining compatibility evidence |
| --- | --- | --- | --- | --- |
| Server and CLI | `github.com/latchway/latchway` | Latest local authenticated multi-rule proxy evidence at `925dc94a05374cf233b2836f9429d6ffa71dcf02`; earlier full race/fuzz/contracts/bundle/`make check` and local non-root OCI evidence at `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` | Source of truth | Full quota/pricing, native attestation, live canary/SDK conformance, operations, current Compose/registry image proof, and release gates |
| JavaScript | `@latchway/client` | Local browser/Node/package gates pass at `273925d73a5a959f95664b1b1d838505dcce5f6c` | `8df68931730bad05ef110fe53e09d857b5bd61f8` | Live current-core conformance and publication evidence |
| Swift | `Latchway` | Local Swift package, fixture, and conformance-source gates pass at `2972f99c59b652722a586510a9c943ac57a69a5c` | `fd670a04004787901bb19b3ab762f4d2dc050a07` | Live current-core conformance, published dependency proof, and physical App Attest validation |
| Android | `dev.latchway:latchway-*` | Local static tests and independent Kotlin/JVM compatibility gates pass at `0042a916580d14295bd944104aae6deb2ac136c5` | `cd96781426831f464fc1e5350094aab91ca11dd2` | Configured Android SDK/`ANDROID_HOME`, user-accepted licenses, official Gradle gates, live current-core conformance, publication, and Play-distributed validation |
| React Native | `@latchway/react-native` | Local source, type, test, code-generation, build, and native-boundary gates pass at `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0` | `bf1d5e9319c859edc215677e6c02b7d0f91cc811` | CocoaPods (`pod` is absent locally), native-consumer/published-dependency gates, live current-core conformance, and physical-device validation |

## Synchronized lock fields

Each SDK's existing lock serialization now records these shared values:

| Field | Synchronized value |
| --- | --- |
| Contract version | `0.1.0` |
| Core commit | `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` |
| Bundle SHA-256 | `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12` |
| Wire protocol | `1` |
| Declared minimum server version | `0.1.0` |
| Declared maximum tested server series | `0.1.x` |

The field name for wire protocol is repository-specific (`wire_protocol` or `wire_protocol_version`). Release-label metadata is also repository-specific and is not evidence that a server or SDK release exists. No release tag, registry publication, or minimum compatible released pair is claimed by this document.
