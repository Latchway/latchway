# Protocol compatibility

This document records the exact version 1 source baseline. It is a local source
compatibility declaration, not proof that packages or images exist in public
registries.

## Normative baseline

| Field | Value |
| --- | --- |
| Server release coordinate | `v1.0.0` |
| Contract version | `0.5.1` |
| Contract status | `released` |
| Contract released at | `2026-08-29T07:14:27Z` |
| Wire protocol | `1` |
| Normative core checkpoint | `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Contract archive | `latchway-contract-0.5.1.tar.gz` |
| Contract archive SHA-256 | `52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754` |
| Database schema | `19` |
| Minimum server | `1.0.0` |
| Maximum tested server series | `1.0.x` |

`contract_status: released` means that the normative contract source is
frozen. It does not mean that server `v1.0.0`, its OCI image, or any SDK package
has been publicly tagged or published.

## Version 1 component matrix

| Component | Package coordinate | Version | Exact source commit | Minimum platform/runtime |
| --- | --- | --- | --- | --- |
| Core server, CLI, dashboard | `github.com/latchway/latchway` | `1.0.0` | Contract checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` | PostgreSQL 15+; OCI `linux/amd64` and `linux/arm64` |
| JavaScript | `@latchway/client` | `1.0.0` | `857f4e12b98b36a9bf4026babaf97a2ae936575e` | Node `>=24.19.0`; pnpm `10.15.0`; standards-based browser WebCrypto/fetch runtime |
| Swift | Swift package `Latchway`; CocoaPods `Latchway/AppAttest` | `1.0.0` | `57b45999fbc6edb717ebbf365ec59efb5abba2e2` | iOS 15+; macOS 12+ for supported package surfaces; Swift tools 6.2 |
| Android | `dev.latchway:latchway-core`, `latchway-okhttp`, `latchway-play-integrity`, `latchway-firebase-auth`, `latchway-bom` | `1.0.0` | `7d099fff11f6730917f37d019ad730a3973672d7` | Android API 23+; Java 17; compile SDK 37 |
| React Native | `@latchway/react-native` | `1.0.0` | `1e71658b3397fc8f508e5a11124aa48f1788cbba` | React Native `0.82.x`; React `19.1.x`; iOS 15+; Android API 24+; Node `>=24.19.0` |

The React Native release manifest deliberately pins these native dependency
commits rather than accepting whatever happens to be latest:

- JavaScript: `857f4e12b98b36a9bf4026babaf97a2ae936575e`
- Swift: `57b45999fbc6edb717ebbf365ec59efb5abba2e2`
- Android: `7d099fff11f6730917f37d019ad730a3973672d7`

## Shared fixture identity

The core bundle and every SDK contain byte-identical copies of the required
fixtures:

| Fixture | SHA-256 |
| --- | --- |
| `attestation-binding-v1.json` | `e24ec75cc37b331060c67637fe3a4421c644e354fe73b9049b652d61a9e2896b` |
| `dpop-v1.json` | `d14702db02a4498e8d52b5b39d5bc25d141dcf87ea4f7c4aeb929fd191eb8101` |
| `protocol-version.json` | `c469ab7c23c78dc5de2430bdc1d524268afe400f7af7eb8efb36b1c5d739fd51` |

Every SDK lock contains contract `0.5.1`, wire protocol `1`, core release
`v1.0.0`, core checkpoint
`2f5e5e67c824e270431f1232cc6dc2824848e380`, bundle SHA-256
`52ebacd1e38c522b89bb14a1f34782176be32cdf91d22b7ab962003dbca2d754`,
minimum server `1.0.0`, and maximum tested server series `1.0.x`.

## Required client declaration

SDKs send the versioned transport headers:

```http
X-Latchway-SDK: ios|android|javascript|react-native
X-Latchway-SDK-Version: 1.0.0
X-Latchway-Protocol-Version: 1
X-Latchway-Feature: <configured-feature>
```

`X-Latchway-Request-ID` is an optional correlation hint and is never an
authorization input. The server returns the stable
`protocol_version_unsupported` problem when a wire version is outside its
supported set.

## Compatibility policy

- The contract bundle uses Semantic Versioning. Wire changes are explicit in
  `api/protocol-version.json`; editorial or Admin-only changes do not silently
  change the wire protocol.
- Public SDK APIs are handwritten and idiomatic. Generated contract DTOs do not
  define the public API.
- A matching lock, fixture, version, and source commit is necessary but not
  sufficient. A supported compatibility claim additionally requires the exact
  release image, live conformance, platform-specific proof, public dependency
  resolution, and post-publication smoke tests.
- Production App Attest and Play Integrity compatibility requires real device
  observations. Simulator, emulator, fixture, and debug-attestation results do
  not satisfy that requirement.
- Later core commits may contain release automation or documentation while SDKs
  remain pinned to the normative checkpoint only when `api/` is byte-unchanged
  from that checkpoint.

## Evidence still required for a supported pair

The source matrix above has passed repository-local contract, package, and
consumer gates. A supported public server/SDK pair is intentionally not
declared until the protected release process verifies live SDK behavior against
the exact image, physical native attestation, provider canaries, cloud
deployments, resilience, signatures/provenance, public tags, and public
registry installations.
