# Protocol compatibility

## Current contract

| Field | Value |
| --- | --- |
| Contract version | `0.1.0` |
| Wire protocol version | `1` |
| Status | Draft; no released contract implementation |
| Minimum server | None |
| Previous wire version supported | None; version 1 is the initial draft |

The working-tree server foundation advertises contract `0.1.0` and protocol `1` from its health response, but it does not implement the client or Admin contract surfaces. No SDK implements the contract. “Compatible” must not be reported until a repository pins the reviewed bundle hash in `contract.lock` and passes shared vectors plus live conformance against the corresponding core image.

## Required client declaration

SDKs send:

```http
X-Latchway-SDK: ios|android|javascript|react-native
X-Latchway-SDK-Version: <semantic-version>
X-Latchway-Protocol-Version: 1
X-Latchway-Feature: <configured-feature>
```

The optional `X-Latchway-Request-ID` is a client correlation hint, not an authorization input. Servers generate a safe request identifier when it is absent or invalid.

## Compatibility policy

- Contract versions use Semantic Versioning for the bundle as a whole.
- Wire protocol changes are explicit in `api/protocol-version.json`; file-only clarifications do not automatically change the wire version.
- Before 1.0, coordinated breaking changes are allowed only with a new contract and explicit compatibility record.
- At server 1.0, the current wire version and at least the previous minor protocol version must be supported during the documented migration window.
- An incompatible client receives an RFC 9457 problem with `protocol_version_unsupported`, the request ID, supported versions, and safe upgrade guidance.
- Generated wire DTOs may change with the contract. Handwritten public SDK APIs remain idiomatic and must not be replaced by generated surfaces.

## Repository matrix

| Component | Intended package | Current implementation | Contract lock |
| --- | --- | --- | --- |
| Server and CLI | `github.com/latchway/latchway` | Health/migration foundation only; contract endpoints not implemented | Source of truth |
| Swift | `Latchway` | Not implemented | Not created |
| Android | `dev.latchway:latchway-*` | Not implemented | Not created |
| JavaScript | `@latchway/client` | Not implemented | Not created |
| React Native | `@latchway/react-native` | Not implemented | Not created |

## Contract lock format

Each SDK repository will record:

```yaml
contract_version: 0.1.0
core_release: unreleased
bundle_sha256: "<sha256 after the reviewed bundle is produced>"
minimum_server_version: 0.1.0
maximum_tested_server_version: 0.1.x
```

The literal hash is intentionally not asserted until the working tree is reviewed and the deterministic bundle is produced.
