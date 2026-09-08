# Shared native apps — unreleased implementation notes

This describes the current development APIs, not published package support.
Do not enable this working tree for Habitify production yet. No live policy,
database, deployment, npm package, pod or Maven artifact was changed by this work.

## Ownership and login lifecycle

A native host process owns a registry of named apps. Names alias a canonical
gateway/app/environment/root storage scope. Matching configuration returns the
same backend, preserves omitted settings and does not activate an account.
Conflicting immutable configuration fails. Neither a new RN screen nor a new
client handle is permission to sign in again after logout.

An app's first registration supplies one account-aware identity authority.
The authority returns issuer, tenant, subject and current token together.
These are local cache-isolation inputs; the server still verifies the token and
owns the quota principal. Firebase and LangChain remain optional dependencies.

After a successful app-owned sign-in:

1. Explicitly activate the app account.
2. Obtain fresh native/RN client and model handles.
3. Observe opaque generation/revision snapshots to update UI.

For sign-out, capture the generation, stop application-owned chat/tool work,
await Latchway logout, then sign out the application's Firebase Auth instance.
An external auth-state change must use its captured old generation to retire
Latchway. Never ask a delayed callback to discover whichever account is current.
Logout is local and offline: it does not reset usage or remotely revoke an
installation. Requests already dispatched may still settle against the old user.

Old handles remain terminal. A storage/cleanup failure blocks new activation;
retry cleanup for the same captured generation. Disposal releases a client
lease, not the shared account. Do not call first-time logout on a disposed lease.

## Embedded React Native

The host registers its native authority before RN starts. RN can retrieve it
without a JS ID-token provider:

```ts
import { Latchway } from '@latchway/react-native';

const app = await Latchway.getApp('habitify-production');
const snapshot = await app.snapshot();
if (snapshot.state !== 'active') {
  throw new Error('The host must explicitly activate the signed-in account.');
}
const client = await app.makeClient();
// Give this account-bound client to the existing @latchway/langchain adapter.
// Dispose model/client handles on screen teardown; logout belongs to host auth.
```

`Latchway.configure` with matching explicit gateway/app/environment settings also
returns that backend. Omitted identity/security settings inherit the host's
registration. A redundant JS callback never replaces the existing native owner.

iOS consumers must resolve a single native SDK implementation: an independent
SPM copy plus the RN CocoaPods copy is not a proven shared registry arrangement.
Android consumers must align the host and RN native artifacts. The current
published dependency pins do not contain these new APIs; local test overrides
are development-only, not release conformance.

## Standalone React Native

The development `configure` API accepts `identity` (stable registration name,
issuer and optional tenant) plus an async `getIdentitySnapshot` returning one
consistent `{ issuer, tenant?, subject, token }` or `null`. It also needs the
platform's normal App Attest/Play Integrity settings on first registration.
Read the same Firebase user before and after asynchronous token retrieval.

The native broker requests a fresh snapshot when needed. If JS is unavailable
or stalls, authorization fails closed after its bounded identity wait; native
logout does not require JS. Explicit ownership transfer is now implemented:

```ts
const previous = await app.snapshot();
await app.transferIdentityAuthority({
  identity: { name: 'host-firebase', issuer: 'https://securetoken.google.com/your-project' },
  expectedAuthorityInstanceID: previous.authorityInstanceID,
  getIdentitySnapshot: currentAtomicSnapshot,
});
// Old account cleanup finished. Activation is still an explicit login action.
await app.activate();
const newClient = await app.makeClient();
```

The expected owner is a compare-and-swap precondition, not a secret or an auth
token. A competing/stale transfer fails. Repeating configure never replaces an
owner. Transfer retires old clients even when the replacement returns the same
UID. It neither invokes Firebase sign-out nor resets usage. Swift rejects a
transfer during an unfinished activation; let it finish/retire and retry with a
fresh snapshot. Android fences late activation by epoch. Native background work
should use a native-owned authority; this JS API is for deliberate ownership
changes/reload recovery, not screen remount effects. Bridge fixture tests do not
prove actual device Fast Refresh or multiple independent RN runtimes.

## Native API outline

Swift uses `LatchwayApp.configure(..., authority: ..., attestationFactory: ...)`,
`app.activate()`, `app.makeClient()`, `app.snapshot()`/`snapshots()`, and
`app.logout(generationID:)`, and explicit `transferIdentityAuthority`. The app's attestation factory must construct state
for the supplied account namespace, not return a global provider for all users.
Use a stable `attestationPolicyID` for a custom factory (default: `app-attest`).
`FirebaseLatchwayIdentityAuthority` keeps Firebase access on the main actor and
checks both user object identity and UID/tenant after retrieving the token.

Android uses `LatchwayAppRegistry.configure(context, options, authority = ...,
attestationProvider = ...)`, `app.activate()`, `app.makeClient()`, `app.snapshots`,
and `app.logout(generationId)` / `transferIdentityAuthority`. `FirebaseIdentityAuthority` binds one selected
Firebase Auth instance and performs the same post-token user check. Neither
adapter signs out Firebase or installs another auth listener.

## Server opt-in and verification

Keep the existing host verifier configuration intact; add the allowed callers
only to the explicitly selected required host policy, for example
`sharedNativeCallers: [ios, react-native]` for iOS and
`sharedNativeCallers: [android, react-native]` for Android. Do not reinterpret a
legacy `react_native_ios`/`react_native_android` installation as a shared root.
Incompatible caller declarations return `request_invalid`; they are not reported
as a revoked session and cannot consume a refresh token or proof.

Same-host delegated components may declare protocol 3 using their own keys,
grants and sessions. The component definition must match the actual iOS/Android
parent host platform and the caller must be on its explicit allowlist. Root
credentials are never exported. Watch and legacy runtime-specific definitions
are not automatically converted. PostgreSQL tests verify component access and
refresh, policy-denial-before-grant/proof consumption, legacy-policy compatibility
and rejection of a watch component relabeled as a shared phone component.

Local evidence includes PostgreSQL-backed server regressions, shared Swift
and Android session/refresh and unique-proof tests, native lifecycle/Firebase tests, and
React Native bridge/wrapper regressions. Test doubles are not physical App Attest,
Play-distributed Integrity, extension-process, or minimum-RN host evidence.

Logical request records now persist `caller_sdk`; the Admin API, CLI detail view
and console show it. Migration 30 adds a nullable column, preserving historical
records and quota buckets. This remains request attribution, not trust evidence.

All four SDK repositories consume an exact draft through
`contract.shared-native.lock.json` and separate shared-native fixtures. The
existing `contract.lock` remains the released legacy pin. The draft lock records
the core base commit plus exact bundle/member hashes and explicitly has no
release tag. Published package/native dependency pins have not been advanced.

Root key retention now bounds inactive/current accounts to eight scopes, records
eviction before deleting exact inactive keys, and retries interrupted deletion
before activation. Corrupt/oversized/duplicate indexes fail closed. Swift stream
checks use a synchronous locked read fence, including buffered response bytes,
while persistence and cancellation remain actor-owned. Legacy migration waits for
old native/RN owners to drain before erasure; Android keeps a closed owner tracked
until its coroutine job has actually completed.

## Delegated lifecycle and migration

Shared components retain independent credentials and account-scoped keys. The
root registers local component coordinates before requesting a delegated grant.
Offline logout retires registered local scopes and blocks late saves and cached
response reads before reporting completion. A different process must read the
persistent marker; a process-local event is not sufficient. Missing or corrupt
required storage fails closed and cleanup can be retried after restart.

iOS hands an opaque account/generation descriptor to the authorized extension;
its Keychain group stores a revision-checked component envelope. Android uses
private no-backup files with OS locking and fresh reads for same-UID services.
Neither arrangement grants root signing or Firebase-token access to a component.
Remote watches/devices are outside local erasure: their existing independent
server revocation and trust-expiry behavior remains unchanged.

iOS registers allowed `componentKeychainAccessGroups` separately from the private
root group. The default is no groups; native-owned RN clients inherit this
immutable allowlist. A new RN callback or equivalent configure call cannot widen
the authorized extension boundary.

The account-scoped extension handoff is a native SDK API. The historical RN
extension-client constructor remains a legacy boundary; it is not an adapter for
opening newly account-scoped extension state. Embedded hosts perform this handoff
in Swift/Kotlin and keep root session material out of extension configuration.

Migration fences upgraded legacy constructors across restart and drains known
native/RN stores. Hosts must inventory additional authorized groups, custom
attestation stores and custom credential stores through the native migration
hooks. The SDK cannot discover arbitrary developer storage or make an old binary
understand a new retirement marker. Migration success is scoped to that explicit
inventory, not every historical storage location or downgraded binary.

The actual LatchwayChat apps use explicit account activation and offline logout.
The RN example also contains native-owned embedded chat hosts and a local source
overlay that resolves one native implementation. Candidate dependency versions
are recorded in the RN repository's `release-candidate.shared-native.json`;
historical release locks are not relabeled as a published shared-native release.
Signed physical-device, extension-process, Keystore and actual Fast Refresh
acceptance remain distinct from local fixture tests and consumer builds.

Final local RN consumers build on iOS and Android for RN 0.74 / React 18.2 and
RN 0.82 / React 19.1. The RN example's `SHARED_NATIVE_VERIFICATION.md` records
the exact tests, source overrides and limits; this is not registry publication
or physical account-switch evidence.
