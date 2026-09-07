# Native mobile and React Native in one signed app

A single signed iOS bundle can contain both the native and React Native SDKs.
Configure two `main_app` root Component Definitions: one `ios`, one
`react_native_ios`, with the same bundle identifier. Both must use direct
`app_attest` verification, and each platform must have its own exactly matched
required App Attest selection. An explicit `ios` root does not authorize RN by
itself; adding only a platform policy without its root definition is insufficient.

Android supports the corresponding `android` / `react_native_android` pair of
`android_app` roots sharing one package name. Both roots must be directly verified
by required Play Integrity selections whose package names match the configured
root. Use matching certificate, licensing and device-integrity policies for the
same signed application.

These are the only duplicate-identifier exceptions. Same-platform duplicates,
additional roots for either platform, delegated component overlaps, watchOS
overlaps, unsupported root kinds, cross-OS collisions, and mismatched providers
remain rejected by both configuration validation and runtime snapshot reconstruction.

The roots remain distinct, resolved from the exact platform and verified
attestation provider. Their sessions, keys, attestation bindings and component
grants are not aliases. Existing native installations are not reassigned or
revoked. Keep a consistent feature allowlist and trust policy when embedding
both SDKs in the same product. A user/feature quota without platform in its scope
is shared by the two transports in the same application environment.

This is additive configuration acceptance: contract 1.0.0, wire protocol 2 and
database schema 29 are unchanged. Before rolling back to a server that rejects
shared identifiers, reactivate compatible pre-change configuration revisions
first; do not start an older runtime against the new active documents.
