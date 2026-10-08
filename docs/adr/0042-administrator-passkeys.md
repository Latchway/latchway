# ADR 0042: Administrator passkeys

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0, alongside ADR 0041.

## Context

ADR 0041 added TOTP as a second factor and noted that codes can be phished in
real time. Passkeys (WebAuthn discoverable credentials) are bound to the
console's origin, so a look-alike site can't use them, and they replace both
the password and the code with one gesture. The server must stay free of new
external services and of attestation trust stores.

## Decision

- **One implementation, ES256 only.** `internal/webauthn` verifies the two
  ceremonies with the standard library and the existing CBOR dependency. It
  offers and accepts only ES256 (P-256), which every platform authenticator and
  security key supports. Registration requests attestation `none` and does not
  evaluate attestation statements; the authenticator data's public key is
  trusted the way that conveyance intends. Both ceremonies require user presence
  and user verification, an exact origin match, no cross-origin iframe, and the
  relying-party ID hash. Extension data is accepted only when flagged.
- **Relying party.** The RP ID is the host of `LATCHWAY_PUBLIC_ORIGIN` and the
  origin must match it exactly. Browsers refuse IP addresses as RP IDs, so
  passkeys are offered only for a domain name over HTTPS or `localhost`;
  `GET /auth/info` lists `passkey` in `sign_in_methods` only then, and the
  ceremony endpoints answer `server_not_ready` otherwise.
- **Storage.** `admin_passkeys` keeps the credential ID, the public key's
  coordinates, the signature counter, the AAGUID, the backup flags and a name.
  Each administrator gets a random 32-byte WebAuthn user handle on first use;
  it carries no account data. Challenges are 32 random bytes, stored as SHA-256
  hashes in `admin_webauthn_challenges` with a purpose (register, sign-in or
  second factor), a five-minute lifetime and single use. A second-factor
  challenge is tied to the password sign-in challenge it completes and is
  deleted with it.
- **Counter.** An authenticator that reports a signature counter must advance
  it; a non-advancing counter refuses the assertion and is logged as a possible
  clone. A counter of zero means the authenticator keeps none, as synced
  passkeys commonly do.
- **Adding and removing.** Both are console-session-only and require the current
  password (under the password-change limiter), because a passkey can sign in on
  its own and a stolen session cookie must not be able to plant one. The first
  second factor on an account also issues recovery codes. Removing the last
  second factor is refused while any of the administrator's organizations
  requires one, and otherwise also removes the recovery codes.
- **Sign-in.** `POST /auth/passkeys/sign-in-options` (public) returns request
  options with no allowed-credential list; `POST /auth/passkeys/sign-in`
  verifies the assertion and its user handle and opens a session in the
  requested, last-used or first organization. User verification on the
  authenticator stands in for both the password and the second factor. At most
  1,000 unauthenticated prompts may be pending at once, bounding the table; the
  password path is unaffected when that bound is hit.
- **Second factor.** Passkeys count wherever ADR 0041 counted a confirmed
  authenticator: the `202` after a password lists `passkey` among the methods,
  `POST /auth/login/two-factor/passkey-options` starts a prompt limited to the
  account's passkeys, and `POST /auth/login/two-factor` accepts the assertion
  under the same challenge attempts and per-administrator limiter.
- **Changes to ADR 0041 behavior.** `POST /auth/two-factor/disable` now removes
  only the authenticator app (passkeys stay), with the same refusal when no
  factor would remain under an organization requirement. Recovery codes can be
  replaced with the password when there's no authenticator app. An owner's
  two-factor reset removes the member's passkeys too. The two-factor status adds
  `enabled` and `passkeys`.

The feature is negotiated by the `admin_passkeys` server capability.

## Consequences

Administrators can sign in phishing-resistantly and without a password. Synced
passkeys inherit the security of the platform account that syncs them, which
the console shows as "Synced"; organizations needing device-bound credentials
would need attestation policies, which this ADR deliberately leaves out. The
password remains required for adding or removing passkeys and for recovery.
The client contract and shared error registry are unchanged; the request and
response bodies follow the WebAuthn Level 3 JSON encoding, so standard browser
helpers can produce them.
