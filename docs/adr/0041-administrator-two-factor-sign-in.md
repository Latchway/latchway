# ADR 0041: Administrator two-factor sign-in

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

Console sign-in relied on a password alone. Operators asked for a second factor
and for owners to be able to require one. The deployment already depends on a
32-byte master key for provider secrets, and PostgreSQL remains the only
external service.

## Decision

- **TOTP (RFC 6238)** with HMAC-SHA-1, six digits and a 30-second period, the
  parameters every authenticator app accepts. A code is accepted one period
  either side for clock drift and only once: the newest accepted time step is
  stored and a code at or before it is refused.
- **Key storage.** The 160-bit key is sealed with AES-256-GCM under a key
  derived from the master key for the domain
  `latchway/admin/second-factor/v1`, with the administrator ID as associated
  data, so a sealed key cannot be opened for another account or as a provider
  secret. The plaintext key is returned once, during enrollment, as text and an
  `otpauth://` link; it is never readable again.
- **Recovery codes.** Confirming an authenticator issues ten single-use codes
  (about 59 bits each), stored as domain-separated SHA-256 hashes and shown
  once. Replacing them requires a current authenticator code.
- **Sign-in.** A correct password for an account with a confirmed factor returns
  `202` with an opaque challenge (stored hashed, five-minute lifetime, five
  failed attempts) and no cookie. `POST /auth/login/two-factor` finishes with a
  code or a recovery code. Wrong codes are also counted per administrator by
  the existing failure limiter across challenges.
- **Self-service and owners.** Enrollment, recovery-code replacement and
  turning the factor off are console-session-only. Turning it off needs the
  password and a current code and is refused while any organization the
  administrator belongs to requires a second factor. An owner can reset a
  member's factor (revoking that member's sessions in the organization) under
  the same cross-organization rule as a password reset.
- **Organization requirement.** `organizations.require_two_factor` makes a
  member's console session without a confirmed factor enrollment-only: it may
  set one up, change its password, read its session and system status, and
  sign out. API tokens are not affected; they are separately scoped,
  expiring credentials.

The feature is negotiated by the `admin_two_factor` server capability.

## Consequences

Losing both the authenticator and the recovery codes leaves an owner reset (or,
for a lone owner, the database) as the way back in; the console says so. TOTP
remains phishable in real time; passkeys (ADR 0042) address that. The client
contract and shared error registry are unchanged; the console renders the
enrollment QR code locally with the bundled MIT-licensed `uqr` encoder.
