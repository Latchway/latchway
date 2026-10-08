# ADR 0040: Administrator account self-service

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

Owners create administrators and reset their passwords with a password the owner
chooses. Until now that password stayed in use indefinitely: the
`password_reset_required` column existed but was never set, and administrators
had no way to change their own password, see their own sessions, or switch
organization without signing in again. A console session that stopped working
returned the same `authentication_required` problem whatever the cause, so the
console could not tell an operator that, for example, their password had been
changed elsewhere.

## Decision

- **Owner-set passwords are temporary.** Creating an administrator or resetting
  their password sets `password_reset_required`. A console session for that
  administrator may only read its session, read `GET /system`, change its own
  password and sign out; every other Admin API call returns
  `permission_denied` until the password changes. The bootstrap owner chooses
  their own password and is not affected.
- **Own password change** (`POST /auth/password`) is available to console
  sessions only, never to API tokens. It verifies the current password under
  the login failure limiter, refuses reuse, clears the forced change, and
  revokes every other console session of the administrator in every
  organization (passwords are global to an administrator). API tokens are not
  revoked by a self-service change; an owner reset still revokes them.
- **Session end reasons are disclosed to the cookie holder.** When a presented
  cookie belongs to a session that has ended, the Admin API returns
  `session_expired` or `session_revoked` from the existing shared error
  registry, with a detail naming the reason. Unknown cookies keep
  `authentication_required`, so the response never confirms that an arbitrary
  value was a session. No new error codes are introduced.
- **Organization switch** (`POST /auth/organization`) replaces the console
  session with one for another active membership in a single transaction,
  without asking for the password again. Membership is the authorization;
  the old session is revoked so exactly one stays usable.
- **Last organization.** Each session records the administrator's
  `last_organization_id`; a sign-in that names no organization uses it while
  that membership is active, otherwise the first membership.
- **Device summaries, not network metadata.** Sessions store a coarse
  "Browser on OS" phrase derived server-side from the User-Agent. The raw
  header and network addresses are not stored, preserving the existing rule
  that session views carry no network metadata.
- **Pre-sign-in information** (`GET /auth/info`) is public and reports only the
  advertised client contract, protocols, whether first-owner setup is still
  open and the enabled sign-in methods. It reports no build version.

The new endpoints are negotiated by the `admin_account_self_service` server
capability. The console treats it as optional and hides the features on older
servers.

## Consequences

Administrators created or reset by an owner must pass through "Choose your
password" before using the console, including those created with the CLI. The
CLI keeps using API tokens and therefore cannot change its holder's password.
The client contract, wire protocol and shared error registry are unchanged.
