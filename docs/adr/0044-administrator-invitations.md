# ADR 0044: Administrator invitations

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

Owners added members by choosing a first password and passing it on, which
puts a credential in chat history or email. People should choose their own
password, and an owner should be able to send the invitation without the
server becoming a mail service or needing one.

## Decision

- **Links.** An owner invites an address with a role (any role, including
  owner) and an optional name. The server returns a link
  `/invitation#lwinv_…` once: 32 random bytes, stored only as a
  domain-separated SHA-256 hash, valid for seven days and one use. The token
  sits in the URL fragment, so it never reaches server logs or referrers; the
  console reads it at startup, removes it from the address bar and history,
  and keeps it only in memory. A new invitation for the same address replaces
  any open one, and "New Link" rotates a link and its expiry.
- **New accounts.** `POST /auth/invitations/accept` creates the account with
  the name and password the invited person chooses (no forced change) and its
  membership, then opens a console session.
- **Existing accounts.** An address that already has an account isn't asked
  for its password on the invitation screen. The person signs in normally, so
  two-factor, passkeys and single sign-on all apply, and then claims the
  invitation with `POST /auth/invitations/claim`, which only works for the
  invited address. The console then switches the session to the new
  organization, except for single sign-on sessions, which stay where they are.
- **Email, optional.** With `LATCHWAY_SMTP_HOST` and `LATCHWAY_SMTP_FROM` set,
  owners can have the link emailed. The relay must offer STARTTLS or use
  implicit TLS; plaintext is accepted only for a relay on localhost.
  Credentials come from the environment and are used only over TLS. Delivery
  happens during the request; a failure is recorded on the invitation and the
  link is still returned to share by hand. Messages are plain text with
  validated addresses and no user-controlled headers.
- **Single sign-on.** While an organization requires single sign-on, owners
  can't invite members other than owners, who join by signing in with SSO.

The feature is negotiated by the `admin_invitations` server capability.

## Consequences

Owners no longer handle anyone's password. Whoever holds a link can create the
invited account until it is used, revoked, replaced or expires, so links
should be shared privately; the email path inherits the relay's and the
mailbox's security. The existing "Add member with a first password" path
stays for servers without browser access. The client contract and shared
error registry are unchanged.
