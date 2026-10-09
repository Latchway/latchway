# ADR 0043: Administrator single sign-on

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0, alongside ADRs 0040 to 0042.

## Context

Organizations want console access to follow their identity provider: people
join and leave in one place, and the provider's own policies (MFA, device
checks) apply. Latchway must not take on SAML, SCIM or a dependency on any one
vendor, and the server's only external service stays PostgreSQL.

## Decision

- **OpenID Connect only.** Each organization may configure one provider by its
  issuer URL, a client ID and a client secret. Saving reads the issuer's
  discovery document and refuses providers that don't name the same issuer,
  use HTTPS endpoints without queries, offer the authorization code flow and
  PKCE S256, and sign ID tokens with RS256 or ES256. Discovery, the token
  exchange and the JWKS go through the same DNS-rebinding-resistant,
  redirect-free transport as AI upstreams, which allows only public
  destinations; providers on private networks aren't supported.
- **Secrets.** The client secret is sealed with AES-256-GCM under a key derived
  from the master key for `latchway/admin/sso-client-secret/v1`, bound to the
  organization, and is never returned. The server authenticates to the token
  endpoint with `client_secret_post`.
- **Flow.** `POST /auth/sso/start` takes the organization's slug and returns the
  authorization URL with a random state, nonce and PKCE verifier, and sets a
  ten-minute HttpOnly `SameSite=Lax` cookie binding the sign-in to the browser.
  Only hashes of the state and the binding are stored, with the nonce and
  verifier, for ten minutes and single use; at most 500 may be pending per
  organization. `GET /auth/sso/callback` requires the binding cookie, redeems
  the code with the verifier, and verifies the ID token's signature, issuer,
  audience (and authorized party with several audiences), expiry, issue time
  and nonce. Success sets the usual session cookies and redirects to `/`;
  failure redirects to `/?sso_error=` with a stable reason and nothing about
  the identity.
- **Accounts.** An identity is the issuer and subject, linked to one
  administrator per organization. A linked identity signs in as its
  administrator. Otherwise the provider must have verified the email, and it
  must be in an allowed domain when the organization lists any: it then links
  to the active member with that email, or, when the organization provisions
  accounts, a membership is created with the provisioning role (never owner),
  creating the account without a password if needed. Owners can set a password
  for such accounts with the existing reset.
- **Sessions.** Sessions record how they signed in (`password`, `passkey` or
  `sso`). A single sign-on session relies on the provider for further factors,
  so the organization's two-factor requirement and a pending password change
  don't apply to it, and it can't switch to another organization, whose own
  rules would apply.
- **Requiring it.** An organization can require single sign-on: password and
  passkey sign-in, and switching in from another organization, are refused for
  members other than owners, who keep their other methods as a break-glass
  path. Requiring it ends members' other sessions; disabling or removing the
  provider ends single sign-on sessions (except the acting owner's). The new
  session end reason is `sso_changed`.

The feature is negotiated by the `admin_sso` server capability.

## Consequences

An organization's identity provider is trusted for that organization: whoever
controls it can sign in as any member whose email it asserts as verified, as
with any SSO deployment, and allowed domains narrow that. Removing someone at
the provider stops new sign-ins but not a session already open; owners can end
it from Team › Sessions. SAML, SCIM and group-to-role mapping are out of scope.
The client contract and shared error registry are unchanged.
