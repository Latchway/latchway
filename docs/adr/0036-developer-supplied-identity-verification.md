# ADR 0036: Verify developer-supplied identity independently of credential refresh

Status: Accepted for the 1.1.0 release candidate, 2026-09-08.

## Context

Native and React Native may share one native app/session registry without
depending on an external authentication SDK. Applications supply ID tokens and
report authentication lifecycle changes. Cached Latchway credentials do not
prove that a replacement token is authentic. Local JWT decoding cannot renew
authorization freshness, and ordinary refresh must remain credential-only.

## Decision

Discovery capability `supplied_identity_v1` advertises
`POST /client/v1/sessions/identity`. Protocol 3 requests contain exactly
`refresh_token` and `identity: {provider, token}`. A fresh RFC 9449 proof is bound
to the refresh token's registered key and the exact method/URL; as with refresh,
there is no access-token `ath` requirement or Authorization header.

An active, unexpired, unrevoked refresh credential authorizes this recovery even
when the old identity or access token has expired. Current tenant, installation,
component, user, caller, origin and attestation policy must remain valid. The
configured identity verifier authenticates the new token before transactional
locks. In the transaction the server rechecks policy revision, key and durable
revocation; matches the verified provider/issuer/subject to the existing private
application user; updates the configured claims and current grant identity
freshness; and records the proof replay key atomically. A different valid user's
token is rejected without creating/linking a user or altering any grant.

Success returns only `installation_id` and verified identity metadata:
`provider`, `issuer`, `subject`, `audience`, `verified_at`, `expires_at`.
These are the requesting account's verification result, not diagnostics or a
client-chosen trust assertion. Responses are `no-store`; tokens, raw evidence
and normalized claims are not returned or logged. SDKs retain provider ID tokens
in native memory only and commit freshness only for the captured live generation.

This operation does not rotate credentials or keys, extend attestation or refresh
expiry, create installations, or alter quota. Concurrent credential rotation is
serialized by the existing refresh-row lock. A lost response can be retried using
the unchanged refresh token and a new proof; a rotated refresh token is rejected
without replay-family revocation by this verification-only operation. Ordinary
credential refresh retains its documented reuse behavior.

Initial sign-in still uses the identity-verified challenge/attestation exchange;
it requires no existing session. Expired possession or attestation requires that
flow again, without reactivating a retired SDK account. Local generation fencing
is SDK-owned; no API resets user quota or infers external-provider logout.

## Compatibility

This is additive to contract 1.1.0 / wire 3. Existing wire 1/2 routes are unchanged.
ADR 0032's exact one-field refresh body remains normative. Its old recovery advice
now has this capability-negotiated same-account identity alternative; attestation
renewal still uses the challenge exchange. Server 1.1.1 and migration 31 correct
the historical issuance-only timestamp constraint, permitting revalidation after
issuance without changing grant/attestation lifetime. The initial 1.1.0 tests
froze the clock and missed that real-device case; use 1.1.1 for supplied identity.

Clients must check both the capability and same-origin canonical endpoint. An
older server is an explicit unsupported configuration, not permission to trust a
locally parsed replacement token or dispatch a dummy model request to test it.

## Verification

The PostgreSQL-backed HTTP vertical slice covers forged/expired/wrong-account
tokens, provider and DPoP-key mismatch, expired identity suspension, successful
same-grant recovery, proof replay and lost-response retries. It asserts stable
user/grant/quota counts. Additional lifecycle tests cover revoked or rotated
possession and stale post-verification work. SDK/device acceptance is reported
separately from server unit and database verification.
