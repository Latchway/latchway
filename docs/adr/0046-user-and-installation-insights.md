# ADR 0046: User and installation insights

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

The users and installations lists came back in creation order with no
filters, sorts, totals or per-user usage, so the console filtered only the rows
it had loaded and said so. Installation signals were computed in the browser
from loaded rows, action previews for installations used stale counts, and
acting on several users meant one request per user.

## Decision

- **Lists.** `GET /users` accepts `status`, `has_override`, `provider`, a
  single exact normalized-claim match `claim=name:value`, and `sort` (`oldest`,
  `newest`, `recently_seen`). `GET /installation-families` accepts `status`,
  `platform`, `signal` and the same sorts. Every value is a bound parameter;
  only the closed sort names select SQL text. Cursors encode the position for
  their sort. `include_total=true` adds a count of every match, capped at
  100,000, so a total never costs more than that.
- **Signals move to the server.** Each installation carries `signals` from a
  closed set: `debug_trust` (debug attestation outside Development),
  `trust_expiring` (root trust within seven days), `token_reuse` (a reused
  refresh token), `weak_key_storage` (a native part keeping its key in
  software or memory) and `failed_sessions` (a part with three or more
  sessions that ended uncleanly). They match the console's earlier rules and
  are filterable (`signal=any` for any of them).
- **Per-user usage.** `GET /users/{id}/usage` sums usage for that user's
  requests started in a range, with the same values and provenance as the
  environment summary.
- **Impact previews** for installation (`revoke`, `require_renewal`) and
  component (`revoke`, `require_reattestation`) actions count active parts,
  sessions, refresh tokens and requests in the last day, following the whole
  delegation tree. They change nothing; the actions re-check state.
- **Batches.** `POST /users/batch-impact` previews one action for up to 100
  users, returning each user's impact and token. `POST /users/batch` applies
  it with those tokens: each user changes in its own transaction with its own
  audit event and operation ID, and a user whose state changed since the
  preview is skipped as `changed`, keeping the single-user guarantee that no
  one is acted on from a stale preview.

The features are negotiated by the `admin_user_insights` server capability;
older servers keep the console's loaded-rows behavior, still labeled.

## Consequences

Large tenants get server-side narrowing and honest totals. Claim search is
exact match on configured normalized claims only; raw subjects and identity
tokens stay unsearchable by design.
