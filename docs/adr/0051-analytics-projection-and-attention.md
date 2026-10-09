# ADR 0051: Analytics projection, settlement warnings and the attention indicator

Status: Accepted for implementation, 2026-10-08. Unreleased; ships with server
1.2.0.

## Context

The redesigned Analytics page had no month-end view of cost, no breakdown by
AI connection, no count of errors by code, and no warning when usage totals
were behind. The console had no way to see, from any page, that something
needed attention. Overview, Settings and the new indicator also relied on an
environment's `active_revision_id`, which the Admin contract has declared since
0.1.0 but the server never sent, so every environment looked unconfigured.

## Decision

- **Month-end projection.** The Cost tab reads this UTC calendar month so far
  and last month from `GET /usage/summary` (providers bill by UTC month). The
  projection is a straight line: month-to-date cost times the month's length
  over the time elapsed, in exact integer nano-USD (`BigInt`), rounded half up.
  It appears only after a full day of the month and never for a missing cost,
  and it is labeled as a straight line, not a forecast. Unpriced models are
  called out because they make both figures low.
- **Breakdowns.** Cost, Performance and Reliability show a per-connection table
  from `GET /usage/connections` (ADR 0050), and Reliability counts requests by
  final error code from `GET /requests/facets` (ADR 0047), for ranges of at
  most 90 days. Older servers or longer ranges get a sentence instead of a
  guess.
- **Settlement warnings.** The usage APIs read the usage ledger directly, so
  rollup lag doesn't affect them; settlement lag does. Analytics reads the
  server self-check's `usage_settlement_backlog`, worker count and
  `usage_reconciliation_freshness` and says when recent totals may be low.
  These facts cover the whole server.
- **Attention indicator.** The header shows a count of what needs attention,
  computed by the same model as Overview's list from server records only:
  newest revision, API token expiry, readiness, the last 24 hours of usage
  and, when the server keeps them, the newest health sample if it is at most
  15 minutes old. Nothing is dismissable and nothing runs the full self-check
  from the header.
- **Active revision.** `GET /applications/{id}/environments` now includes
  `active_revision_id` for environments with a live configuration. Responses
  to environment mutations still omit it, because CLIs released before it was
  sent decode those responses strictly and would reject an unknown field.
- **Flat routes.** Every console route is one path segment. The embedded build
  loads its assets by relative URL so it can sit below any prefix, and the CSP's
  `base-uri 'none'` rules out a `<base>` element, so a reload of a nested path
  fetched assets from the wrong place and rendered nothing. Analytics moved
  from `/analytics/*` to `/usage`, `/cost`, `/performance` and `/reliability`.

## Consequences

Operators see where the month is heading, which connection costs or fails
most, which error codes dominate, and when totals are still settling, and the
header says from anywhere whether anything needs a look. Overview's setup
checklist and Settings' live revision column now reflect real configuration.
The projection knows nothing about seasonality or upcoming launches, and the
settlement warning cannot say which environment the backlog belongs to.
