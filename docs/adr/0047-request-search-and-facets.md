# ADR 0047: Request search, totals and facets

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

The request list already filtered on the server, but the console could only
offer free-text filter fields, couldn't say how many requests matched, and
had no way to find a request from the correlation identifier a client logged.
Rows didn't name the platform that sent them, and the new-request pill could
only say requests "may have arrived". The CLI's `requests list` took no
filters.

## Decision

- **Fields.** Each request carries `platform` (from the installation that
  sent it) and `client_request_id` when the client sent one. The runtime
  already accepts only `[A-Za-z0-9][A-Za-z0-9._:-]`, 8 to 128 characters, and
  treats the identifier as correlation only; the Admin API keeps it that way
  and rejects stored values outside that shape as corrupt.
- **Search.** `GET /requests` accepts `client_request_id` (exact match on the
  existing per-environment index) and `include_total=true`, a count of every
  match capped at 100,000. Filters share one condition builder with the
  count, so the total always describes the list.
- **Facets.** `GET /requests/facets` counts requests started in a half-open
  range of at most 90 days by outcome, feature, failure code, connection,
  model, route, platform, component kind and trust source, most common first,
  up to 100 values each, with a `truncated` flag. Outcomes and failure codes
  use their public names, so every value is one the matching list filter
  accepts. Facets ignore other filters and count the selected route,
  connection and model, while the list filters also match retried attempts;
  the contract says so.
- **The event stream stays data-free.** It keeps signaling topics only. A
  stream carrying request rows would bypass paging and the per-request read
  path and widen what a long-lived connection exposes. Instead, the console
  answers a `requests` signal by counting matches since the newest row it
  shows (one `page_size=1&include_total=true` request) and shows "N new
  requests" before loading them.
- **CLI.** `latchway requests list` takes every list filter as a flag plus
  `--total`, shows a PLATFORM column, and `latchway requests facets` prints the
  counts. The console's Export menu copies the equivalent CLI command.

The features are negotiated by the `admin_request_search` server capability.
Older servers keep free-text filters, the generic new-request notice and
ID-only search, and the console says so where it matters.

## Consequences

Operators can find a request from a client log line and pick filter values
from what actually happened. Counting is bounded (total cap, 90-day facet
range, 1,000 grouped values per facet) so neither endpoint scans more than
the list could. Facets are environment-wide for the range; narrowing them by
the other active filters would need a separate decision.
