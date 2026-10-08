# ADR 0049: Policy insights and simulation

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

Plan editing gave no sense of who a limit would stop, removing a plan couldn't
list users overridden to it, and a plan's rules couldn't be compared with real
traffic. The simulator worked out connection outages in the browser without
the server's retry and fallback rules, ran its coverage grid one request at a
time, couldn't keep scenarios, and didn't say how much of a limit a real user
had used.

## Decision

- **Usage distribution.** `GET /usage/distribution` sums a usage metric per
  subject (user, feature or installation, as a limit scopes) in every calendar
  window of a limit's window and timezone, aligned by the quota package's own
  period function (exported as `quota.CalendarPeriods`), over at most 90 days
  and 2,000 windows. It returns each subject's busiest window as percentiles
  and a 1-2-5 histogram and, with `maximum`, how many subjects and users would
  have exceeded it. Only counts leave the server.
- **Override list.** `GET /user-overrides` pages through the existing retained
  override rows: active (unrevoked, unexpired) or ended (revoked or expired),
  filterable by plan and user.
- **Plan share.** Request facets gain a `limit_plan` facet and an optional
  `feature` filter, so a feature's recent requests can be split by the plan
  they were recorded with.
- **Limit usage.** A user's effective configuration includes each limit's
  current quota state for the user's current installation, read with the
  quota store's read-only snapshot, one rule at a time so each value maps to
  its limit. Limits scoped on route, upstream or model have no single value
  outside a request and are left out with a warning.
- **Failure simulation.** A simulation can name failing routes and a
  condition. The server walks the route plan exactly as the data plane does
  after a failed attempt (same-route retry when the retry policy names the
  condition, otherwise fallback when the route's `fallbackOn` does, within the
  32-attempt limit and the opaque-HTTP replay rule) and returns the attempts.
  Those decisions moved onto `configuration.Route` so the data plane and the
  simulator share one implementation. Deadlines and partial responses are
  stated as assumptions.
- **Batch.** `POST /config-revisions/{id}/simulate-batch` runs up to 50
  simulations against one compiled revision; each item succeeds or fails on
  its own.
- **Saved scenarios.** `simulation_scenarios` (schema 41) stores named
  simulator inputs per application, validated like a simulation and limited to
  200 per application and 16 KiB each, with optimistic versions. They need
  `activate_configuration` in the application. Audit events mark the input as
  sensitive, so test claim values never enter the audit log.

The features are negotiated by the `admin_policy_insights` server capability.

## Consequences

Operators can size limits against real usage and see the plan split before
they publish, and the simulator's failure answers now match production
behavior. Distributions are environment-wide for the filters given and cover
only usage-record metrics, not concurrency or byte limits.
