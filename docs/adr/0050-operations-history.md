# ADR 0050: Operations history and renames

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

System Health showed only the current self-check, so an operator couldn't
tell whether the server had been unhealthy overnight. AI connection health was
visible only through individual requests. Self-test runs could be read only
by ID, so past runs were unreachable unless a schedule pointed at the latest
one. Applications, environments and organizations kept the display name they
were created with.

## Decision

- **Health samples.** A periodic `record_health_sample` job (every five
  minutes, coalesced like other periodic jobs) runs the server self-check on a
  worker and stores one row in `system_health_samples` (schema 42): the
  overall state and the IDs of failed and warning checks. Summaries,
  remediation text and facts are not stored. The sample time is the job's
  scheduled slot, so concurrent workers write one row (`ON CONFLICT DO
  NOTHING`). Operational retention deletes samples older than 30 days.
  `GET /system/health-history` returns samples for at most 7 days (24 hours by
  default) to any authenticated administrator, matching the doctor's
  visibility. A gap means no worker was sampling; the console never fills it.
- **Connection health.** `GET /usage/connections` aggregates upstream attempts
  per AI connection over at most 90 days: outcomes, 429 and 5xx counts,
  attempts that another attempt followed, failures by public category,
  first-byte and duration percentiles, and recorded usage, with an optional
  hourly (at most 14 days) or daily series and at most 200 connections. It
  reads only what requests recorded and needs the same access as other usage
  reads. Nothing probes a provider.
- **Self-test list.** `GET /self-tests` pages an environment's runs newest
  first, filtered by schedule or state, with the run document already
  returned by `GET /self-tests/{id}`. It needs `run_self_tests` in the
  environment.
- **Renames.** `PATCH /organizations/{id}`, `/applications/{id}` and
  `/environments/{id}` change only `display_name` (1 to 200 characters, one
  line). Organizations need `manage_owners`; applications and environments
  need `activate_configuration` in the application. Each rename records an
  `admin.*_rename` audit event with a public `display_name` marker. Slugs never
  change, because configuration documents, console URLs and scripts use them.
- **No deletion.** Applications, environments and organizations still can't
  be deleted. Requests, usage, audit events and immutable configuration
  revisions reference them, and removing those rows would break the audit
  trail and the retention contract. Disabling remains the way to retire one.

The features are negotiated by the `admin_operations_history` server
capability. The CLI gains `status history`, `usage connections`,
`verify runs`, and `applications rename` / `environments rename`.

## Consequences

Operators can see when the server was degraded and which checks failed,
compare AI connections without opening requests, find past self-test runs and
correct names. Health history exists only while a worker runs and only from
the upgrade onward. Connection health reflects real traffic, so a connection
with no recent requests shows nothing rather than a guess.
