# ADR 0048: Configuration draft lifecycle

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0. Amends ADR 0009.

## Context

ADR 0009 says an update replaces the document of a never-activated draft, but
the server froze a draft as soon as it validated. The console validates after
every save, so its next save on the same draft was refused with a conflict and
reported as an out-of-date draft. Beyond that bug, drafts had no way to be set
aside (ADR 0009 deferred discard to a later decision), no record of who changed
what, no publish note, no path forward when something else was published
first, and no way to start one environment's draft from another's.

## Decision

- **Editable until activated.** A validated revision that was never activated
  can be replaced or rebased; it returns to `draft`, its compiled snapshot and
  report are cleared, and its ETag changes, so an earlier plan or approval no
  longer activates it. Nothing at runtime references a never-activated
  revision (self-test schedules bind to the active one). Activated revisions
  keep every immutability guarantee. The database trigger now names exactly
  these transitions and also fixes identity columns for every row.
- **Discard is a tombstone.** `POST /config-revisions/{id}/discard` (strong
  ETag) moves a never-activated draft to `discarded`, records who and when,
  clears its compiled snapshot, and keeps its document readable. A discarded
  revision can't be edited, validated, simulated or activated, and the trigger
  refuses any change to it. Nothing is deleted, which satisfies ADR 0009's
  audit-integrity condition.
- **Edit history.** Every create, replace, rebase and promotion appends a row
  to `config_revision_edits`: author, time, kind and the value-free structural
  paths (at most 100, with the full count). The table is append-only.
  `GET /config-revisions/{id}/edits` lists the newest 200. Revisions carry
  `updated_at`/`updated_by` from the latest edit, plus `base_revision_id` and
  `description`, which the server already stored.
- **Publish notes.** Activation accepts an optional `{ "note": ... }` (1 to 500
  characters, no control characters other than line breaks), stored as
  `activation_note` and immutable once activated. The audit event marks the
  field as sensitive and never contains the text.
- **Rebase.** A draft records the live revision it started from, and activation
  still refuses a draft whose base isn't live. `GET /rebase-preview` lists, by
  path, what the draft and the live revision each changed since that base and
  where both changed the same path differently. `POST /rebase` (strong ETag)
  merges with `live_revision_id` (which must still be live) and an explicit
  `draft` or `live` for every conflict and nothing else; objects merge by key,
  lists of identified entries by `id`, and reordered lists, sensitive subtrees
  and other values are taken whole. Paths, never values, cross the API; the
  console reads the three revisions to show values side by side.
- **Promotion.** `POST /environments/{id}/config-revisions/promote` starts a
  draft from another environment's live revision in the same application.
  Product settings (features, models, input accounting, pricing, limit plans,
  session, privacy) come from the source. Sign-in providers, attestation
  policies, component definitions and AI connections the target already has
  stay; entries only the source has are copied and returned under `review`,
  since they may point at the source's projects, identifiers, URLs or secrets.
  Metadata always names the target. It refuses while the target has an
  unpublished, undiscarded draft newer than its live revision.

The features are negotiated by the `admin_configuration_drafts` server
capability. Schema 40 adds the columns, the edit table and the trigger.

## Consequences

The console edits one working draft in place and shows who changed it. Against
older servers it carries a validated draft's content into a fresh draft
instead of editing it, which fixes the same failed second save there. Stale
drafts can be merged instead of redone. Edits made before schema 40 have no
history rows; revisions report their creation instead.
