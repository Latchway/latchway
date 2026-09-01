# ADR 0009: Immutable configuration revisions

## Context

Mutable rows can expose a partially applied routing/policy state, lose concurrent edits and make audit or rollback unreliable.

## Decision

Store complete immutable environment configuration documents as revisions. Draft creation and replacement use ETags. Validation covers JSON Schema, references, secret availability, CEL compilation, protocol capabilities, pricing and route simulation. Activation atomically updates the environment's single active revision pointer. Rollback activates a prior valid revision without mutating history.

For version 1, this immutable lifecycle is the configuration CRUD contract:

- create makes a new draft, either from a complete document or an exact active
  base revision;
- read lists and retrieves redaction-safe immutable revisions and the active
  revision;
- update replaces the complete document of a never-activated draft under a
  strong ETag;
- activate and rollback publish one complete validated revision atomically;
- delete and abandon are deliberately unsupported. Leaving a draft
  unpublished is the only abandon operation: it is inert, remains visible in
  audited history, and can never affect traffic unless separately validated
  and activated.

The Admin API, CLI, and console must not imply that an unpublished revision can
be erased. Any future archive, tombstone, retention deletion, or content
redaction operation requires a new decision that preserves audit integrity and
defines its concurrency and incident-response semantics.

## Alternatives

- Independently mutable resource tables: ergonomic CRUD but partial activation and complex rollback.
- Configuration files only: reproducible but cannot provide the canonical Admin API workflow.
- Last-write-wins documents: silently loses concurrent changes.

## Consequences

Compiled normalized configuration can be cached by revision ID. Diffs and audit events are deterministic. Large documents require size limits and careful secret references.

Operators may accumulate inert drafts. Version 1 chooses deterministic audit
and rollback evidence over destructive draft cleanup; the console identifies
that tradeoff where it shows unpublished revisions.

## Security implications

Secrets are referenced, never embedded. Invalid or unsafe debug, CEL, pricing, protocol or destination configuration cannot activate. Tenant ownership and ETags prevent cross-scope or stale writes.

## Migration implications

Schema evolution requires explicit `apiVersion` conversion or rejection. Active revisions remain interpretable across rolling upgrades, and rollback support is tested before release.

## Status

Accepted for version 1 on 2026-08-27.

The explicit version 1 CRUD mapping and no-delete/no-abandon boundary were
clarified on 2026-09-01 without changing the original immutable-revision
decision.
