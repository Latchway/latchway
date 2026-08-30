# ADR 0009: Immutable configuration revisions

## Context

Mutable rows can expose a partially applied routing/policy state, lose concurrent edits and make audit or rollback unreliable.

## Decision

Store complete immutable environment configuration documents as revisions. Draft creation and replacement use ETags. Validation covers JSON Schema, references, secret availability, CEL compilation, protocol capabilities, pricing and route simulation. Activation atomically updates the environment's single active revision pointer. Rollback activates a prior valid revision without mutating history.

## Alternatives

- Independently mutable resource tables: ergonomic CRUD but partial activation and complex rollback.
- Configuration files only: reproducible but cannot provide the canonical Admin API workflow.
- Last-write-wins documents: silently loses concurrent changes.

## Consequences

Compiled normalized configuration can be cached by revision ID. Diffs and audit events are deterministic. Large documents require size limits and careful secret references.

## Security implications

Secrets are referenced, never embedded. Invalid or unsafe debug, CEL, pricing, protocol or destination configuration cannot activate. Tenant ownership and ETags prevent cross-scope or stale writes.

## Migration implications

Schema evolution requires explicit `apiVersion` conversion or rejection. Active revisions remain interpretable across rolling upgrades, and rollback support is tested before release.

## Status

Accepted for version 1 on 2026-08-27.
