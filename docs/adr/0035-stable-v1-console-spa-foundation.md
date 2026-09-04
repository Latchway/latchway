# ADR 0035: Retain the stable static Console SPA foundation for version 1

## Context

The original version 1 implementation plan selected a React Console built with
Vite, TanStack Router, TanStack Query, and Zod, then embedded its static output
in the single Latchway server image. The implemented Console follows that
design and has generated Admin API types, capability and safe-mode handling,
optimistic-concurrency controls, unit tests, browser tests, and accessibility
coverage.

A later Admin Console direction proposed TanStack Start in SPA mode, TanStack
Form, TanStack Table, and shadcn/ui. Its primary requirement is an operator-
focused product that supports complete first-run setup and ordinary operations
without weakening server-side validation or requiring a separate Node runtime.
It also permits a plain TanStack Router fallback if the Start integration adds
risk.

Replacing the working application foundation and component system at the
version 1 release boundary would be a broad migration. It would not itself add
an Admin API capability or close a missing operator workflow, and it would put
the already-tested static embedding, Content Security Policy, generated API
boundary, and accessibility behavior back into an unproven state.

## Decision

Version 1 retains the existing static Vite and React SPA with TanStack Router,
TanStack Query, and Zod. The Console remains a build-time artifact embedded in
the Go binary; it has no Console-specific server functions and requires no
Node.js runtime in the release image.

The outcome and quality requirements of the later Console direction remain
normative. In particular, version 1 must provide task-oriented first-run and
ongoing configuration, platform-specific guidance, capability-gated actions,
accessible interactions, explicit unavailable states, safe redaction, and
server-canonical validation. Domain-specific forms and tables may remain on
the existing component foundation when their behavior and accessibility are
covered by tests.

TanStack Start, TanStack Form, TanStack Table, and shadcn/ui are not required
version 1 dependencies. A post-version-1 proposal may adopt any of them after
demonstrating an incremental migration that preserves the single-image static
deployment, generated API contract, security headers, browser compatibility,
accessibility, and clean build reproducibility.

## Alternatives

- Migrate the entire Console to TanStack Start before version 1: rejected
  because it reopens the deployment and browser surface while leaving the
  operator outcomes to be implemented afterward.
- Introduce only TanStack Form, TanStack Table, or shadcn/ui immediately:
  rejected as a release requirement because replacing stable primitives does
  not close a current functional gap. Individual post-version-1 changes may
  still justify these dependencies.
- Treat the later Console plan as non-normative: rejected. Its task-oriented
  workflows, platform guidance, accessibility, safety, and verification bar
  are product requirements even though its suggested framework stack is not.

## Consequences

The version 1 Console can close remaining operator-workflow gaps without a
framework rewrite. Existing lint, type, unit, production-build, browser, and
accessibility gates remain comparable, and the release image retains one
static application served by the Go process.

This decision accepts that the version 1 source will not match every suggested
library in the later plan. That variance must be stated directly rather than
represented as a completed framework migration. Future adoption must be
incremental and evidence-backed; it is not prohibited by this record.

## Security implications

The browser remains an untrusted Admin API client. Authorization, validation,
configuration invariants, capability decisions, optimistic concurrency, and
secret redaction stay server-enforced. The Console must not create a parallel
validation truth, persist credentials in browser storage, bypass safe mode, or
infer that a sample request succeeded without durable server evidence.

Retaining static embedding preserves the reviewed deployment boundary: the
production image contains no Node runtime or Console application server, and
the existing Go server continues to own security headers and API routing.

## Developer-experience implications

Contributors use the existing pinned pnpm, Vite, React, TanStack Router,
TanStack Query, and Zod toolchain for version 1 work. New operator workflows
should reuse established accessible primitives, generated Admin API types, and
test helpers. A dependency migration requires its own ADR or an explicit
amendment with clean-install, bundle, browser, accessibility, and image
evidence.

## Migration implications

No runtime, database, wire-protocol, deployment, or Admin API migration is
required. The remaining version 1 work is confined to closing functional and
guidance gaps on the current foundation and regenerating the embedded static
artifact through the established reproducible build path.

If a later migration is approved, it must support a staged route-by-route or
primitive-by-primitive transition and must not require operators to deploy a
second service.

## Documentation implications

Contributor and architecture documentation must describe the Console as a
Vite-built static React SPA and distinguish binding product outcomes from
non-binding framework suggestions. Public operator documentation remains
organized around tasks and platforms rather than implementation libraries.

## Status

Accepted for version 1 on 2026-09-04. Re-evaluate the optional framework and
component-library migration after the version 1 release is qualified.
