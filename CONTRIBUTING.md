# Contributing to Latchway

Latchway accepts focused, reviewable contributions that preserve the security boundary and contract compatibility described in `AGENTS.md`.

## Before changing code or contracts

1. Read `docs/architecture/overview.md`, the applicable threat-model documents, and recorded ADRs.
2. Check `docs/implementation/STATUS.md` for active work and blockers.
3. For wire or configuration changes, update the normative `api/` source first and state whether compatibility changes.
4. Keep unrelated formatting or generated churn out of the change.

## Required quality

- Add positive, negative, and adversarial tests appropriate to the change.
- Never weaken or disable a failing test to make CI pass.
- Do not add secrets or production-derived sensitive fixtures.
- Keep generated output reproducible and commit it with the source that generates it.
- Update documentation, status, compatibility, and ADRs when behavior changes.
- Run all documented checks for the touched area and report exact commands and results.

## Commits and Developer Certificate of Origin

Use small conventional commits such as `feat(session): add RFC 9449 proof validation` or `docs(security): define web trust limits`. Every commit must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

By signing off, you certify the Developer Certificate of Origin 1.1 at <https://developercertificate.org/>. Use `git commit -s` to add the line.

## Security reports

Do not contribute a public exploit for an undisclosed vulnerability. Follow `SECURITY.md` first.
