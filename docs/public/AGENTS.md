# Public documentation instructions

This directory is the canonical source for Latchway's public Mintlify site. The
standalone `latchway-docs` repository is a generated deployment mirror.

- Keep implementation plans, evidence ledgers, internal ADRs, and maintainer
  notes outside this directory.
- Give every MDX page unique `title` and `description` frontmatter and add it to
  exactly one navigation location.
- Use calm, direct, security-aware language. Avoid “simply,” “just,” “fully
  secure,” and unsupported release claims.
- Distinguish authentication, attestation, authorization, and DPoP. Distinguish
  an Installation Family from a Client Component and a feature from a route or
  physical model.
- Never recommend upstream provider credentials in a client. Never call a
  delegated component directly attested.
- Use generated OpenAPI, compatibility, and SDK-bundle outputs when available.
  Do not hand-edit generated support claims or snippets.
- Run `pnpm check` before synchronization. Use
  `scripts/sync-public-docs.py`; do not edit mirror-owned content directly.
