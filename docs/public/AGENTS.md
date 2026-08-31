# Public documentation instructions

The core repository directory `latchway/docs/public` is the canonical source
for Latchway's public Mintlify site. When this file appears in the standalone
`latchway-docs` repository, that repository is a generated deployment mirror,
not a second authoring source.

- Keep implementation plans, evidence ledgers, internal ADRs, and maintainer
  notes outside this directory.
- Give every MDX page unique `title`, `description`, `icon`, `audience`,
  `pageType`, `serverVersion`, `sdkVersion`, `lastVerified`, and `owner`
  frontmatter and add it to exactly one navigation location. Only the five
  generated SDK-bundle routes may use the validated metadata overlay.
- Use calm, direct, security-aware language. Avoid “simply,” “just,” “fully
  secure,” and unsupported release claims.
- Distinguish authentication, attestation, authorization, and DPoP. Distinguish
  an Installation Family from a Client Component and a feature from a route or
  physical model.
- Never recommend upstream provider credentials in a client. Never call a
  delegated component directly attested.
- Treat Web and React Native as separate platforms. WebCrypto key possession,
  App Check, and Turnstile do not inherit native hardware-attestation claims.
- Use generated OpenAPI, compatibility, and SDK-bundle outputs when available.
  Do not hand-edit generated support claims or snippets.
- Run `pnpm check` in the canonical directory before synchronization. From the
  core `latchway` repository, use `scripts/sync-public-docs.py`; do not edit
  mirror-owned content directly.
