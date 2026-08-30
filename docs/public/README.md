# Latchway public documentation

The authoritative Mintlify source is `docs/public/` in the core `latchway`
repository. The standalone `Latchway/latchway-docs` repository is a generated
deployment mirror. Do not author mirror-owned content there.

Latchway is a self-hostable gateway that lets mobile and web applications call
configured AI infrastructure without embedding upstream-provider credentials.

The documentation currently describes the repository-local tested version 1
source candidate. It is not an independent security review or an announcement
that the server image or SDK packages have been published. Release status is
tracked on the site and in the core repository's evidence ledger.

## Local development

Requirements:

- Node.js 20.17 or newer
- pnpm 10.15.0
- Vale 3.17.0 (the checked-in `mise.toml` installs the exact toolchain)

Install the pinned Mintlify CLI and validate the site:

```sh
mise install
pnpm install --frozen-lockfile
pnpm check
```

The package install supplies the pinned `mdx2vast` parser that Vale uses for
MDX. The prose gate applies the repository-owned terminology and verifiable-
language rules before Mintlify validation.

Start a local preview at `http://localhost:3000`:

```sh
pnpm dev
```

The structural check requires only Python 3 and can run before dependencies are
installed:

```sh
python3 scripts/check-structure.py
```

## Source and mirror ownership

Internal implementation plans, evidence ledgers, ADRs, and maintainer notes are
outside `docs/public/` and outside the Mintlify publish root.

The core synchronizer owns only files recorded in the mirror manifest. It
preserves mirror workflows and other unowned files, and refuses to overwrite an
owned file changed after the last synchronization.

From the core repository, synchronize a sibling deployment mirror with:

```sh
python3 scripts/sync-public-docs.py --target ../latchway-docs --write
python3 scripts/sync-public-docs.py --target ../latchway-docs --check
```

The first adoption of an existing byte-identical mirror uses `--initialize`.
That mode refuses to mutate a mismatched mirror.

## Deployment

Mintlify deployment is GitHub-App driven from the generated
`Latchway/latchway-docs` `main` branch. The mirror workflow validates
configuration, internal links, anchors, redirects, snippets, accessibility, and
the fail-closed hashes in the checked-in source manifest before changes merge.
The core-side synchronizer performs the byte-for-byte canonical-source
comparison before updating that manifest. Neither validation path deploys or
requires a cross-repository credential.

## Content policy

- Keep security and protocol claims aligned with the canonical core and SDK
  repositories.
- Do not describe a source candidate as a published release.
- Never add credentials, real user identifiers, raw attestation evidence, or
  private deployment endpoints.
- Use root-relative links for pages in this site.

## License

Apache License 2.0. See the canonical project repositories for `LICENSE` and
`NOTICE`.
