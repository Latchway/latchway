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

- Node.js 24.19.0 (the repository and CI pin this exact release)
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
pnpm check:generated
python3 scripts/check-structure.py
python3 scripts/check_metadata.py
python3 scripts/check-visual-assets.py
```

The visual gate byte-locks the four plan-required custom SVGs, rejects unsafe
or externally loaded SVG content, requires an accessible title and description,
dark-mode and forced-color policies, an exact text alternative, and one
captioned page use. It gives every pull request a deterministic visual-source
diff without requiring a browser credential. It does not claim pixel-level
Mintlify layout equivalence: a rendered screenshot baseline and human review of
the provider preview remain external repository/service configuration until a
stable production theme and canonical domain exist.

The generated gate derives the Client and Admin APIs, stable errors,
configuration schema, framework compatibility pages, and release-bound SDK
examples and catalogs from the canonical core contracts and locked SDK
documentation bundles.
Editing a generated page or snippet without its normative source fails the
drift check. Update SDK material only with the commands documented on
[SDK documentation bundles](/reference/sdk-bundles).

Every canonical page resolves title, description, icon, audience, page type,
server version, SDK version, verification date, and stable owner metadata.
Authored pages carry those fields physically. The five generated SDK-bundle
routes receive the same fields from a strictly validated deterministic overlay;
tests fail when any route or field is absent.

The setup-path chooser may persist only its explicit non-secret allowlist:
public gateway and Console origins, application resource ID, Console
application slug, environment, feature and Component Definition IDs, version
coordinates, and reader-path selections. URL values pass the same validation
before use. The chooser never accepts a token, credential, proof, attestation
evidence, request body, or provider key. Anonymous placeholders and every
navigation path remain usable when browser storage is unavailable.

The public Mintlify API playground is disabled and proxying is off. Protected
Client API operations require live DPoP and platform trust, so a static token
form would be misleading. Admin API examples target localhost or an owned
sandbox with a short-lived scoped token held in a private shell environment;
the documentation site never receives or prefills that token.

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

Commit the canonical public-doc changes before the final `--write`. The mirror
manifest records that exact core commit, and the required mirror workflow
checks out `Latchway/latchway` at the recorded revision and byte-compares the
complete publishable tree. If a working-tree preview was synchronized first,
rerun `--write` after the core commit and before committing the mirror.

The first adoption of an existing byte-identical mirror uses `--initialize`.
That mode refuses to mutate a mismatched mirror.

## Deployment

Mintlify deployment is GitHub-App driven from the generated
`Latchway/latchway-docs` `main` branch. The mirror workflow validates
configuration, internal links, anchors, redirects, MDX snippet references,
accessibility, and the fail-closed hashes in the checked-in source manifests
before changes merge. The core gate also revalidates each vendored SDK archive,
manifest, checksum closure, source provenance, lock, and generated output.
Owning SDK release workflows compile or run the source examples before building
their bundles; Mintlify validation does not substitute for those SDK tests.
The core-side synchronizer performs the byte-for-byte canonical-source
comparison before updating that manifest. The mirror and protected production
evidence workflows independently repeat the comparison against the exact
recorded public core commit. Neither validation path deploys or requires a
private cross-repository credential.

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
