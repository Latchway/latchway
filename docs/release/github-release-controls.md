# GitHub and npm release controls

Latchway keeps the reviewable desired state for all six controlled repositories
in [`.github/release-controls.json`](../../.github/release-controls.json). The
standard-library reconciler in
[`scripts/github-release-controls.py`](../../scripts/github-release-controls.py)
plans, verifies, or additively applies that state. The manifest contains
repository names, public integration identities, the non-secret sentinel
values, and configuration-variable and secret **names**. Other than those
public sentinel values, it never contains a configuration-variable value or
any credential value.

The controls cover:

- every privileged release environment, with self-review prevention, at least
  one reviewer distinct from the authenticated operator, an exact approval
  threshold of one, and an exact custom deployment policy for `main` only;
- the exact environment-scoped
  `LATCHWAY_RELEASE_CONTROL_POLICY_ID` variable, whose unique value is
  `latchway-release-controls-v1:<repository>:<environment>`;
- exact environment configuration-variable and secret-name inventories,
  including zero secrets for
  credential-free publishing, OIDC, and GitHub release environments;
- an active `refs/tags/v*` ruleset that restricts creation, update, and deletion
  and grants the only bypass to the GitHub Actions integration
  (`Integration` ID `15368`, mode `always`);
- an active `refs/heads/main` ruleset with no bypass, no deletion or force
  pushes, linear history, a zero-approval pull-request rule for the current
  single-maintainer topology, resolved review threads, and repository-specific
  Actions status checks;
- the five npm trusted-publisher tuples for the JavaScript and React Native
  packages.

The checked-in status contexts are real check-run names observed on `main` from
the GitHub Actions application. Online verification re-reads the current
`main` check runs and refuses to apply a ruleset if any named context is absent
or is not associated with integration ID `15368`. Every required pull-request
workflow must run without pull-request path filters. In particular,
`Validate canonical Mintlify source` runs on every pull request so an unrelated
change cannot leave that required context permanently Pending, and on every
push to `main` so online reconciliation can observe it on the current commit.

## Fail-closed environment sentinel

GitHub creates an environment without protection when a workflow references a
name that does not exist. Every privileged job must therefore make its first
step an exact assertion of its unique environment policy ID, before checkout,
OIDC, credential access, or any mutation through `GITHUB_TOKEN`. The exact
value is a reversible authorization lease: any other environment-scoped value
fails the workflow closed. For example:

```yaml
- name: Require the protected release environment
  shell: bash
  env:
    LATCHWAY_POLICY_ID: ${{ vars.LATCHWAY_RELEASE_CONTROL_POLICY_ID }}
  run: >-
    test "$LATCHWAY_POLICY_ID" =
    'latchway-release-controls-v1:latchway:release'
```

The reconciler rejects the sentinel name at repository or organization scope.
That absence is essential: GitHub's `vars` lookup falls back to broader scopes,
which could otherwise make an auto-created environment appear valid. For each
environment it also requires the exact declared configuration-variable names
plus the unique sentinel. Missing required names withhold the sentinel;
unknown names require manual remediation. Every declared configuration name
must be absent from repository variables and from any applicable organization
variable. Organization `all`, `private`, and `selected` visibility is evaluated
against each repository just as secret visibility is. Values are read only to
compare the non-secret sentinel and are never emitted in evidence.

The same fallback rule applies to credentials. Every secret name allowed in a
protected release environment must be absent from repository Actions secrets
and from any organization secret visible to that repository. Otherwise an
auto-created or misspelled environment could inherit a broader secret through
`${{ secrets.NAME }}`. Verification reads
secret metadata names only; it never requests or records a secret value. For an
organization secret with `selected` visibility, the reconciler also enumerates
the selected repositories and rejects it only where it applies; `private`
visibility is evaluated against the repository's current visibility. The
manifest's `protected_secret_scope: environment_only` policy and equal required
and allowed name lists make every privileged credential mandatory in exactly
its named environment.

The manifest also lists retired credential names that are forbidden at every
scope. In particular, `LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN` is prohibited
in every environment and at repository or applicable organization scope: all
Latchway sibling repositories are public, so cross-repository and
release-domain source capture use anonymous, credential-disabled Git reads for
sibling repositories. The built-in token remains limited to core-repository
API authority where a workflow needs it.

The manifest seals 51 concrete boundaries across all six repositories: 22 in
the core repository, three in JavaScript, five in iOS, ten in Android, ten in
React Native, and one in the production-documentation repository. Core covers
release and preview/bootstrap image publication;
release-evidence publication, signing, live-provider, GitHub-read,
physical-device, Firebase App Check, and Turnstile; security and
private-sibling-read; deployment authentication, Compose, Cloud Run, AWS,
Fly.io, Cloudflare Containers, and signing; operational resilience; and
failure/load evidence. The SDK boundaries separately protect package and
GitHub releases, physical-device production and evidence signing, Android
candidate construction/upload signing/verification, and credential-free
publication verification. Deferred physical execution does not weaken these
controls: an unprovisioned boundary remains unsealed and its workflow fails at
the first step. Dynamic workflow syntax is permitted only where the workflow
closes it over manifest names and maps every input choice or matrix row to its
exact policy ID.

The source-free `publish` and `sign` jobs in `preview-image.yml` deliberately
reuse the single `preview-image-publishing` boundary. Each job asserts that
boundary's exact policy ID as its literal first step. Workflow validation
requires the manifest-backed consumer set to be exactly those two jobs, so a
job split changes the privileged-job topology without inventing a second
environment or weakening the 51-boundary inventory.

## Plan and verify

Supply one to six reviewer selectors as `user:LOGIN` or `team:SLUG`. The same
resolved reviewer set is required on every selected environment. Online modes
also resolve the authenticated GitHub user and fail closed unless at least one
selected user, or one member of a selected team, is a different account.
Planning is offline and writes canonical JSON evidence:

```sh
# Replace second-maintainer with a real reviewer distinct from the token owner.
python3 scripts/github-release-controls.py plan \
  --reviewer user:second-maintainer \
  --output /tmp/latchway-release-controls-plan.json
```

Online verification is read-only. Use a fine-grained GitHub token from an
environment variable, never a command-line argument. It must be able to read
repository metadata, organization and repository variables and secret names,
environment configuration, environment variables and secret names, check
runs, and repository rulesets. A `403`, malformed response, missing pagination
page, or drift is a hard failure.

```sh
GH_TOKEN="$(security find-generic-password -w -s latchway-release-controls)" \
python3 scripts/github-release-controls.py verify \
  --reviewer user:second-maintainer \
  --skip-npm \
  --output /tmp/latchway-release-controls-verify.json
```

Omit `--skip-npm` to verify npm trusted publishers with npm `11.15.0` or newer.
Before doing so, bootstrap the npm side explicitly:

1. Publish each manifest package at least once.
2. Authenticate the npm CLI as the operator at `https://registry.npmjs.org/`
   using a local npm session (for example, `npm login --registry
   https://registry.npmjs.org/`).
3. Give that authenticated npm identity `read-write` access to every selected
   package.
4. Enable account-level npm two-factor authentication. Trusted-publisher
   creation will otherwise be refused; any interactive OTP challenge remains
   the operator's responsibility.

Preflight pins both the default npmjs registry and the `@latchway` scoped
registry for every package-status, package-access, trusted-publisher list, and
trusted-publisher create command; identity and profile commands retain the
default registry pin. The explicit scope pin defeats hostile scoped npm
environment or user configuration.
Evidence records only the authenticated public username, registry, package
names, and prerequisite booleans. It never records email, other profile fields,
access maps, command output, or authentication material. The reconciler also
removes `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, and the
selected `--token-environment` name from every npm subprocess environment.
npm credentials must therefore come from the operator's local npm
configuration, and GitHub administration credentials cannot cross into npm
commands or evidence.

## Additive apply

Apply requires the literal confirmation below and GitHub write access for
environments, environment variables, and repository rulesets:

```sh
GH_TOKEN="$(security find-generic-password -w -s latchway-release-controls)" \
python3 scripts/github-release-controls.py apply \
  --reviewer user:second-maintainer \
  --confirm apply-latchway-release-controls-v1 \
  --output /tmp/latchway-release-controls-apply.json
```

Apply creates missing environments, adds the exact `main` deployment policy,
creates or completes managed rulesets, and adds or restores the owned sentinel
only after the environment and both repository rulesets are already live-exact.
It also creates missing npm trusted publishers. It never sends `DELETE`,
removes an unknown reviewer, branch policy, variable, secret, ruleset rule, or
bypass actor, revokes npm trust, or writes a secret value. Unknown or broader
control state suppresses every ordinary mutation. The only mutation allowed
while such drift exists is a restrictive, tool-owned quarantine of the
environment authorization lease. Required configuration
variable or secret names that are absent remain explicit failed checks for an
operator to provision.

For an existing environment whose deployment-branch mode is not already exact,
the reconciler stops for manual remediation. GitHub does not allow custom branch
policies to be enumerated while custom policies are disabled, so changing that
mode automatically would not be provably additive. Missing environments remain
safe to bootstrap because there is no hidden prior branch policy to preserve.

GitHub exposes the environment administrator-bypass state for verification but
does not expose it in the environment update request used by this tool. Disable
administrator bypass for every release environment in repository settings.
Verification treats an enabled or unobservable bypass as failure, and a newly
created environment will not pass until this manual setting is disabled.

Environment bootstrap is deliberately two-stage. The first apply may create a
missing environment, attach its reviewer configuration, and add the exact
`main` branch policy, but it withholds the sentinel. The operator must then
disable administrator bypass and provision every required environment secret
and configuration variable. A later live inspection must prove no bypass, the
exact independent reviewer policy, exact `main`-only branch policy, exact
environment variable and secret inventories, no broader fallback, current
`main` status contexts, and exact active main/tag rulesets. Rulesets are
inspected before every environment sentinel decision. A ruleset created or
completed in the current apply therefore cannot authorize a same-run seal; a
later live inspection must observe it as exact. Only then may apply install the
accepting lease as the final seal. If an accepting lease is present while any
repository or environment invariant is false, apply replaces it with a
deterministic environment-scoped quarantine value by `PATCH`; a missing
environment-scoped lease remains absent, except that apply installs the
quarantine value to shadow a dangerous repository/organization fallback. It
may create the environment solely to install that shadow. Quarantine never
uses `DELETE`, never exposes the value in evidence, and suppresses all ordinary
GitHub/npm reconciliation in that invocation. After a later invocation proves
every invariant live-exact, apply may restore the accepting lease; quarantine
and restoration never occur in the same inspection/apply cycle.

Apply immediately re-verifies the selected state. Evidence is canonical JSON
and contains mutation identities but excludes request bodies and all tokens.
If a later GitHub or npm operation fails after earlier operations succeeded,
the error evidence preserves the manifest hash, selected repositories, exact
successful GitHub mutation identities, exact successful npm publisher
identities, and the remaining pending identities. This journal makes partial
success auditable without exposing request bodies or credentials. Re-running a
successful apply produces no mutations.

## API references

The reconciler uses GitHub's documented REST APIs for
[environments](https://docs.github.com/en/rest/deployments/environments),
[deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies),
[environment variables](https://docs.github.com/en/rest/actions/variables),
[environment secret metadata](https://docs.github.com/en/rest/actions/secrets),
[check runs](https://docs.github.com/en/rest/checks/runs), and
[repository rulesets](https://docs.github.com/en/rest/repos/rules).
