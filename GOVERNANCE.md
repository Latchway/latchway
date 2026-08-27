# Governance

Latchway uses maintainer stewardship with transparent technical records.

## Roles

- **Contributors** propose changes and participate in review.
- **Maintainers** merge changes, uphold compatibility and security gates, and manage releases.
- **Security maintainers** receive private reports and coordinate remediation.
- **Release maintainers** verify cross-repository artifacts, provenance, signatures, and completion evidence.

Role membership is recorded through repository permissions and the public organization membership appropriate to the role. No role grants permission to bypass required reviews, security checks, or release evidence.

## Decisions

Routine implementation decisions use pull-request review. Durable or security-sensitive decisions require an ADR containing context, alternatives, consequences, security implications, migration implications, and status. Amendments supersede rather than silently rewrite accepted historical decisions.

Maintainers seek consensus. When consensus cannot be reached, a repository owner records the decision and rationale in the relevant ADR. Conflicts of interest must be disclosed; an affected maintainer should recuse from the final approval.

## Releases

A release maintainer may publish only after the applicable gates in `docs/implementation/MASTER_PLAN.md` pass and evidence is recorded in `COMPLETION_REPORT.md`. Version 1.0 requires compatible releases in all five repositories and no unfinished version-1 requirement.

## Changes to governance

Governance changes require a documented proposal, at least two maintainer approvals once two maintainers exist, and a public review period of at least seven days. Until then, the repository owner may approve a change but must record the rationale.
