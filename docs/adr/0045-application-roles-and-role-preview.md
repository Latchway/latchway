# ADR 0045: Application roles and role preview

Status: Accepted for implementation, 2026-10-08. Unreleased; ships in the Admin
contract bundle edition 1.1.3 with server 1.2.0.

## Context

Roles were organization-wide: giving someone control of one app meant giving it
for every app. Owners also had no way to check what a teammate with a smaller
role would see without signing in as them.

## Decision

- **Application roles raise, never lower.** An owner can give a member Admin or
  Operator in one application. In that application the member acts with the
  higher of the two roles; everywhere else, and for organization-wide actions
  (creating applications, the team, single sign-on, invitations), the
  organization role applies. Restricting a member below their organization
  role is out of scope: it would need every read path filtered, and a missed
  check would leak data, whereas a missed check in this model only fails
  closed.
- **Enforcement.** `Principal` loads the application roles with the session or
  API token on every request. Application-scoped checks (configuration drafts,
  validation, plans, activation and rollback; environments and application
  status; secrets; user limit overrides; self-tests and schedules;
  installation, family, component and user actions) first ask whether the
  capability is held anywhere, then check the exact application once the
  target is loaded. API tokens may carry any capability their holder has in
  some application; each use is still checked against the target
  application.
- **Hygiene.** Owners hold no application roles, a grant must be higher than
  the organization role, and raising the organization role drops grants it
  covers. Grants disappear with the membership. Changes are audited
  (`admin.application_role_set`, `admin.application_role_remove`) and take
  effect on the member's next request.
- **Role preview** is a console view for owners: it shows the console as an
  Admin, Operator or Viewer would see it (organization role only), turns
  changes off, and says so. It doesn't change what the server allows: every
  request is still checked against the owner's own role. There is no
  impersonation.

The feature is negotiated by the `admin_application_roles` server capability;
the session document carries `application_roles`.

## Consequences

Teams can hand an app to its own admins without widening anyone's access to
other apps. The console computes per-application capabilities from the
session for display only. A per-application restriction model would need a
separate decision.
