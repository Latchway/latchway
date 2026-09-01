-- name: CreateOrganization :one
INSERT INTO organizations (
    organization_id,
    slug,
    display_name,
    status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, 'active', $4, $4)
RETURNING organization_id, slug, display_name, status, created_at, updated_at;

-- name: ListOrganizationsForAdmin :many
SELECT
    organization.organization_id,
    organization.slug,
    organization.display_name,
    organization.status,
    membership.role,
    organization.created_at,
    organization.updated_at
FROM organizations AS organization
JOIN admin_memberships AS membership
    ON membership.organization_id = organization.organization_id
WHERE membership.admin_user_id = sqlc.arg(admin_user_id)
  AND membership.status = 'active'
  AND organization.status = 'active'
  AND (
      sqlc.narg(cursor_created_at)::timestamptz IS NULL
      OR (organization.created_at, organization.organization_id) > (
          sqlc.narg(cursor_created_at)::timestamptz,
          sqlc.narg(cursor_id)::text
      )
  )
ORDER BY organization.created_at, organization.organization_id
LIMIT sqlc.arg(page_limit);

-- name: CreateApplication :one
INSERT INTO applications (
    application_id,
    organization_id,
    slug,
    display_name,
    status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, 'active', $5, $5)
RETURNING application_id, organization_id, slug, display_name, status, disabled_at, created_at, updated_at;

-- name: ListApplications :many
SELECT application_id, organization_id, slug, display_name, status, disabled_at, created_at, updated_at
FROM applications
WHERE organization_id = sqlc.arg(organization_id)
  AND (
      sqlc.narg(cursor_created_at)::timestamptz IS NULL
      OR (created_at, application_id) > (
          sqlc.narg(cursor_created_at)::timestamptz,
          sqlc.narg(cursor_id)::text
      )
  )
ORDER BY created_at, application_id
LIMIT sqlc.arg(page_limit);

-- name: CreateEnvironment :one
INSERT INTO environments (
    environment_id,
    organization_id,
    application_id,
    slug,
    display_name,
    kind,
    status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)
RETURNING environment_id, organization_id, application_id, slug, display_name, kind, status, disabled_at, created_at, updated_at;

-- name: ListEnvironments :many
SELECT environment_id, organization_id, application_id, slug, display_name, kind, status, disabled_at, created_at, updated_at
FROM environments
WHERE organization_id = $1
  AND application_id = $2
ORDER BY created_at, environment_id;

-- name: AdminSessionView :many
SELECT
    admin.admin_user_id,
    admin.email,
    admin.display_name,
    admin.status,
    membership.organization_id,
    membership.role
FROM admin_users AS admin
JOIN admin_memberships AS membership
    ON membership.admin_user_id = admin.admin_user_id
WHERE admin.admin_user_id = $1
  AND admin.status = 'active'
  AND membership.status = 'active'
ORDER BY membership.organization_id;
