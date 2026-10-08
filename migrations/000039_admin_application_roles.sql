-- Application roles raise a member's organization role for one application,
-- for example an organization Viewer who is an Admin of one app. They never
-- lower the organization role, and owners can't hold them. A grant goes away
-- with its membership.
CREATE TABLE admin_application_roles (
    organization_id text NOT NULL,
    admin_user_id text NOT NULL,
    application_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'operator')),
    granted_by_admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (admin_user_id, application_id),
    FOREIGN KEY (organization_id, admin_user_id) REFERENCES admin_memberships (organization_id, admin_user_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, application_id) REFERENCES applications (organization_id, application_id),
    CHECK (updated_at >= created_at)
);

CREATE INDEX admin_application_roles_organization_idx ON admin_application_roles (organization_id, application_id);

COMMENT ON TABLE admin_application_roles IS
    'Per-application roles that raise, never lower, a member''s organization role.';
