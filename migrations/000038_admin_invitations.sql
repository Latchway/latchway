-- Invitations to join an organization. The invitation link's token is stored
-- only as a SHA-256 hash. An invitation is pending until it is accepted,
-- revoked, superseded by a newer one for the same address, or expires.
CREATE TABLE admin_invitations (
    admin_invitation_id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    email text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
    email_normalized text NOT NULL CHECK (char_length(email_normalized) BETWEEN 3 AND 320),
    display_name text CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 200),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by_admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_admin_user_id text REFERENCES admin_users (admin_user_id),
    revoked_at timestamptz,
    email_status text NOT NULL DEFAULT 'not_requested' CHECK (email_status IN ('not_requested', 'sent', 'failed')),
    email_sent_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK ((accepted_at IS NULL) = (accepted_admin_user_id IS NULL)),
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE UNIQUE INDEX admin_invitations_one_open_per_address
    ON admin_invitations (organization_id, email_normalized)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX admin_invitations_organization_idx ON admin_invitations (organization_id, created_at DESC);

COMMENT ON TABLE admin_invitations IS
    'Invitations to join an organization; link tokens are stored only as hashes.';
