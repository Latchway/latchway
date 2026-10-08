-- Administrator two-factor sign-in. The authenticator key is sealed with a
-- key derived from the master key and bound to its administrator; only the
-- non-secret envelope metadata and ciphertext are stored. Recovery codes are
-- stored as domain-separated SHA-256 hashes and are single use. A sign-in
-- challenge exists only between a correct password and the second factor.
CREATE TABLE admin_totp_factors (
    admin_user_id text PRIMARY KEY REFERENCES admin_users (admin_user_id),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 256),
    created_at timestamptz NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint CHECK (last_used_step IS NULL OR last_used_step > 0),
    CHECK (confirmed_at IS NULL OR confirmed_at >= created_at)
);

CREATE TABLE admin_recovery_codes (
    admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    created_at timestamptz NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (admin_user_id, code_hash),
    CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE TABLE admin_sign_in_challenges (
    challenge_hash bytea PRIMARY KEY CHECK (octet_length(challenge_hash) = 32),
    admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    device_summary text CHECK (device_summary IS NULL OR device_summary ~ '^[A-Za-z0-9 .()/-]{1,80}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    failed_attempts smallint NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX admin_sign_in_challenges_expiry_idx ON admin_sign_in_challenges (expires_at);

ALTER TABLE organizations
    ADD COLUMN require_two_factor boolean NOT NULL DEFAULT false;

COMMENT ON TABLE admin_totp_factors IS
    'Sealed administrator authenticator keys; plaintext keys are never stored.';
COMMENT ON TABLE admin_recovery_codes IS
    'Hashed single-use administrator recovery codes.';
COMMENT ON TABLE admin_sign_in_challenges IS
    'Pending second-factor sign-ins after a correct password; hashed, short-lived and attempt-bounded.';
COMMENT ON COLUMN organizations.require_two_factor IS
    'When true, members without a confirmed second factor may only enroll one after signing in.';
