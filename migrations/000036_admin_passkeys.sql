-- Administrator passkeys (WebAuthn, ES256 only). Only the credential ID and
-- public key are stored; there is no shared secret. A WebAuthn challenge is
-- stored as a hash and serves registration, passwordless sign-in, or the
-- second factor of a password sign-in (linked to that sign-in's challenge).
ALTER TABLE admin_users
    ADD COLUMN webauthn_user_handle bytea UNIQUE
        CHECK (webauthn_user_handle IS NULL OR octet_length(webauthn_user_handle) = 32);

CREATE TABLE admin_passkeys (
    admin_passkey_id text PRIMARY KEY
        CHECK (admin_passkey_id ~ '^apk_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    credential_id bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    public_key_x bytea NOT NULL CHECK (octet_length(public_key_x) = 32),
    public_key_y bytea NOT NULL CHECK (octet_length(public_key_y) = 32),
    sign_count bigint NOT NULL CHECK (sign_count >= 0),
    aaguid bytea NOT NULL CHECK (octet_length(aaguid) = 16),
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE INDEX admin_passkeys_user_idx ON admin_passkeys (admin_user_id);

CREATE TABLE admin_webauthn_challenges (
    challenge_hash bytea PRIMARY KEY CHECK (octet_length(challenge_hash) = 32),
    purpose text NOT NULL CHECK (purpose IN ('register', 'sign_in', 'second_factor')),
    admin_user_id text REFERENCES admin_users (admin_user_id),
    sign_in_challenge_hash bytea REFERENCES admin_sign_in_challenges (challenge_hash) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK ((purpose = 'sign_in') = (admin_user_id IS NULL)),
    CHECK ((purpose = 'second_factor') = (sign_in_challenge_hash IS NOT NULL))
);

CREATE INDEX admin_webauthn_challenges_expiry_idx ON admin_webauthn_challenges (expires_at);

COMMENT ON TABLE admin_passkeys IS
    'Administrator WebAuthn credentials: public keys only, never private material.';
COMMENT ON TABLE admin_webauthn_challenges IS
    'Hashed, short-lived WebAuthn challenges for registration, passwordless sign-in and second factors.';
