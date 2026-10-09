-- Administrator single sign-on with OpenID Connect. Each organization may
-- configure one identity provider. The client secret is sealed with a key
-- derived from the master key and bound to the organization. Identities link
-- an issuer and subject to one administrator per organization. A login state
-- exists only between starting a sign-in and the provider's callback; its
-- value and the browser binding are stored as hashes.
CREATE TABLE organization_sso_providers (
    organization_id text PRIMARY KEY REFERENCES organizations (organization_id),
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 9 AND 2048 AND issuer LIKE 'https://%'),
    authorization_endpoint text NOT NULL CHECK (char_length(authorization_endpoint) BETWEEN 9 AND 2048 AND authorization_endpoint LIKE 'https://%'),
    token_endpoint text NOT NULL CHECK (char_length(token_endpoint) BETWEEN 9 AND 2048 AND token_endpoint LIKE 'https://%'),
    jwks_uri text NOT NULL CHECK (char_length(jwks_uri) BETWEEN 9 AND 2048 AND jwks_uri LIKE 'https://%'),
    client_id text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 512),
    secret_key_id text NOT NULL CHECK (char_length(secret_key_id) BETWEEN 1 AND 128),
    secret_nonce bytea NOT NULL CHECK (octet_length(secret_nonce) = 12),
    secret_ciphertext bytea NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 17 AND 2048),
    allowed_email_domains text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_email_domains) <= 20),
    provision_role text CHECK (provision_role IS NULL OR provision_role IN ('admin', 'operator', 'viewer')),
    enabled boolean NOT NULL,
    require_sso boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (NOT require_sso OR enabled)
);

CREATE TABLE admin_sso_identities (
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 9 AND 2048),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    PRIMARY KEY (organization_id, issuer, subject),
    UNIQUE (organization_id, admin_user_id)
);

CREATE TABLE admin_sso_states (
    state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    nonce text NOT NULL CHECK (char_length(nonce) BETWEEN 32 AND 128),
    code_verifier text NOT NULL CHECK (char_length(code_verifier) BETWEEN 43 AND 128),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX admin_sso_states_expiry_idx ON admin_sso_states (expires_at);

ALTER TABLE admin_sessions
    ADD COLUMN sign_in_method text NOT NULL DEFAULT 'password'
        CHECK (sign_in_method IN ('password', 'passkey', 'sso'));

COMMENT ON TABLE organization_sso_providers IS
    'One OpenID Connect provider per organization; the client secret is sealed and never returned.';
COMMENT ON TABLE admin_sso_identities IS
    'Links an identity provider subject to an administrator within one organization.';
COMMENT ON TABLE admin_sso_states IS
    'Pending single sign-on logins between the redirect and the callback; single use and short-lived.';
COMMENT ON COLUMN admin_sessions.sign_in_method IS
    'How the session was signed in; single sign-on sessions rely on the identity provider for further factors.';
