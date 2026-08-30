-- Shared, public-only identity verification-key cache. The endpoint and issuer
-- remain configuration-owned; only their one-way identities are persisted.
-- Refresh leases are short database state transitions and are never held open
-- while a worker performs protected HTTPS I/O.

CREATE TABLE identity_jwks_cache (
    issuer_sha256 bytea NOT NULL,
    source_sha256 bytea NOT NULL,
    source_format text NOT NULL
        CHECK (source_format IN ('jwks', 'x509_certificate_map')),
    document bytea,
    document_sha256 bytea,
    etag text,
    last_modified timestamptz,
    fetched_at timestamptz,
    fresh_until timestamptz,
    stale_until timestamptz,
    refresh_lease_token bytea,
    refresh_lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer_sha256, source_sha256),
    CHECK (octet_length(issuer_sha256) = 32),
    CHECK (issuer_sha256 <> decode(repeat('00', 32), 'hex')),
    CHECK (octet_length(source_sha256) = 32),
    CHECK (source_sha256 <> decode(repeat('00', 32), 'hex')),
    CHECK (
        (document IS NULL AND document_sha256 IS NULL AND fetched_at IS NULL
            AND fresh_until IS NULL AND stale_until IS NULL AND etag IS NULL
            AND last_modified IS NULL)
        OR
        (document IS NOT NULL AND document_sha256 IS NOT NULL AND fetched_at IS NOT NULL
            AND fresh_until IS NOT NULL AND stale_until IS NOT NULL
            AND octet_length(document) BETWEEN 2 AND 1048576
            AND octet_length(document_sha256) = 32
            AND document_sha256 <> decode(repeat('00', 32), 'hex')
            AND fresh_until >= fetched_at
            AND fresh_until <= fetched_at + interval '24 hours'
            AND stale_until >= fresh_until
            AND stale_until <= fresh_until + interval '24 hours')
    ),
    CHECK (etag IS NULL OR (char_length(etag) BETWEEN 1 AND 1024
        AND position(chr(10) in etag) = 0 AND position(chr(13) in etag) = 0)),
    CHECK (refresh_lease_token IS NULL = (refresh_lease_until IS NULL)),
    CHECK (refresh_lease_token IS NULL OR (
        octet_length(refresh_lease_token) = 32
        AND refresh_lease_token <> decode(repeat('00', 32), 'hex')
        AND refresh_lease_until > updated_at
        AND refresh_lease_until <= updated_at + interval '1 minute'
    ))
);

CREATE INDEX identity_jwks_cache_refresh_idx
    ON identity_jwks_cache (refresh_lease_until)
    WHERE refresh_lease_token IS NOT NULL;

CREATE INDEX identity_jwks_cache_stale_idx
    ON identity_jwks_cache (stale_until)
    WHERE document IS NOT NULL;
