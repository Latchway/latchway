-- Client diagnostics distinguishes the active refresh credential attached to
-- the authenticated access grant from a refresh credential that has already
-- rotated. Keep that bounded read index-backed as refresh history grows.

CREATE INDEX refresh_tokens_client_diagnostics_idx
    ON refresh_tokens (session_grant_id, expires_at)
    WHERE status = 'active';
