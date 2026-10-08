-- Administrator account self-service. A console session keeps a coarse device
-- summary derived server-side from the browser's User-Agent (for example
-- "Chrome on macOS"); raw User-Agent strings and network addresses are
-- intentionally not stored. An administrator's last signed-in organization is
-- the default for a later sign-in that names none.
ALTER TABLE admin_sessions
    ADD COLUMN device_summary text
        CHECK (device_summary IS NULL OR device_summary ~ '^[A-Za-z0-9 .()/-]{1,80}$');

ALTER TABLE admin_users
    ADD COLUMN last_organization_id text REFERENCES organizations (organization_id);

COMMENT ON COLUMN admin_sessions.device_summary IS
    'Coarse browser and operating-system summary for the session owner and owners; never a raw User-Agent or network address.';
COMMENT ON COLUMN admin_users.last_organization_id IS
    'Organization of the administrator''s most recent session; used only when a sign-in names no organization.';
