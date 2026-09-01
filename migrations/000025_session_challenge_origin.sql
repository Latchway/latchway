-- Session challenges are ephemeral authorization state. Existing rows predate
-- an exact browser-origin binding and cannot be upgraded without inventing an
-- authority value, so invalidate them before making the new field mandatory.
-- Durable attestation audit events no longer reference challenge rows through
-- a foreign key (schema 5), and therefore remain intact.
DELETE FROM session_challenge_consumptions;
DELETE FROM session_challenges;

ALTER TABLE session_challenges
    ADD COLUMN browser_origin text NOT NULL,
    ADD CONSTRAINT session_challenges_browser_origin_scope_check
        CHECK (
            (
                platform = 'web'
                AND char_length(browser_origin) BETWEEN 9 AND 2048
                AND browser_origin !~ '[[:cntrl:][:space:]]'
            )
            OR (platform <> 'web' AND browser_origin = '')
        );

COMMENT ON COLUMN session_challenges.browser_origin IS
    'Exact canonical browser Origin accepted when the challenge was created; empty for native and server runtimes.';
