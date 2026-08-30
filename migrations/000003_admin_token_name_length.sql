ALTER TABLE admin_api_tokens
    DROP CONSTRAINT admin_api_tokens_name_check;

ALTER TABLE admin_api_tokens
    ADD CONSTRAINT admin_api_tokens_name_length_check
    CHECK (char_length(name) BETWEEN 1 AND 256);
