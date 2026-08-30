-- Schema 12 required every durable trusted-input proof to carry a positive
-- output bound. OpenAI Embeddings has no generated-token output, so its exact
-- server-owned output bound is zero and total_tokens equals input_tokens.
-- Application and quota validation remain protocol-aware: generative
-- protocols still require a positive output bound before this row is written.
ALTER TABLE upstream_attempts
    DROP CONSTRAINT upstream_attempts_input_accounting_binding_check,
    ADD CONSTRAINT upstream_attempts_input_accounting_binding_check
        CHECK (
            (
                input_accounting_binding_version = 0
                AND attempt_number = 1
                AND input_accounting_method IS NULL
                AND input_accounting_profile_id IS NULL
                AND input_accounting_profile_digest IS NULL
                AND rewritten_body_sha256 IS NULL
                AND input_token_bound IS NULL
                AND output_token_bound IS NULL
                AND total_token_bound IS NULL
            )
            OR (
                input_accounting_binding_version = 1
                AND (
                    (
                        input_accounting_method IS NULL
                        AND input_accounting_profile_id IS NULL
                        AND input_accounting_profile_digest IS NULL
                        AND rewritten_body_sha256 IS NULL
                        AND input_token_bound IS NULL
                        AND output_token_bound IS NULL
                        AND total_token_bound IS NULL
                    )
                    OR (
                        input_accounting_method = 'utf8_byte_bpe_declared_framing_v1'
                        AND input_accounting_profile_id IS NOT NULL
                        AND input_accounting_profile_digest IS NOT NULL
                        AND rewritten_body_sha256 IS NOT NULL
                        AND input_token_bound IS NOT NULL
                        AND output_token_bound IS NOT NULL
                        AND total_token_bound IS NOT NULL
                        AND input_accounting_profile_id ~ '^[a-z][a-z0-9_-]{0,62}$'
                        AND octet_length(input_accounting_profile_digest) = 32
                        AND octet_length(rewritten_body_sha256) = 32
                        AND input_accounting_profile_digest <> decode(repeat('00', 32), 'hex')
                        AND rewritten_body_sha256 <> decode(repeat('00', 32), 'hex')
                        AND input_token_bound > 0
                        AND output_token_bound >= 0
                        AND total_token_bound = input_token_bound + output_token_bound
                        AND total_token_bound >= input_token_bound
                    )
                )
            )
        );

COMMENT ON COLUMN upstream_attempts.output_token_bound IS
    'Exact server-applied generated-token maximum: zero only for a protocol without generated tokens, positive for generative protocols.';
