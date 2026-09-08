-- Content-free diagnostics for an already enforced input bound. Historical
-- attempts retain NULL; these components never change a quota allocation.
CREATE FUNCTION latchway_input_accounting_breakdown_valid(value jsonb, input_bound bigint)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    member text;
BEGIN
    IF value IS NULL OR input_bound IS NULL OR jsonb_typeof(value) <> 'object' THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(value)) <> 6
       OR NOT (value ?& ARRAY['version', 'rewritten_request_bytes', 'framing_unit_count',
          'maximum_framing_tokens_per_request', 'maximum_framing_tokens_per_unit', 'expanded_schema_bytes']) THEN
        RETURN false;
    END IF;
    FOREACH member IN ARRAY ARRAY['version', 'rewritten_request_bytes', 'framing_unit_count',
        'maximum_framing_tokens_per_request', 'maximum_framing_tokens_per_unit', 'expanded_schema_bytes'] LOOP
        IF jsonb_typeof(value -> member) <> 'number' OR (value ->> member) !~ '^[0-9]+$'
           OR (value ->> member)::numeric > 9223372036854775807 THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN (value ->> 'version')::numeric = 1
       AND (value ->> 'rewritten_request_bytes')::numeric BETWEEN 1 AND 104857600
       AND (value ->> 'framing_unit_count')::numeric BETWEEN 1 AND 4096
       AND (value ->> 'expanded_schema_bytes')::numeric BETWEEN 0 AND 4194304
       AND input_bound::numeric = (value ->> 'rewritten_request_bytes')::numeric
           + (value ->> 'maximum_framing_tokens_per_request')::numeric
           + (value ->> 'framing_unit_count')::numeric * (value ->> 'maximum_framing_tokens_per_unit')::numeric
           + (value ->> 'expanded_schema_bytes')::numeric;
END;
$$;

ALTER TABLE upstream_attempts
    ADD COLUMN input_accounting_breakdown jsonb,
    ADD CONSTRAINT upstream_attempts_input_accounting_breakdown_check CHECK (
        input_accounting_breakdown IS NULL OR (
            input_accounting_method IS NOT NULL
            AND input_accounting_method = 'utf8_byte_bpe_declared_framing_v1'
            AND latchway_input_accounting_breakdown_valid(input_accounting_breakdown, input_token_bound)
        )
    );

COMMENT ON COLUMN upstream_attempts.input_accounting_breakdown IS
    'Versioned aggregate explanation of the trusted input bound; contains no prompt/schema contents, is not quota authority, and is NULL for historical attempts.';
