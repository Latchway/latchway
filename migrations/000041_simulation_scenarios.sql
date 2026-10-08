-- Saved route-simulation scenarios (ADR 0049). A scenario is an
-- administrator-written test input for one application, never a recorded
-- request or real user data.
CREATE TABLE simulation_scenarios (
    simulation_scenario_id text PRIMARY KEY
        CHECK (simulation_scenario_id ~ '^ssc_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    input jsonb NOT NULL
        CHECK (jsonb_typeof(input) = 'object' AND octet_length(input::text) <= 16384),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_admin_user_id text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_by_admin_user_id text NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (organization_id, application_id)
        REFERENCES applications (organization_id, application_id),
    FOREIGN KEY (organization_id, created_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    FOREIGN KEY (organization_id, updated_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (updated_at >= created_at),
    UNIQUE (organization_id, application_id, name)
);

CREATE INDEX simulation_scenarios_application_idx
    ON simulation_scenarios (organization_id, application_id, updated_at DESC, simulation_scenario_id DESC);
