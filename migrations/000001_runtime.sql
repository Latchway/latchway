CREATE TABLE IF NOT EXISTS runtime_instances (
    instance_id text PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('all', 'api', 'worker')),
    started_at timestamptz NOT NULL DEFAULT now(),
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS runtime_instances_heartbeat_idx
    ON runtime_instances (heartbeat_at);
