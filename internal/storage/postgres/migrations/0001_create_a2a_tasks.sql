CREATE TABLE a2a_tasks (
    task_id text PRIMARY KEY,
    tenant_id text NOT NULL CHECK (btrim(tenant_id) <> ''),
    owner_subject text NOT NULL CHECK (btrim(owner_subject) <> ''),
    context_id text NOT NULL,
    state text NOT NULL,
    status_timestamp timestamptz NULL,
    task_json jsonb NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX a2a_tasks_scope_updated_idx
    ON a2a_tasks (tenant_id, owner_subject, updated_at DESC, task_id DESC);

CREATE INDEX a2a_tasks_scope_context_updated_idx
    ON a2a_tasks (tenant_id, owner_subject, context_id, updated_at DESC, task_id DESC);

CREATE INDEX a2a_tasks_scope_state_updated_idx
    ON a2a_tasks (tenant_id, owner_subject, state, updated_at DESC, task_id DESC);
