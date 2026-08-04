CREATE TABLE a2a_dispatch_executions (
    execution_id text PRIMARY KEY,
    command_id text NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    context_id text NOT NULL DEFAULT '',
    message_id text NOT NULL,
    state text NOT NULL DEFAULT 'dispatching'
        CHECK (state IN ('dispatching', 'active', 'cancel_requested', 'completed', 'failed', 'canceled')),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    CHECK (length(execution_id) BETWEEN 1 AND 4096),
    CHECK (length(command_id) BETWEEN 1 AND 4096),
    CHECK (length(tenant_id) BETWEEN 1 AND 4096),
    CHECK (length(owner_issuer) BETWEEN 1 AND 4096),
    CHECK (length(owner_subject) BETWEEN 1 AND 4096),
    CHECK (length(task_id) BETWEEN 1 AND 4096),
    CHECK (length(message_id) BETWEEN 1 AND 4096),
    UNIQUE (tenant_id, owner_issuer, owner_subject, task_id, execution_id),
    UNIQUE (execution_id, tenant_id, owner_issuer, owner_subject, task_id)
);

CREATE INDEX a2a_dispatch_executions_active_task_idx
    ON a2a_dispatch_executions (tenant_id, owner_issuer, owner_subject, task_id, updated_at DESC)
    WHERE state IN ('dispatching', 'active', 'cancel_requested');

CREATE TABLE a2a_command_outbox (
    event_id text PRIMARY KEY,
    execution_id text NOT NULL,
    command_id text NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    topic text NOT NULL,
    record_key bytea NOT NULL,
    envelope_json jsonb NOT NULL,
    envelope_digest char(64) NOT NULL,
    state text NOT NULL DEFAULT 'ready'
        CHECK (state IN ('ready', 'leased', 'published', 'dead')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token text,
    lease_until timestamptz,
    last_failure text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at timestamptz,
    CHECK (length(event_id) BETWEEN 1 AND 4096),
    CHECK (length(topic) BETWEEN 1 AND 249),
    CHECK (octet_length(record_key) BETWEEN 1 AND 1024),
    CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY (execution_id, tenant_id, owner_issuer, owner_subject, task_id)
        REFERENCES a2a_dispatch_executions (execution_id, tenant_id, owner_issuer, owner_subject, task_id)
        ON DELETE CASCADE
);

CREATE INDEX a2a_command_outbox_ready_idx
    ON a2a_command_outbox (available_at, created_at)
    WHERE state = 'ready';

CREATE INDEX a2a_command_outbox_expired_lease_idx
    ON a2a_command_outbox (lease_until)
    WHERE state = 'leased';

CREATE TABLE a2a_result_inbox (
    event_id text PRIMARY KEY,
    execution_id text NOT NULL,
    command_id text NOT NULL,
    causation_id text NOT NULL DEFAULT '',
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    context_id text NOT NULL DEFAULT '',
    kind text NOT NULL CHECK (kind IN ('artifact', 'heartbeat', 'completed', 'failed', 'canceled')),
    sequence bigint NOT NULL CHECK (sequence > 0),
    issued_at timestamptz NOT NULL,
    envelope_json jsonb NOT NULL,
    envelope_digest char(64) NOT NULL,
    topic text NOT NULL,
    partition_id integer NOT NULL,
    record_offset bigint NOT NULL CHECK (record_offset >= 0),
    record_key bytea NOT NULL,
    broker_timestamp timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    UNIQUE (execution_id, sequence),
    UNIQUE (topic, partition_id, record_offset),
    FOREIGN KEY (execution_id, tenant_id, owner_issuer, owner_subject, task_id)
        REFERENCES a2a_dispatch_executions (execution_id, tenant_id, owner_issuer, owner_subject, task_id)
        ON DELETE CASCADE
);

CREATE INDEX a2a_result_inbox_replay_idx
    ON a2a_result_inbox (tenant_id, task_id, execution_id, sequence);

CREATE TABLE a2a_artifact_objects (
    object_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    artifact_id text NOT NULL,
    part_index integer NOT NULL CHECK (part_index >= 0),
    bucket text NOT NULL,
    object_key text NOT NULL UNIQUE,
    version_id text NOT NULL DEFAULT '',
    etag text NOT NULL DEFAULT '',
    media_type text NOT NULL DEFAULT 'application/octet-stream',
    filename text NOT NULL DEFAULT '',
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sha256_hex char(64) NOT NULL CHECK (sha256_hex ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'ready' CHECK (state IN ('ready', 'attached', 'deleting', 'deleted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attached_at timestamptz,
    delete_after timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
    deleted_at timestamptz,
    CHECK (length(object_id) BETWEEN 1 AND 256)
);

CREATE INDEX a2a_artifact_objects_cleanup_idx
    ON a2a_artifact_objects (delete_after)
    WHERE state = 'ready';

CREATE INDEX a2a_artifact_objects_task_idx
    ON a2a_artifact_objects (tenant_id, owner_issuer, owner_subject, task_id);

CREATE TABLE a2a_push_configs (
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    config_id text NOT NULL,
    target_url text NOT NULL,
    encrypted_config bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, owner_issuer, owner_subject, task_id, config_id),
    CHECK (length(config_id) BETWEEN 1 AND 4096),
    CHECK (length(target_url) BETWEEN 1 AND 8192),
    CHECK (octet_length(encrypted_config) > 0)
);

CREATE INDEX a2a_push_configs_task_idx
    ON a2a_push_configs (tenant_id, owner_issuer, owner_subject, task_id, created_at);

CREATE TABLE a2a_webhook_outbox (
    delivery_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    task_id text NOT NULL,
    config_id text NOT NULL,
    target_url text NOT NULL,
    payload bytea NOT NULL,
    encrypted_credentials bytea NOT NULL DEFAULT ''::bytea,
    state text NOT NULL DEFAULT 'ready'
        CHECK (state IN ('ready', 'leased', 'succeeded', 'dead')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    lease_owner text,
    lease_token text,
    lease_until timestamptz,
    last_http_status integer CHECK (last_http_status IS NULL OR last_http_status BETWEEN 100 AND 599),
    last_failure text CHECK (last_failure IS NULL OR last_failure IN (
        'network', 'timeout', 'response_status', 'redirect',
        'invalid_target', 'invalid_credentials', 'invalid_delivery'
    )),
    created_at timestamptz NOT NULL,
    finished_at timestamptz,
    PRIMARY KEY (tenant_id, delivery_id),
    CHECK (length(delivery_id) BETWEEN 1 AND 256),
    CHECK (length(task_id) BETWEEN 1 AND 4096),
    CHECK (length(target_url) BETWEEN 1 AND 8192),
    CHECK (octet_length(payload) BETWEEN 1 AND 1048576)
);

CREATE INDEX a2a_webhook_outbox_ready_idx
    ON a2a_webhook_outbox (available_at, created_at)
    WHERE state = 'ready';

CREATE INDEX a2a_webhook_outbox_expired_lease_idx
    ON a2a_webhook_outbox (lease_until)
    WHERE state = 'leased';
