package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/redpanda"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrResultIdleTimeout = errors.New("timed out waiting for Redpanda results")

// RedpandaStore is the durable result inbox and replay source used between the
// Redpanda consumer and A2A request executions.
type RedpandaStore struct {
	pool        *pgxpool.Pool
	idleTimeout time.Duration
	pollPeriod  time.Duration
}

var (
	_ redpanda.DurableResultStore      = (*RedpandaStore)(nil)
	_ redpanda.ResultSource            = (*RedpandaStore)(nil)
	_ redpanda.ActiveExecutionResolver = (*RedpandaStore)(nil)
)

func NewRedpandaStore(pool *pgxpool.Pool, idleTimeout time.Duration) (*RedpandaStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	if idleTimeout <= 0 {
		return nil, fmt.Errorf("result idle timeout must be positive")
	}
	return &RedpandaStore{pool: pool, idleTimeout: idleTimeout, pollPeriod: 200 * time.Millisecond}, nil
}

func (s *RedpandaStore) StoreResult(ctx context.Context, record redpanda.ResultRecord) error {
	if err := validateResultRecord(record); err != nil {
		return err
	}
	payload, err := json.Marshal(record.Envelope)
	if err != nil {
		return fmt.Errorf("encode result envelope: %w", err)
	}
	envelope := record.Envelope
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		var lastSequence int64
		var currentState string
		var ownerIssuer, ownerSubject string
		err := tx.QueryRow(ctx, `
SELECT last_sequence, state, owner_issuer, owner_subject
FROM a2a_dispatch_executions
WHERE execution_id = $1 AND tenant_id = $2 AND task_id = $3 AND context_id = $4
FOR UPDATE`, envelope.ExecutionID, envelope.TenantID, string(envelope.TaskID), envelope.ContextID,
		).Scan(&lastSequence, &currentState, &ownerIssuer, &ownerSubject)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("result has no matching durable execution")
		}
		if err != nil {
			return fmt.Errorf("lock result execution: %w", err)
		}
		if int64(envelope.Sequence) <= lastSequence {
			return verifyStoredResult(ctx, tx, record)
		}
		if int64(envelope.Sequence) != lastSequence+1 {
			return fmt.Errorf("result sequence gap: expected %d, received %d", lastSequence+1, envelope.Sequence)
		}
		if isExecutionTerminal(currentState) {
			return fmt.Errorf("result arrived after terminal execution state")
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO a2a_result_inbox (
    event_id, execution_id, command_id, causation_id, tenant_id, owner_issuer,
    owner_subject, task_id, context_id, kind, sequence, issued_at, envelope_json,
    envelope_digest, topic, partition_id, record_offset, record_key, broker_timestamp
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16, $17, $18, $19)`,
			envelope.EventID, envelope.ExecutionID, envelope.CommandID, envelope.CausationID,
			envelope.TenantID, ownerIssuer, ownerSubject, string(envelope.TaskID), envelope.ContextID,
			string(envelope.Kind), int64(envelope.Sequence), envelope.IssuedAt.UTC(), payload,
			strings.ToLower(record.Digest), record.Topic, record.Partition, record.Offset,
			record.Key, record.Timestamp.UTC(),
		); err != nil {
			return fmt.Errorf("insert durable result: %w", err)
		}
		nextState, finished := executionStateForResult(envelope.Kind)
		if _, err := tx.Exec(ctx, `
UPDATE a2a_dispatch_executions
SET last_sequence = $2,
    state = COALESCE($3, state),
    updated_at = clock_timestamp(),
    finished_at = $4
WHERE execution_id = $1`, envelope.ExecutionID, int64(envelope.Sequence), nextState, finished); err != nil {
			return fmt.Errorf("advance durable execution: %w", err)
		}
		return nil
	})
}

func (s *RedpandaStore) Open(ctx context.Context, query redpanda.ResultQuery) (redpanda.ResultCursor, error) {
	if strings.TrimSpace(query.TenantID) == "" || query.TaskID == "" || strings.TrimSpace(query.ExecutionID) == "" {
		return nil, fmt.Errorf("tenant, task, and execution are required")
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM a2a_dispatch_executions
    WHERE tenant_id = $1 AND task_id = $2 AND context_id = $3 AND execution_id = $4
)`, query.TenantID, string(query.TaskID), query.ContextID, query.ExecutionID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("locate durable execution: %w", err)
	}
	if !exists {
		return nil, redpanda.ErrExecutionNotFound
	}
	cursorCtx, cancel := context.WithCancel(ctx)
	return &postgresResultCursor{
		ctx: cursorCtx, cancel: cancel, pool: s.pool, query: query,
		nextSequence: query.AfterSequence + 1, idleTimeout: s.idleTimeout,
		pollPeriod: s.pollPeriod, lastResultAt: time.Now(),
	}, nil
}

func (s *RedpandaStore) ActiveExecution(ctx context.Context, tenantID string, taskID a2a.TaskID) (string, error) {
	var executionID string
	err := s.pool.QueryRow(ctx, `
SELECT execution_id
FROM a2a_dispatch_executions
WHERE tenant_id = $1 AND task_id = $2
  AND state IN ('dispatching', 'active', 'cancel_requested')
ORDER BY updated_at DESC, execution_id DESC
LIMIT 1`, tenantID, string(taskID)).Scan(&executionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", redpanda.ErrExecutionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("find active execution: %w", err)
	}
	return executionID, nil
}

type postgresResultCursor struct {
	ctx          context.Context
	cancel       context.CancelFunc
	pool         *pgxpool.Pool
	query        redpanda.ResultQuery
	nextSequence uint64
	idleTimeout  time.Duration
	pollPeriod   time.Duration
	lastResultAt time.Time
}

func (c *postgresResultCursor) Next(ctx context.Context) (*redpanda.Envelope, error) {
	for {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var payload []byte
		err := c.pool.QueryRow(ctx, `
SELECT envelope_json
FROM a2a_result_inbox
WHERE tenant_id = $1 AND task_id = $2 AND context_id = $3
  AND execution_id = $4 AND sequence >= $5
ORDER BY sequence
LIMIT 1`, c.query.TenantID, string(c.query.TaskID), c.query.ContextID,
			c.query.ExecutionID, int64(c.nextSequence)).Scan(&payload)
		if err == nil {
			envelope, err := decodeStoredEnvelope(payload)
			if err != nil {
				return nil, err
			}
			c.nextSequence = envelope.Sequence + 1
			c.lastResultAt = time.Now()
			return envelope, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("read durable result: %w", err)
		}
		var state string
		if err := c.pool.QueryRow(ctx, `
SELECT state FROM a2a_dispatch_executions WHERE execution_id = $1`, c.query.ExecutionID).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("read durable execution state: %w", err)
		}
		if isExecutionTerminal(state) {
			return nil, io.EOF
		}
		if time.Since(c.lastResultAt) >= c.idleTimeout {
			return nil, ErrResultIdleTimeout
		}
		timer := time.NewTimer(c.pollPeriod)
		select {
		case <-c.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, c.ctx.Err()
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *postgresResultCursor) Close() error {
	c.cancel()
	return nil
}

func verifyStoredResult(ctx context.Context, tx pgx.Tx, record redpanda.ResultRecord) error {
	var eventID, digest, topic string
	var partition int32
	var offset int64
	err := tx.QueryRow(ctx, `
SELECT event_id, envelope_digest, topic, partition_id, record_offset
FROM a2a_result_inbox
WHERE execution_id = $1 AND sequence = $2`, record.Envelope.ExecutionID, int64(record.Envelope.Sequence),
	).Scan(&eventID, &digest, &topic, &partition, &offset)
	if err != nil {
		return fmt.Errorf("verify replayed result: %w", err)
	}
	if eventID != record.Envelope.EventID || !strings.EqualFold(digest, record.Digest) ||
		topic != record.Topic || partition != record.Partition || offset != record.Offset {
		return fmt.Errorf("result replay conflicts with durable event identity")
	}
	return nil
}

func decodeStoredEnvelope(payload []byte) (*redpanda.Envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope redpanda.Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode stored result: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode stored result: trailing data")
	}
	return &envelope, nil
}

func validateResultRecord(record redpanda.ResultRecord) error {
	if record.Envelope == nil || record.Topic == "" || record.Partition < 0 || record.Offset < 0 ||
		record.Timestamp.IsZero() || len(record.Key) == 0 || len(record.Digest) != 64 {
		return fmt.Errorf("durable result record is invalid")
	}
	return nil
}

func executionStateForResult(kind redpanda.Kind) (any, any) {
	switch kind {
	case redpanda.KindCompleted:
		return "completed", time.Now().UTC()
	case redpanda.KindFailed:
		return "failed", time.Now().UTC()
	case redpanda.KindCanceled:
		return "canceled", time.Now().UTC()
	case redpanda.KindArtifact, redpanda.KindHeartbeat:
		return "active", nil
	default:
		return nil, nil
	}
}

func isExecutionTerminal(state string) bool {
	return state == "completed" || state == "failed" || state == "canceled"
}
