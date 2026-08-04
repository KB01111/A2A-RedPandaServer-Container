package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/redpanda"
	"github.com/jackc/pgx/v5"
)

var _ redpanda.CommandRepository = (*RedpandaStore)(nil)

func (s *RedpandaStore) EnqueueCommand(ctx context.Context, command redpanda.NewCommand) error {
	if err := validateNewCommand(command); err != nil {
		return err
	}
	envelope := command.Envelope
	principal := commandPrincipal(envelope)
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if envelope.Kind == redpanda.KindExecute {
			commandTag, err := tx.Exec(ctx, `
INSERT INTO a2a_dispatch_executions (
    execution_id, command_id, tenant_id, owner_issuer, owner_subject,
    task_id, context_id, message_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (execution_id) DO NOTHING`, envelope.ExecutionID, envelope.CommandID,
				envelope.TenantID, principal.Issuer, principal.Subject, string(envelope.TaskID),
				envelope.ContextID, envelope.Execute.Message.ID)
			if err != nil {
				return fmt.Errorf("create durable execution: %w", err)
			}
			if commandTag.RowsAffected() == 0 {
				if err := verifyDurableExecution(ctx, tx, envelope, principal); err != nil {
					return err
				}
			}
		} else {
			commandTag, err := tx.Exec(ctx, `
UPDATE a2a_dispatch_executions
SET state = CASE WHEN state IN ('dispatching', 'active') THEN 'cancel_requested' ELSE state END,
    updated_at = clock_timestamp()
WHERE execution_id = $1 AND tenant_id = $2 AND owner_issuer = $3
  AND owner_subject = $4 AND task_id = $5
  AND state IN ('dispatching', 'active', 'cancel_requested')`, envelope.ExecutionID,
				envelope.TenantID, principal.Issuer, principal.Subject, string(envelope.TaskID))
			if err != nil {
				return fmt.Errorf("mark durable cancellation: %w", err)
			}
			if commandTag.RowsAffected() != 1 {
				return redpanda.ErrExecutionNotFound
			}
		}

		commandTag, err := tx.Exec(ctx, `
INSERT INTO a2a_command_outbox (
    event_id, execution_id, command_id, tenant_id, owner_issuer, owner_subject,
    task_id, topic, record_key, envelope_json, envelope_digest, created_at, available_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $12)
ON CONFLICT (event_id) DO NOTHING`, envelope.EventID, envelope.ExecutionID,
			envelope.CommandID, envelope.TenantID, principal.Issuer, principal.Subject,
			string(envelope.TaskID), command.Topic, command.Key, command.Payload,
			strings.ToLower(command.Digest), command.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("enqueue Redpanda command: %w", err)
		}
		if commandTag.RowsAffected() == 0 {
			var digest, topic string
			var key, payload []byte
			if err := tx.QueryRow(ctx, `
SELECT envelope_digest, topic, record_key, envelope_json
FROM a2a_command_outbox
WHERE event_id = $1`, envelope.EventID).Scan(&digest, &topic, &key, &payload); err != nil {
				return fmt.Errorf("verify existing Redpanda command: %w", err)
			}
			if !strings.EqualFold(digest, command.Digest) || topic != command.Topic ||
				!bytes.Equal(key, command.Key) || !jsonBytesEqual(payload, command.Payload) {
				return fmt.Errorf("Redpanda command identifier conflicts with different immutable metadata")
			}
		}
		return nil
	})
}

func (s *RedpandaStore) ClaimCommands(ctx context.Context, request redpanda.CommandClaim) ([]redpanda.Command, error) {
	if request.WorkerID == "" || request.LeaseToken == "" || request.Now.IsZero() ||
		request.LeaseDuration <= 0 || request.Limit < 1 || request.Limit > 1000 {
		return nil, fmt.Errorf("invalid Redpanda command claim")
	}
	claimed := make([]redpanda.Command, 0, request.Limit)
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
UPDATE a2a_command_outbox
SET state = 'ready', lease_token = NULL, lease_until = NULL
WHERE state = 'leased' AND lease_until <= $1`, request.Now.UTC()); err != nil {
			return fmt.Errorf("release expired Redpanda command leases: %w", err)
		}
		rows, err := tx.Query(ctx, `
WITH candidates AS (
    SELECT event_id
    FROM a2a_command_outbox
    WHERE state = 'ready' AND available_at <= $1
    ORDER BY available_at, created_at, event_id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE a2a_command_outbox AS command
SET state = 'leased', lease_token = $3, lease_until = $4
FROM candidates
WHERE command.event_id = candidates.event_id
RETURNING command.envelope_json, command.topic, command.record_key,
          command.envelope_digest, command.created_at, command.attempts,
          command.lease_token, command.lease_until`, request.Now.UTC(), request.Limit,
			request.LeaseToken, request.Now.UTC().Add(request.LeaseDuration))
		if err != nil {
			return fmt.Errorf("claim Redpanda commands: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var command redpanda.Command
			var payload []byte
			if err := rows.Scan(&payload, &command.Topic, &command.Key, &command.Digest,
				&command.CreatedAt, &command.Attempts, &command.LeaseToken, &command.LeaseUntil); err != nil {
				return fmt.Errorf("scan claimed Redpanda command: %w", err)
			}
			envelope, err := decodeStoredEnvelope(payload)
			if err != nil {
				return err
			}
			command.Envelope = envelope
			command.Payload = append([]byte(nil), payload...)
			claimed = append(claimed, command)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (s *RedpandaStore) MarkCommandPublished(ctx context.Context, completion redpanda.CommandCompletion) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		commandTag, err := tx.Exec(ctx, `
UPDATE a2a_command_outbox
SET state = 'published', attempts = $3, published_at = $4,
    lease_token = NULL, lease_until = NULL, last_failure = NULL
WHERE event_id = $1 AND state = 'leased' AND lease_token = $2 AND attempts = $3 - 1`,
			completion.EventID, completion.LeaseToken, completion.Attempt, completion.At.UTC())
		if err != nil {
			return fmt.Errorf("mark Redpanda command published: %w", err)
		}
		if commandTag.RowsAffected() != 1 {
			return redpanda.ErrCommandLeaseLost
		}
		if _, err := tx.Exec(ctx, `
UPDATE a2a_dispatch_executions AS execution
SET state = CASE WHEN command.envelope_json->>'kind' = 'execute' AND execution.state = 'dispatching'
                 THEN 'active' ELSE execution.state END,
    updated_at = clock_timestamp()
FROM a2a_command_outbox AS command
WHERE command.event_id = $1 AND execution.execution_id = command.execution_id`, completion.EventID); err != nil {
			return fmt.Errorf("activate published execution: %w", err)
		}
		return nil
	})
}

func (s *RedpandaStore) MarkCommandRetry(ctx context.Context, completion redpanda.CommandCompletion) error {
	if completion.NextAttempt.IsZero() {
		return fmt.Errorf("command retry time is required")
	}
	return s.completeCommand(ctx, completion, "ready", completion.NextAttempt)
}

func (s *RedpandaStore) MarkCommandDead(ctx context.Context, completion redpanda.CommandCompletion) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		commandTag, err := tx.Exec(ctx, `
UPDATE a2a_command_outbox
SET state = 'dead', attempts = $3, last_failure = $4,
    lease_token = NULL, lease_until = NULL
WHERE event_id = $1 AND state = 'leased' AND lease_token = $2 AND attempts = $3 - 1`,
			completion.EventID, completion.LeaseToken, completion.Attempt, completion.Failure)
		if err != nil {
			return fmt.Errorf("mark Redpanda command dead: %w", err)
		}
		if commandTag.RowsAffected() != 1 {
			return redpanda.ErrCommandLeaseLost
		}
		if _, err := tx.Exec(ctx, `
UPDATE a2a_dispatch_executions AS execution
SET state = CASE WHEN command.envelope_json->>'kind' = 'execute' THEN 'failed' ELSE execution.state END,
    updated_at = clock_timestamp(),
    finished_at = CASE WHEN command.envelope_json->>'kind' = 'execute' THEN clock_timestamp() ELSE execution.finished_at END
FROM a2a_command_outbox AS command
WHERE command.event_id = $1 AND execution.execution_id = command.execution_id`, completion.EventID); err != nil {
			return fmt.Errorf("fail dead command execution: %w", err)
		}
		return nil
	})
}

func (s *RedpandaStore) completeCommand(ctx context.Context, completion redpanda.CommandCompletion, state string, availableAt time.Time) error {
	commandTag, err := s.pool.Exec(ctx, `
UPDATE a2a_command_outbox
SET state = $4, attempts = $3, last_failure = $5, available_at = $6,
    lease_token = NULL, lease_until = NULL
WHERE event_id = $1 AND state = 'leased' AND lease_token = $2 AND attempts = $3 - 1`,
		completion.EventID, completion.LeaseToken, completion.Attempt, state,
		completion.Failure, availableAt.UTC())
	if err != nil {
		return fmt.Errorf("retry Redpanda command: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return redpanda.ErrCommandLeaseLost
	}
	return nil
}

func validateNewCommand(command redpanda.NewCommand) error {
	if command.Envelope == nil || command.Topic == "" || len(command.Key) == 0 ||
		len(command.Payload) == 0 || len(command.Digest) != 64 || command.CreatedAt.IsZero() {
		return fmt.Errorf("durable Redpanda command is invalid")
	}
	if command.Envelope.Kind != redpanda.KindExecute && command.Envelope.Kind != redpanda.KindCancel {
		return fmt.Errorf("durable Redpanda command kind is invalid")
	}
	principal := commandPrincipal(command.Envelope)
	if principal.Issuer == "" || principal.Subject == "" {
		return fmt.Errorf("durable Redpanda command principal is required")
	}
	return nil
}

func commandPrincipal(envelope *redpanda.Envelope) redpanda.Principal {
	if envelope.Kind == redpanda.KindExecute && envelope.Execute != nil {
		return envelope.Execute.Principal
	}
	if envelope.Kind == redpanda.KindCancel && envelope.Cancel != nil {
		return envelope.Cancel.Principal
	}
	return redpanda.Principal{}
}

func verifyDurableExecution(ctx context.Context, tx pgx.Tx, envelope *redpanda.Envelope, principal redpanda.Principal) error {
	var commandID, tenant, issuer, subject, taskID, contextID, messageID string
	err := tx.QueryRow(ctx, `
SELECT command_id, tenant_id, owner_issuer, owner_subject, task_id, context_id, message_id
FROM a2a_dispatch_executions
WHERE execution_id = $1`, envelope.ExecutionID).Scan(
		&commandID, &tenant, &issuer, &subject, &taskID, &contextID, &messageID,
	)
	if err != nil {
		return fmt.Errorf("verify durable execution: %w", err)
	}
	if commandID != envelope.CommandID || tenant != envelope.TenantID || issuer != principal.Issuer ||
		subject != principal.Subject || taskID != string(envelope.TaskID) || contextID != envelope.ContextID ||
		messageID != envelope.Execute.Message.ID {
		return fmt.Errorf("execution identifier conflicts with different immutable metadata")
	}
	return nil
}

func jsonBytesEqual(first, second []byte) bool {
	var left, right any
	if json.Unmarshal(first, &left) != nil || json.Unmarshal(second, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}
