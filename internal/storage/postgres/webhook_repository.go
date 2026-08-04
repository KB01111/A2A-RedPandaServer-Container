package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/webhook"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookRepository is a leased PostgreSQL outbox. Claim transactions commit
// before network delivery begins, and all completion writes use lease-token
// compare-and-swap guards.
type WebhookRepository struct {
	pool *pgxpool.Pool
}

var _ webhook.Repository = (*WebhookRepository)(nil)

func NewWebhookRepository(pool *pgxpool.Pool) (*WebhookRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &WebhookRepository{pool: pool}, nil
}

func (r *WebhookRepository) EnqueueDelivery(ctx context.Context, delivery webhook.NewDelivery) error {
	if err := validateNewDelivery(delivery); err != nil {
		return err
	}
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return err
	}
	if delivery.Tenant != identity.Tenant {
		return fmt.Errorf("webhook tenant does not match authenticated tenant")
	}
	commandTag, err := r.pool.Exec(ctx, `
INSERT INTO a2a_webhook_outbox (
    delivery_id, tenant_id, owner_issuer, owner_subject, task_id, config_id,
    target_url, payload, encrypted_credentials, created_at, available_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, delivery_id) DO NOTHING`,
		string(delivery.ID), delivery.Tenant, identity.Issuer, identity.Subject,
		delivery.TaskID, delivery.ConfigID, delivery.TargetURL, delivery.Payload,
		delivery.EncryptedCredentials, delivery.CreatedAt.UTC(), delivery.AvailableAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("enqueue webhook delivery: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		var taskID, configID, targetURL, ownerIssuer, ownerSubject string
		var payload []byte
		err := r.pool.QueryRow(ctx, `
SELECT task_id, config_id, target_url, owner_issuer, owner_subject, payload
FROM a2a_webhook_outbox
WHERE tenant_id = $1 AND delivery_id = $2`, delivery.Tenant, string(delivery.ID),
		).Scan(&taskID, &configID, &targetURL, &ownerIssuer, &ownerSubject, &payload)
		if err != nil {
			return fmt.Errorf("verify existing webhook delivery: %w", err)
		}
		if taskID != delivery.TaskID || configID != delivery.ConfigID || targetURL != delivery.TargetURL ||
			ownerIssuer != identity.Issuer || ownerSubject != identity.Subject || !bytes.Equal(payload, delivery.Payload) {
			return fmt.Errorf("webhook delivery identifier conflicts with different immutable metadata")
		}
	}
	return nil
}

func (r *WebhookRepository) ClaimReady(ctx context.Context, request webhook.ClaimRequest) ([]webhook.Delivery, error) {
	if strings.TrimSpace(request.WorkerID) == "" || request.WorkerID != strings.TrimSpace(request.WorkerID) ||
		strings.TrimSpace(request.LeaseToken) == "" || request.LeaseToken != strings.TrimSpace(request.LeaseToken) ||
		request.Now.IsZero() || request.LeaseDuration <= 0 || request.Limit < 1 || request.Limit > 1000 {
		return nil, fmt.Errorf("invalid webhook claim request")
	}
	claimed := make([]webhook.Delivery, 0, request.Limit)
	err := pgx.BeginTxFunc(ctx, r.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
UPDATE a2a_webhook_outbox
SET state = 'ready', lease_owner = NULL, lease_token = NULL, lease_until = NULL
WHERE state = 'leased' AND lease_until <= $1`, request.Now.UTC()); err != nil {
			return fmt.Errorf("release expired webhook leases: %w", err)
		}
		rows, err := tx.Query(ctx, `
WITH candidates AS (
    SELECT tenant_id, delivery_id
    FROM a2a_webhook_outbox
    WHERE state = 'ready' AND available_at <= $1
    ORDER BY available_at, created_at, delivery_id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE a2a_webhook_outbox AS delivery
SET state = 'leased', lease_owner = $3, lease_token = $4, lease_until = $5
FROM candidates
WHERE delivery.tenant_id = candidates.tenant_id
  AND delivery.delivery_id = candidates.delivery_id
RETURNING delivery.delivery_id, delivery.tenant_id, delivery.task_id,
          delivery.config_id, delivery.target_url, delivery.payload,
          delivery.encrypted_credentials, delivery.created_at,
          delivery.available_at, delivery.attempts, delivery.lease_token,
          delivery.lease_until`, request.Now.UTC(), request.Limit, request.WorkerID,
			request.LeaseToken, request.Now.UTC().Add(request.LeaseDuration))
		if err != nil {
			return fmt.Errorf("claim webhook deliveries: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var delivery webhook.Delivery
			if err := rows.Scan(
				&delivery.ID, &delivery.Tenant, &delivery.TaskID, &delivery.ConfigID,
				&delivery.TargetURL, &delivery.Payload, &delivery.EncryptedCredentials,
				&delivery.CreatedAt, &delivery.AvailableAt, &delivery.Attempts,
				&delivery.LeaseToken, &delivery.LeaseUntil,
			); err != nil {
				return fmt.Errorf("scan claimed webhook delivery: %w", err)
			}
			claimed = append(claimed, delivery)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate claimed webhook deliveries: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (r *WebhookRepository) MarkSucceeded(ctx context.Context, result webhook.DeliverySuccess) error {
	return r.complete(ctx, result.Tenant, result.ID, result.LeaseToken, result.Attempt,
		result.HTTPStatus, "succeeded", "", time.Time{}, result.FinishedAt)
}

func (r *WebhookRepository) MarkRetry(ctx context.Context, result webhook.DeliveryRetry) error {
	return r.complete(ctx, result.Tenant, result.ID, result.LeaseToken, result.Attempt,
		result.HTTPStatus, "ready", result.Failure, result.NextAttempt, result.FinishedAt)
}

func (r *WebhookRepository) MarkDead(ctx context.Context, result webhook.DeliveryDead) error {
	return r.complete(ctx, result.Tenant, result.ID, result.LeaseToken, result.Attempt,
		result.HTTPStatus, "dead", result.Failure, time.Time{}, result.FinishedAt)
}

func (r *WebhookRepository) complete(
	ctx context.Context,
	tenant string,
	id webhook.DeliveryID,
	leaseToken string,
	attempt int,
	httpStatus int,
	state string,
	failure webhook.FailureKind,
	nextAttempt time.Time,
	finishedAt time.Time,
) error {
	if tenant == "" || id == "" || leaseToken == "" || attempt < 1 || finishedAt.IsZero() {
		return fmt.Errorf("invalid webhook completion")
	}
	var availableAt any
	var completedAt any = finishedAt.UTC()
	if state == "ready" {
		if nextAttempt.IsZero() {
			return fmt.Errorf("webhook retry requires next attempt time")
		}
		availableAt = nextAttempt.UTC()
		completedAt = nil
	}
	var status any
	if httpStatus != 0 {
		status = httpStatus
	}
	var failureValue any
	if failure != "" {
		failureValue = string(failure)
	}
	commandTag, err := r.pool.Exec(ctx, `
UPDATE a2a_webhook_outbox
SET state = $5, attempts = $6, last_http_status = $7, last_failure = $8,
    available_at = COALESCE($9, available_at), finished_at = $10,
    lease_owner = NULL, lease_token = NULL, lease_until = NULL
WHERE tenant_id = $1 AND delivery_id = $2 AND state = 'leased'
  AND lease_token = $3 AND attempts = $4`,
		tenant, string(id), leaseToken, attempt-1, state, attempt, status,
		failureValue, availableAt, completedAt,
	)
	if err != nil {
		return fmt.Errorf("complete webhook delivery: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return webhook.ErrLeaseLost
	}
	return nil
}

func validateNewDelivery(delivery webhook.NewDelivery) error {
	for name, value := range map[string]string{
		"delivery ID": string(delivery.ID), "tenant": delivery.Tenant,
		"task ID": delivery.TaskID, "target URL": delivery.TargetURL,
	} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("webhook %s is invalid", name)
		}
	}
	if len(delivery.Payload) == 0 || len(delivery.Payload) > 1<<20 || delivery.CreatedAt.IsZero() || delivery.AvailableAt.IsZero() {
		return fmt.Errorf("webhook delivery payload or timestamps are invalid")
	}
	return nil
}
