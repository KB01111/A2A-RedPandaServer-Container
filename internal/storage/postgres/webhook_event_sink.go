package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	appauth "github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/webhook"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"github.com/jackc/pgx/v5"
)

// WebhookEventSink writes notification deliveries inside the same transaction
// as each task version. The SDK's later push.Sender call derives the same ID,
// making that second enqueue an idempotent confirmation.
type WebhookEventSink struct {
	cipher *webhook.CredentialCipher
	policy webhook.TargetPolicy
}

var _ TaskEventSink = (*WebhookEventSink)(nil)

func NewWebhookEventSink(cipher *webhook.CredentialCipher, policy webhook.TargetPolicy) (*WebhookEventSink, error) {
	if cipher == nil {
		return nil, fmt.Errorf("webhook credential cipher is required")
	}
	return &WebhookEventSink{cipher: cipher, policy: policy}, nil
}

func (s *WebhookEventSink) EnqueueTaskEvent(
	ctx context.Context,
	tx pgx.Tx,
	identity appauth.Identity,
	taskID a2a.TaskID,
	_ taskstore.TaskVersion,
	event a2a.Event,
) error {
	rows, err := tx.Query(ctx, `
SELECT config_id, encrypted_config
FROM a2a_push_configs
WHERE tenant_id = $1 AND owner_issuer = $2 AND owner_subject = $3 AND task_id = $4
ORDER BY created_at, config_id`, identity.Tenant, identity.Issuer, identity.Subject, string(taskID))
	if err != nil {
		return fmt.Errorf("list transactional push configurations: %w", err)
	}
	defer rows.Close()
	configs := make([]*a2a.PushConfig, 0)
	decoder := &PushConfigStore{cipher: s.cipher}
	for rows.Next() {
		var configID string
		var encrypted []byte
		if err := rows.Scan(&configID, &encrypted); err != nil {
			return fmt.Errorf("scan transactional push configuration: %w", err)
		}
		config, err := decoder.decrypt(identity.Issuer, identity.Tenant, identity.Subject, taskID, configID, encrypted)
		if err != nil {
			return err
		}
		configs = append(configs, config)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate transactional push configurations: %w", err)
	}
	rows.Close()

	for _, config := range configs {
		delivery, err := webhook.BuildDelivery(s.cipher, s.policy, 0, 0, config, event, eventTime(event), "")
		if err != nil {
			return fmt.Errorf("build transactional webhook delivery: %w", err)
		}
		if err := enqueueWebhookDeliveryTx(ctx, tx, identity, delivery); err != nil {
			return err
		}
	}
	return nil
}

func enqueueWebhookDeliveryTx(ctx context.Context, tx pgx.Tx, identity appauth.Identity, delivery webhook.NewDelivery) error {
	commandTag, err := tx.Exec(ctx, `
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
		return fmt.Errorf("enqueue transactional webhook delivery: %w", err)
	}
	if commandTag.RowsAffected() == 1 {
		return nil
	}
	var taskID, configID, targetURL, ownerIssuer, ownerSubject string
	var payload []byte
	if err := tx.QueryRow(ctx, `
SELECT task_id, config_id, target_url, owner_issuer, owner_subject, payload
FROM a2a_webhook_outbox
WHERE tenant_id = $1 AND delivery_id = $2`, delivery.Tenant, string(delivery.ID),
	).Scan(&taskID, &configID, &targetURL, &ownerIssuer, &ownerSubject, &payload); err != nil {
		return fmt.Errorf("verify transactional webhook delivery: %w", err)
	}
	if taskID != delivery.TaskID || configID != delivery.ConfigID || targetURL != delivery.TargetURL ||
		ownerIssuer != identity.Issuer || ownerSubject != identity.Subject || !bytes.Equal(payload, delivery.Payload) {
		return fmt.Errorf("webhook delivery identifier conflicts with different immutable metadata")
	}
	return nil
}

func eventTime(event a2a.Event) time.Time {
	switch value := event.(type) {
	case *a2a.Task:
		if value != nil && value.Status.Timestamp != nil {
			return *value.Status.Timestamp
		}
	case *a2a.TaskStatusUpdateEvent:
		if value != nil && value.Status.Timestamp != nil {
			return *value.Status.Timestamp
		}
	}
	return time.Now().UTC()
}
