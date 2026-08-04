package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	appwebhook "github.com/KB01111/A2A-RedPandaServer-Container/internal/webhook"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/push"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxPushConfigJSONBytes = 128 << 10

// PushConfigStore persists encrypted, owner-scoped A2A push configurations.
// The callback URL remains queryable for operational diagnostics, while all
// tokens and authentication credentials are encrypted at rest.
type PushConfigStore struct {
	pool   *pgxpool.Pool
	cipher *appwebhook.CredentialCipher
	policy appwebhook.TargetPolicy
}

var _ push.ConfigStore = (*PushConfigStore)(nil)

func NewPushConfigStore(pool *pgxpool.Pool, cipher *appwebhook.CredentialCipher, policy appwebhook.TargetPolicy) (*PushConfigStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	if cipher == nil {
		return nil, fmt.Errorf("push configuration cipher is required")
	}
	return &PushConfigStore{pool: pool, cipher: cipher, policy: policy}, nil
}

func (s *PushConfigStore) Save(ctx context.Context, taskID a2a.TaskID, config *a2a.PushConfig) (*a2a.PushConfig, error) {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if config == nil || !validPushIdentifier(string(taskID)) {
		return nil, fmt.Errorf("task ID and push configuration are required: %w", a2a.ErrInvalidParams)
	}
	if config.Tenant != "" && config.Tenant != identity.Tenant {
		return nil, fmt.Errorf("push tenant does not match authenticated tenant: %w", a2a.ErrInvalidParams)
	}
	if _, err := appwebhook.ValidateTarget(config.URL, s.policy); err != nil {
		return nil, fmt.Errorf("invalid push target: %w", a2a.ErrInvalidParams)
	}

	toSave := clonePushConfig(config)
	toSave.Tenant = identity.Tenant
	toSave.TaskID = taskID
	if toSave.ID == "" {
		toSave.ID = uuid.Must(uuid.NewV7()).String()
	}
	if !validPushIdentifier(toSave.ID) {
		return nil, fmt.Errorf("push configuration ID is invalid: %w", a2a.ErrInvalidParams)
	}
	payload, err := json.Marshal(toSave)
	if err != nil {
		return nil, fmt.Errorf("encode push configuration: %w", err)
	}
	defer wipeBytes(payload)
	if len(payload) == 0 || len(payload) > maxPushConfigJSONBytes {
		return nil, fmt.Errorf("push configuration exceeds %d bytes: %w", maxPushConfigJSONBytes, a2a.ErrInvalidParams)
	}
	encrypted, err := s.cipher.Encrypt(payload, pushConfigAAD(identity.Issuer, identity.Tenant, identity.Subject, string(taskID), toSave.ID))
	if err != nil {
		return nil, fmt.Errorf("encrypt push configuration: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO a2a_push_configs (
    tenant_id, owner_issuer, owner_subject, task_id, config_id, target_url, encrypted_config
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, owner_issuer, owner_subject, task_id, config_id)
DO UPDATE SET target_url = EXCLUDED.target_url,
              encrypted_config = EXCLUDED.encrypted_config,
              updated_at = clock_timestamp()`,
		identity.Tenant, identity.Issuer, identity.Subject, string(taskID), toSave.ID, toSave.URL, encrypted,
	); err != nil {
		return nil, fmt.Errorf("save push configuration: %w", err)
	}
	return clonePushConfig(toSave), nil
}

func (s *PushConfigStore) Get(ctx context.Context, taskID a2a.TaskID, configID string) (*a2a.PushConfig, error) {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validPushIdentifier(string(taskID)) || !validPushIdentifier(configID) {
		return nil, push.ErrPushConfigNotFound
	}
	var encrypted []byte
	err = s.pool.QueryRow(ctx, `
SELECT encrypted_config
FROM a2a_push_configs
WHERE tenant_id = $1 AND owner_issuer = $2 AND owner_subject = $3
  AND task_id = $4 AND config_id = $5`,
		identity.Tenant, identity.Issuer, identity.Subject, string(taskID), configID,
	).Scan(&encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, push.ErrPushConfigNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get push configuration: %w", err)
	}
	return s.decrypt(identity.Issuer, identity.Tenant, identity.Subject, taskID, configID, encrypted)
}

func (s *PushConfigStore) List(ctx context.Context, taskID a2a.TaskID) ([]*a2a.PushConfig, error) {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validPushIdentifier(string(taskID)) {
		return []*a2a.PushConfig{}, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT config_id, encrypted_config
FROM a2a_push_configs
WHERE tenant_id = $1 AND owner_issuer = $2 AND owner_subject = $3 AND task_id = $4
ORDER BY created_at, config_id`, identity.Tenant, identity.Issuer, identity.Subject, string(taskID))
	if err != nil {
		return nil, fmt.Errorf("list push configurations: %w", err)
	}
	defer rows.Close()
	result := make([]*a2a.PushConfig, 0)
	for rows.Next() {
		var configID string
		var encrypted []byte
		if err := rows.Scan(&configID, &encrypted); err != nil {
			return nil, fmt.Errorf("scan push configuration: %w", err)
		}
		config, err := s.decrypt(identity.Issuer, identity.Tenant, identity.Subject, taskID, configID, encrypted)
		if err != nil {
			return nil, err
		}
		result = append(result, config)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate push configurations: %w", err)
	}
	return result, nil
}

func (s *PushConfigStore) Delete(ctx context.Context, taskID a2a.TaskID, configID string) error {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return err
	}
	if !validPushIdentifier(string(taskID)) || !validPushIdentifier(configID) {
		return nil
	}
	if _, err := s.pool.Exec(ctx, `
DELETE FROM a2a_push_configs
WHERE tenant_id = $1 AND owner_issuer = $2 AND owner_subject = $3
  AND task_id = $4 AND config_id = $5`,
		identity.Tenant, identity.Issuer, identity.Subject, string(taskID), configID,
	); err != nil {
		return fmt.Errorf("delete push configuration: %w", err)
	}
	return nil
}

func (s *PushConfigStore) DeleteAll(ctx context.Context, taskID a2a.TaskID) error {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return err
	}
	if !validPushIdentifier(string(taskID)) {
		return nil
	}
	if _, err := s.pool.Exec(ctx, `
DELETE FROM a2a_push_configs
WHERE tenant_id = $1 AND owner_issuer = $2 AND owner_subject = $3 AND task_id = $4`,
		identity.Tenant, identity.Issuer, identity.Subject, string(taskID),
	); err != nil {
		return fmt.Errorf("delete push configurations: %w", err)
	}
	return nil
}

func (s *PushConfigStore) decrypt(issuer, tenant, subject string, taskID a2a.TaskID, configID string, encrypted []byte) (*a2a.PushConfig, error) {
	plaintext, err := s.cipher.Decrypt(encrypted, pushConfigAAD(issuer, tenant, subject, string(taskID), configID))
	if err != nil {
		return nil, fmt.Errorf("decrypt push configuration: %w", err)
	}
	defer wipeBytes(plaintext)
	var config a2a.PushConfig
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode push configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode push configuration: trailing data")
	}
	if config.Tenant != tenant || config.TaskID != taskID || config.ID != configID {
		return nil, fmt.Errorf("stored push configuration ownership mismatch")
	}
	return clonePushConfig(&config), nil
}

func validPushIdentifier(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 4096 && !strings.ContainsRune(value, '\x00')
}

func clonePushConfig(config *a2a.PushConfig) *a2a.PushConfig {
	if config == nil {
		return nil
	}
	result := *config
	if config.Auth != nil {
		auth := *config.Auth
		result.Auth = &auth
	}
	return &result
}

func pushConfigAAD(values ...string) []byte {
	result := make([]byte, 0, 128)
	result = append(result, "bridge.a2a.push-config/v1"...)
	for _, value := range values {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		result = append(result, size[:]...)
		result = append(result, value...)
	}
	return result
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
