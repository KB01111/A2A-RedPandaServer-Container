package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/push"
)

const (
	defaultMaxPayloadBytes    = 1 << 20
	defaultMaxCredentialBytes = 64 << 10
)

// PushSenderConfig configures the durable push.Sender adapter.
type PushSenderConfig struct {
	Repository         Repository
	CredentialCipher   *CredentialCipher
	TargetPolicy       TargetPolicy
	MaxPayloadBytes    int
	MaxCredentialBytes int
	Now                func() time.Time
	NewID              func(time.Time) (string, error)
}

// PushSender serializes an A2A event and durably enqueues it. It performs no
// webhook network I/O, so an endpoint outage cannot block agent execution.
type PushSender struct {
	repository         Repository
	cipher             *CredentialCipher
	policy             TargetPolicy
	maxPayloadBytes    int
	maxCredentialBytes int
	now                func() time.Time
	newID              func(time.Time) (string, error)
}

var _ push.Sender = (*PushSender)(nil)

// NewPushSender constructs the durable A2A push sender.
func NewPushSender(cfg PushSenderConfig) (*PushSender, error) {
	if cfg.Repository == nil {
		return nil, fmt.Errorf("webhook repository is required")
	}
	if cfg.CredentialCipher == nil {
		return nil, fmt.Errorf("webhook credential cipher is required")
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = defaultMaxPayloadBytes
	}
	if cfg.MaxCredentialBytes <= 0 {
		cfg.MaxCredentialBytes = defaultMaxCredentialBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &PushSender{
		repository:         cfg.Repository,
		cipher:             cfg.CredentialCipher,
		policy:             cfg.TargetPolicy,
		maxPayloadBytes:    cfg.MaxPayloadBytes,
		maxCredentialBytes: cfg.MaxCredentialBytes,
		now:                cfg.Now,
		newID:              cfg.NewID,
	}, nil
}

// SendPush implements push.Sender. The event wrapper and authentication
// behavior intentionally match a2a-go v2.4.0.
func (s *PushSender) SendPush(ctx context.Context, cfg *a2a.PushConfig, event a2a.Event) error {
	now := s.now().UTC()
	id := ""
	var err error
	if s.newID != nil {
		id, err = s.newID(now)
		if err != nil {
			return fmt.Errorf("generate webhook delivery ID: %w", err)
		}
	}
	delivery, err := BuildDelivery(s.cipher, s.policy, s.maxPayloadBytes, s.maxCredentialBytes, cfg, event, now, id)
	if err != nil {
		return err
	}
	if err := s.repository.EnqueueDelivery(ctx, delivery); err != nil {
		return fmt.Errorf("enqueue webhook delivery: %w", err)
	}
	return nil
}

// BuildDelivery validates and serializes one immutable notification. An empty
// ID derives a deterministic, secret-safe SHA-256 identifier so an in-task
// transaction and the SDK's subsequent SendPush call converge on one row.
func BuildDelivery(cipher *CredentialCipher, policy TargetPolicy, maxPayloadBytes, maxCredentialBytes int, cfg *a2a.PushConfig, event a2a.Event, now time.Time, id string) (NewDelivery, error) {
	if cfg == nil {
		return NewDelivery{}, fmt.Errorf("push configuration is required")
	}
	if cipher == nil {
		return NewDelivery{}, fmt.Errorf("webhook credential cipher is required")
	}
	if event == nil {
		return NewDelivery{}, fmt.Errorf("webhook event is required")
	}
	if _, err := ValidateTarget(cfg.URL, policy); err != nil {
		return NewDelivery{}, err
	}
	payload, err := json.Marshal(a2a.StreamResponse{Event: event})
	if err != nil {
		return NewDelivery{}, fmt.Errorf("serialize webhook event: %w", err)
	}
	if maxPayloadBytes <= 0 {
		maxPayloadBytes = defaultMaxPayloadBytes
	}
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return NewDelivery{}, fmt.Errorf("webhook payload exceeds %d bytes", maxPayloadBytes)
	}
	tenant := strings.TrimSpace(cfg.Tenant)
	if tenant == "" || tenant != cfg.Tenant {
		return NewDelivery{}, fmt.Errorf("webhook tenant is required without surrounding whitespace")
	}
	taskID := string(cfg.TaskID)
	if strings.TrimSpace(taskID) == "" || taskID != strings.TrimSpace(taskID) {
		return NewDelivery{}, fmt.Errorf("webhook task ID is required without surrounding whitespace")
	}
	eventTaskID := string(event.TaskInfo().TaskID)
	if eventTaskID == "" || eventTaskID != taskID {
		return NewDelivery{}, fmt.Errorf("webhook configuration task does not match the event task")
	}
	if strings.TrimSpace(cfg.ID) == "" || cfg.ID != strings.TrimSpace(cfg.ID) {
		return NewDelivery{}, fmt.Errorf("webhook configuration ID is required without surrounding whitespace")
	}
	credentials, err := credentialsFromPushConfig(cfg)
	if err != nil {
		return NewDelivery{}, err
	}
	if id == "" {
		id = stableDeliveryID(cfg, credentials, payload)
	}
	if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) || !validHeaderValue(id) || len(id) > 256 {
		return NewDelivery{}, fmt.Errorf("generated webhook delivery ID is invalid")
	}
	now = now.UTC()
	if now.IsZero() {
		return NewDelivery{}, fmt.Errorf("webhook delivery time is required")
	}
	delivery := NewDelivery{
		ID:                   DeliveryID(id),
		Tenant:               tenant,
		TaskID:               taskID,
		ConfigID:             cfg.ID,
		TargetURL:            cfg.URL,
		Payload:              append([]byte(nil), payload...),
		EncryptedCredentials: []byte{},
		CreatedAt:            now,
		AvailableAt:          now,
	}
	if credentials != (deliveryCredentials{}) {
		plaintext, err := json.Marshal(credentials)
		if err != nil {
			return NewDelivery{}, fmt.Errorf("serialize webhook credentials: %w", err)
		}
		defer wipe(plaintext)
		if maxCredentialBytes <= 0 {
			maxCredentialBytes = defaultMaxCredentialBytes
		}
		if len(plaintext) > maxCredentialBytes {
			return NewDelivery{}, fmt.Errorf("webhook credentials exceed %d bytes", maxCredentialBytes)
		}
		delivery.EncryptedCredentials, err = cipher.Encrypt(plaintext, credentialAAD(delivery))
		if err != nil {
			return NewDelivery{}, fmt.Errorf("encrypt webhook credentials: %w", err)
		}
	}
	return delivery, nil
}

func stableDeliveryID(cfg *a2a.PushConfig, credentials deliveryCredentials, payload []byte) string {
	hash := sha256.New()
	for _, value := range [][]byte{
		[]byte("bridge.a2a.webhook-delivery/v1"), []byte(cfg.Tenant), []byte(cfg.TaskID),
		[]byte(cfg.ID), []byte(cfg.URL), []byte(credentials.NotificationToken),
		[]byte(credentials.AuthScheme), []byte(credentials.AuthCredentials), payload,
	} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type deliveryCredentials struct {
	NotificationToken string `json:"notificationToken,omitempty"`
	AuthScheme        string `json:"authScheme,omitempty"`
	AuthCredentials   string `json:"authCredentials,omitempty"`
}

func credentialsFromPushConfig(cfg *a2a.PushConfig) (deliveryCredentials, error) {
	result := deliveryCredentials{NotificationToken: cfg.Token}
	if cfg.Auth == nil || cfg.Auth.Credentials == "" {
		return result, nil
	}
	switch strings.ToLower(cfg.Auth.Scheme) {
	case "basic":
		result.AuthScheme = "Basic"
	case "bearer":
		result.AuthScheme = "Bearer"
	default:
		return deliveryCredentials{}, fmt.Errorf("unsupported webhook authentication scheme")
	}
	result.AuthCredentials = cfg.Auth.Credentials
	return result, nil
}
