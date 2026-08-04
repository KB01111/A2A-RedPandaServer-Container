package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestPushSenderEnqueuesImmutableStreamResponseWithEncryptedCredentials(t *testing.T) {
	t.Parallel()
	repository := &recordingRepository{}
	cipher := testCredentialCipher(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	sender, err := NewPushSender(PushSenderConfig{
		Repository: repository, CredentialCipher: cipher,
		TargetPolicy: TargetPolicy{}, Now: func() time.Time { return now },
		NewID: func(time.Time) (string, error) { return "delivery-stable", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	event := a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("done"))
	event.TaskID = "task-1"
	config := &a2a.PushConfig{
		Tenant: "tenant-1", TaskID: "task-1", ID: "config-1", URL: "https://receiver.example.test/hook",
		Token: "notification-secret", Auth: &a2a.PushAuthInfo{Scheme: "bEaReR", Credentials: "bearer-secret"},
	}
	if err := sender.SendPush(context.Background(), config, event); err != nil {
		t.Fatal(err)
	}
	delivery := repository.enqueued
	if delivery.ID != "delivery-stable" || delivery.Tenant != "tenant-1" || delivery.TaskID != "task-1" || delivery.ConfigID != "config-1" {
		t.Fatalf("enqueued identity = %+v", delivery)
	}
	var stream a2a.StreamResponse
	if err := json.Unmarshal(delivery.Payload, &stream); err != nil {
		t.Fatalf("payload is not an A2A StreamResponse: %v", err)
	}
	if _, ok := stream.Event.(*a2a.Message); !ok {
		t.Fatalf("stream event type = %T, want *a2a.Message", stream.Event)
	}
	if bytes.Contains(delivery.EncryptedCredentials, []byte("secret")) {
		t.Fatal("enqueued credentials contain plaintext")
	}
	plaintext, err := cipher.Decrypt(delivery.EncryptedCredentials, credentialAAD(delivery))
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(plaintext)
	var credentials deliveryCredentials
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		t.Fatal(err)
	}
	if credentials.NotificationToken != "notification-secret" || credentials.AuthScheme != "Bearer" || credentials.AuthCredentials != "bearer-secret" {
		t.Fatalf("decrypted credentials = %+v", credentials)
	}
	event.Parts[0] = a2a.NewTextPart("mutated")
	if bytes.Contains(delivery.Payload, []byte("mutated")) {
		t.Fatal("queued payload changed after the source event was mutated")
	}
}

func TestPushSenderValidation(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	tests := []struct {
		name   string
		config *a2a.PushConfig
		event  a2a.Event
		max    int
	}{
		{name: "nil config", event: testWebhookEvent()},
		{name: "missing tenant", config: &a2a.PushConfig{ID: "config", URL: "https://receiver.example/hook", TaskID: "task"}, event: testWebhookEvent()},
		{name: "mismatched task", config: &a2a.PushConfig{Tenant: "tenant", ID: "config", URL: "https://receiver.example/hook", TaskID: "other-task"}, event: testWebhookEvent()},
		{name: "missing config ID", config: &a2a.PushConfig{Tenant: "tenant", URL: "https://receiver.example/hook", TaskID: "task"}, event: testWebhookEvent()},
		{name: "HTTP production target", config: &a2a.PushConfig{Tenant: "tenant", ID: "config", URL: "http://receiver.example/hook", TaskID: "task"}, event: testWebhookEvent()},
		{name: "target credentials", config: &a2a.PushConfig{Tenant: "tenant", ID: "config", URL: "https://user:pass@receiver.example/hook", TaskID: "task"}, event: testWebhookEvent()},
		{name: "unsupported auth", config: &a2a.PushConfig{Tenant: "tenant", ID: "config", URL: "https://receiver.example/hook", TaskID: "task", Auth: &a2a.PushAuthInfo{Scheme: "Digest", Credentials: "secret"}}, event: testWebhookEvent()},
		{name: "payload cap", config: &a2a.PushConfig{Tenant: "tenant", ID: "config", URL: "https://receiver.example/hook", TaskID: "task"}, event: testWebhookEvent(), max: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sender, err := NewPushSender(PushSenderConfig{Repository: &recordingRepository{}, CredentialCipher: cipher, MaxPayloadBytes: test.max})
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.SendPush(context.Background(), test.config, test.event); err == nil {
				t.Fatal("SendPush() error = nil")
			}
		})
	}
}

func TestNewPushSenderRequiresCredentialCipher(t *testing.T) {
	t.Parallel()
	if _, err := NewPushSender(PushSenderConfig{Repository: &recordingRepository{}}); err == nil {
		t.Fatal("NewPushSender() accepted a nil credential cipher")
	}
}

func TestBuildDeliveryDerivesStableIDWithoutReusingCiphertext(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	config := &a2a.PushConfig{
		Tenant: "tenant", TaskID: "task", ID: "config",
		URL: "https://receiver.example.test/hook", Token: "secret",
	}
	event := testWebhookEvent()
	first, err := BuildDelivery(cipher, TargetPolicy{}, 0, 0, config, event, now, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDelivery(cipher, TargetPolicy{}, 0, 0, config, event, now.Add(time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("stable IDs = %q and %q", first.ID, second.ID)
	}
	if bytes.Equal(first.EncryptedCredentials, second.EncryptedCredentials) {
		t.Fatal("credential encryption reused ciphertext/nonce")
	}
}

func testWebhookEvent() a2a.Event {
	message := a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("done"))
	message.TaskID = "task"
	return message
}

func testCredentialCipher(t *testing.T) *CredentialCipher {
	t.Helper()
	cipher, err := NewCredentialCipher(1, map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

type recordingRepository struct {
	enqueued NewDelivery
	claim    []Delivery
	claimErr error
	success  []DeliverySuccess
	retries  []DeliveryRetry
	dead     []DeliveryDead
}

func (r *recordingRepository) EnqueueDelivery(_ context.Context, delivery NewDelivery) error {
	r.enqueued = delivery
	return nil
}

func (r *recordingRepository) ClaimReady(_ context.Context, request ClaimRequest) ([]Delivery, error) {
	for index := range r.claim {
		if r.claim[index].LeaseToken == "" {
			r.claim[index].LeaseToken = request.LeaseToken
		}
	}
	return r.claim, r.claimErr
}

func (r *recordingRepository) MarkSucceeded(_ context.Context, result DeliverySuccess) error {
	r.success = append(r.success, result)
	return nil
}

func (r *recordingRepository) MarkRetry(_ context.Context, result DeliveryRetry) error {
	r.retries = append(r.retries, result)
	return nil
}

func (r *recordingRepository) MarkDead(_ context.Context, result DeliveryDead) error {
	r.dead = append(r.dead, result)
	return nil
}
