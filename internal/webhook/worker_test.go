package webhook

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWorkerDeliversSignedA2APayloadWithTokenAndBearerCredentials(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	payload := []byte(`{"statusUpdate":{"taskId":"task-1","contextId":"context-1","status":{"state":"TASK_STATE_WORKING"}}}`)
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var readErr error
		receivedBody, readErr = io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
		}
		if got := request.Header.Get(HeaderNotificationToken); got != "notification-secret" {
			t.Errorf("notification token = %q", got)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer bearer-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get(HeaderDeliveryKeyID); got != "key-1" {
			t.Errorf("signing key ID = %q", got)
		}
		if !VerifySignature(publicKey, DeliveryID(request.Header.Get(HeaderDeliveryID)), request.Header.Get(HeaderDeliveryTimestamp), request.Header.Get(HeaderDeliverySignature), receivedBody) {
			t.Error("delivery signature did not verify")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	delivery := encryptedTestDelivery(t, cipher, server.URL, payload, deliveryCredentials{
		NotificationToken: "notification-secret", AuthScheme: "Bearer", AuthCredentials: "bearer-secret",
	})
	repository := &recordingRepository{claim: []Delivery{{NewDelivery: delivery}}}
	worker := newTestWorker(t, repository, cipher, privateKey, now, WorkerConfig{})
	processed, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 1 || len(repository.success) != 1 || len(repository.retries) != 0 || len(repository.dead) != 0 {
		t.Fatalf("processed=%d success=%v retries=%v dead=%v", processed, repository.success, repository.retries, repository.dead)
	}
	if !bytes.Equal(receivedBody, payload) {
		t.Fatalf("request body = %q, want %q", receivedBody, payload)
	}
	result := repository.success[0]
	if result.ID != delivery.ID || result.LeaseToken != "lease-stable" || result.Attempt != 1 || result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("success result = %+v", result)
	}
}

func TestWorkerPreservesBasicCredentialsWithoutReencoding(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
			t.Errorf("Authorization = %q", got)
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	delivery := encryptedTestDelivery(t, cipher, server.URL, []byte(`{"task":{}}`), deliveryCredentials{AuthScheme: "Basic", AuthCredentials: "dXNlcjpwYXNz"})
	repository := &recordingRepository{claim: []Delivery{{NewDelivery: delivery}}}
	worker := newTestWorker(t, repository, cipher, privateKey, time.Unix(1_700_000_000, 0), WorkerConfig{})
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repository.success) != 1 {
		t.Fatalf("success results = %v", repository.success)
	}
}

func TestWorkerClassifiesRetryDeadAndRetryAfter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		retryAfter  string
		attempts    int
		maxAttempts int
		wantRetry   bool
		wantFailure FailureKind
		wantDelay   time.Duration
	}{
		{name: "429 honors Retry-After", status: http.StatusTooManyRequests, retryAfter: "5", maxAttempts: 4, wantRetry: true, wantFailure: FailureResponseStatus, wantDelay: 5 * time.Second},
		{name: "503 full jitter", status: http.StatusServiceUnavailable, maxAttempts: 4, wantRetry: true, wantFailure: FailureResponseStatus, wantDelay: 2 * time.Second},
		{name: "400 is permanent", status: http.StatusBadRequest, maxAttempts: 4, wantFailure: FailureResponseStatus},
		{name: "redirect is permanent", status: http.StatusFound, maxAttempts: 4, wantFailure: FailureRedirect},
		{name: "retry budget exhausted", status: http.StatusInternalServerError, attempts: 3, maxAttempts: 4, wantFailure: FailureResponseStatus},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cipher := testCredentialCipher(t)
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if test.retryAfter != "" {
					response.Header().Set("Retry-After", test.retryAfter)
				}
				if test.status >= 300 && test.status < 400 {
					response.Header().Set("Location", "/must-not-run")
				}
				response.WriteHeader(test.status)
			}))
			defer server.Close()
			delivery := encryptedTestDelivery(t, cipher, server.URL, []byte(`{"task":{}}`), deliveryCredentials{})
			repository := &recordingRepository{claim: []Delivery{{NewDelivery: delivery, Attempts: test.attempts}}}
			now := time.Unix(1_700_000_000, 0).UTC()
			worker := newTestWorker(t, repository, cipher, privateKey, now, WorkerConfig{
				MaxAttempts: test.maxAttempts, BaseBackoff: 4 * time.Second, MaxBackoff: 10 * time.Second,
				Jitter: func(time.Duration) time.Duration { return 2 * time.Second },
			})
			if _, err := worker.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if test.wantRetry {
				if len(repository.retries) != 1 || len(repository.dead) != 0 {
					t.Fatalf("retries=%v dead=%v", repository.retries, repository.dead)
				}
				result := repository.retries[0]
				if result.Failure != test.wantFailure || result.HTTPStatus != test.status || result.NextAttempt.Sub(now) != test.wantDelay {
					t.Fatalf("retry result = %+v", result)
				}
			} else {
				if len(repository.dead) != 1 || len(repository.retries) != 0 {
					t.Fatalf("retries=%v dead=%v", repository.retries, repository.dead)
				}
				if repository.dead[0].Failure != test.wantFailure || repository.dead[0].HTTPStatus != test.status {
					t.Fatalf("dead result = %+v", repository.dead[0])
				}
			}
		})
	}
}

func TestWorkerMarksCorruptCredentialsDeadWithoutNetworkRequest(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	delivery := encryptedTestDelivery(t, cipher, server.URL, []byte(`{"task":{}}`), deliveryCredentials{NotificationToken: "secret"})
	delivery.EncryptedCredentials[len(delivery.EncryptedCredentials)-1] ^= 1
	repository := &recordingRepository{claim: []Delivery{{NewDelivery: delivery}}}
	worker := newTestWorker(t, repository, cipher, privateKey, time.Unix(1_700_000_000, 0), WorkerConfig{})
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 0 || len(repository.dead) != 1 || repository.dead[0].Failure != FailureInvalidCredentials {
		t.Fatalf("requests=%d dead=%v", requests, repository.dead)
	}
}

func TestWorkerDeadLettersRetryableFailureAtMaximumRetryAge(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	delivery := encryptedTestDelivery(t, cipher, server.URL, []byte(`{"task":{}}`), deliveryCredentials{})
	delivery.CreatedAt = now.Add(-48 * time.Hour)
	repository := &recordingRepository{claim: []Delivery{{NewDelivery: delivery}}}
	worker := newTestWorker(t, repository, cipher, privateKey, now, WorkerConfig{MaxAttempts: 100, MaxRetryAge: 48 * time.Hour})
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repository.retries) != 0 || len(repository.dead) != 1 {
		t.Fatalf("retries=%v dead=%v", repository.retries, repository.dead)
	}
	if repository.dead[0].Failure != FailureResponseStatus || repository.dead[0].HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("dead result = %+v", repository.dead[0])
	}
}

func TestWorkerRunStopsCleanlyOnCancellation(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := &recordingRepository{}
	worker := newTestWorker(t, repository, cipher, privateKey, time.Now(), WorkerConfig{PollInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
}

func TestNewWorkerDefaultsAndRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := WorkerConfig{
		Repository: &recordingRepository{}, CredentialCipher: cipher,
		Signer: Ed25519Signer{KeyID: "key-1", PrivateKey: privateKey}, WorkerID: "worker-1",
	}
	worker, err := NewWorker(base)
	if err != nil {
		t.Fatal(err)
	}
	if worker.maxRetryAge != 48*time.Hour {
		t.Fatalf("default max retry age = %s", worker.maxRetryAge)
	}
	base.MaxRetryAge = -time.Second
	if _, err := NewWorker(base); err == nil {
		t.Fatal("NewWorker() accepted a negative maximum retry age")
	}
	base.MaxRetryAge = 0
	base.Signer.KeyID = "unsafe\r\nheader"
	if _, err := NewWorker(base); err == nil {
		t.Fatal("NewWorker() accepted an unsafe signing key ID")
	}
}

func TestWorkerDeliversAClaimedBatchConcurrently(t *testing.T) {
	t.Parallel()
	cipher := testCredentialCipher(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		entered <- struct{}{}
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	first := encryptedTestDelivery(t, cipher, server.URL, []byte(`{"task":{}}`), deliveryCredentials{})
	second := first
	second.ID = "delivery-2"
	repository := &recordingRepository{claim: []Delivery{{NewDelivery: first}, {NewDelivery: second}}}
	worker := newTestWorker(t, repository, cipher, privateKey, now, WorkerConfig{BatchSize: 2})
	done := make(chan error, 1)
	go func() {
		_, runErr := worker.RunOnce(context.Background())
		done <- runErr
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("claimed deliveries were not attempted concurrently")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(repository.success) != 2 {
		t.Fatalf("success results = %v", repository.success)
	}
}

func encryptedTestDelivery(t *testing.T, cipher *CredentialCipher, target string, payload []byte, credentials deliveryCredentials) NewDelivery {
	t.Helper()
	delivery := NewDelivery{
		ID: "delivery-1", Tenant: "tenant-1", TaskID: "task-1", ConfigID: "config-1",
		TargetURL: target, Payload: append([]byte(nil), payload...), CreatedAt: time.Unix(1_700_000_000, 0), AvailableAt: time.Unix(1_700_000_000, 0),
	}
	if credentials == (deliveryCredentials{}) {
		return delivery
	}
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(plaintext)
	delivery.EncryptedCredentials, err = cipher.Encrypt(plaintext, credentialAAD(delivery))
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func newTestWorker(t *testing.T, repository Repository, cipher *CredentialCipher, privateKey ed25519.PrivateKey, now time.Time, override WorkerConfig) *Worker {
	t.Helper()
	override.Repository = repository
	override.CredentialCipher = cipher
	override.Signer = Ed25519Signer{KeyID: "key-1", PrivateKey: privateKey}
	override.WorkerID = "worker-1"
	override.HTTP.Policy = TargetPolicy{AllowHTTP: true, AllowPrivateNetworks: true}
	override.Now = func() time.Time { return now }
	override.NewID = func(time.Time) (string, error) { return "lease-stable", nil }
	worker, err := NewWorker(override)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}
