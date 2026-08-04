package webhook

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultMaxResponseBytes int64 = 64 << 10

// WorkerConfig configures a leased, at-least-once webhook worker.
type WorkerConfig struct {
	Repository       Repository
	CredentialCipher *CredentialCipher
	Signer           Ed25519Signer
	HTTP             HTTPClientConfig
	WorkerID         string
	BatchSize        int
	LeaseDuration    time.Duration
	PollInterval     time.Duration
	MaxAttempts      int
	MaxRetryAge      time.Duration
	BaseBackoff      time.Duration
	MaxBackoff       time.Duration
	MaxPayloadBytes  int
	MaxResponseBytes int64
	Now              func() time.Time
	NewID            func(time.Time) (string, error)
	Jitter           func(time.Duration) time.Duration
}

// Worker claims ready deliveries, releases the repository transaction, and
// only then performs HTTP requests. Completion updates are lease-token CAS
// operations, providing at-least-once behavior across crashes.
type Worker struct {
	repository       Repository
	cipher           *CredentialCipher
	signer           Ed25519Signer
	client           *http.Client
	policy           TargetPolicy
	workerID         string
	batchSize        int
	leaseDuration    time.Duration
	pollInterval     time.Duration
	maxAttempts      int
	maxRetryAge      time.Duration
	baseBackoff      time.Duration
	maxBackoff       time.Duration
	maxPayloadBytes  int
	maxResponseBytes int64
	now              func() time.Time
	newID            func(time.Time) (string, error)
	jitter           func(time.Duration) time.Duration
}

// NewWorker constructs a webhook worker with production-safe defaults.
func NewWorker(cfg WorkerConfig) (*Worker, error) {
	if cfg.Repository == nil {
		return nil, fmt.Errorf("webhook repository is required")
	}
	if strings.TrimSpace(cfg.WorkerID) == "" || cfg.WorkerID != strings.TrimSpace(cfg.WorkerID) {
		return nil, fmt.Errorf("webhook worker ID is required without surrounding whitespace")
	}
	if cfg.CredentialCipher == nil {
		return nil, fmt.Errorf("webhook credential cipher is required")
	}
	if strings.TrimSpace(cfg.Signer.KeyID) == "" || cfg.Signer.KeyID != strings.TrimSpace(cfg.Signer.KeyID) ||
		!validHeaderValue(cfg.Signer.KeyID) || len(cfg.Signer.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("valid webhook Ed25519 signer is required")
	}
	client, err := NewHTTPClient(cfg.HTTP)
	if err != nil {
		return nil, err
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 20
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = time.Minute
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	if cfg.MaxRetryAge < 0 {
		return nil, fmt.Errorf("webhook maximum retry age must not be negative")
	}
	if cfg.MaxRetryAge == 0 {
		cfg.MaxRetryAge = 48 * time.Hour
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 15 * time.Minute
	}
	if cfg.BaseBackoff > cfg.MaxBackoff {
		return nil, fmt.Errorf("webhook base backoff must not exceed maximum backoff")
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = defaultMaxPayloadBytes
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponseBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = func(now time.Time) (string, error) { return NewStableID(now, cryptorand.Reader) }
	}
	if cfg.Jitter == nil {
		cfg.Jitter = fullJitter
	}
	return &Worker{
		repository:       cfg.Repository,
		cipher:           cfg.CredentialCipher,
		signer:           cfg.Signer,
		client:           client,
		policy:           cfg.HTTP.Policy,
		workerID:         cfg.WorkerID,
		batchSize:        cfg.BatchSize,
		leaseDuration:    cfg.LeaseDuration,
		pollInterval:     cfg.PollInterval,
		maxAttempts:      cfg.MaxAttempts,
		maxRetryAge:      cfg.MaxRetryAge,
		baseBackoff:      cfg.BaseBackoff,
		maxBackoff:       cfg.MaxBackoff,
		maxPayloadBytes:  cfg.MaxPayloadBytes,
		maxResponseBytes: cfg.MaxResponseBytes,
		now:              cfg.Now,
		newID:            cfg.NewID,
		jitter:           cfg.Jitter,
	}, nil
}

// Run polls until ctx is canceled. Cancellation is a clean shutdown; an
// in-flight delivery remains leased and becomes claimable after lease expiry.
func (w *Worker) Run(ctx context.Context) error {
	for {
		processed, err := w.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if processed > 0 {
			continue
		}
		timer := time.NewTimer(w.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

// RunOnce claims one batch and attempts it outside the claim transaction.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	now := w.now().UTC()
	leaseToken, err := w.newID(now)
	if err != nil {
		return 0, fmt.Errorf("generate webhook lease token: %w", err)
	}
	deliveries, err := w.repository.ClaimReady(ctx, ClaimRequest{
		WorkerID:      w.workerID,
		LeaseToken:    leaseToken,
		Now:           now,
		LeaseDuration: w.leaseDuration,
		Limit:         w.batchSize,
	})
	if err != nil {
		return 0, fmt.Errorf("claim webhook deliveries: %w", err)
	}
	var resultErr error
	processed := len(deliveries)
	attempts := make(chan deliveryAttempt, len(deliveries))
	pending := 0
	for _, delivery := range deliveries {
		if ctx.Err() != nil {
			return 0, errors.Join(resultErr, ctx.Err())
		}
		if delivery.LeaseToken == "" || delivery.LeaseToken != leaseToken {
			resultErr = errors.Join(resultErr, fmt.Errorf("delivery %s returned with an invalid lease token", delivery.ID))
			continue
		}
		pending++
		go func(item Delivery) {
			attempts <- deliveryAttempt{delivery: item, outcome: w.deliver(ctx, item)}
		}(delivery)
	}
	for range pending {
		attempt := <-attempts
		if attempt.outcome.canceled || ctx.Err() != nil {
			resultErr = errors.Join(resultErr, ctx.Err())
			continue
		}
		if err := w.complete(ctx, attempt.delivery, attempt.outcome); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	return processed, resultErr
}

type deliveryAttempt struct {
	delivery Delivery
	outcome  deliveryOutcome
}

func (w *Worker) complete(ctx context.Context, delivery Delivery, outcome deliveryOutcome) error {
	attempt := delivery.Attempts + 1
	finishedAt := w.now().UTC()
	var err error
	if outcome.success {
		err = w.repository.MarkSucceeded(ctx, DeliverySuccess{
			Tenant: delivery.Tenant, ID: delivery.ID, LeaseToken: delivery.LeaseToken,
			Attempt: attempt, HTTPStatus: outcome.status, FinishedAt: finishedAt,
		})
	} else if !outcome.retryable || attempt >= w.maxAttempts || !finishedAt.Before(delivery.CreatedAt.Add(w.maxRetryAge)) {
		err = w.repository.MarkDead(ctx, DeliveryDead{
			Tenant: delivery.Tenant, ID: delivery.ID, LeaseToken: delivery.LeaseToken,
			Attempt: attempt, HTTPStatus: outcome.status, Failure: outcome.failure, FinishedAt: finishedAt,
		})
	} else {
		delay := w.retryDelay(attempt, outcome.retryAfter)
		nextAttempt := finishedAt.Add(delay)
		retryDeadline := delivery.CreatedAt.Add(w.maxRetryAge)
		if nextAttempt.After(retryDeadline) {
			nextAttempt = retryDeadline
		}
		err = w.repository.MarkRetry(ctx, DeliveryRetry{
			Tenant: delivery.Tenant, ID: delivery.ID, LeaseToken: delivery.LeaseToken,
			Attempt: attempt, HTTPStatus: outcome.status, Failure: outcome.failure,
			NextAttempt: nextAttempt, FinishedAt: finishedAt,
		})
	}
	if err != nil {
		return fmt.Errorf("complete webhook delivery %s: %w", delivery.ID, err)
	}
	return nil
}

type deliveryOutcome struct {
	success    bool
	retryable  bool
	canceled   bool
	status     int
	failure    FailureKind
	retryAfter time.Duration
}

func (w *Worker) deliver(ctx context.Context, delivery Delivery) deliveryOutcome {
	if delivery.ID == "" || !validHeaderValue(string(delivery.ID)) || delivery.Tenant == "" || delivery.TaskID == "" || delivery.CreatedAt.IsZero() || delivery.Attempts < 0 || len(delivery.Payload) == 0 || len(delivery.Payload) > w.maxPayloadBytes {
		return deliveryOutcome{failure: FailureInvalidDelivery}
	}
	target, err := ValidateTarget(delivery.TargetURL, w.policy)
	if err != nil {
		return deliveryOutcome{failure: FailureInvalidTarget}
	}
	credentials, err := w.decryptCredentials(delivery)
	if err != nil {
		return deliveryOutcome{failure: FailureInvalidCredentials}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(delivery.Payload))
	if err != nil {
		return deliveryOutcome{failure: FailureInvalidTarget}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "bridge-a2a-webhook/1")
	if credentials.NotificationToken != "" {
		if !validHeaderValue(credentials.NotificationToken) {
			return deliveryOutcome{failure: FailureInvalidCredentials}
		}
		request.Header.Set(HeaderNotificationToken, credentials.NotificationToken)
	}
	if credentials.AuthCredentials != "" {
		if !validHeaderValue(credentials.AuthCredentials) || (credentials.AuthScheme != "Basic" && credentials.AuthScheme != "Bearer") {
			return deliveryOutcome{failure: FailureInvalidCredentials}
		}
		request.Header.Set("Authorization", credentials.AuthScheme+" "+credentials.AuthCredentials)
	}
	signatureHeaders, err := w.signer.sign(delivery.ID, w.now().UTC(), delivery.Payload)
	if err != nil {
		return deliveryOutcome{failure: FailureInvalidDelivery}
	}
	for key, value := range signatureHeaders {
		request.Header.Set(key, value)
	}

	response, err := w.client.Do(request)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
			_ = response.Body.Close()
		}
		if ctx.Err() != nil {
			return deliveryOutcome{canceled: true}
		}
		if errors.Is(err, errRedirectsDisabled) {
			return deliveryOutcome{status: status, failure: FailureRedirect}
		}
		var networkError net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
			return deliveryOutcome{retryable: true, failure: FailureTimeout}
		}
		return deliveryOutcome{retryable: true, failure: FailureNetwork}
	}
	_, _ = io.CopyN(io.Discard, response.Body, w.maxResponseBytes+1)
	_ = response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return deliveryOutcome{success: true, status: response.StatusCode}
	}
	outcome := deliveryOutcome{status: response.StatusCode, failure: FailureResponseStatus}
	if retryableStatus(response.StatusCode) {
		outcome.retryable = true
		outcome.retryAfter = parseRetryAfter(response.Header.Get("Retry-After"), w.now().UTC())
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		outcome.failure = FailureRedirect
	}
	return outcome
}

func (w *Worker) decryptCredentials(delivery Delivery) (deliveryCredentials, error) {
	if len(delivery.EncryptedCredentials) == 0 {
		return deliveryCredentials{}, nil
	}
	plaintext, err := w.cipher.Decrypt(delivery.EncryptedCredentials, credentialAAD(delivery.NewDelivery))
	if err != nil {
		return deliveryCredentials{}, err
	}
	defer wipe(plaintext)
	var credentials deliveryCredentials
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return deliveryCredentials{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return deliveryCredentials{}, fmt.Errorf("credential envelope contains trailing data")
	}
	return credentials, nil
}

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64((24*time.Hour)/time.Second) {
			return 24 * time.Hour
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func (w *Worker) retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	ceiling := w.baseBackoff
	for step := 1; step < attempt && ceiling < w.maxBackoff; step++ {
		if ceiling > w.maxBackoff/2 {
			ceiling = w.maxBackoff
			break
		}
		ceiling *= 2
	}
	if ceiling > w.maxBackoff {
		ceiling = w.maxBackoff
	}
	delay := w.jitter(ceiling)
	if delay < 0 {
		delay = 0
	}
	if delay > ceiling {
		delay = ceiling
	}
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay > w.maxBackoff {
		delay = w.maxBackoff
	}
	return delay
}

func fullJitter(ceiling time.Duration) time.Duration {
	if ceiling <= 0 {
		return 0
	}
	maximum := big.NewInt(int64(ceiling))
	maximum.Add(maximum, big.NewInt(1))
	value, err := cryptorand.Int(cryptorand.Reader, maximum)
	if err != nil {
		return ceiling / 2
	}
	return time.Duration(value.Int64())
}

func validHeaderValue(value string) bool {
	for index := range len(value) {
		character := value[index]
		if (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}
