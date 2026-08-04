package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type WebhookConfig struct {
	Enabled             bool
	SigningKeyFile      string
	CredentialKeysFile  string
	WorkerCount         int
	BatchSize           int
	LeaseDuration       time.Duration
	DeliveryTimeout     time.Duration
	MaxAttempts         int
	MaxRetryAge         time.Duration
	AllowPrivateTargets bool
}

func loadWebhookConfig(environment string) (WebhookConfig, error) {
	enabled, err := strconv.ParseBool(envOrDefault("WEBHOOK_ENABLED", "false"))
	if err != nil {
		return WebhookConfig{}, fmt.Errorf("WEBHOOK_ENABLED must be true or false")
	}
	keys := []string{"WEBHOOK_SIGNING_PRIVATE_KEY_FILE", "WEBHOOK_CREDENTIAL_KEYS_FILE", "WEBHOOK_WORKERS", "WEBHOOK_BATCH_SIZE", "WEBHOOK_LEASE_DURATION", "WEBHOOK_DELIVERY_TIMEOUT", "WEBHOOK_MAX_ATTEMPTS", "WEBHOOK_MAX_RETRY_AGE"}
	if !enabled {
		if key, ok := anyConfigured(keys...); ok {
			return WebhookConfig{}, fmt.Errorf("%s requires WEBHOOK_ENABLED=true", key)
		}
		return WebhookConfig{}, nil
	}
	signingFile := strings.TrimSpace(envOrDefault("WEBHOOK_SIGNING_PRIVATE_KEY_FILE", ""))
	credentialFile := strings.TrimSpace(envOrDefault("WEBHOOK_CREDENTIAL_KEYS_FILE", ""))
	if signingFile == "" || credentialFile == "" {
		return WebhookConfig{}, fmt.Errorf("WEBHOOK_SIGNING_PRIVATE_KEY_FILE and WEBHOOK_CREDENTIAL_KEYS_FILE are required")
	}
	if err := requireAbsolutePath("WEBHOOK_SIGNING_PRIVATE_KEY_FILE", signingFile); err != nil {
		return WebhookConfig{}, err
	}
	if err := requireAbsolutePath("WEBHOOK_CREDENTIAL_KEYS_FILE", credentialFile); err != nil {
		return WebhookConfig{}, err
	}
	workers, err := parseInt32("WEBHOOK_WORKERS", 4, 1, 64)
	if err != nil {
		return WebhookConfig{}, err
	}
	batch, err := parseInt32("WEBHOOK_BATCH_SIZE", 50, 1, 500)
	if err != nil {
		return WebhookConfig{}, err
	}
	lease, err := parsePositiveDuration("WEBHOOK_LEASE_DURATION", "1m")
	if err != nil {
		return WebhookConfig{}, err
	}
	timeout, err := parsePositiveDuration("WEBHOOK_DELIVERY_TIMEOUT", "10s")
	if err != nil {
		return WebhookConfig{}, err
	}
	maxAttempts, err := parseInt32("WEBHOOK_MAX_ATTEMPTS", 12, 1, 100)
	if err != nil {
		return WebhookConfig{}, err
	}
	maxAge, err := parsePositiveDuration("WEBHOOK_MAX_RETRY_AGE", "48h")
	if err != nil {
		return WebhookConfig{}, err
	}
	return WebhookConfig{
		Enabled:             true,
		SigningKeyFile:      signingFile,
		CredentialKeysFile:  credentialFile,
		WorkerCount:         int(workers),
		BatchSize:           int(batch),
		LeaseDuration:       lease,
		DeliveryTimeout:     timeout,
		MaxAttempts:         int(maxAttempts),
		MaxRetryAge:         maxAge,
		AllowPrivateTargets: environment == "development" || environment == "test",
	}, nil
}
