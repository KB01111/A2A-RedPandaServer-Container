package config

import "testing"

func TestLoadLeavesPhaseThreeServicesDisabledByDefault(t *testing.T) {
	setValidEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Redpanda.Enabled() || cfg.S3.Enabled() || cfg.Webhook.Enabled {
		t.Fatalf("services unexpectedly enabled: %#v %#v %#v", cfg.Redpanda, cfg.S3, cfg.Webhook)
	}
}

func TestLoadRedpandaConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("REDPANDA_BROKERS", "127.0.0.1:9092,[::1]:9093")
	t.Setenv("REDPANDA_SECURITY_PROTOCOL", "PLAINTEXT")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Redpanda.Brokers) != 2 || cfg.Redpanda.CommandTopic() != "bridge-a2a.agent-commands.v1" || cfg.Redpanda.MaxMessageBytes != 8<<20 {
		t.Fatalf("Redpanda config = %#v", cfg.Redpanda)
	}
}

func TestLoadRejectsUnsafeRedpandaConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T)
	}{
		{name: "partial", setup: func(t *testing.T) { t.Setenv("REDPANDA_USERNAME", "bridge") }},
		{name: "URL broker", setup: func(t *testing.T) { t.Setenv("REDPANDA_BROKERS", "kafka://localhost:9092") }},
		{name: "production plaintext", setup: func(t *testing.T) {
			t.Setenv("APP_ENV", "production")
			t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
			t.Setenv("REDPANDA_BROKERS", "broker.example.test:9092")
			t.Setenv("REDPANDA_SECURITY_PROTOCOL", "PLAINTEXT")
		}},
		{name: "production auto topic", setup: func(t *testing.T) {
			t.Setenv("APP_ENV", "production")
			t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
			t.Setenv("REDPANDA_BROKERS", "broker.example.test:9092")
			t.Setenv("REDPANDA_SECURITY_PROTOCOL", "SASL_SSL")
			t.Setenv("REDPANDA_USERNAME", "bridge")
			t.Setenv("REDPANDA_PASSWORD_FILE", "/run/secrets/redpanda_password")
			t.Setenv("REDPANDA_ALLOW_AUTO_TOPIC_CREATION", "true")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidEnvironment(t)
			test.setup(t)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want Redpanda rejection")
			}
		})
	}
}

func TestLoadS3Configuration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("S3_ENDPOINT", "http://127.0.0.1:9000")
	t.Setenv("S3_BUCKET", "bridge-a2a-artifacts")
	t.Setenv("S3_ACCESS_KEY_FILE", "/run/secrets/s3_access_key")
	t.Setenv("S3_SECRET_KEY_FILE", "/run/secrets/s3_secret_key")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.S3.Enabled() || !cfg.S3.UsePathStyle || cfg.S3.ExternalizeAt != 64<<10 || !cfg.S3.AllowPrivateIPs {
		t.Fatalf("S3 config = %#v", cfg.S3)
	}
}

func TestLoadRejectsUnsafeS3Configuration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T)
	}{
		{name: "partial", setup: func(t *testing.T) { t.Setenv("S3_BUCKET", "bridge-a2a-artifacts") }},
		{name: "missing credentials", setup: func(t *testing.T) { t.Setenv("S3_ENDPOINT", "https://storage.example.test") }},
		{name: "production cleartext", setup: func(t *testing.T) {
			t.Setenv("APP_ENV", "production")
			t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
			t.Setenv("S3_ENDPOINT", "http://storage.example.test")
			t.Setenv("S3_BUCKET", "bridge-a2a-artifacts")
			t.Setenv("S3_ACCESS_KEY_FILE", "/run/secrets/access")
			t.Setenv("S3_SECRET_KEY_FILE", "/run/secrets/secret")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidEnvironment(t)
			test.setup(t)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want S3 rejection")
			}
		})
	}
}

func TestLoadWebhookConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("WEBHOOK_ENABLED", "true")
	t.Setenv("WEBHOOK_SIGNING_PRIVATE_KEY_FILE", "/run/secrets/webhook_signing_key")
	t.Setenv("WEBHOOK_CREDENTIAL_KEYS_FILE", "/run/secrets/webhook_credential_keys")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Webhook.Enabled || cfg.Webhook.WorkerCount != 4 || cfg.Webhook.MaxAttempts != 12 || !cfg.Webhook.AllowPrivateTargets {
		t.Fatalf("Webhook config = %#v", cfg.Webhook)
	}
}

func TestLoadRejectsPartialWebhookConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("WEBHOOK_SIGNING_PRIVATE_KEY_FILE", "/run/secrets/webhook_signing_key")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want WEBHOOK_ENABLED requirement")
	}
}
