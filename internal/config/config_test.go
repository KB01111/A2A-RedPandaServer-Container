package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Address() != ":8080" {
		t.Fatalf("Address() = %q, want %q", got.Address(), ":8080")
	}
	if got.PublicBaseURL != "http://localhost:8080" {
		t.Fatalf("PublicBaseURL = %q", got.PublicBaseURL)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "port", key: "PORT", value: "70000"},
		{name: "environment", key: "APP_ENV", value: "prod"},
		{name: "public URL", key: "PUBLIC_BASE_URL", value: "localhost"},
		{name: "public URL credentials", key: "PUBLIC_BASE_URL", value: "https://user:secret@a2a.example.com"},
		{name: "public URL path", key: "PUBLIC_BASE_URL", value: "https://a2a.example.com/base"},
		{name: "public URL query", key: "PUBLIC_BASE_URL", value: "https://a2a.example.com?tenant=x"},
		{name: "shutdown timeout", key: "SHUTDOWN_TIMEOUT", value: "0s"},
		{name: "read timeout", key: "HTTP_READ_TIMEOUT", value: "0s"},
		{name: "request body limit", key: "MAX_REQUEST_BODY_BYTES", value: "0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(test.key, test.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestLoadRequiresHTTPSInProduction(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("APP_ENV", " production ")
	t.Setenv("PUBLIC_BASE_URL", "http://a2a.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want HTTPS validation error")
	}
}

func TestLoadUsesAbsoluteAgentCardPathInProduction(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.com")
	t.Setenv("AGENT_CARD_PATH", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AgentCardPath != "/app/config/agent-card.json" {
		t.Fatalf("AgentCardPath = %q", cfg.AgentCardPath)
	}
}

var configEnvironmentKeys = []string{
	"APP_ENV",
	"PORT",
	"PUBLIC_BASE_URL",
	"AGENT_CARD_PATH",
	"SHUTDOWN_TIMEOUT",
	"A2A_KEEP_ALIVE_INTERVAL",
	"A2A_AGENT_INACTIVITY_TIMEOUT",
	"HTTP_READ_TIMEOUT",
	"MAX_REQUEST_BODY_BYTES",
	"OIDC_ISSUER",
	"OIDC_AUDIENCE",
	"OIDC_TENANT_CLAIM",
	"OIDC_REQUIRED_SCOPES",
	"OIDC_ALLOWED_ALGORITHMS",
	"OIDC_CLOCK_SKEW",
	"OIDC_HTTP_TIMEOUT",
	"DATABASE_URL",
	"DATABASE_PASSWORD_FILE",
	"DATABASE_MAX_CONNECTIONS",
	"DATABASE_MIN_CONNECTIONS",
	"DATABASE_MAX_CONNECTION_LIFETIME",
	"DATABASE_MAX_CONNECTION_IDLE",
	"DATABASE_HEALTH_CHECK_PERIOD",
	"REDPANDA_BROKERS",
	"REDPANDA_SECURITY_PROTOCOL",
	"REDPANDA_SASL_MECHANISM",
	"REDPANDA_USERNAME",
	"REDPANDA_PASSWORD_FILE",
	"REDPANDA_CA_FILE",
	"REDPANDA_CLIENT_CERT_FILE",
	"REDPANDA_CLIENT_KEY_FILE",
	"REDPANDA_TOPIC_PREFIX",
	"REDPANDA_CONSUMER_GROUP",
	"REDPANDA_CLIENT_ID",
	"REDPANDA_PRODUCE_TIMEOUT",
	"REDPANDA_RESULT_IDLE_TIMEOUT",
	"REDPANDA_MAX_MESSAGE_BYTES",
	"REDPANDA_ALLOW_AUTO_TOPIC_CREATION",
	"S3_ENDPOINT",
	"S3_PUBLIC_ENDPOINT",
	"S3_REGION",
	"S3_BUCKET",
	"S3_ACCESS_KEY_FILE",
	"S3_SECRET_KEY_FILE",
	"S3_USE_PATH_STYLE",
	"S3_EXTERNALIZE_AT_BYTES",
	"S3_MAX_OBJECT_BYTES",
	"S3_PRESIGN_TTL",
	"WEBHOOK_ENABLED",
	"WEBHOOK_SIGNING_PRIVATE_KEY_FILE",
	"WEBHOOK_CREDENTIAL_KEYS_FILE",
	"WEBHOOK_WORKERS",
	"WEBHOOK_BATCH_SIZE",
	"WEBHOOK_LEASE_DURATION",
	"WEBHOOK_DELIVERY_TIMEOUT",
	"WEBHOOK_MAX_ATTEMPTS",
	"WEBHOOK_MAX_RETRY_AGE",
}

func TestLoadOIDCConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("OIDC_ISSUER", "http://localhost:5556/")
	t.Setenv("OIDC_AUDIENCE", "bridge-a2a")
	t.Setenv("OIDC_ALLOWED_ALGORITHMS", "RS256, ES256")
	t.Setenv("OIDC_REQUIRED_SCOPES", "a2a, tasks.read")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OIDC.Enabled() || cfg.OIDC.Issuer != "http://localhost:5556/" || len(cfg.OIDC.AllowedAlgorithms) != 2 || len(cfg.OIDC.RequiredScopes) != 2 || !cfg.OIDC.AllowPrivateIPs {
		t.Fatalf("OIDC config = %#v", cfg.OIDC)
	}
}

func TestLoadDisallowsPrivateOIDCAddressesOutsideDevelopment(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
	t.Setenv("OIDC_ISSUER", "https://issuer.example.test")
	t.Setenv("OIDC_AUDIENCE", "bridge-a2a")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OIDC.AllowPrivateIPs {
		t.Fatal("production OIDC configuration allows private IP destinations")
	}
}

func TestLoadRejectsUnsafeOIDCConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "missing audience", key: "OIDC_AUDIENCE", value: ""},
		{name: "symmetric algorithm", key: "OIDC_ALLOWED_ALGORITHMS", value: "HS256"},
		{name: "excessive skew", key: "OIDC_CLOCK_SKEW", value: "10m"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv("OIDC_ISSUER", "http://localhost:5556")
			t.Setenv("OIDC_AUDIENCE", "bridge-a2a")
			t.Setenv(test.key, test.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want OIDC validation error")
			}
		})
	}
}

func TestLoadRejectsNonLoopbackHTTPOIDCIssuer(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("OIDC_ISSUER", "http://issuer.example.test")
	t.Setenv("OIDC_AUDIENCE", "bridge-a2a")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want HTTPS requirement")
	}
}

func TestLoadRejectsLoopbackHTTPOIDCIssuerOutsideDevelopment(t *testing.T) {
	for _, environment := range []string{"staging", "production"} {
		t.Run(environment, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv("APP_ENV", environment)
			t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
			t.Setenv("OIDC_ISSUER", "http://localhost:5556")
			t.Setenv("OIDC_AUDIENCE", "bridge-a2a")
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want HTTPS requirement")
			}
		})
	}
}

func TestLoadRejectsOIDCPolicyWithoutProvider(t *testing.T) {
	for _, key := range []string{
		"OIDC_TENANT_CLAIM",
		"OIDC_REQUIRED_SCOPES",
		"OIDC_ALLOWED_ALGORITHMS",
		"OIDC_CLOCK_SKEW",
		"OIDC_HTTP_TIMEOUT",
	} {
		t.Run(key, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(key, "configured")
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want incomplete OIDC configuration error")
			}
		})
	}
}

func TestLoadDatabaseConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DATABASE_URL", "postgresql://bridge_a2a@db.internal:5432/bridge_a2a?sslmode=verify-full")
	t.Setenv("DATABASE_PASSWORD_FILE", "/run/secrets/database_password")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Database.MaxConnections != 20 || cfg.Database.MinConnections != 2 || cfg.Database.PasswordFile != "/run/secrets/database_password" {
		t.Fatalf("database config = %#v", cfg.Database)
	}
}

func TestLoadRequiresDatabasePasswordFileOutsideDevelopment(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("APP_ENV", "staging")
	t.Setenv("PUBLIC_BASE_URL", "https://a2a.example.test")
	t.Setenv("DATABASE_URL", "postgresql://bridge@db.internal/bridge?sslmode=verify-full")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DATABASE_PASSWORD_FILE") {
		t.Fatalf("Load() error = %v, want password file requirement", err)
	}
}

func TestLoadRejectsDatabasePasswordInURL(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DATABASE_URL", "postgresql://bridge:secret@db.internal/bridge")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want password-in-URL validation error")
	}
}

func TestLoadRejectsDatabaseCredentialQueryParameters(t *testing.T) {
	for _, parameter := range []string{"password=secret", "sslpassword=secret", "passfile=/run/secrets/pgpass", "service=secret-service", "servicefile=/run/secrets/pg_service.conf"} {
		t.Run(parameter, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv("DATABASE_URL", "postgresql://bridge@db.internal/bridge?"+parameter)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want implicit credential source rejection")
			}
		})
	}
}

func TestLoadRejectsInvalidDatabasePasswordFileConfiguration(t *testing.T) {
	t.Run("without database URL", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("DATABASE_PASSWORD_FILE", "/run/secrets/database_password")
		if _, err := Load(); err == nil {
			t.Fatal("Load() error = nil, want DATABASE_URL requirement")
		}
	})

	t.Run("relative path", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("DATABASE_URL", "postgresql://bridge@db.internal/bridge")
		t.Setenv("DATABASE_PASSWORD_FILE", "relative/password")
		if _, err := Load(); err == nil {
			t.Fatal("Load() error = nil, want absolute path requirement")
		}
	})
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}
	values := map[string]string{
		"APP_ENV":                      "test",
		"PORT":                         "8080",
		"PUBLIC_BASE_URL":              "http://localhost:8080",
		"AGENT_CARD_PATH":              "config/agent-card.json",
		"SHUTDOWN_TIMEOUT":             "20s",
		"A2A_KEEP_ALIVE_INTERVAL":      "15s",
		"A2A_AGENT_INACTIVITY_TIMEOUT": "5m",
		"HTTP_READ_TIMEOUT":            "30s",
		"MAX_REQUEST_BODY_BYTES":       "1048576",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}
