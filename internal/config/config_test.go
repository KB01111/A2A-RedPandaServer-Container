package config

import "testing"

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
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
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
