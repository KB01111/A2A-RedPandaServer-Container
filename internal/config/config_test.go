package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")

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
			t.Setenv("PORT", "8080")
			t.Setenv("PUBLIC_BASE_URL", "http://localhost:8080")
			t.Setenv("SHUTDOWN_TIMEOUT", "20s")
			t.Setenv(test.key, test.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestLoadRequiresHTTPSInProduction(t *testing.T) {
	t.Setenv("APP_ENV", " production ")
	t.Setenv("PUBLIC_BASE_URL", "http://a2a.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want HTTPS validation error")
	}
}
