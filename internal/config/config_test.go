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
		{name: "public URL", key: "PUBLIC_BASE_URL", value: "localhost"},
		{name: "shutdown timeout", key: "SHUTDOWN_TIMEOUT", value: "0s"},
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
	t.Setenv("APP_ENV", "production")
	t.Setenv("PUBLIC_BASE_URL", "http://a2a.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want HTTPS validation error")
	}
}
