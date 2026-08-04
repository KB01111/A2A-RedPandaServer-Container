package postgres

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePoolConfigInjectsPasswordFileAndOverrides(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "database-password")
	if err := os.WriteFile(passwordPath, []byte(" secret with spaces \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parsePoolConfig(PoolConfig{
		DatabaseURL:       "postgresql://bridge@db.example.test:5432/bridge",
		PasswordFile:      passwordPath,
		ApplicationName:   "bridge-test",
		MaxConns:          12,
		MinConns:          2,
		MaxConnLifetime:   2 * time.Hour,
		MaxConnIdleTime:   15 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("parsePoolConfig() error = %v", err)
	}
	if got.ConnConfig.Password != " secret with spaces " {
		t.Fatalf("password = %q", got.ConnConfig.Password)
	}
	if got.ConnConfig.RuntimeParams["application_name"] != "bridge-test" {
		t.Fatalf("application_name = %q", got.ConnConfig.RuntimeParams["application_name"])
	}
	if got.MaxConns != 12 || got.MinConns != 2 {
		t.Fatalf("pool limits = %d/%d", got.MinConns, got.MaxConns)
	}
	if got.MaxConnLifetime != 2*time.Hour || got.MaxConnIdleTime != 15*time.Minute || got.HealthCheckPeriod != 30*time.Second {
		t.Fatal("pool durations were not applied")
	}
}

func TestParsePoolConfigValidation(t *testing.T) {
	if _, err := parsePoolConfig(PoolConfig{}); err == nil {
		t.Fatal("empty database URL succeeded")
	}
	if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://localhost/db", MinConns: 2, MaxConns: 1}); err == nil {
		t.Fatal("invalid pool limits succeeded")
	}
	if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://bridge:secret@localhost/db"}); err == nil {
		t.Fatal("password embedded in database URL succeeded")
	}

	emptyPassword := filepath.Join(t.TempDir(), "empty-password")
	if err := os.WriteFile(emptyPassword, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://localhost/db", PasswordFile: emptyPassword}); err == nil {
		t.Fatal("empty password file succeeded")
	}
}

func TestParsePoolConfigRejectsImplicitCredentialEnvironment(t *testing.T) {
	for _, key := range []string{"PGPASSWORD", "PGPASSFILE", "PGSSLPASSWORD", "PGSERVICE", "PGSERVICEFILE"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "secret")
			if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://bridge@localhost/db"}); err == nil {
				t.Fatal("parsePoolConfig() error = nil, want implicit credential rejection")
			}
		})
	}
	t.Run("whitespace PGSSLPASSWORD", func(t *testing.T) {
		t.Setenv("PGSSLPASSWORD", " ")
		if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://bridge@localhost/db"}); err == nil {
			t.Fatal("parsePoolConfig() error = nil, want whitespace credential rejection")
		}
	})
}

func TestParsePoolConfigRejectsImplicitCredentialURLParameters(t *testing.T) {
	for _, parameter := range []string{"password=secret", "sslpassword=secret", "passfile=/run/secrets/pgpass", "service=secret", "servicefile=/run/secrets/service"} {
		t.Run(parameter, func(t *testing.T) {
			if _, err := parsePoolConfig(PoolConfig{DatabaseURL: "postgresql://bridge@localhost/db?" + parameter}); err == nil {
				t.Fatal("parsePoolConfig() error = nil, want implicit credential rejection")
			}
		})
	}
}
