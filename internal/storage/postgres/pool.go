package postgres

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const maxPasswordFileBytes = 64 * 1024

// PoolConfig configures the PostgreSQL connection pool.
type PoolConfig struct {
	DatabaseURL       string
	PasswordFile      string
	ApplicationName   string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// OpenPool creates a PostgreSQL pool and verifies that it can establish a
// connection before returning it.
func OpenPool(ctx context.Context, cfg PoolConfig) (*pgxpool.Pool, error) {
	poolConfig, err := parsePoolConfig(cfg)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	return pool, nil
}

func parsePoolConfig(cfg PoolConfig) (*pgxpool.Config, error) {
	databaseURL := strings.TrimSpace(cfg.DatabaseURL)
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	if cfg.MaxConns < 0 || cfg.MinConns < 0 {
		return nil, fmt.Errorf("database pool connection limits must not be negative")
	}
	if cfg.MaxConns > 0 && cfg.MinConns > cfg.MaxConns {
		return nil, fmt.Errorf("database pool minimum connections must not exceed maximum connections")
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	if poolConfig.ConnConfig.Password != "" {
		return nil, fmt.Errorf("database URL and process environment must not contain a password; use the database password file")
	}
	if cfg.PasswordFile != "" {
		password, err := readPasswordFile(cfg.PasswordFile)
		if err != nil {
			return nil, err
		}
		poolConfig.ConnConfig.Password = password
	}
	if cfg.ApplicationName != "" {
		poolConfig.ConnConfig.RuntimeParams["application_name"] = cfg.ApplicationName
	}
	if cfg.MaxConns > 0 {
		poolConfig.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		poolConfig.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod
	}
	return poolConfig, nil
}

func readPasswordFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat database password file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("database password file must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("database password file permissions must not grant group or other access")
	}
	if info.Size() > maxPasswordFileBytes {
		return "", fmt.Errorf("database password file exceeds %d bytes", maxPasswordFileBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read database password file: %w", err)
	}
	password := strings.TrimRight(string(contents), "\r\n")
	if password == "" {
		return "", fmt.Errorf("database password file is empty")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return "", fmt.Errorf("database password file contains a NUL byte")
	}
	return password, nil
}
