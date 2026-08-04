package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	logger.Info("database schema is current", "version", postgres.CurrentSchemaVersion())
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	pool, err := postgres.OpenPool(ctx, postgres.PoolConfig{
		DatabaseURL:     databaseURL,
		PasswordFile:    strings.TrimSpace(os.Getenv("DATABASE_PASSWORD_FILE")),
		ApplicationName: "bridge-a2a-migrate",
		MaxConns:        1,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	return postgres.VerifySchema(ctx, pool)
}
