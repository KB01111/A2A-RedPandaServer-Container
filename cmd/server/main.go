package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	appserver "github.com/KB01111/A2A-RedPandaServer-Container/internal/server"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if cfg.Environment != "development" && cfg.Environment != "test" {
		return fmt.Errorf("redpanda dispatcher is not configured for %s", cfg.Environment)
	}

	shutdownSignals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dependencies := appserver.Dependencies{
		Dispatcher: orchestrator.LoopbackDispatcher{},
		Logger:     logger,
	}
	if cfg.OIDC.Enabled() {
		verifier, err := auth.NewOIDCVerifier(shutdownSignals, cfg.OIDC)
		if err != nil {
			return fmt.Errorf("initialize OIDC verifier: %w", err)
		}
		dependencies.Authentication, err = auth.NewAuthenticator(verifier, cfg.OIDC.Issuer, cfg.OIDC.RequiredScopes)
		if err != nil {
			return fmt.Errorf("initialize authentication: %w", err)
		}
	}

	if cfg.Database.URL != "" {
		if dependencies.Authentication == nil {
			return fmt.Errorf("DATABASE_URL requires OIDC authentication")
		}
		pool, err := postgres.OpenPool(shutdownSignals, postgres.PoolConfig{
			DatabaseURL:       cfg.Database.URL,
			PasswordFile:      cfg.Database.PasswordFile,
			ApplicationName:   "bridge-a2a-server",
			MaxConns:          cfg.Database.MaxConnections,
			MinConns:          cfg.Database.MinConnections,
			MaxConnLifetime:   cfg.Database.MaxConnectionLife,
			MaxConnIdleTime:   cfg.Database.MaxConnectionIdle,
			HealthCheckPeriod: cfg.Database.HealthCheckPeriod,
		})
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := postgres.VerifySchema(shutdownSignals, pool); err != nil {
			return fmt.Errorf("verify database schema: %w", err)
		}
		dependencies.TaskStore, err = postgres.NewStore(pool)
		if err != nil {
			return err
		}
	}

	handler, err := appserver.New(cfg, dependencies)
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.Address(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.HTTPReadTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		<-shutdownSignals.Done()
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown", "error", err)
		}
	}()

	logger.Info("starting A2A server", "address", server.Addr, "environment", cfg.Environment)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}
