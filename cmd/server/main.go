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

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	appserver "github.com/KB01111/A2A-RedPandaServer-Container/internal/server"
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
	shutdownSignals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runContext, cancel := context.WithCancel(shutdownSignals)
	defer cancel()
	runtime, err := buildApplicationRuntime(runContext, cfg, logger)
	if err != nil {
		return err
	}
	defer runtime.close()
	workerErrors := runtime.start(runContext)
	runtimeFailure := make(chan error, 1)
	if len(runtime.workers) > 0 {
		go func() {
			if workerErr := <-workerErrors; workerErr != nil {
				logger.Error("background worker failed", "error", workerErr)
				runtimeFailure <- workerErr
				cancel()
			}
		}()
	}

	handler, err := appserver.New(cfg, runtime.dependencies)
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
		<-runContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown", "error", err)
		}
	}()

	logger.Info("starting A2A server", "address", server.Addr, "environment", cfg.Environment)
	serveErr := server.ListenAndServe()
	cancel()
	runtime.wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", serveErr)
	}
	select {
	case workerErr := <-runtimeFailure:
		return fmt.Errorf("background worker failed: %w", workerErr)
	default:
	}
	return nil
}
