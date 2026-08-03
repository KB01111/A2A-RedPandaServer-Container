package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
)

type Dependencies struct {
	Dispatcher orchestrator.Dispatcher
	TaskStore  taskstore.Store
	Logger     *slog.Logger
}

func New(cfg config.Config, dependencies Dependencies) (http.Handler, error) {
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = 15 * time.Second
	}
	if cfg.AgentInactivity <= 0 {
		cfg.AgentInactivity = 5 * time.Minute
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 1 << 20
	}
	card, err := loadAgentCard(cfg.AgentCardPath, cfg.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	executor, err := orchestrator.NewExecutor(dependencies.Dispatcher, dependencies.Logger)
	if err != nil {
		return nil, err
	}
	if dependencies.TaskStore == nil {
		if cfg.Environment != "development" && cfg.Environment != "test" {
			return nil, fmt.Errorf("task store is required in %s", cfg.Environment)
		}
		dependencies.TaskStore = taskstore.NewInMemory(&taskstore.InMemoryStoreConfig{
			Authenticator: func(context.Context) (string, error) { return "anonymous", nil },
		})
	}
	requestHandler := a2asrv.NewHandler(
		executor,
		a2asrv.WithTaskStore(dependencies.TaskStore),
		a2asrv.WithCapabilityChecks(&card.Capabilities),
		a2asrv.WithCallInterceptors(protocolVersionInterceptor{}),
		a2asrv.WithAgentInactivityTimeout(cfg.AgentInactivity),
		a2asrv.WithExecutionPanicHandler(func(recovered any) error {
			dependencies.Logger.Error("agent execution panic", "panic", recovered)
			return a2a.ErrInternalError
		}),
		a2asrv.WithLogger(dependencies.Logger),
	)

	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("/", a2asrv.NewRESTHandler(
		requestHandler,
		a2asrv.WithTransportKeepAlive(cfg.KeepAlive),
		a2asrv.WithTransportPanicHandler(func(recovered any) error {
			dependencies.Logger.Error("transport panic", "panic", recovered)
			return a2a.ErrInternalError
		}),
	))
	return limitRequestBody(cfg.MaxRequestBytes, normalizeServiceParameters(mux)), nil
}
