package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
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
	card, err := loadAgentCard(cfg.AgentCardPath, cfg.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	executor, err := orchestrator.NewExecutor(dependencies.Dispatcher)
	if err != nil {
		return nil, err
	}
	if dependencies.TaskStore == nil {
		dependencies.TaskStore = taskstore.NewInMemory(&taskstore.InMemoryStoreConfig{
			Authenticator: func(context.Context) (string, error) { return "anonymous", nil },
		})
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}

	requestHandler := a2asrv.NewHandler(
		executor,
		a2asrv.WithTaskStore(dependencies.TaskStore),
		a2asrv.WithCapabilityChecks(&card.Capabilities),
		a2asrv.WithCallInterceptors(protocolVersionInterceptor{}),
		a2asrv.WithAgentInactivityTimeout(cfg.AgentInactivity),
		a2asrv.WithExecutionPanicHandler(func(recovered any) error {
			return fmt.Errorf("agent execution panic: %v", recovered)
		}),
		a2asrv.WithLogger(dependencies.Logger),
	)

	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("/", a2asrv.NewRESTHandler(
		requestHandler,
		a2asrv.WithTransportKeepAlive(cfg.KeepAlive),
		a2asrv.WithTransportPanicHandler(func(recovered any) error {
			return fmt.Errorf("transport panic: %v", recovered)
		}),
	))
	return normalizeServiceParameters(mux), nil
}
