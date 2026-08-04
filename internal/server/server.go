package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/a2aproject/a2a-go/v2/a2asrv/push"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
)

type Dependencies struct {
	Dispatcher       orchestrator.Dispatcher
	TaskStore        taskstore.Store
	Logger           *slog.Logger
	Authentication   *auth.Authenticator
	PushConfigStore  push.ConfigStore
	PushSender       push.Sender
	ArtifactPipeline *orchestrator.ArtifactPipeline
	ArtifactResolver artifact.DownloadResolver
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
	var executor *orchestrator.Executor
	if dependencies.ArtifactPipeline != nil {
		executor, err = orchestrator.NewExecutorWithArtifacts(dependencies.Dispatcher, *dependencies.ArtifactPipeline, dependencies.Logger)
	} else {
		executor, err = orchestrator.NewExecutor(dependencies.Dispatcher, dependencies.Logger)
	}
	if err != nil {
		return nil, err
	}
	if dependencies.TaskStore == nil {
		if cfg.Environment != "development" && cfg.Environment != "test" {
			return nil, fmt.Errorf("task store is required in %s", cfg.Environment)
		}
		authenticator := taskstore.Authenticator(func(context.Context) (string, error) { return "anonymous", nil })
		if dependencies.Authentication != nil {
			authenticator = a2asrv.NewTaskStoreAuthenticator()
		}
		dependencies.TaskStore = taskstore.NewInMemory(&taskstore.InMemoryStoreConfig{Authenticator: authenticator})
	}
	if dependencies.Authentication == nil && cfg.Environment != "development" && cfg.Environment != "test" {
		return nil, fmt.Errorf("authentication is required in %s", cfg.Environment)
	}
	if dependencies.Authentication != nil {
		dependencies.Authentication.ConfigureAgentCard(card)
	}
	pushConfigured := dependencies.PushConfigStore != nil || dependencies.PushSender != nil
	if pushConfigured && (dependencies.PushConfigStore == nil || dependencies.PushSender == nil) {
		return nil, fmt.Errorf("push configuration store and sender must be configured together")
	}
	if pushConfigured {
		card.Capabilities.PushNotifications = true
	}
	interceptors := []a2asrv.CallInterceptor{protocolVersionInterceptor{}}
	if dependencies.Authentication != nil {
		interceptors = append(interceptors, dependencies.Authentication.CallInterceptor())
	}
	interceptors = append(interceptors, errorBoundaryInterceptor{logger: dependencies.Logger})
	requestOptions := []a2asrv.RequestHandlerOption{
		a2asrv.WithTaskStore(dependencies.TaskStore),
		a2asrv.WithCapabilityChecks(&card.Capabilities),
		a2asrv.WithCallInterceptors(interceptors...),
		a2asrv.WithAgentInactivityTimeout(cfg.AgentInactivity),
		a2asrv.WithExecutionPanicHandler(func(recovered any) error {
			dependencies.Logger.Error("agent execution panic", "panic", recovered)
			return a2a.ErrInternalError
		}),
		a2asrv.WithLogger(dependencies.Logger),
	}
	if pushConfigured {
		requestOptions = append(requestOptions, a2asrv.WithPushNotifications(dependencies.PushConfigStore, dependencies.PushSender))
	}
	requestHandler := a2asrv.NewHandler(executor, requestOptions...)

	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	if dependencies.ArtifactResolver != nil {
		if dependencies.Authentication == nil {
			return nil, fmt.Errorf("artifact resolver requires authentication")
		}
		mux.Handle("GET /artifacts/{objectID}", dependencies.Authentication.Middleware(
			newArtifactDownloadHandler(dependencies.ArtifactResolver, dependencies.Logger),
		))
	}
	restHandler := a2asrv.NewRESTHandler(
		requestHandler,
		a2asrv.WithTransportKeepAlive(cfg.KeepAlive),
		a2asrv.WithTransportPanicHandler(func(recovered any) error {
			dependencies.Logger.Error("transport panic", "panic", recovered)
			return a2a.ErrInternalError
		}),
	)
	var protectedHandler http.Handler = normalizeServiceParameters(restHandler)
	protectedHandler = limitRequestBody(cfg.MaxRequestBytes, protectedHandler)
	if dependencies.Authentication != nil {
		protectedHandler = dependencies.Authentication.Middleware(protectedHandler)
	}
	mux.Handle("/", protectedHandler)
	return mux, nil
}
