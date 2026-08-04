package orchestrator

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"strings"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type DispatchRequest struct {
	TaskID         a2a.TaskID
	ContextID      string
	Tenant         string
	Message        *a2a.Message
	Metadata       map[string]any
	User           *a2asrv.User
	Extensions     []string
	RelatedTaskIDs []a2a.TaskID
}

type CancelRequest struct {
	TaskID     a2a.TaskID
	Tenant     string
	User       *a2asrv.User
	Extensions []string
}

type Output struct {
	ArtifactID a2a.ArtifactID
	Parts      []*a2a.Part
	LastChunk  bool
	Heartbeat  bool
}

var ErrExecutionCanceled = errors.New("remote execution canceled")

type Dispatcher interface {
	Dispatch(context.Context, DispatchRequest) iter.Seq2[Output, error]
	Cancel(context.Context, CancelRequest) error
}

type Executor struct {
	dispatcher       Dispatcher
	logger           *slog.Logger
	artifactPipeline *ArtifactPipeline
}

type ArtifactRecorder interface {
	SaveReadyObject(context.Context, artifact.ObjectRecord) error
}

// ArtifactPipeline externalizes large raw artifact parts and persists their
// metadata before the URL-bearing event reaches the task store.
type ArtifactPipeline struct {
	Externalizer *artifact.Externalizer
	Recorder     ArtifactRecorder
}

func NewExecutor(dispatcher Dispatcher, loggers ...*slog.Logger) (*Executor, error) {
	return newExecutor(dispatcher, nil, loggers...)
}

func NewExecutorWithArtifacts(dispatcher Dispatcher, pipeline ArtifactPipeline, loggers ...*slog.Logger) (*Executor, error) {
	if pipeline.Externalizer == nil || pipeline.Recorder == nil {
		return nil, errors.New("artifact externalizer and recorder are required")
	}
	return newExecutor(dispatcher, &pipeline, loggers...)
}

func newExecutor(dispatcher Dispatcher, pipeline *ArtifactPipeline, loggers ...*slog.Logger) (*Executor, error) {
	if dispatcher == nil {
		return nil, errors.New("dispatcher is required")
	}
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &Executor{dispatcher: dispatcher, logger: logger, artifactPipeline: pipeline}, nil
}

func (e *Executor) Execute(ctx context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if execCtx.Message == nil {
			yield(nil, errors.New("message is required"))
			return
		}
		if execCtx.StoredTask == nil && !yield(a2a.NewSubmittedTask(execCtx, execCtx.Message), nil) {
			return
		}
		if !yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateWorking, nil), nil) {
			return
		}
		var artifactSession *artifact.Session
		if e.artifactPipeline != nil {
			owner, err := executorOwner(execCtx)
			if err != nil {
				e.logger.Error("artifact owner is unavailable", "task_id", execCtx.TaskID, "error", err)
				yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed, agentErrorMessage()), nil)
				return
			}
			var existing []*a2a.Artifact
			if execCtx.StoredTask != nil {
				existing = execCtx.StoredTask.Artifacts
			}
			artifactSession, err = e.artifactPipeline.Externalizer.NewSession(owner, execCtx.TaskID, existing)
			if err != nil {
				e.logger.Error("initialize artifact session", "task_id", execCtx.TaskID, "error", err)
				yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed, agentErrorMessage()), nil)
				return
			}
		}

		dispatchRequest := DispatchRequest{
			TaskID:         execCtx.TaskID,
			ContextID:      execCtx.ContextID,
			Tenant:         executorTenant(execCtx),
			Message:        execCtx.Message,
			Metadata:       execCtx.Metadata,
			User:           execCtx.User,
			Extensions:     serviceExtensions(execCtx.ServiceParams),
			RelatedTaskIDs: relatedTaskIDs(execCtx.RelatedTasks),
		}
		artifacts := make(map[a2a.ArtifactID]a2a.ArtifactID)
		for output, err := range e.dispatcher.Dispatch(ctx, dispatchRequest) {
			if err != nil {
				e.logger.Error("dispatcher execution failed", "task_id", execCtx.TaskID, "error", err)
				state := a2a.TaskStateFailed
				message := agentErrorMessage()
				if errors.Is(err, ErrExecutionCanceled) {
					state = a2a.TaskStateCanceled
					message = nil
				}
				yield(a2a.NewStatusUpdateEvent(execCtx, state, message), nil)
				return
			}
			if output.Heartbeat {
				if !yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateWorking, nil), nil) {
					return
				}
				continue
			}
			if len(output.Parts) > 0 {
				artifactKey := output.ArtifactID
				artifactID, exists := artifacts[artifactKey]
				var event *a2a.TaskArtifactUpdateEvent
				if !exists {
					event = a2a.NewArtifactEvent(execCtx, output.Parts...)
					if output.ArtifactID != "" {
						event.Artifact.ID = output.ArtifactID
					}
					artifactID = event.Artifact.ID
					artifacts[artifactKey] = artifactID
				} else {
					event = a2a.NewArtifactUpdateEvent(execCtx, artifactID, output.Parts...)
				}
				event.LastChunk = output.LastChunk
				if artifactSession != nil {
					externalized, err := artifactSession.ExternalizeEvent(ctx, event)
					for _, record := range externalized.Objects {
						if persistErr := e.artifactPipeline.Recorder.SaveReadyObject(ctx, record); persistErr != nil {
							e.logger.Error("persist artifact object metadata", "task_id", execCtx.TaskID, "object_id", record.ObjectID, "error", persistErr)
							yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed, agentErrorMessage()), nil)
							return
						}
					}
					if err != nil {
						e.logger.Error("externalize artifact", "task_id", execCtx.TaskID, "error", err)
						yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed, agentErrorMessage()), nil)
						return
					}
					event = externalized.Event
				}
				if !yield(event, nil) {
					return
				}
			}
		}

		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCompleted, nil), nil)
	}
}

func (e *Executor) Cancel(ctx context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		request := CancelRequest{
			TaskID:     execCtx.TaskID,
			Tenant:     executorTenant(execCtx),
			User:       execCtx.User,
			Extensions: serviceExtensions(execCtx.ServiceParams),
		}
		if err := e.dispatcher.Cancel(ctx, request); err != nil {
			e.logger.Error("dispatcher cancellation failed", "task_id", execCtx.TaskID, "error", err)
			yield(nil, a2a.ErrInternalError)
			return
		}
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCanceled, nil), nil)
	}
}

func executorTenant(execCtx *a2asrv.ExecutorContext) string {
	if execCtx.Tenant != "" {
		return execCtx.Tenant
	}
	if execCtx.User != nil {
		if tenant, ok := execCtx.User.Attributes["tenant"].(string); ok {
			return tenant
		}
	}
	return ""
}

func executorOwner(execCtx *a2asrv.ExecutorContext) (artifact.Owner, error) {
	if execCtx == nil || execCtx.User == nil {
		return artifact.Owner{}, errors.New("authenticated executor user is required")
	}
	issuer, issuerOK := execCtx.User.Attributes["issuer"].(string)
	subject, subjectOK := execCtx.User.Attributes["subject"].(string)
	tenant := executorTenant(execCtx)
	if !issuerOK || !subjectOK || issuer == "" || tenant == "" || subject == "" {
		return artifact.Owner{}, errors.New("authenticated issuer, tenant, and subject are required")
	}
	return artifact.Owner{Issuer: issuer, Tenant: tenant, Subject: subject}, nil
}

func serviceExtensions(params *a2asrv.ServiceParams) []string {
	if params == nil {
		return nil
	}
	values, ok := params.Get(a2a.SvcParamExtensions)
	if !ok {
		return nil
	}
	return append([]string(nil), values...)
}

func relatedTaskIDs(tasks []*a2a.Task) []a2a.TaskID {
	result := make([]a2a.TaskID, 0, len(tasks))
	for _, task := range tasks {
		if task != nil {
			result = append(result, task.ID)
		}
	}
	return result
}

func agentErrorMessage() *a2a.Message {
	return a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("execution failed"))
}

// LoopbackDispatcher provides a deterministic local backend for development and
// protocol conformance tests. Production wiring replaces it with Redpanda.
type LoopbackDispatcher struct{}

func (LoopbackDispatcher) Dispatch(_ context.Context, request DispatchRequest) iter.Seq2[Output, error] {
	return func(yield func(Output, error) bool) {
		var text []string
		for _, part := range request.Message.Parts {
			if value := part.Text(); value != "" {
				text = append(text, value)
			}
		}
		message := "Task accepted for orchestration"
		if len(text) > 0 {
			message += ": " + strings.Join(text, " ")
		}
		yield(Output{Parts: []*a2a.Part{a2a.NewTextPart(message)}, LastChunk: true}, nil)
	}
}

func (LoopbackDispatcher) Cancel(context.Context, CancelRequest) error { return nil }
