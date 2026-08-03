package orchestrator

import (
	"context"
	"errors"
	"iter"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type DispatchRequest struct {
	TaskID    a2a.TaskID
	ContextID string
	Message   *a2a.Message
	Metadata  map[string]any
	User      *a2asrv.User
}

type Output struct {
	Parts []*a2a.Part
}

type Dispatcher interface {
	Dispatch(context.Context, DispatchRequest) iter.Seq2[Output, error]
	Cancel(context.Context, a2a.TaskID) error
}

type Executor struct {
	dispatcher Dispatcher
}

func NewExecutor(dispatcher Dispatcher) (*Executor, error) {
	if dispatcher == nil {
		return nil, errors.New("dispatcher is required")
	}
	return &Executor{dispatcher: dispatcher}, nil
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

		dispatchRequest := DispatchRequest{
			TaskID:    execCtx.TaskID,
			ContextID: execCtx.ContextID,
			Message:   execCtx.Message,
			Metadata:  execCtx.Metadata,
			User:      execCtx.User,
		}
		for output, err := range e.dispatcher.Dispatch(ctx, dispatchRequest) {
			if err != nil {
				yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateFailed, agentErrorMessage(err)), nil)
				return
			}
			if len(output.Parts) > 0 && !yield(a2a.NewArtifactEvent(execCtx, output.Parts...), nil) {
				return
			}
		}

		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCompleted, nil), nil)
	}
}

func (e *Executor) Cancel(ctx context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if err := e.dispatcher.Cancel(ctx, execCtx.TaskID); err != nil {
			yield(nil, err)
			return
		}
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCanceled, nil), nil)
	}
}

func agentErrorMessage(err error) *a2a.Message {
	return a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("execution failed: "+err.Error()))
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
		yield(Output{Parts: []*a2a.Part{a2a.NewTextPart(message)}}, nil)
	}
}

func (LoopbackDispatcher) Cancel(context.Context, a2a.TaskID) error { return nil }
