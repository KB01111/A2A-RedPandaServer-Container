package orchestrator

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

func TestExecutorLifecycle(t *testing.T) {
	executor, err := NewExecutor(LoopbackDispatcher{})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	message := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))
	execCtx := &a2asrv.ExecutorContext{
		Message:   message,
		TaskID:    "task-1",
		ContextID: "context-1",
	}

	var events []a2a.Event
	for event, executeErr := range executor.Execute(t.Context(), execCtx) {
		if executeErr != nil {
			t.Fatalf("Execute() error = %v", executeErr)
		}
		events = append(events, event)
	}
	if len(events) != 4 {
		t.Fatalf("Execute() emitted %d events, want 4", len(events))
	}
	status, ok := events[len(events)-1].(*a2a.TaskStatusUpdateEvent)
	if !ok || status.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("last event = %#v, want completed status", events[len(events)-1])
	}
}

func TestExecutorStreamsChunksForOneArtifact(t *testing.T) {
	executor, err := NewExecutor(chunkDispatcher{})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	execCtx := &a2asrv.ExecutorContext{
		Message:   a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
		TaskID:    "task-1",
		ContextID: "context-1",
	}

	var updates []*a2a.TaskArtifactUpdateEvent
	for event, executeErr := range executor.Execute(t.Context(), execCtx) {
		if executeErr != nil {
			t.Fatalf("Execute() error = %v", executeErr)
		}
		if update, ok := event.(*a2a.TaskArtifactUpdateEvent); ok {
			updates = append(updates, update)
		}
	}
	if len(updates) != 2 {
		t.Fatalf("artifact updates = %d, want 2", len(updates))
	}
	if updates[0].Artifact.ID != "answer" || updates[1].Artifact.ID != "answer" {
		t.Fatalf("artifact IDs = %q, %q", updates[0].Artifact.ID, updates[1].Artifact.ID)
	}
	if updates[0].Append || updates[0].LastChunk {
		t.Fatalf("first chunk flags = append:%v last:%v", updates[0].Append, updates[0].LastChunk)
	}
	if !updates[1].Append || !updates[1].LastChunk {
		t.Fatalf("final chunk flags = append:%v last:%v", updates[1].Append, updates[1].LastChunk)
	}
}

func TestNewExecutorRequiresDispatcher(t *testing.T) {
	if _, err := NewExecutor(nil); err == nil {
		t.Fatal("NewExecutor(nil) error = nil")
	}
}

func TestExecutorRejectsNilMessageBeforeDispatch(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	executor, err := NewExecutor(dispatcher)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}

	var gotErr error
	for _, executeErr := range executor.Execute(t.Context(), &a2asrv.ExecutorContext{TaskID: "task-1"}) {
		gotErr = executeErr
	}
	if gotErr == nil || gotErr.Error() != "message is required" {
		t.Fatalf("Execute() error = %v, want message validation error", gotErr)
	}
	if dispatcher.dispatched {
		t.Fatal("dispatcher was called for a nil message")
	}
}

func TestExecutorTurnsDispatcherErrorIntoFailedStatus(t *testing.T) {
	dispatchErr := errors.New("worker unavailable")
	executor, err := NewExecutor(&recordingDispatcher{dispatchErr: dispatchErr})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	execCtx := &a2asrv.ExecutorContext{
		Message:   a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
		TaskID:    "task-1",
		ContextID: "context-1",
	}

	var last a2a.Event
	for event, executeErr := range executor.Execute(t.Context(), execCtx) {
		if executeErr != nil {
			t.Fatalf("Execute() transport error = %v", executeErr)
		}
		last = event
	}
	status, ok := last.(*a2a.TaskStatusUpdateEvent)
	if !ok || status.Status.State != a2a.TaskStateFailed {
		t.Fatalf("last event = %#v, want failed status", last)
	}
	if status.Status.Message == nil || len(status.Status.Message.Parts) == 0 || status.Status.Message.Parts[0].Text() != "execution failed" {
		t.Fatalf("failure message = %#v", status.Status.Message)
	}
}

func TestExecutorCancel(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	executor, err := NewExecutor(dispatcher)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	user := a2asrv.NewAuthenticatedUser("alice", nil)
	execCtx := &a2asrv.ExecutorContext{
		TaskID: "task-1", ContextID: "context-1", Tenant: "tenant-1", User: user,
		ServiceParams: a2asrv.NewServiceParams(map[string][]string{
			a2a.SvcParamExtensions: {"https://extension.example"},
		}),
	}

	var last a2a.Event
	for event, cancelErr := range executor.Cancel(t.Context(), execCtx) {
		if cancelErr != nil {
			t.Fatalf("Cancel() error = %v", cancelErr)
		}
		last = event
	}
	status, ok := last.(*a2a.TaskStatusUpdateEvent)
	if !ok || status.Status.State != a2a.TaskStateCanceled {
		t.Fatalf("last event = %#v, want canceled status", last)
	}
	if !dispatcher.canceled || dispatcher.cancelRequest.TaskID != "task-1" || dispatcher.cancelRequest.Tenant != "tenant-1" || dispatcher.cancelRequest.User != user {
		t.Fatalf("dispatcher cancel = (%v, %#v)", dispatcher.canceled, dispatcher.cancelRequest)
	}
	if len(dispatcher.cancelRequest.Extensions) != 1 || dispatcher.cancelRequest.Extensions[0] != "https://extension.example" {
		t.Fatalf("cancel extensions = %#v", dispatcher.cancelRequest.Extensions)
	}
}

func TestExecutorForwardsSanitizedProtocolContext(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	executor, err := NewExecutor(dispatcher)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	user := a2asrv.NewAuthenticatedUser("alice", nil)
	execCtx := &a2asrv.ExecutorContext{
		Message:      a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
		TaskID:       "task-1",
		ContextID:    "context-1",
		Tenant:       "tenant-1",
		User:         user,
		RelatedTasks: []*a2a.Task{{ID: "related-1"}, nil},
		ServiceParams: a2asrv.NewServiceParams(map[string][]string{
			a2a.SvcParamExtensions: {"https://extension.example"},
			"Authorization":        {"Bearer must-not-forward"},
		}),
	}
	for range executor.Execute(t.Context(), execCtx) {
	}
	got := dispatcher.dispatchRequest
	if got.Tenant != "tenant-1" || got.User != user {
		t.Fatalf("identity context = (%q, %#v)", got.Tenant, got.User)
	}
	if len(got.Extensions) != 1 || got.Extensions[0] != "https://extension.example" {
		t.Fatalf("extensions = %#v", got.Extensions)
	}
	if len(got.RelatedTaskIDs) != 1 || got.RelatedTaskIDs[0] != "related-1" {
		t.Fatalf("related task IDs = %#v", got.RelatedTaskIDs)
	}
}

func TestExecutorPropagatesCancelFailureWithoutFalseCanceledState(t *testing.T) {
	cancelErr := errors.New("cancel publish failed")
	dispatcher := &recordingDispatcher{cancelErr: cancelErr}
	executor, err := NewExecutor(dispatcher)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}

	var gotEvent a2a.Event
	var gotErr error
	for event, err := range executor.Cancel(t.Context(), &a2asrv.ExecutorContext{TaskID: "task-1"}) {
		gotEvent, gotErr = event, err
	}
	if !errors.Is(gotErr, a2a.ErrInternalError) {
		t.Fatalf("Cancel() error = %v, want sanitized internal error", gotErr)
	}
	if gotEvent != nil {
		t.Fatalf("Cancel() event = %#v, want no false canceled event", gotEvent)
	}
}

type recordingDispatcher struct {
	dispatchErr     error
	cancelErr       error
	dispatched      bool
	canceled        bool
	dispatchRequest DispatchRequest
	cancelRequest   CancelRequest
}

func (d *recordingDispatcher) Dispatch(_ context.Context, request DispatchRequest) iter.Seq2[Output, error] {
	d.dispatched = true
	d.dispatchRequest = request
	return func(yield func(Output, error) bool) {
		if d.dispatchErr != nil {
			yield(Output{}, d.dispatchErr)
		}
	}
}

func (d *recordingDispatcher) Cancel(_ context.Context, request CancelRequest) error {
	d.canceled = true
	d.cancelRequest = request
	return d.cancelErr
}

type chunkDispatcher struct{}

func (chunkDispatcher) Dispatch(context.Context, DispatchRequest) iter.Seq2[Output, error] {
	return func(yield func(Output, error) bool) {
		if !yield(Output{ArtifactID: "answer", Parts: []*a2a.Part{a2a.NewTextPart("hel")}}, nil) {
			return
		}
		yield(Output{ArtifactID: "answer", Parts: []*a2a.Part{a2a.NewTextPart("lo")}, LastChunk: true}, nil)
	}
}

func (chunkDispatcher) Cancel(context.Context, CancelRequest) error { return nil }
