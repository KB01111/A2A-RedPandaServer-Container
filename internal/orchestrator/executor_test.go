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
	if status.Status.Message == nil || len(status.Status.Message.Parts) == 0 || status.Status.Message.Parts[0].Text() != "execution failed: worker unavailable" {
		t.Fatalf("failure message = %#v", status.Status.Message)
	}
}

func TestExecutorCancel(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	executor, err := NewExecutor(dispatcher)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	execCtx := &a2asrv.ExecutorContext{TaskID: "task-1", ContextID: "context-1"}

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
	if !dispatcher.canceled || dispatcher.canceledTask != "task-1" {
		t.Fatalf("dispatcher cancel = (%v, %q)", dispatcher.canceled, dispatcher.canceledTask)
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
	if !errors.Is(gotErr, cancelErr) {
		t.Fatalf("Cancel() error = %v, want %v", gotErr, cancelErr)
	}
	if gotEvent != nil {
		t.Fatalf("Cancel() event = %#v, want no false canceled event", gotEvent)
	}
}

type recordingDispatcher struct {
	dispatchErr  error
	cancelErr    error
	dispatched   bool
	canceled     bool
	canceledTask a2a.TaskID
}

func (d *recordingDispatcher) Dispatch(context.Context, DispatchRequest) iter.Seq2[Output, error] {
	d.dispatched = true
	return func(yield func(Output, error) bool) {
		if d.dispatchErr != nil {
			yield(Output{}, d.dispatchErr)
		}
	}
}

func (d *recordingDispatcher) Cancel(_ context.Context, taskID a2a.TaskID) error {
	d.canceled = true
	d.canceledTask = taskID
	return d.cancelErr
}
