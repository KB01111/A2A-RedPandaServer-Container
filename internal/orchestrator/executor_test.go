package orchestrator

import (
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
