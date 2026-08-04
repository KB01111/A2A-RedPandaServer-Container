package redpanda

import (
	"context"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

type ResultQuery struct {
	TenantID      string
	TaskID        a2a.TaskID
	ContextID     string
	ExecutionID   string
	AfterSequence uint64
}

// ResultCursor must return durably stored result envelopes in ascending
// sequence order. Implementations may replay rows and then follow database
// notifications; they must not expose broker records awaiting an offset commit.
type ResultCursor interface {
	Next(context.Context) (*Envelope, error)
	Close() error
}

type ResultSource interface {
	Open(context.Context, ResultQuery) (ResultCursor, error)
}

// ActiveExecutionResolver is an optional durable lookup used by cancellation
// after a process restart or when another replica dispatched the task.
type ActiveExecutionResolver interface {
	ActiveExecution(context.Context, string, a2a.TaskID) (string, error)
}
