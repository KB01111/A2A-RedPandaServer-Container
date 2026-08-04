package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

func TestErrorBoundarySanitizesUnknownErrors(t *testing.T) {
	interceptor := errorBoundaryInterceptor{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	response := &a2asrv.Response{Err: errors.New("postgres db.internal relation a2a_tasks")}
	if err := interceptor.After(context.Background(), &a2asrv.CallContext{}, response); err != nil {
		t.Fatal(err)
	}
	if response.Err != a2a.ErrInternalError {
		t.Fatalf("response error = %v", response.Err)
	}
}

func TestErrorBoundaryPreservesOnlyClientSafeProtocolErrors(t *testing.T) {
	custom := a2a.NewError(a2a.ErrInvalidParams, "safe client detail")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "canceled", err: fmt.Errorf("request stopped: %w", context.Canceled), want: context.Canceled},
		{name: "deadline", err: fmt.Errorf("request stopped: %w", context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "wrapped known sentinel", err: fmt.Errorf("storage lookup: %w", a2a.ErrTaskNotFound), want: a2a.ErrTaskNotFound},
		{name: "explicit protocol error", err: custom, want: custom},
		{name: "wrapped internal", err: fmt.Errorf("database detail: %w", a2a.ErrInternalError), want: a2a.ErrInternalError},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := clientSafeError(test.err); got != test.want {
				t.Fatalf("clientSafeError() = %v, want %v", got, test.want)
			}
		})
	}
}
