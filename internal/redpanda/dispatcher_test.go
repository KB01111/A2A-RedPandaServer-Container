package redpanda

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
)

type fakePublisher struct {
	mu        sync.Mutex
	envelopes []*Envelope
	err       error
	published chan struct{}
}

func (publisher *fakePublisher) Publish(_ context.Context, envelope *Envelope) error {
	publisher.mu.Lock()
	publisher.envelopes = append(publisher.envelopes, envelope)
	publisher.mu.Unlock()
	if publisher.published != nil {
		select {
		case publisher.published <- struct{}{}:
		default:
		}
	}
	return publisher.err
}

func (publisher *fakePublisher) snapshot() []*Envelope {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	return append([]*Envelope(nil), publisher.envelopes...)
}

type sliceCursor struct {
	values []*Envelope
	err    error
	index  int
	closed bool
}

func (cursor *sliceCursor) Next(context.Context) (*Envelope, error) {
	if cursor.index < len(cursor.values) {
		value := cursor.values[cursor.index]
		cursor.index++
		return value, nil
	}
	if cursor.err != nil {
		return nil, cursor.err
	}
	return nil, io.EOF
}

func (cursor *sliceCursor) Close() error {
	cursor.closed = true
	return nil
}

type fakeResultSource struct {
	query  ResultQuery
	cursor ResultCursor
	err    error
}

func (source *fakeResultSource) Open(_ context.Context, query ResultQuery) (ResultCursor, error) {
	source.query = query
	return source.cursor, source.err
}

type resolverFunc func(context.Context, string, a2a.TaskID) (string, error)

func (function resolverFunc) ActiveExecution(ctx context.Context, tenant string, taskID a2a.TaskID) (string, error) {
	return function(ctx, tenant, taskID)
}

func dispatchRequest() orchestrator.DispatchRequest {
	message := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))
	message.ID = "message-1"
	return orchestrator.DispatchRequest{
		TaskID:         "task-1",
		ContextID:      "context-1",
		Tenant:         "tenant-1",
		Message:        message,
		Metadata:       map[string]any{"priority": "normal"},
		User:           a2asrv.NewAuthenticatedUser("alice", map[string]any{"issuer": "https://issuer", "subject": "user-1"}),
		Extensions:     []string{"urn:extension"},
		RelatedTaskIDs: []a2a.TaskID{"task-0"},
	}
}

func correlatedResult(request orchestrator.DispatchRequest, kind Kind, sequence uint64) *Envelope {
	executionID := StableExecutionID(request.Tenant, request.TaskID, request.Message.ID)
	envelope := validResultEnvelope(kind, sequence)
	envelope.ExecutionID = executionID
	envelope.TenantID = request.Tenant
	envelope.TaskID = request.TaskID
	envelope.ContextID = request.ContextID
	return envelope
}

func newTestDispatcher(t *testing.T, publisher Publisher, source ResultSource, resolver ActiveExecutionResolver) *Dispatcher {
	t.Helper()
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Publisher:         publisher,
		Results:           source,
		ExecutionResolver: resolver,
		Validation:        testPolicy(),
		CommandTTL:        time.Minute,
		Now:               func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	return dispatcher
}

func collectDispatch(dispatcher *Dispatcher, request orchestrator.DispatchRequest) ([]orchestrator.Output, []error) {
	var outputs []orchestrator.Output
	var errs []error
	for output, err := range dispatcher.Dispatch(context.Background(), request) {
		if err != nil {
			errs = append(errs, err)
		} else {
			outputs = append(outputs, output)
		}
	}
	return outputs, errs
}

func TestDispatcherPublishesExecuteAndStreamsOrderedResults(t *testing.T) {
	request := dispatchRequest()
	cursor := &sliceCursor{values: []*Envelope{
		correlatedResult(request, KindArtifact, 1),
		correlatedResult(request, KindArtifact, 1), // durable replay duplicate
		correlatedResult(request, KindHeartbeat, 2),
		correlatedResult(request, KindCompleted, 3),
	}}
	publisher := &fakePublisher{}
	source := &fakeResultSource{cursor: cursor}
	dispatcher := newTestDispatcher(t, publisher, source, nil)

	outputs, errs := collectDispatch(dispatcher, request)
	if len(errs) != 0 {
		t.Fatalf("Dispatch() errors = %v", errs)
	}
	if len(outputs) != 2 || outputs[0].ArtifactID != "artifact-1" || len(outputs[0].Parts) != 1 || !outputs[1].Heartbeat {
		t.Fatalf("Dispatch() outputs = %#v, want one artifact followed by one heartbeat", outputs)
	}
	produced := publisher.snapshot()
	if len(produced) != 1 || produced[0].Kind != KindExecute {
		t.Fatalf("published envelopes = %#v, want execute", produced)
	}
	if produced[0].Execute.Principal.Subject != "user-1" || produced[0].Execute.Principal.Issuer != "https://issuer" {
		t.Fatalf("principal = %#v", produced[0].Execute.Principal)
	}
	if source.query.ExecutionID != produced[0].ExecutionID || source.query.AfterSequence != 0 {
		t.Fatalf("result query = %#v, execute = %#v", source.query, produced[0])
	}
	if !cursor.closed {
		t.Fatal("result cursor was not closed")
	}
}

func TestDispatcherRejectsSequenceGapAndCorrelationMismatch(t *testing.T) {
	request := dispatchRequest()
	for name, result := range map[string]*Envelope{
		"gap":         correlatedResult(request, KindHeartbeat, 2),
		"correlation": correlatedResult(request, KindHeartbeat, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "correlation" {
				result.TenantID = "another-tenant"
			}
			dispatcher := newTestDispatcher(t, &fakePublisher{}, &fakeResultSource{cursor: &sliceCursor{values: []*Envelope{result}}}, nil)
			_, errs := collectDispatch(dispatcher, request)
			if len(errs) != 1 {
				t.Fatalf("Dispatch() errors = %v, want one", errs)
			}
		})
	}
}

func TestDispatcherMapsTerminalResults(t *testing.T) {
	request := dispatchRequest()
	tests := []struct {
		kind Kind
		want error
	}{
		{kind: KindFailed, want: &RemoteError{}},
		{kind: KindCanceled, want: ErrExecutionCanceled},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			dispatcher := newTestDispatcher(t, &fakePublisher{}, &fakeResultSource{cursor: &sliceCursor{values: []*Envelope{correlatedResult(request, test.kind, 1)}}}, nil)
			_, errs := collectDispatch(dispatcher, request)
			if len(errs) != 1 {
				t.Fatalf("Dispatch() errors = %v, want one", errs)
			}
			if test.kind == KindCanceled && !errors.Is(errs[0], test.want) {
				t.Fatalf("Dispatch() error = %v, want canceled", errs[0])
			}
			if test.kind == KindFailed {
				var remote *RemoteError
				if !errors.As(errs[0], &remote) || remote.Code != "worker_failed" {
					t.Fatalf("Dispatch() error = %#v, want RemoteError", errs[0])
				}
			}
		})
	}
}

func TestDispatcherTreatsEOFBeforeTerminalAsError(t *testing.T) {
	request := dispatchRequest()
	dispatcher := newTestDispatcher(t, &fakePublisher{}, &fakeResultSource{cursor: &sliceCursor{}}, nil)
	_, errs := collectDispatch(dispatcher, request)
	if len(errs) != 1 || !errors.Is(errs[0], ErrResultStreamEnded) {
		t.Fatalf("Dispatch() errors = %v, want ErrResultStreamEnded", errs)
	}
}

func TestCancelUsesDurableExecutionResolver(t *testing.T) {
	publisher := &fakePublisher{}
	resolver := resolverFunc(func(_ context.Context, tenant string, taskID a2a.TaskID) (string, error) {
		if tenant != "tenant-1" || taskID != "task-1" {
			t.Fatalf("resolver arguments = %q/%q", tenant, taskID)
		}
		return "execution-from-postgres", nil
	})
	dispatcher := newTestDispatcher(t, publisher, &fakeResultSource{cursor: &sliceCursor{}}, resolver)
	err := dispatcher.Cancel(context.Background(), orchestrator.CancelRequest{Tenant: "tenant-1", TaskID: "task-1"})
	if err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	produced := publisher.snapshot()
	if len(produced) != 1 || produced[0].Kind != KindCancel || produced[0].Cancel.TargetExecutionID != "execution-from-postgres" {
		t.Fatalf("published cancellation = %#v", produced)
	}
}

type blockingCursor struct {
	opened chan struct{}
}

func (cursor *blockingCursor) Next(ctx context.Context) (*Envelope, error) {
	select {
	case cursor.opened <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingCursor) Close() error { return nil }

func TestCancelFindsProcessLocalActiveExecution(t *testing.T) {
	request := dispatchRequest()
	publisher := &fakePublisher{}
	cursor := &blockingCursor{opened: make(chan struct{}, 1)}
	dispatcher := newTestDispatcher(t, publisher, &fakeResultSource{cursor: cursor}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range dispatcher.Dispatch(ctx, request) {
		}
	}()
	select {
	case <-cursor.opened:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not open result cursor")
	}
	if err := dispatcher.Cancel(context.Background(), orchestrator.CancelRequest{Tenant: request.Tenant, TaskID: request.TaskID}); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
	produced := publisher.snapshot()
	if len(produced) != 2 || produced[1].Kind != KindCancel || produced[1].ExecutionID != produced[0].ExecutionID {
		t.Fatalf("published envelopes = %#v", produced)
	}
}
