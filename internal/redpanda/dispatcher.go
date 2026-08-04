package redpanda

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
)

var (
	ErrExecutionNotFound = errors.New("active execution not found")
	ErrExecutionCanceled = orchestrator.ErrExecutionCanceled
	ErrResultStreamEnded = errors.New("result stream ended before a terminal result")
)

type RemoteError struct {
	Code string
}

func (e *RemoteError) Error() string {
	if e == nil || e.Code == "" {
		return "remote execution failed"
	}
	return "remote execution failed: " + e.Code
}

type DispatcherConfig struct {
	Publisher         Publisher
	Results           ResultSource
	ExecutionResolver ActiveExecutionResolver
	Validation        ValidationPolicy
	CommandTTL        time.Duration
	Now               func() time.Time
}

type Dispatcher struct {
	publisher         Publisher
	results           ResultSource
	executionResolver ActiveExecutionResolver
	validation        ValidationPolicy
	commandTTL        time.Duration
	now               func() time.Time

	mu     sync.RWMutex
	active map[taskKey]string
}

type taskKey struct {
	tenantID string
	taskID   a2a.TaskID
}

func NewDispatcher(config DispatcherConfig) (*Dispatcher, error) {
	if config.Publisher == nil {
		return nil, errors.New("command publisher is required")
	}
	if config.Results == nil {
		return nil, errors.New("result source is required")
	}
	if config.CommandTTL == 0 {
		config.CommandTTL = 15 * time.Minute
	}
	if config.CommandTTL <= 0 {
		return nil, errors.New("command TTL must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Validation.Now == nil {
		config.Validation.Now = config.Now
	}
	config.Validation = config.Validation.normalized()
	if err := config.Validation.validate(); err != nil {
		return nil, err
	}
	if config.CommandTTL > config.Validation.MaxTTL {
		return nil, errors.New("command TTL exceeds envelope maximum TTL")
	}
	return &Dispatcher{
		publisher:         config.Publisher,
		results:           config.Results,
		executionResolver: config.ExecutionResolver,
		validation:        config.Validation,
		commandTTL:        config.CommandTTL,
		now:               config.Now,
		active:            make(map[taskKey]string),
	}, nil
}

func (dispatcher *Dispatcher) Dispatch(ctx context.Context, request orchestrator.DispatchRequest) iter.Seq2[orchestrator.Output, error] {
	return func(yield func(orchestrator.Output, error) bool) {
		if err := validateDispatchRequest(request); err != nil {
			yield(orchestrator.Output{}, err)
			return
		}

		now := dispatcher.now().UTC()
		executionID := StableExecutionID(request.Tenant, request.TaskID, request.Message.ID)
		commandID := StableCommandID(KindExecute, executionID)
		deadline := now.Add(dispatcher.commandTTL)
		envelope := &Envelope{
			Schema:      SchemaV1,
			Kind:        KindExecute,
			EventID:     StableEventID(KindExecute, commandID, 0),
			ExecutionID: executionID,
			CommandID:   commandID,
			TenantID:    request.Tenant,
			TaskID:      request.TaskID,
			ContextID:   request.ContextID,
			IssuedAt:    now,
			Deadline:    &deadline,
			Execute: &ExecutePayload{
				Message:        request.Message,
				Metadata:       request.Metadata,
				Extensions:     append([]string(nil), request.Extensions...),
				RelatedTaskIDs: append([]a2a.TaskID(nil), request.RelatedTaskIDs...),
				Principal:      principalFromUser(request.User),
			},
		}

		key := taskKey{tenantID: request.Tenant, taskID: request.TaskID}
		dispatcher.setActive(key, executionID)
		defer dispatcher.clearActive(key, executionID)
		if err := dispatcher.publisher.Publish(ctx, envelope); err != nil {
			yield(orchestrator.Output{}, fmt.Errorf("publish execute command: %w", err))
			return
		}

		query := ResultQuery{
			TenantID:    request.Tenant,
			TaskID:      request.TaskID,
			ContextID:   request.ContextID,
			ExecutionID: executionID,
		}
		cursor, err := dispatcher.results.Open(ctx, query)
		if err != nil {
			yield(orchestrator.Output{}, fmt.Errorf("open result stream: %w", err))
			return
		}
		if cursor == nil {
			yield(orchestrator.Output{}, errors.New("result source returned a nil cursor"))
			return
		}
		defer cursor.Close()

		expected := query.AfterSequence + 1
		for {
			result, err := cursor.Next(ctx)
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = ErrResultStreamEnded
				}
				yield(orchestrator.Output{}, err)
				return
			}
			if result == nil {
				yield(orchestrator.Output{}, errors.New("result source returned a nil envelope"))
				return
			}
			if err := dispatcher.validateCorrelation(query, result); err != nil {
				yield(orchestrator.Output{}, err)
				return
			}
			if result.Sequence < expected {
				continue
			}
			if result.Sequence > expected {
				yield(orchestrator.Output{}, fmt.Errorf("result sequence gap: expected %d, received %d", expected, result.Sequence))
				return
			}
			expected++

			switch result.Kind {
			case KindArtifact:
				if !yield(orchestrator.Output{
					ArtifactID: result.Result.ArtifactID,
					Parts:      result.Result.Parts,
					LastChunk:  result.Result.LastChunk,
				}, nil) {
					return
				}
			case KindHeartbeat:
				if !yield(orchestrator.Output{Heartbeat: true}, nil) {
					return
				}
			case KindCompleted:
				return
			case KindFailed:
				yield(orchestrator.Output{}, &RemoteError{Code: result.Result.ErrorCode})
				return
			case KindCanceled:
				yield(orchestrator.Output{}, ErrExecutionCanceled)
				return
			default:
				yield(orchestrator.Output{}, fmt.Errorf("unexpected result kind %q", result.Kind))
				return
			}
		}
	}
}

func (dispatcher *Dispatcher) Cancel(ctx context.Context, request orchestrator.CancelRequest) error {
	if err := validateCancelRequest(request); err != nil {
		return err
	}
	executionID, err := dispatcher.findExecution(ctx, request.Tenant, request.TaskID)
	if err != nil {
		return err
	}
	now := dispatcher.now().UTC()
	deadline := now.Add(dispatcher.commandTTL)
	commandID := StableCommandID(KindCancel, executionID)
	envelope := &Envelope{
		Schema:      SchemaV1,
		Kind:        KindCancel,
		EventID:     StableEventID(KindCancel, commandID, 0),
		ExecutionID: executionID,
		CommandID:   commandID,
		TenantID:    request.Tenant,
		TaskID:      request.TaskID,
		IssuedAt:    now,
		Deadline:    &deadline,
		Cancel: &CancelPayload{
			TargetExecutionID: executionID,
			Extensions:        append([]string(nil), request.Extensions...),
			Principal:         principalFromUser(request.User),
		},
	}
	if err := dispatcher.publisher.Publish(ctx, envelope); err != nil {
		return fmt.Errorf("publish cancel command: %w", err)
	}
	return nil
}

func (dispatcher *Dispatcher) validateCorrelation(query ResultQuery, envelope *Envelope) error {
	if err := envelope.Validate(dispatcher.validation); err != nil {
		return fmt.Errorf("invalid result envelope: %w", err)
	}
	if envelope.TenantID != query.TenantID || envelope.TaskID != query.TaskID || envelope.ExecutionID != query.ExecutionID || envelope.ContextID != query.ContextID {
		return errors.New("result envelope correlation mismatch")
	}
	return nil
}

func (dispatcher *Dispatcher) findExecution(ctx context.Context, tenantID string, taskID a2a.TaskID) (string, error) {
	key := taskKey{tenantID: tenantID, taskID: taskID}
	dispatcher.mu.RLock()
	executionID := dispatcher.active[key]
	dispatcher.mu.RUnlock()
	if executionID != "" {
		return executionID, nil
	}
	if dispatcher.executionResolver == nil {
		return "", ErrExecutionNotFound
	}
	executionID, err := dispatcher.executionResolver.ActiveExecution(ctx, tenantID, taskID)
	if err != nil {
		return "", fmt.Errorf("resolve active execution: %w", err)
	}
	if executionID == "" {
		return "", ErrExecutionNotFound
	}
	return executionID, nil
}

func (dispatcher *Dispatcher) setActive(key taskKey, executionID string) {
	dispatcher.mu.Lock()
	dispatcher.active[key] = executionID
	dispatcher.mu.Unlock()
}

func (dispatcher *Dispatcher) clearActive(key taskKey, executionID string) {
	dispatcher.mu.Lock()
	if dispatcher.active[key] == executionID {
		delete(dispatcher.active, key)
	}
	dispatcher.mu.Unlock()
}

func validateDispatchRequest(request orchestrator.DispatchRequest) error {
	if err := validateIdentifier("tenant", request.Tenant); err != nil {
		return err
	}
	if err := validateIdentifier("task ID", string(request.TaskID)); err != nil {
		return err
	}
	if request.Message == nil {
		return errors.New("message is required")
	}
	if err := validateIdentifier("message ID", request.Message.ID); err != nil {
		return err
	}
	return validateOptionalString("context ID", request.ContextID)
}

func validateCancelRequest(request orchestrator.CancelRequest) error {
	if err := validateIdentifier("tenant", request.Tenant); err != nil {
		return err
	}
	return validateIdentifier("task ID", string(request.TaskID))
}

func principalFromUser(user *a2asrv.User) Principal {
	if user == nil {
		return Principal{}
	}
	principal := Principal{Subject: user.Name}
	if value, ok := user.Attributes["issuer"].(string); ok {
		principal.Issuer = value
	}
	if value, ok := user.Attributes["subject"].(string); ok && value != "" {
		principal.Subject = value
	}
	return principal
}

var _ orchestrator.Dispatcher = (*Dispatcher)(nil)
