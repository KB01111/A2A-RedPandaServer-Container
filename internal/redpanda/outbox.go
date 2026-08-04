package redpanda

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type NewCommand struct {
	Envelope  *Envelope
	Topic     string
	Key       []byte
	Payload   []byte
	Digest    string
	CreatedAt time.Time
}

type Command struct {
	NewCommand
	Attempts   int
	LeaseToken string
	LeaseUntil time.Time
}

type CommandClaim struct {
	WorkerID      string
	LeaseToken    string
	Now           time.Time
	LeaseDuration time.Duration
	Limit         int
}

type CommandCompletion struct {
	EventID     string
	LeaseToken  string
	Attempt     int
	At          time.Time
	NextAttempt time.Time
	Failure     string
}

type CommandRepository interface {
	EnqueueCommand(context.Context, NewCommand) error
	ClaimCommands(context.Context, CommandClaim) ([]Command, error)
	MarkCommandPublished(context.Context, CommandCompletion) error
	MarkCommandRetry(context.Context, CommandCompletion) error
	MarkCommandDead(context.Context, CommandCompletion) error
}

var ErrCommandLeaseLost = errors.New("Redpanda command lease lost")

// DurablePublisher implements Publisher by committing commands to PostgreSQL.
// A CommandWorker performs broker I/O independently and survives process
// crashes through leased replay.
type DurablePublisher struct {
	repository CommandRepository
	topics     Topics
	policy     ValidationPolicy
}

func NewDurablePublisher(repository CommandRepository, topics Topics, policy ValidationPolicy) (*DurablePublisher, error) {
	if repository == nil {
		return nil, fmt.Errorf("command outbox repository is required")
	}
	if err := topics.Validate(); err != nil {
		return nil, err
	}
	policy = policy.normalized()
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &DurablePublisher{repository: repository, topics: topics, policy: policy}, nil
}

func (p *DurablePublisher) Publish(ctx context.Context, envelope *Envelope) error {
	payload, err := MarshalEnvelope(envelope, p.policy)
	if err != nil {
		return fmt.Errorf("validate durable command envelope: %w", err)
	}
	var topic string
	switch envelope.Kind {
	case KindExecute, KindCancel:
		topic = p.topics.Commands
	default:
		return fmt.Errorf("durable publisher accepts only execute and cancel commands")
	}
	return p.repository.EnqueueCommand(ctx, NewCommand{
		Envelope: envelope, Topic: topic, Key: RecordKey(envelope.TenantID, envelope.TaskID),
		Payload: payload, Digest: EnvelopeDigest(payload), CreatedAt: envelope.IssuedAt.UTC(),
	})
}

type CommandWorkerConfig struct {
	Repository    CommandRepository
	Publisher     Publisher
	WorkerID      string
	BatchSize     int
	LeaseDuration time.Duration
	PollInterval  time.Duration
	MaxAttempts   int
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
	Now           func() time.Time
	NewLeaseToken func(time.Time) (string, error)
}

type CommandWorker struct {
	repository    CommandRepository
	publisher     Publisher
	workerID      string
	batchSize     int
	leaseDuration time.Duration
	pollInterval  time.Duration
	maxAttempts   int
	baseBackoff   time.Duration
	maxBackoff    time.Duration
	now           func() time.Time
	newLeaseToken func(time.Time) (string, error)
}

func NewCommandWorker(config CommandWorkerConfig) (*CommandWorker, error) {
	if config.Repository == nil || config.Publisher == nil {
		return nil, fmt.Errorf("command repository and broker publisher are required")
	}
	if strings.TrimSpace(config.WorkerID) == "" || config.WorkerID != strings.TrimSpace(config.WorkerID) {
		return nil, fmt.Errorf("command worker ID is required")
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 50
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = time.Minute
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 250 * time.Millisecond
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 20
	}
	if config.BaseBackoff <= 0 {
		config.BaseBackoff = time.Second
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = time.Minute
	}
	if config.BaseBackoff > config.MaxBackoff {
		return nil, fmt.Errorf("command base backoff exceeds maximum backoff")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewLeaseToken == nil {
		config.NewLeaseToken = func(time.Time) (string, error) {
			value := make([]byte, 16)
			if _, err := cryptorand.Read(value); err != nil {
				return "", fmt.Errorf("generate command lease randomness: %w", err)
			}
			return hex.EncodeToString(value), nil
		}
	}
	return &CommandWorker{
		repository: config.Repository, publisher: config.Publisher, workerID: config.WorkerID,
		batchSize: config.BatchSize, leaseDuration: config.LeaseDuration,
		pollInterval: config.PollInterval, maxAttempts: config.MaxAttempts,
		baseBackoff: config.BaseBackoff, maxBackoff: config.MaxBackoff,
		now: config.Now, newLeaseToken: config.NewLeaseToken,
	}, nil
}

func (w *CommandWorker) Run(ctx context.Context) error {
	for {
		processed, err := w.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if processed != 0 {
			continue
		}
		timer := time.NewTimer(w.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func (w *CommandWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.now().UTC()
	leaseToken, err := w.newLeaseToken(now)
	if err != nil {
		return 0, fmt.Errorf("generate command lease token: %w", err)
	}
	commands, err := w.repository.ClaimCommands(ctx, CommandClaim{
		WorkerID: w.workerID, LeaseToken: leaseToken, Now: now,
		LeaseDuration: w.leaseDuration, Limit: w.batchSize,
	})
	if err != nil {
		return 0, fmt.Errorf("claim commands: %w", err)
	}
	for _, command := range commands {
		if command.Envelope == nil || command.LeaseToken != leaseToken {
			return 0, fmt.Errorf("claimed command is invalid")
		}
		attempt := command.Attempts + 1
		publishErr := w.publisher.Publish(ctx, command.Envelope)
		completion := CommandCompletion{
			EventID: command.Envelope.EventID, LeaseToken: leaseToken,
			Attempt: attempt, At: w.now().UTC(),
		}
		if publishErr == nil {
			err = w.repository.MarkCommandPublished(ctx, completion)
		} else if attempt >= w.maxAttempts {
			completion.Failure = "broker_publish"
			err = w.repository.MarkCommandDead(ctx, completion)
		} else {
			completion.Failure = "broker_publish"
			completion.NextAttempt = completion.At.Add(w.retryDelay(attempt))
			err = w.repository.MarkCommandRetry(ctx, completion)
		}
		if err != nil {
			return 0, fmt.Errorf("complete command %s: %w", command.Envelope.EventID, err)
		}
	}
	return len(commands), nil
}

func (w *CommandWorker) retryDelay(attempt int) time.Duration {
	delay := w.baseBackoff
	for index := 1; index < attempt && delay < w.maxBackoff; index++ {
		if delay > w.maxBackoff/2 {
			return w.maxBackoff
		}
		delay *= 2
	}
	if delay > w.maxBackoff {
		return w.maxBackoff
	}
	return delay
}
