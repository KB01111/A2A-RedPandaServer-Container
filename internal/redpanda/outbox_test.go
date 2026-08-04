package redpanda

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestDurablePublisherEnqueuesWithoutBrokerIO(t *testing.T) {
	now := time.Now().UTC()
	repository := &fakeCommandRepository{}
	publisher, err := NewDurablePublisher(repository, outboxTopics(), ValidationPolicy{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	envelope := testExecuteEnvelope(now)
	if err := publisher.Publish(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if repository.enqueued.Envelope != envelope || repository.enqueued.Topic != outboxTopics().Commands ||
		len(repository.enqueued.Payload) == 0 || len(repository.enqueued.Key) == 0 || len(repository.enqueued.Digest) != 64 {
		t.Fatalf("enqueued command = %#v", repository.enqueued)
	}
}

func TestCommandWorkerRetriesThenPublishesWithLeaseCAS(t *testing.T) {
	now := time.Now().UTC()
	envelope := testExecuteEnvelope(now)
	repository := &fakeCommandRepository{claimed: []Command{{
		NewCommand: NewCommand{Envelope: envelope}, Attempts: 0,
	}}}
	downstream := &failingPublisher{errors: []error{errors.New("broker down"), nil}}
	worker, err := NewCommandWorker(CommandWorkerConfig{
		Repository: repository, Publisher: downstream, WorkerID: "worker",
		Now: func() time.Time { return now },
		NewLeaseToken: func(time.Time) (string, error) { return "lease", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := worker.RunOnce(context.Background()); err != nil || processed != 1 {
		t.Fatalf("first RunOnce() = %d, %v", processed, err)
	}
	if len(repository.retries) != 1 || repository.retries[0].Attempt != 1 || repository.retries[0].NextAttempt.IsZero() {
		t.Fatalf("retry = %#v", repository.retries)
	}
	repository.claimed[0].Attempts = 1
	if processed, err := worker.RunOnce(context.Background()); err != nil || processed != 1 {
		t.Fatalf("second RunOnce() = %d, %v", processed, err)
	}
	if len(repository.published) != 1 || repository.published[0].Attempt != 2 {
		t.Fatalf("published = %#v", repository.published)
	}
}

func outboxTopics() Topics {
	return Topics{Commands: "bridge.commands", Results: "bridge.results", DeadLetter: "bridge.dlq"}
}

func testExecuteEnvelope(now time.Time) *Envelope {
	deadline := now.Add(time.Minute)
	message := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("work"))
	message.ID = "message"
	executionID := StableExecutionID("tenant", "task", message.ID)
	commandID := StableCommandID(KindExecute, executionID)
	return &Envelope{
		Schema: SchemaV1, Kind: KindExecute, EventID: StableEventID(KindExecute, commandID, 0),
		ExecutionID: executionID, CommandID: commandID, TenantID: "tenant", TaskID: "task",
		ContextID: "context", IssuedAt: now, Deadline: &deadline,
		Execute: &ExecutePayload{Message: message, Principal: Principal{Issuer: "https://issuer", Subject: "owner"}},
	}
}

type fakeCommandRepository struct {
	enqueued  NewCommand
	claimed   []Command
	published []CommandCompletion
	retries   []CommandCompletion
	dead      []CommandCompletion
}

func (r *fakeCommandRepository) EnqueueCommand(_ context.Context, command NewCommand) error {
	r.enqueued = command
	return nil
}

func (r *fakeCommandRepository) ClaimCommands(_ context.Context, claim CommandClaim) ([]Command, error) {
	result := make([]Command, len(r.claimed))
	copy(result, r.claimed)
	for index := range result {
		result[index].LeaseToken = claim.LeaseToken
	}
	return result, nil
}

func (r *fakeCommandRepository) MarkCommandPublished(_ context.Context, completion CommandCompletion) error {
	r.published = append(r.published, completion)
	return nil
}

func (r *fakeCommandRepository) MarkCommandRetry(_ context.Context, completion CommandCompletion) error {
	r.retries = append(r.retries, completion)
	return nil
}

func (r *fakeCommandRepository) MarkCommandDead(_ context.Context, completion CommandCompletion) error {
	r.dead = append(r.dead, completion)
	return nil
}

type failingPublisher struct {
	errors []error
}

func (p *failingPublisher) Publish(context.Context, *Envelope) error {
	if len(p.errors) == 0 {
		return nil
	}
	err := p.errors[0]
	p.errors = p.errors[1:]
	return err
}
