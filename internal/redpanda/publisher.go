package redpanda

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	headerSchema      = "a2a-schema"
	headerKind        = "a2a-kind"
	headerEventID     = "a2a-event-id"
	headerExecutionID = "a2a-execution-id"
)

type Topics struct {
	Commands   string
	Results    string
	DeadLetter string
}

func (topics Topics) Validate() error {
	for name, topic := range map[string]string{
		"commands":    topics.Commands,
		"results":     topics.Results,
		"dead-letter": topics.DeadLetter,
	} {
		if err := validateTopic(topic); err != nil {
			return fmt.Errorf("%s topic: %w", name, err)
		}
	}
	if topics.Commands == topics.Results || topics.Commands == topics.DeadLetter || topics.Results == topics.DeadLetter {
		return errors.New("Redpanda topics must be distinct")
	}
	return nil
}

type Publisher interface {
	Publish(context.Context, *Envelope) error
}

type SyncProducer interface {
	ProduceSync(context.Context, ...*kgo.Record) kgo.ProduceResults
}

type KgoPublisher struct {
	producer SyncProducer
	topics   Topics
	policy   ValidationPolicy
}

func NewPublisher(producer SyncProducer, topics Topics, policy ValidationPolicy) (*KgoPublisher, error) {
	if producer == nil {
		return nil, errors.New("Redpanda producer is required")
	}
	if err := topics.Validate(); err != nil {
		return nil, err
	}
	policy = policy.normalized()
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &KgoPublisher{producer: producer, topics: topics, policy: policy}, nil
}

// Publish does not return until Redpanda has acknowledged the record using the
// client's configured all-ISR acknowledgement policy.
func (publisher *KgoPublisher) Publish(ctx context.Context, envelope *Envelope) error {
	if publisher == nil || publisher.producer == nil {
		return errors.New("Redpanda publisher is not initialized")
	}
	data, err := MarshalEnvelope(envelope, publisher.policy)
	if err != nil {
		return fmt.Errorf("validate Redpanda envelope: %w", err)
	}
	topic, err := publisher.topicFor(envelope.Kind)
	if err != nil {
		return err
	}
	record := &kgo.Record{
		Topic:     topic,
		Key:       RecordKey(envelope.TenantID, envelope.TaskID),
		Value:     data,
		Timestamp: envelope.IssuedAt,
		Headers: []kgo.RecordHeader{
			{Key: headerSchema, Value: []byte(envelope.Schema)},
			{Key: headerKind, Value: []byte(envelope.Kind)},
			{Key: headerEventID, Value: []byte(envelope.EventID)},
			{Key: headerExecutionID, Value: []byte(envelope.ExecutionID)},
		},
	}
	if envelope.Kind == KindDeadLetter {
		record.Key = []byte(StableDigest("dead-letter-key/v1", envelope.EventID, envelope.DeadLetter.OriginalDigest))
	}
	if err := publisher.producer.ProduceSync(ctx, record).FirstErr(); err != nil {
		return fmt.Errorf("publish %s envelope: %w", envelope.Kind, err)
	}
	return nil
}

func (publisher *KgoPublisher) topicFor(kind Kind) (string, error) {
	switch kind {
	case KindExecute, KindCancel:
		return publisher.topics.Commands, nil
	case KindArtifact, KindHeartbeat, KindCompleted, KindFailed, KindCanceled:
		return publisher.topics.Results, nil
	case KindDeadLetter:
		return publisher.topics.DeadLetter, nil
	default:
		return "", fmt.Errorf("cannot publish unsupported envelope kind %q", kind)
	}
}
