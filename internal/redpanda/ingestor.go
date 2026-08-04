package redpanda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

const defaultDeadLetterValueLimit = 64 << 10

type RecordConsumer interface {
	PollRecords(context.Context, int) kgo.Fetches
	CommitRecords(context.Context, ...*kgo.Record) error
	AllowRebalance()
}

type ResultRecord struct {
	Envelope  *Envelope
	Topic     string
	Partition int32
	Offset    int64
	Timestamp time.Time
	Key       []byte
	Digest    string
}

// DurableResultStore must return nil only after the result is durably
// committed. It must be idempotent by broker position and event identity,
// because a successful insert followed by a failed offset commit is replayed.
type DurableResultStore interface {
	StoreResult(context.Context, ResultRecord) error
}

type IngestorConfig struct {
	Consumer            RecordConsumer
	Store               DurableResultStore
	DeadLetterPublisher Publisher
	ResultsTopic        string
	Validation          ValidationPolicy
	MaxPollRecords      int
	Now                 func() time.Time
}

type ResultIngestor struct {
	consumer            RecordConsumer
	store               DurableResultStore
	deadLetterPublisher Publisher
	resultsTopic        string
	validation          ValidationPolicy
	maxPollRecords      int
	now                 func() time.Time
}

func NewResultIngestor(config IngestorConfig) (*ResultIngestor, error) {
	if config.Consumer == nil {
		return nil, errors.New("result consumer is required")
	}
	if config.Store == nil {
		return nil, errors.New("durable result store is required")
	}
	if config.DeadLetterPublisher == nil {
		return nil, errors.New("dead-letter publisher is required")
	}
	if err := validateTopic(config.ResultsTopic); err != nil {
		return nil, fmt.Errorf("results topic: %w", err)
	}
	if config.MaxPollRecords == 0 {
		config.MaxPollRecords = defaultMaxPollRecords
	}
	if config.MaxPollRecords < 1 {
		return nil, errors.New("max poll records must be positive")
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
	return &ResultIngestor{
		consumer:            config.Consumer,
		store:               config.Store,
		deadLetterPublisher: config.DeadLetterPublisher,
		resultsTopic:        config.ResultsTopic,
		validation:          config.Validation,
		maxPollRecords:      config.MaxPollRecords,
		now:                 config.Now,
	}, nil
}

func (ingestor *ResultIngestor) Run(ctx context.Context) error {
	for {
		_, err := ingestor.RunOnce(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}
	}
}

// RunOnce processes a bounded poll. Every valid record is inserted before its
// offset is committed. Invalid records are published synchronously to the DLQ
// before their original offsets are committed. Channel delivery is never part
// of the acknowledgement path.
func (ingestor *ResultIngestor) RunOnce(ctx context.Context) (int, error) {
	if ingestor == nil || ingestor.consumer == nil {
		return 0, errors.New("result ingestor is not initialized")
	}
	fetches := ingestor.consumer.PollRecords(ctx, ingestor.maxPollRecords)
	recordCount := 0
	for _, fetch := range fetches {
		for _, topic := range fetch.Topics {
			for _, partition := range topic.Partitions {
				recordCount += len(partition.Records)
			}
		}
	}
	if recordCount > 0 {
		defer ingestor.consumer.AllowRebalance()
	}
	if fetchErrors := fetches.Errors(); len(fetchErrors) > 0 {
		first := fetchErrors[0]
		return 0, fmt.Errorf("poll results topic %s partition %d: %w", first.Topic, first.Partition, first.Err)
	}
	if recordCount == 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, nil
	}

	processed := 0
	for _, fetch := range fetches {
		for _, topic := range fetch.Topics {
			for _, partition := range topic.Partitions {
				for _, record := range partition.Records {
					if record == nil {
						return processed, errors.New("consumer returned a nil record")
					}
					if err := ingestor.ingestRecord(ctx, record); err != nil {
						return processed, err
					}
					processed++
				}
			}
		}
	}
	return processed, nil
}

func (ingestor *ResultIngestor) ingestRecord(ctx context.Context, record *kgo.Record) error {
	envelope, validationErr := ingestor.validateRecord(record)
	if validationErr != nil {
		if err := ingestor.publishDeadLetter(ctx, record, validationErr); err != nil {
			return fmt.Errorf("publish invalid result to dead-letter topic: %w", err)
		}
	} else {
		stored := ResultRecord{
			Envelope:  envelope,
			Topic:     record.Topic,
			Partition: record.Partition,
			Offset:    record.Offset,
			Timestamp: record.Timestamp,
			Key:       bytes.Clone(record.Key),
			Digest:    EnvelopeDigest(record.Value),
		}
		if err := ingestor.store.StoreResult(ctx, stored); err != nil {
			return fmt.Errorf("durably store result at %s/%d/%d: %w", record.Topic, record.Partition, record.Offset, err)
		}
	}
	if err := ingestor.consumer.CommitRecords(ctx, record); err != nil {
		return fmt.Errorf("commit result offset %s/%d/%d: %w", record.Topic, record.Partition, record.Offset, err)
	}
	return nil
}

func (ingestor *ResultIngestor) validateRecord(record *kgo.Record) (*Envelope, error) {
	if record.Topic != ingestor.resultsTopic {
		return nil, fmt.Errorf("unexpected topic %q", record.Topic)
	}
	if record.Partition < 0 || record.Offset < 0 {
		return nil, errors.New("invalid broker position")
	}
	envelope, err := DecodeEnvelope(record.Value, ingestor.validation)
	if err != nil {
		return nil, err
	}
	switch envelope.Kind {
	case KindArtifact, KindHeartbeat, KindCompleted, KindFailed, KindCanceled:
	default:
		return nil, fmt.Errorf("unexpected result kind %q", envelope.Kind)
	}
	expectedKey := RecordKey(envelope.TenantID, envelope.TaskID)
	if !bytes.Equal(record.Key, expectedKey) {
		return nil, errors.New("record key does not match tenant and task")
	}
	return envelope, nil
}

func (ingestor *ResultIngestor) publishDeadLetter(ctx context.Context, record *kgo.Record, cause error) error {
	value := record.Value
	if len(value) > defaultDeadLetterValueLimit {
		value = value[:defaultDeadLetterValueLimit]
	}
	digest := EnvelopeDigest(record.Value)
	now := ingestor.now().UTC()
	envelope := &Envelope{
		Schema:   SchemaV1,
		Kind:     KindDeadLetter,
		EventID:  StableDigest("dead-letter-event/v1", record.Topic, fmt.Sprintf("%d", record.Partition), fmt.Sprintf("%d", record.Offset), digest),
		IssuedAt: now,
		DeadLetter: &DeadLetterPayload{
			OriginalTopic:  record.Topic,
			Partition:      record.Partition,
			Offset:         record.Offset,
			Reason:         deadLetterReason(cause),
			OriginalDigest: digest,
			OriginalValue:  bytes.Clone(value),
		},
	}
	return ingestor.deadLetterPublisher.Publish(ctx, envelope)
}

func deadLetterReason(err error) string {
	const prefix = "invalid result record: "
	reason := prefix + err.Error()
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	return reason
}
