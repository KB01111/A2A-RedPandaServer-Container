package redpanda

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeRecordConsumer struct {
	fetches   kgo.Fetches
	commitErr error
	events    *[]string
	committed []*kgo.Record
	allowed   int
}

func (consumer *fakeRecordConsumer) PollRecords(context.Context, int) kgo.Fetches {
	if consumer.events != nil {
		*consumer.events = append(*consumer.events, "poll")
	}
	return consumer.fetches
}

func (consumer *fakeRecordConsumer) CommitRecords(_ context.Context, records ...*kgo.Record) error {
	if consumer.events != nil {
		*consumer.events = append(*consumer.events, "commit")
	}
	consumer.committed = append(consumer.committed, records...)
	return consumer.commitErr
}

func (consumer *fakeRecordConsumer) AllowRebalance() {
	if consumer.events != nil {
		*consumer.events = append(*consumer.events, "allow")
	}
	consumer.allowed++
}

type fakeDurableStore struct {
	err     error
	events  *[]string
	records []ResultRecord
}

func (store *fakeDurableStore) StoreResult(_ context.Context, record ResultRecord) error {
	if store.events != nil {
		*store.events = append(*store.events, "store")
	}
	store.records = append(store.records, record)
	return store.err
}

type orderedPublisher struct {
	err       error
	events    *[]string
	envelopes []*Envelope
}

func (publisher *orderedPublisher) Publish(_ context.Context, envelope *Envelope) error {
	if publisher.events != nil {
		*publisher.events = append(*publisher.events, "dlq")
	}
	publisher.envelopes = append(publisher.envelopes, envelope)
	return publisher.err
}

func kafkaFetch(record *kgo.Record) kgo.Fetches {
	return kgo.Fetches{{Topics: []kgo.FetchTopic{{
		Topic: record.Topic,
		Partitions: []kgo.FetchPartition{{
			Partition: record.Partition,
			Records:   []*kgo.Record{record},
		}},
	}}}}
}

func validKafkaResult(t *testing.T) *kgo.Record {
	t.Helper()
	envelope := validResultEnvelope(KindArtifact, 1)
	data, err := MarshalEnvelope(envelope, testPolicy())
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}
	return &kgo.Record{
		Topic:     "a2a.results",
		Partition: 2,
		Offset:    41,
		Timestamp: testNow,
		Key:       RecordKey(envelope.TenantID, envelope.TaskID),
		Value:     data,
	}
}

func newTestIngestor(t *testing.T, consumer RecordConsumer, store DurableResultStore, dlq Publisher) *ResultIngestor {
	t.Helper()
	ingestor, err := NewResultIngestor(IngestorConfig{
		Consumer:            consumer,
		Store:               store,
		DeadLetterPublisher: dlq,
		ResultsTopic:        "a2a.results",
		Validation:          testPolicy(),
		Now:                 func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewResultIngestor() error = %v", err)
	}
	return ingestor
}

func TestResultIngestorStoresBeforeOffsetCommit(t *testing.T) {
	events := []string{}
	record := validKafkaResult(t)
	consumer := &fakeRecordConsumer{fetches: kafkaFetch(record), events: &events}
	store := &fakeDurableStore{events: &events}
	dlq := &orderedPublisher{events: &events}
	ingestor := newTestIngestor(t, consumer, store, dlq)

	processed, err := ingestor.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if processed != 1 || len(store.records) != 1 || len(consumer.committed) != 1 {
		t.Fatalf("processed/store/commit = %d/%d/%d", processed, len(store.records), len(consumer.committed))
	}
	if got, want := events, []string{"poll", "store", "commit", "allow"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
	stored := store.records[0]
	if stored.Topic != record.Topic || stored.Partition != record.Partition || stored.Offset != record.Offset || stored.Digest != EnvelopeDigest(record.Value) {
		t.Fatalf("stored record = %#v", stored)
	}
	if len(dlq.envelopes) != 0 {
		t.Fatalf("published %d DLQ records for valid result", len(dlq.envelopes))
	}
}

func TestResultIngestorDoesNotCommitWhenDurableStoreFails(t *testing.T) {
	events := []string{}
	storeErr := errors.New("database unavailable")
	consumer := &fakeRecordConsumer{fetches: kafkaFetch(validKafkaResult(t)), events: &events}
	store := &fakeDurableStore{events: &events, err: storeErr}
	ingestor := newTestIngestor(t, consumer, store, &orderedPublisher{events: &events})

	_, err := ingestor.RunOnce(context.Background())
	if err == nil || !errors.Is(err, storeErr) {
		t.Fatalf("RunOnce() error = %v, want store error", err)
	}
	if len(consumer.committed) != 0 {
		t.Fatalf("committed %d records after store failure", len(consumer.committed))
	}
	if got, want := events, []string{"poll", "store", "allow"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
}

func TestResultIngestorDLQsInvalidRecordBeforeCommit(t *testing.T) {
	events := []string{}
	record := validKafkaResult(t)
	record.Key = []byte("wrong-key")
	consumer := &fakeRecordConsumer{fetches: kafkaFetch(record), events: &events}
	store := &fakeDurableStore{events: &events}
	dlq := &orderedPublisher{events: &events}
	ingestor := newTestIngestor(t, consumer, store, dlq)

	processed, err := ingestor.RunOnce(context.Background())
	if err != nil || processed != 1 {
		t.Fatalf("RunOnce() = %d, %v", processed, err)
	}
	if got, want := events, []string{"poll", "dlq", "commit", "allow"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
	if len(store.records) != 0 || len(dlq.envelopes) != 1 {
		t.Fatalf("stored/DLQ = %d/%d, want 0/1", len(store.records), len(dlq.envelopes))
	}
	if err := dlq.envelopes[0].Validate(testPolicy()); err != nil {
		t.Fatalf("dead-letter envelope invalid: %v", err)
	}
	if dlq.envelopes[0].DeadLetter.OriginalDigest != EnvelopeDigest(record.Value) {
		t.Fatalf("DLQ digest = %q", dlq.envelopes[0].DeadLetter.OriginalDigest)
	}
}

func TestResultIngestorDoesNotCommitWhenDLQFails(t *testing.T) {
	record := validKafkaResult(t)
	record.Value = []byte(`{"unknown":true}`)
	consumer := &fakeRecordConsumer{fetches: kafkaFetch(record)}
	dlqErr := errors.New("DLQ unavailable")
	ingestor := newTestIngestor(t, consumer, &fakeDurableStore{}, &orderedPublisher{err: dlqErr})

	_, err := ingestor.RunOnce(context.Background())
	if err == nil || !errors.Is(err, dlqErr) {
		t.Fatalf("RunOnce() error = %v, want DLQ error", err)
	}
	if len(consumer.committed) != 0 {
		t.Fatalf("committed %d records after DLQ failure", len(consumer.committed))
	}
}

func TestResultIngestorCommitFailureReplaysDurablyStoredResult(t *testing.T) {
	events := []string{}
	commitErr := errors.New("commit failed")
	consumer := &fakeRecordConsumer{fetches: kafkaFetch(validKafkaResult(t)), events: &events, commitErr: commitErr}
	store := &fakeDurableStore{events: &events}
	ingestor := newTestIngestor(t, consumer, store, &orderedPublisher{events: &events})

	_, err := ingestor.RunOnce(context.Background())
	if err == nil || !errors.Is(err, commitErr) {
		t.Fatalf("RunOnce() error = %v, want commit error", err)
	}
	if len(store.records) != 1 {
		t.Fatalf("stored %d records before commit error, want 1", len(store.records))
	}
	if got, want := events, []string{"poll", "store", "commit", "allow"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
}

func TestResultIngestorReturnsPartitionFetchErrorWithoutCommit(t *testing.T) {
	fetchErr := errors.New("authorization failed")
	consumer := &fakeRecordConsumer{fetches: kgo.Fetches{{Topics: []kgo.FetchTopic{{
		Topic:      "a2a.results",
		Partitions: []kgo.FetchPartition{{Partition: 1, Err: fetchErr}},
	}}}}}
	ingestor := newTestIngestor(t, consumer, &fakeDurableStore{}, &orderedPublisher{})
	_, err := ingestor.RunOnce(context.Background())
	if err == nil || !errors.Is(err, fetchErr) {
		t.Fatalf("RunOnce() error = %v, want fetch error", err)
	}
	if len(consumer.committed) != 0 {
		t.Fatalf("committed %d records", len(consumer.committed))
	}
}
