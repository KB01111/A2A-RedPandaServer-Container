package redpanda

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeSyncProducer struct {
	records []*kgo.Record
	err     error
}

func (producer *fakeSyncProducer) ProduceSync(_ context.Context, records ...*kgo.Record) kgo.ProduceResults {
	producer.records = append(producer.records, records...)
	results := make(kgo.ProduceResults, 0, len(records))
	for _, record := range records {
		results = append(results, kgo.ProduceResult{Record: record, Err: producer.err})
	}
	return results
}

func testTopics() Topics {
	return Topics{Commands: "a2a.commands", Results: "a2a.results", DeadLetter: "a2a.dlq"}
}

func TestPublisherBuildsKeyedSynchronousRecord(t *testing.T) {
	producer := &fakeSyncProducer{}
	publisher, err := NewPublisher(producer, testTopics(), testPolicy())
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	envelope := validExecuteEnvelope()
	if err := publisher.Publish(context.Background(), envelope); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if len(producer.records) != 1 {
		t.Fatalf("produced %d records, want 1", len(producer.records))
	}
	record := producer.records[0]
	if record.Topic != testTopics().Commands {
		t.Fatalf("record topic = %q, want command topic", record.Topic)
	}
	if !bytes.Equal(record.Key, RecordKey(envelope.TenantID, envelope.TaskID)) {
		t.Fatalf("record key = %q, want stable tenant/task key", record.Key)
	}
	decoded, err := DecodeEnvelope(record.Value, testPolicy())
	if err != nil || decoded.EventID != envelope.EventID {
		t.Fatalf("produced envelope = %#v, %v", decoded, err)
	}
	wantHeaders := map[string]string{
		headerSchema: SchemaV1, headerKind: string(KindExecute), headerEventID: envelope.EventID, headerExecutionID: envelope.ExecutionID,
	}
	for _, header := range record.Headers {
		delete(wantHeaders, header.Key)
	}
	if len(wantHeaders) != 0 {
		t.Fatalf("missing record headers: %v", wantHeaders)
	}
}

func TestPublisherRoutesResultsAndPropagatesProduceError(t *testing.T) {
	producer := &fakeSyncProducer{err: errors.New("broker unavailable")}
	publisher, err := NewPublisher(producer, testTopics(), testPolicy())
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	err = publisher.Publish(context.Background(), validResultEnvelope(KindHeartbeat, 1))
	if err == nil || !errors.Is(err, producer.err) {
		t.Fatalf("Publish() error = %v, want producer error", err)
	}
	if got := producer.records[0].Topic; got != testTopics().Results {
		t.Fatalf("result record topic = %q", got)
	}
}

func TestPublisherRejectsInvalidEnvelopeBeforeProducing(t *testing.T) {
	producer := &fakeSyncProducer{}
	publisher, err := NewPublisher(producer, testTopics(), testPolicy())
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	envelope := validExecuteEnvelope()
	envelope.TenantID = ""
	if err := publisher.Publish(context.Background(), envelope); err == nil {
		t.Fatal("Publish() error = nil, want validation error")
	}
	if len(producer.records) != 0 {
		t.Fatalf("produced %d records after validation failure", len(producer.records))
	}
}
