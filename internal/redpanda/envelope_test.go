package redpanda

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

var testNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func testPolicy() ValidationPolicy {
	return ValidationPolicy{Now: func() time.Time { return testNow }}
}

func validExecuteEnvelope() *Envelope {
	deadline := testNow.Add(time.Minute)
	return &Envelope{
		Schema:      SchemaV1,
		Kind:        KindExecute,
		EventID:     "event-1",
		ExecutionID: "execution-1",
		CommandID:   "command-1",
		TenantID:    "tenant-1",
		TaskID:      "task-1",
		ContextID:   "context-1",
		IssuedAt:    testNow,
		Deadline:    &deadline,
		Execute: &ExecutePayload{
			Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
		},
	}
}

func validResultEnvelope(kind Kind, sequence uint64) *Envelope {
	result := &ResultPayload{}
	if kind == KindArtifact {
		result.ArtifactID = "artifact-1"
		result.Parts = []*a2a.Part{a2a.NewTextPart("chunk")}
	}
	if kind == KindFailed {
		result.ErrorCode = "worker_failed"
	}
	return &Envelope{
		Schema:      SchemaV1,
		Kind:        kind,
		EventID:     StableEventID(kind, "command-1", sequence),
		ExecutionID: "execution-1",
		CommandID:   "command-1",
		TenantID:    "tenant-1",
		TaskID:      "task-1",
		ContextID:   "context-1",
		Sequence:    sequence,
		IssuedAt:    testNow,
		Result:      result,
	}
}

func TestEnvelopeRoundTripStrict(t *testing.T) {
	original := validExecuteEnvelope()
	data, err := MarshalEnvelope(original, testPolicy())
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}
	decoded, err := DecodeEnvelope(data, testPolicy())
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if decoded.EventID != original.EventID || decoded.Execute.Message.ID != original.Execute.Message.ID {
		t.Fatalf("decoded envelope = %#v, want identifiers from %#v", decoded, original)
	}

	unknown := bytes.Replace(data, []byte(`"schema"`), []byte(`"unknown":true,"schema"`), 1)
	if _, err := DecodeEnvelope(unknown, testPolicy()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeEnvelope(unknown) error = %v, want unknown field", err)
	}
	if _, err := DecodeEnvelope(append(data, []byte(" {}")...), testPolicy()); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("DecodeEnvelope(trailing) error = %v, want trailing data", err)
	}
	duplicate := bytes.Replace(data, []byte(`"event_id":"event-1"`), []byte(`"event_id":"event-1","event_id":"event-2"`), 1)
	if _, err := DecodeEnvelope(duplicate, testPolicy()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("DecodeEnvelope(duplicate) error = %v, want duplicate key", err)
	}
	if _, err := DecodeEnvelope(data, ValidationPolicy{Now: func() time.Time { return testNow }, MaxEnvelopeBytes: 8}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("DecodeEnvelope(oversize) error = %v, want size error", err)
	}
}

func TestEnvelopeValidationRejectsInvalidPayloadAndTime(t *testing.T) {
	tests := map[string]func(*Envelope){
		"unsupported schema": func(e *Envelope) { e.Schema = "v2" },
		"missing tenant":     func(e *Envelope) { e.TenantID = "" },
		"payload mismatch": func(e *Envelope) {
			e.Kind = KindCancel
		},
		"expired deadline": func(e *Envelope) {
			deadline := testNow.Add(-time.Second)
			e.Deadline = &deadline
		},
		"future issued_at": func(e *Envelope) {
			e.IssuedAt = testNow.Add(2 * time.Minute)
			deadline := e.IssuedAt.Add(time.Minute)
			e.Deadline = &deadline
		},
		"too old": func(e *Envelope) {
			e.IssuedAt = testNow.Add(-25 * time.Hour)
			deadline := testNow.Add(time.Minute)
			e.Deadline = &deadline
		},
		"sequence on command": func(e *Envelope) { e.Sequence = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := validExecuteEnvelope()
			mutate(envelope)
			if err := envelope.Validate(testPolicy()); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestResultValidation(t *testing.T) {
	if err := validResultEnvelope(KindArtifact, 1).Validate(testPolicy()); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	if err := validResultEnvelope(KindHeartbeat, 1).Validate(testPolicy()); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	for name, envelope := range map[string]*Envelope{
		"zero sequence":     validResultEnvelope(KindCompleted, 0),
		"artifact no parts": validResultEnvelope(KindArtifact, 1),
		"failed no code":    validResultEnvelope(KindFailed, 1),
		"terminal payload":  validResultEnvelope(KindCompleted, 1),
	} {
		switch name {
		case "artifact no parts":
			envelope.Result.Parts = nil
		case "failed no code":
			envelope.Result.ErrorCode = ""
		case "terminal payload":
			envelope.Result.Parts = []*a2a.Part{a2a.NewTextPart("not allowed")}
		}
		t.Run(name, func(t *testing.T) {
			if err := envelope.Validate(testPolicy()); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestStableHelpersAreDeterministicAndUnambiguous(t *testing.T) {
	first := StableDigest("domain", "ab", "c")
	if got := StableDigest("domain", "ab", "c"); got != first {
		t.Fatalf("StableDigest() = %q, want %q", got, first)
	}
	if ambiguous := StableDigest("domain", "a", "bc"); ambiguous == first {
		t.Fatal("length-prefixed digest collided for different fields")
	}
	if got, want := string(RecordKey("tenant-1", "task-1")), StableDigest("record-key/v1", "tenant-1", "task-1"); got != want {
		t.Fatalf("RecordKey() = %q, want %q", got, want)
	}
}
