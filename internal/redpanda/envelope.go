// Package redpanda defines the bridge's durable Redpanda command and result
// protocol, plus the franz-go adapters that implement it.
package redpanda

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

const (
	SchemaV1               = "bridge.a2a.redpanda/v1"
	DefaultMaxEnvelopeSize = 1 << 20
	defaultMaxStringSize   = 4096
)

type Kind string

const (
	KindExecute    Kind = "execute"
	KindCancel     Kind = "cancel"
	KindArtifact   Kind = "artifact"
	KindHeartbeat  Kind = "heartbeat"
	KindCompleted  Kind = "completed"
	KindFailed     Kind = "failed"
	KindCanceled   Kind = "canceled"
	KindDeadLetter Kind = "dead_letter"
)

type Principal struct {
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type ExecutePayload struct {
	Message        *a2a.Message   `json:"message"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Extensions     []string       `json:"extensions,omitempty"`
	RelatedTaskIDs []a2a.TaskID   `json:"related_task_ids,omitempty"`
	Principal      Principal      `json:"principal,omitempty"`
}

type CancelPayload struct {
	TargetExecutionID string    `json:"target_execution_id"`
	Extensions        []string  `json:"extensions,omitempty"`
	Principal         Principal `json:"principal,omitempty"`
}

type ResultPayload struct {
	ArtifactID a2a.ArtifactID `json:"artifact_id,omitempty"`
	Parts      []*a2a.Part    `json:"parts,omitempty"`
	LastChunk  bool           `json:"last_chunk,omitempty"`
	ErrorCode  string         `json:"error_code,omitempty"`
}

type DeadLetterPayload struct {
	OriginalTopic  string `json:"original_topic"`
	Partition      int32  `json:"partition"`
	Offset         int64  `json:"offset"`
	Reason         string `json:"reason"`
	OriginalDigest string `json:"original_digest"`
	OriginalValue  []byte `json:"original_value,omitempty"`
}

// Envelope is the only wire format used for bridge commands, worker results,
// and dead-letter records. A payload pointer must be present only for the
// corresponding kind.
type Envelope struct {
	Schema      string     `json:"schema"`
	Kind        Kind       `json:"kind"`
	EventID     string     `json:"event_id"`
	ExecutionID string     `json:"execution_id,omitempty"`
	CommandID   string     `json:"command_id,omitempty"`
	CausationID string     `json:"causation_id,omitempty"`
	TenantID    string     `json:"tenant_id,omitempty"`
	TaskID      a2a.TaskID `json:"task_id,omitempty"`
	ContextID   string     `json:"context_id,omitempty"`
	Sequence    uint64     `json:"sequence,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	TraceParent string     `json:"traceparent,omitempty"`
	TraceState  string     `json:"tracestate,omitempty"`

	Execute    *ExecutePayload    `json:"execute,omitempty"`
	Cancel     *CancelPayload     `json:"cancel,omitempty"`
	Result     *ResultPayload     `json:"result,omitempty"`
	DeadLetter *DeadLetterPayload `json:"dead_letter,omitempty"`
}

type ValidationPolicy struct {
	Now              func() time.Time
	MaxEnvelopeBytes int
	MaxAge           time.Duration
	MaxFutureSkew    time.Duration
	MaxTTL           time.Duration
}

func (p ValidationPolicy) normalized() ValidationPolicy {
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.MaxEnvelopeBytes == 0 {
		p.MaxEnvelopeBytes = DefaultMaxEnvelopeSize
	}
	if p.MaxAge == 0 {
		p.MaxAge = 24 * time.Hour
	}
	if p.MaxFutureSkew == 0 {
		p.MaxFutureSkew = time.Minute
	}
	if p.MaxTTL == 0 {
		p.MaxTTL = 24 * time.Hour
	}
	return p
}

func (p ValidationPolicy) validate() error {
	if p.MaxEnvelopeBytes < 1 || p.MaxAge < 0 || p.MaxFutureSkew < 0 || p.MaxTTL < 0 {
		return errors.New("invalid envelope validation policy")
	}
	return nil
}

func (e *Envelope) Validate(policy ValidationPolicy) error {
	policy = policy.normalized()
	if err := policy.validate(); err != nil {
		return err
	}
	if e == nil {
		return errors.New("envelope is required")
	}
	if e.Schema != SchemaV1 {
		return fmt.Errorf("unsupported envelope schema %q", e.Schema)
	}
	if err := validateIdentifier("event_id", e.EventID); err != nil {
		return err
	}
	if e.IssuedAt.IsZero() {
		return errors.New("issued_at is required")
	}
	now := policy.Now().UTC()
	issuedAt := e.IssuedAt.UTC()
	if issuedAt.After(now.Add(policy.MaxFutureSkew)) {
		return errors.New("issued_at is too far in the future")
	}
	if issuedAt.Before(now.Add(-policy.MaxAge)) {
		return errors.New("issued_at is too old")
	}
	if err := validateOptionalString("traceparent", e.TraceParent); err != nil {
		return err
	}
	if err := validateOptionalString("tracestate", e.TraceState); err != nil {
		return err
	}

	payloadCount := boolInt(e.Execute != nil) + boolInt(e.Cancel != nil) + boolInt(e.Result != nil) + boolInt(e.DeadLetter != nil)
	if payloadCount != 1 {
		return errors.New("exactly one envelope payload is required")
	}
	if e.Kind == KindDeadLetter {
		return e.validateDeadLetter()
	}
	if err := validateIdentifier("execution_id", e.ExecutionID); err != nil {
		return err
	}
	if err := validateIdentifier("command_id", e.CommandID); err != nil {
		return err
	}
	if err := validateIdentifier("tenant_id", e.TenantID); err != nil {
		return err
	}
	if err := validateIdentifier("task_id", string(e.TaskID)); err != nil {
		return err
	}
	if err := validateOptionalString("context_id", e.ContextID); err != nil {
		return err
	}
	if err := validateOptionalString("causation_id", e.CausationID); err != nil {
		return err
	}

	switch e.Kind {
	case KindExecute, KindCancel:
		if e.Sequence != 0 {
			return errors.New("command sequence must be zero")
		}
		if e.Deadline == nil {
			return errors.New("command deadline is required")
		}
		deadline := e.Deadline.UTC()
		if !deadline.After(issuedAt) {
			return errors.New("command deadline must be after issued_at")
		}
		if deadline.After(issuedAt.Add(policy.MaxTTL)) {
			return errors.New("command deadline exceeds maximum TTL")
		}
		if deadline.Before(now) {
			return errors.New("command deadline has expired")
		}
		return e.validateCommand()
	case KindArtifact, KindHeartbeat, KindCompleted, KindFailed, KindCanceled:
		if e.Sequence == 0 {
			return errors.New("result sequence must be greater than zero")
		}
		if e.Deadline != nil {
			return errors.New("result deadline must be empty")
		}
		return e.validateResult()
	default:
		return fmt.Errorf("unsupported envelope kind %q", e.Kind)
	}
}

func (e *Envelope) validateCommand() error {
	switch e.Kind {
	case KindExecute:
		if e.Execute == nil || e.Cancel != nil || e.Result != nil || e.DeadLetter != nil {
			return errors.New("execute kind requires only an execute payload")
		}
		if e.Execute.Message == nil {
			return errors.New("execute message is required")
		}
		if err := validateIdentifier("message_id", e.Execute.Message.ID); err != nil {
			return err
		}
		return validatePrincipal(e.Execute.Principal)
	case KindCancel:
		if e.Cancel == nil || e.Execute != nil || e.Result != nil || e.DeadLetter != nil {
			return errors.New("cancel kind requires only a cancel payload")
		}
		if e.Cancel.TargetExecutionID != e.ExecutionID {
			return errors.New("cancel target_execution_id must match execution_id")
		}
		return validatePrincipal(e.Cancel.Principal)
	default:
		return errors.New("not a command kind")
	}
}

func (e *Envelope) validateResult() error {
	if e.Result == nil || e.Execute != nil || e.Cancel != nil || e.DeadLetter != nil {
		return errors.New("result kind requires only a result payload")
	}
	switch e.Kind {
	case KindArtifact:
		if len(e.Result.Parts) == 0 {
			return errors.New("artifact result requires at least one part")
		}
		if e.Result.ErrorCode != "" {
			return errors.New("artifact result cannot contain an error code")
		}
	case KindFailed:
		if err := validateIdentifier("error_code", e.Result.ErrorCode); err != nil {
			return err
		}
		if len(e.Result.Parts) != 0 || e.Result.ArtifactID != "" || e.Result.LastChunk {
			return errors.New("failed result cannot contain artifact fields")
		}
	case KindHeartbeat, KindCompleted, KindCanceled:
		if len(e.Result.Parts) != 0 || e.Result.ArtifactID != "" || e.Result.LastChunk || e.Result.ErrorCode != "" {
			return fmt.Errorf("%s result cannot contain artifact or error fields", e.Kind)
		}
	default:
		return fmt.Errorf("unsupported result kind %q", e.Kind)
	}
	return nil
}

func (e *Envelope) validateDeadLetter() error {
	if e.DeadLetter == nil || e.Execute != nil || e.Cancel != nil || e.Result != nil {
		return errors.New("dead_letter kind requires only a dead_letter payload")
	}
	if e.Sequence != 0 || e.Deadline != nil {
		return errors.New("dead-letter sequence and deadline must be empty")
	}
	if e.ExecutionID != "" || e.CommandID != "" || e.CausationID != "" || e.TenantID != "" || e.TaskID != "" || e.ContextID != "" {
		return errors.New("dead-letter correlation fields must be empty")
	}
	if e.DeadLetter.Partition < 0 || e.DeadLetter.Offset < 0 {
		return errors.New("dead-letter broker position is invalid")
	}
	if err := validateIdentifier("original_topic", e.DeadLetter.OriginalTopic); err != nil {
		return err
	}
	if err := validateIdentifier("dead_letter reason", e.DeadLetter.Reason); err != nil {
		return err
	}
	if len(e.DeadLetter.OriginalDigest) != sha256.Size*2 {
		return errors.New("dead-letter original_digest must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(e.DeadLetter.OriginalDigest); err != nil {
		return errors.New("dead-letter original_digest must be a SHA-256 hex digest")
	}
	return nil
}

func MarshalEnvelope(envelope *Envelope, policy ValidationPolicy) ([]byte, error) {
	policy = policy.normalized()
	if err := envelope.Validate(policy); err != nil {
		return nil, err
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	if len(data) > policy.MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope exceeds %d bytes", policy.MaxEnvelopeBytes)
	}
	return data, nil
}

func DecodeEnvelope(data []byte, policy ValidationPolicy) (*Envelope, error) {
	policy = policy.normalized()
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("envelope is empty")
	}
	if len(data) > policy.MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope exceeds %d bytes", policy.MaxEnvelopeBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("decode envelope: trailing JSON value")
		}
		return nil, fmt.Errorf("decode envelope trailing data: %w", err)
	}
	if err := envelope.Validate(policy); err != nil {
		return nil, err
	}
	return &envelope, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode envelope: trailing JSON value")
		}
		return fmt.Errorf("decode envelope trailing data: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

// StableDigest hashes length-prefixed values so the digest is stable and
// unambiguous across processes and languages.
func StableDigest(domain string, values ...string) string {
	hash := sha256.New()
	writeDigestPart(hash, domain)
	for _, value := range values {
		writeDigestPart(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func EnvelopeDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func StableExecutionID(tenantID string, taskID a2a.TaskID, messageID string) string {
	return StableDigest("execution/v1", tenantID, string(taskID), messageID)
}

func StableCommandID(kind Kind, executionID string) string {
	return StableDigest("command/v1", string(kind), executionID)
}

func StableEventID(kind Kind, commandID string, sequence uint64) string {
	return StableDigest("event/v1", string(kind), commandID, fmt.Sprintf("%d", sequence))
}

func RecordKey(tenantID string, taskID a2a.TaskID) []byte {
	return []byte(StableDigest("record-key/v1", tenantID, string(taskID)))
}

func writeDigestPart(dst io.Writer, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = dst.Write(size[:])
	_, _ = io.WriteString(dst, value)
}

func validatePrincipal(principal Principal) error {
	if err := validateOptionalString("principal issuer", principal.Issuer); err != nil {
		return err
	}
	return validateOptionalString("principal subject", principal.Subject)
}

func validateIdentifier(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	return validateOptionalString(name, value)
}

func validateOptionalString(name, value string) error {
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s cannot have surrounding whitespace", name)
	}
	if len(value) > defaultMaxStringSize {
		return fmt.Errorf("%s exceeds %d bytes", name, defaultMaxStringSize)
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
