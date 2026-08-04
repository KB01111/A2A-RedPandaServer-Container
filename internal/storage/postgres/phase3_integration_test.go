package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/redpanda"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/webhook"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPhase3ArtifactAttachmentIsAtomicOnCreateAndUpdate(t *testing.T) {
	_, pool := newIntegrationStore(t)
	ctx := identityContext("tenant-artifacts", "owner")
	repository, err := NewArtifactStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	owner := artifact.Owner{Issuer: "https://issuer.example.test", Tenant: "tenant-artifacts", Subject: "owner"}
	first := testObjectRecord(owner, "artifact-task", "artifact", 0, "first")
	if err := repository.SaveReadyObject(ctx, first); err != nil {
		t.Fatal(err)
	}
	part := a2a.NewFileURLPart(a2a.URL("https://a2a.example.test/artifacts/"+first.ObjectID), "application/octet-stream")
	part.Metadata = map[string]any{artifact.MetadataObjectID: first.ObjectID}
	task := &a2a.Task{
		ID: "artifact-task", ContextID: "context",
		Status: a2a.TaskStatus{State: a2a.TaskStateWorking},
		Artifacts: []*a2a.Artifact{{ID: "artifact", Parts: []*a2a.Part{part}}},
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	version, err := store.Create(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	assertObjectState(t, pool, first.ObjectID, "attached")

	second := testObjectRecord(owner, "artifact-task", "artifact", 0, "replacement")
	if err := repository.SaveReadyObject(ctx, second); err != nil {
		t.Fatal(err)
	}
	replacementPart := a2a.NewFileURLPart(a2a.URL("https://a2a.example.test/artifacts/"+second.ObjectID), "application/octet-stream")
	replacementPart.Metadata = map[string]any{artifact.MetadataObjectID: second.ObjectID}
	event := &a2a.TaskArtifactUpdateEvent{
		TaskID: "artifact-task", ContextID: "context", Append: false,
		Artifact: &a2a.Artifact{ID: "artifact", Parts: []*a2a.Part{replacementPart}},
	}
	task.Artifacts = []*a2a.Artifact{event.Artifact}
	if _, err := store.Update(ctx, &taskstore.UpdateRequest{Task: task, Event: event, PrevVersion: version}); err != nil {
		t.Fatal(err)
	}
	assertObjectState(t, pool, second.ObjectID, "attached")
}

func TestPhase3WebhookTaskTransactionAndSDKEnqueueAreIdempotent(t *testing.T) {
	_, pool := newIntegrationStore(t)
	ctx := identityContext("tenant-webhook", "owner")
	cipher, err := webhook.NewCredentialCipher(1, map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	policy := webhook.TargetPolicy{}
	pushStore, err := NewPushConfigStore(pool, cipher, policy)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pushStore.Save(ctx, "webhook-task", &a2a.PushConfig{
		ID: "config-1", URL: "https://hooks.example.test/a2a", Token: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewWebhookEventSink(cipher, policy)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, WithTaskEventSink(sink))
	if err != nil {
		t.Fatal(err)
	}
	task := &a2a.Task{ID: "webhook-task", ContextID: "context", Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}
	if _, err := store.Create(ctx, task); err != nil {
		t.Fatal(err)
	}
	repository, err := NewWebhookRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := webhook.NewPushSender(webhook.PushSenderConfig{Repository: repository, CredentialCipher: cipher, TargetPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendPush(ctx, config, task); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM a2a_webhook_outbox WHERE tenant_id = $1 AND task_id = $2`, "tenant-webhook", "webhook-task").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("webhook outbox count = %d, want 1", count)
	}
}

func TestPhase3RedpandaOutboxAndResultReplay(t *testing.T) {
	_, pool := newIntegrationStore(t)
	store, err := NewRedpandaStore(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	message := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("execute"))
	message.ID = "message-1"
	executionID := redpanda.StableExecutionID("tenant-redpanda", "task-1", message.ID)
	commandID := redpanda.StableCommandID(redpanda.KindExecute, executionID)
	envelope := &redpanda.Envelope{
		Schema: redpanda.SchemaV1, Kind: redpanda.KindExecute,
		EventID: redpanda.StableEventID(redpanda.KindExecute, commandID, 0),
		ExecutionID: executionID, CommandID: commandID, TenantID: "tenant-redpanda",
		TaskID: "task-1", ContextID: "context-1", IssuedAt: now, Deadline: &deadline,
		Execute: &redpanda.ExecutePayload{
			Message: message,
			Principal: redpanda.Principal{Issuer: "https://issuer.example.test", Subject: "owner"},
		},
	}
	payload, err := redpanda.MarshalEnvelope(envelope, redpanda.ValidationPolicy{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueCommand(context.Background(), redpanda.NewCommand{
		Envelope: envelope, Topic: "bridge.agent-commands.v1",
		Key: redpanda.RecordKey(envelope.TenantID, envelope.TaskID), Payload: payload,
		Digest: redpanda.EnvelopeDigest(payload), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimCommands(context.Background(), redpanda.CommandClaim{
		WorkerID: "worker", LeaseToken: "lease", Now: now.Add(time.Second), LeaseDuration: time.Minute, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimCommands() = %#v, %v", claimed, err)
	}
	if err := store.MarkCommandPublished(context.Background(), redpanda.CommandCompletion{
		EventID: envelope.EventID, LeaseToken: "lease", Attempt: 1, At: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	result := &redpanda.Envelope{
		Schema: redpanda.SchemaV1, Kind: redpanda.KindCompleted,
		EventID: redpanda.StableEventID(redpanda.KindCompleted, commandID, 1),
		ExecutionID: executionID, CommandID: commandID, TenantID: envelope.TenantID,
		TaskID: envelope.TaskID, ContextID: envelope.ContextID, Sequence: 1,
		IssuedAt: now.Add(3 * time.Second), Result: &redpanda.ResultPayload{},
	}
	resultPayload, err := redpanda.MarshalEnvelope(result, redpanda.ValidationPolicy{Now: func() time.Time { return now.Add(3 * time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreResult(context.Background(), redpanda.ResultRecord{
		Envelope: result, Topic: "bridge.agent-results.v1", Partition: 0, Offset: 1,
		Timestamp: now.Add(3 * time.Second), Key: redpanda.RecordKey(result.TenantID, result.TaskID),
		Digest: redpanda.EnvelopeDigest(resultPayload),
	}); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.Open(context.Background(), redpanda.ResultQuery{
		TenantID: result.TenantID, TaskID: result.TaskID, ContextID: result.ContextID, ExecutionID: result.ExecutionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close()
	got, err := cursor.Next(context.Background())
	if err != nil || got.EventID != result.EventID {
		t.Fatalf("cursor.Next() = %#v, %v", got, err)
	}
}

func testObjectRecord(owner artifact.Owner, taskID, artifactID string, partIndex int, value string) artifact.ObjectRecord {
	digest := sha256.Sum256([]byte(value))
	return artifact.ObjectRecord{
		ObjectID: value + "-object-id", Owner: owner, TaskID: a2a.TaskID(taskID),
		ArtifactID: a2a.ArtifactID(artifactID), PartIndex: partIndex,
		Bucket: "artifacts", Key: "objects/" + value, MediaType: "application/octet-stream",
		Size: int64(len(value)), SHA256: fmt.Sprintf("%x", digest[:]),
	}
}

func assertObjectState(t *testing.T, pool *pgxpool.Pool, objectID, want string) {
	t.Helper()
	var got string
	if err := pool.QueryRow(context.Background(), `SELECT state FROM a2a_artifact_objects WHERE object_id = $1`, objectID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("artifact state = %q, want %q", got, want)
	}
}
