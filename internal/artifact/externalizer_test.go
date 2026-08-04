package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/s3store"
	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestExternalizerKeepsSmallRawAndExternalizesThresholdPart(t *testing.T) {
	store := &fakeObjectStore{}
	externalizer, err := NewExternalizer(store, "https://a2a.example.test/base/", Policy{})
	if err != nil {
		t.Fatalf("NewExternalizer() error = %v", err)
	}
	owner := Owner{Issuer: "https://issuer.example.test", Tenant: "tenant/secret", Subject: "user-1"}
	session, err := externalizer.NewSession(owner, "task/1", nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	small := a2a.NewRawPart(make([]byte, defaultInlinePartBytes-1))
	large := a2a.NewRawPart(make([]byte, defaultInlinePartBytes))
	large.Filename = "report.pdf"
	large.MediaType = "application/pdf"
	large.Metadata = map[string]any{"source": "worker"}
	event := &a2a.TaskArtifactUpdateEvent{
		TaskID:    "task/1",
		ContextID: "context-1",
		Artifact:  &a2a.Artifact{ID: "artifact/1", Parts: a2a.ContentParts{small, large}},
	}
	result, err := session.ExternalizeEvent(t.Context(), event)
	if err != nil {
		t.Fatalf("ExternalizeEvent() error = %v", err)
	}
	if len(result.Objects) != 1 || len(store.puts) != 1 {
		t.Fatalf("objects = %#v, puts = %d", result.Objects, len(store.puts))
	}
	if _, ok := result.Event.Artifact.Parts[0].Content.(a2a.Raw); !ok {
		t.Fatalf("small part content = %T", result.Event.Artifact.Parts[0].Content)
	}
	urlPart := result.Event.Artifact.Parts[1]
	if urlPart.URL() == "" || string(urlPart.URL()) != "https://a2a.example.test/base/artifacts/"+result.Objects[0].ObjectID {
		t.Fatalf("stable URL = %q", urlPart.URL())
	}
	if strings.Contains(string(urlPart.URL()), "?") || urlPart.Filename != "report.pdf" || urlPart.MediaType != "application/pdf" {
		t.Fatalf("URL part = %#v", urlPart)
	}
	if urlPart.Metadata[MetadataObjectID] != result.Objects[0].ObjectID || urlPart.Metadata[MetadataSize] != defaultInlinePartBytes {
		t.Fatalf("URL metadata = %#v", urlPart.Metadata)
	}
	if _, ok := event.Artifact.Parts[1].Content.(a2a.Raw); !ok {
		t.Fatal("ExternalizeEvent() mutated the source event")
	}
	put := store.puts[0]
	if strings.Contains(put.Key, owner.Issuer) || strings.Contains(put.Key, owner.Tenant) || strings.Contains(put.Key, owner.Subject) {
		t.Fatalf("object key contains raw owner data: %q", put.Key)
	}
	if put.Metadata["part-index"] != "1" || put.Metadata["scope-hash"] == "" {
		t.Fatalf("S3 metadata = %#v", put.Metadata)
	}
}

func TestExternalizerEnforcesArtifactAndTaskBudgets(t *testing.T) {
	store := &fakeObjectStore{}
	externalizer, err := NewExternalizer(store, "http://localhost:8080", Policy{
		InlinePartBytes: 10, InlineArtifactBytes: 12, InlineTaskBytes: 16, MaxRawPartBytes: 20,
	})
	if err != nil {
		t.Fatalf("NewExternalizer() error = %v", err)
	}
	session, err := externalizer.NewSession(testOwner(), "task-1", nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	first := artifactEvent("task-1", "artifact-1", false, make([]byte, 8))
	firstResult, err := session.ExternalizeEvent(t.Context(), first)
	if err != nil || len(firstResult.Objects) != 0 {
		t.Fatalf("first result = %#v, error = %v", firstResult, err)
	}
	artifactBudget := artifactEvent("task-1", "artifact-1", true, make([]byte, 5))
	artifactResult, err := session.ExternalizeEvent(t.Context(), artifactBudget)
	if err != nil || len(artifactResult.Objects) != 1 {
		t.Fatalf("artifact budget result = %#v, error = %v", artifactResult, err)
	}
	taskBudget := artifactEvent("task-1", "artifact-2", false, make([]byte, 9))
	taskResult, err := session.ExternalizeEvent(t.Context(), taskBudget)
	if err != nil || len(taskResult.Objects) != 1 {
		t.Fatalf("task budget result = %#v, error = %v", taskResult, err)
	}
	replacement := artifactEvent("task-1", "artifact-1", false, make([]byte, 5))
	replacementResult, err := session.ExternalizeEvent(t.Context(), replacement)
	if err != nil || len(replacementResult.Objects) != 0 {
		t.Fatalf("replacement result = %#v, error = %v", replacementResult, err)
	}
}

func TestExternalizerInitializesResumeBudgetAndHardCap(t *testing.T) {
	store := &fakeObjectStore{}
	externalizer, err := NewExternalizer(store, "https://a2a.example.test", Policy{
		InlinePartBytes: 10, InlineArtifactBytes: 12, InlineTaskBytes: 16, MaxRawPartBytes: 20,
	})
	if err != nil {
		t.Fatalf("NewExternalizer() error = %v", err)
	}
	existing := []*a2a.Artifact{{ID: "artifact-1", Parts: a2a.ContentParts{a2a.NewRawPart(make([]byte, 8))}}}
	session, err := externalizer.NewSession(testOwner(), "task-1", existing)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	result, err := session.ExternalizeEvent(t.Context(), artifactEvent("task-1", "artifact-1", true, make([]byte, 5)))
	if err != nil || len(result.Objects) != 1 || result.Objects[0].PartIndex != 1 {
		t.Fatalf("resume result = %#v, error = %v", result, err)
	}
	if _, err := session.ExternalizeEvent(t.Context(), artifactEvent("task-1", "artifact-2", false, make([]byte, 21))); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("hard-cap error = %v", err)
	}

	overBudget := []*a2a.Artifact{{ID: "artifact-1", Parts: a2a.ContentParts{a2a.NewRawPart(make([]byte, 17))}}}
	if _, err := externalizer.NewSession(testOwner(), "task-1", overBudget); err == nil {
		t.Fatal("over-budget existing task unexpectedly accepted")
	}
}

func TestExternalizerReturnsPartialObjectsOnUploadFailure(t *testing.T) {
	store := &fakeObjectStore{failAt: 2}
	externalizer, err := NewExternalizer(store, "https://a2a.example.test", Policy{
		InlinePartBytes: 1, InlineArtifactBytes: 2, InlineTaskBytes: 2, MaxRawPartBytes: 10,
	})
	if err != nil {
		t.Fatalf("NewExternalizer() error = %v", err)
	}
	session, err := externalizer.NewSession(testOwner(), "task-1", nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	event := &a2a.TaskArtifactUpdateEvent{
		TaskID: "task-1",
		Artifact: &a2a.Artifact{ID: "artifact-1", Parts: a2a.ContentParts{
			a2a.NewRawPart([]byte("a")), a2a.NewRawPart([]byte("b")),
		}},
	}
	result, err := session.ExternalizeEvent(t.Context(), event)
	if err == nil || len(result.Objects) != 1 {
		t.Fatalf("partial result = %#v, error = %v", result, err)
	}
	store.failAt = 0
	retryResult, err := session.ExternalizeEvent(t.Context(), event)
	if err != nil || len(retryResult.Objects) != 2 || retryResult.Objects[0].PartIndex != 0 || retryResult.Objects[1].PartIndex != 1 {
		t.Fatalf("retry result = %#v, error = %v", retryResult, err)
	}
}

func TestDeriveObjectLocationIsDeterministicAndScoped(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	owner := testOwner()
	firstID, firstKey, err := DeriveObjectLocation(owner, "task/1", "artifact/1", 7, digest)
	if err != nil {
		t.Fatalf("DeriveObjectLocation() error = %v", err)
	}
	secondID, secondKey, _ := DeriveObjectLocation(owner, "task/1", "artifact/1", 7, digest)
	if firstID != secondID || firstKey != secondKey {
		t.Fatalf("location is not deterministic: %q/%q versus %q/%q", firstID, firstKey, secondID, secondKey)
	}
	decodedID, err := base64.RawURLEncoding.DecodeString(firstID)
	if err != nil || len(decodedID) != sha256.Size {
		t.Fatalf("opaque ID = %q", firstID)
	}
	other := owner
	other.Tenant = "tenant-2"
	otherID, otherKey, _ := DeriveObjectLocation(other, "task/1", "artifact/1", 7, digest)
	if otherID == firstID || otherKey == firstKey {
		t.Fatal("tenant change did not alter object location")
	}
	if !strings.Contains(firstKey, base64.RawURLEncoding.EncodeToString([]byte("task/1"))) ||
		!strings.Contains(firstKey, base64.RawURLEncoding.EncodeToString([]byte("artifact/1"))) {
		t.Fatalf("key does not contain encoded IDs: %q", firstKey)
	}
}

func artifactEvent(taskID a2a.TaskID, artifactID a2a.ArtifactID, appendPart bool, raw []byte) *a2a.TaskArtifactUpdateEvent {
	return &a2a.TaskArtifactUpdateEvent{
		TaskID: taskID,
		Append: appendPart,
		Artifact: &a2a.Artifact{ID: artifactID, Parts: a2a.ContentParts{
			a2a.NewRawPart(raw),
		}},
	}
}

func testOwner() Owner {
	return Owner{Issuer: "https://issuer.example.test", Tenant: "tenant-1", Subject: "user-1"}
}

type fakeObjectStore struct {
	puts       []s3store.PutRequest
	deletes    []string
	presignKey string
	presigned  s3store.PresignedGet
	failAt     int
	putErr     error
	presignErr error
}

func (f *fakeObjectStore) Put(_ context.Context, request s3store.PutRequest) (s3store.Object, error) {
	f.puts = append(f.puts, request)
	if f.putErr != nil || (f.failAt > 0 && len(f.puts) == f.failAt) {
		if f.putErr != nil {
			return s3store.Object{}, f.putErr
		}
		return s3store.Object{}, errors.New("put failed")
	}
	digest := sha256.Sum256(request.Body)
	return s3store.Object{
		Bucket: "bridge-artifacts", Key: request.Key, Size: int64(len(request.Body)), SHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func (f *fakeObjectStore) Delete(_ context.Context, key string) error {
	f.deletes = append(f.deletes, key)
	return nil
}

func (f *fakeObjectStore) PresignGet(_ context.Context, key string) (s3store.PresignedGet, error) {
	f.presignKey = key
	if f.presignErr != nil {
		return s3store.PresignedGet{}, f.presignErr
	}
	if f.presigned.URL == "" {
		f.presigned = s3store.PresignedGet{URL: "https://objects.example.test/signed", ExpiresAt: time.Now().Add(time.Minute)}
	}
	return f.presigned, nil
}

var _ s3store.ObjectStore = (*fakeObjectStore)(nil)
