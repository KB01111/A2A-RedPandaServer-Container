package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/s3store"
)

func TestResolverEnforcesOwnerAndAttachmentBeforePresigning(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	objectID, key, err := DeriveObjectLocation(testOwner(), "task-1", "artifact-1", 0, digest)
	if err != nil {
		t.Fatalf("DeriveObjectLocation() error = %v", err)
	}
	record := ObjectRecord{
		ObjectID: objectID, Owner: testOwner(), Key: key, Attached: true,
		MediaType: "application/pdf", Filename: "report.pdf", Size: 7, SHA256: "digest",
	}
	repository := &fakeRepository{record: record}
	store := &fakeObjectStore{presigned: s3store.PresignedGet{
		URL: "https://objects.example.test/signed", ExpiresAt: time.Unix(2_000_000_000, 0).UTC(),
	}}
	resolver, err := NewResolver(repository, store)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	download, err := resolver.ResolveDownload(t.Context(), testOwner(), objectID)
	if err != nil {
		t.Fatalf("ResolveDownload() error = %v", err)
	}
	if store.presignKey != key || download.Presigned.URL != store.presigned.URL || download.Filename != "report.pdf" {
		t.Fatalf("download = %#v, presign key = %q", download, store.presignKey)
	}

	for _, test := range []struct {
		name   string
		owner  Owner
		mutate func(*ObjectRecord)
	}{
		{name: "different tenant", owner: Owner{Issuer: testOwner().Issuer, Tenant: "tenant-2", Subject: testOwner().Subject}},
		{name: "different subject", owner: Owner{Issuer: testOwner().Issuer, Tenant: testOwner().Tenant, Subject: "user-2"}},
		{name: "unattached", owner: testOwner(), mutate: func(record *ObjectRecord) { record.Attached = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := record
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			repository.record = candidate
			store.presignKey = ""
			if _, err := resolver.ResolveDownload(t.Context(), test.owner, objectID); !errors.Is(err, ErrObjectNotFound) {
				t.Fatalf("ResolveDownload() error = %v", err)
			}
			if store.presignKey != "" {
				t.Fatalf("unauthorized request presigned %q", store.presignKey)
			}
		})
	}
}

func TestResolverUsesStableNotFoundAndPropagatesInfrastructureErrors(t *testing.T) {
	repository := &fakeRepository{err: ErrObjectNotFound}
	store := &fakeObjectStore{}
	resolver, err := NewResolver(repository, store)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	validID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := resolver.ResolveDownload(t.Context(), testOwner(), "invalid"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("invalid ID error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatal("invalid ID reached repository")
	}
	if _, err := resolver.ResolveDownload(t.Context(), testOwner(), validID); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	repository.err = errors.New("database unavailable")
	if _, err := resolver.ResolveDownload(t.Context(), testOwner(), validID); err == nil || errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("infrastructure error = %v", err)
	}
}

func TestResolverReportsPresignFailureWithoutLeakingAsNotFound(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	objectID, key, _ := DeriveObjectLocation(testOwner(), "task-1", "artifact-1", 0, digest)
	repository := &fakeRepository{record: ObjectRecord{ObjectID: objectID, Owner: testOwner(), Key: key, Attached: true}}
	store := &fakeObjectStore{presignErr: errors.New("S3 unavailable")}
	resolver, _ := NewResolver(repository, store)
	if _, err := resolver.ResolveDownload(t.Context(), testOwner(), objectID); err == nil || errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("presign error = %v", err)
	}
}

type fakeRepository struct {
	record ObjectRecord
	err    error
	calls  int
}

func (f *fakeRepository) FindObject(context.Context, string) (ObjectRecord, error) {
	f.calls++
	return f.record, f.err
}

var _ ObjectRepository = (*fakeRepository)(nil)
var _ DownloadResolver = (*Resolver)(nil)
