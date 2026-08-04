package artifact

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/s3store"
)

// ErrObjectNotFound is returned for absent, unattached, and cross-owner object
// references so the resolver cannot act as a tenant existence oracle.
var ErrObjectNotFound = errors.New("artifact object not found")

// ObjectRepository loads the internal record for an opaque object ID. Resolver
// performs the authoritative owner comparison even if a repository also scopes
// its query for defense in depth.
type ObjectRepository interface {
	FindObject(context.Context, string) (ObjectRecord, error)
}

// Presigner is the narrow S3 capability required by Resolver.
type Presigner interface {
	PresignGet(context.Context, string) (s3store.PresignedGet, error)
}

// DownloadResolver resolves an authenticated object reference to a fresh,
// short-lived download URL.
type DownloadResolver interface {
	ResolveDownload(context.Context, Owner, string) (Download, error)
}

// Download contains a fresh presign plus non-secret response metadata.
type Download struct {
	Presigned s3store.PresignedGet
	MediaType string
	Filename  string
	Size      int64
	SHA256    string
}

type Resolver struct {
	repository ObjectRepository
	presigner  Presigner
}

func NewResolver(repository ObjectRepository, presigner Presigner) (*Resolver, error) {
	if repository == nil {
		return nil, fmt.Errorf("artifact object repository is required")
	}
	if presigner == nil {
		return nil, fmt.Errorf("artifact presigner is required")
	}
	return &Resolver{repository: repository, presigner: presigner}, nil
}

func (r *Resolver) ResolveDownload(ctx context.Context, owner Owner, objectID string) (Download, error) {
	if err := validateOwner(owner); err != nil {
		return Download{}, err
	}
	if !validObjectID(objectID) {
		return Download{}, ErrObjectNotFound
	}
	record, err := r.repository.FindObject(ctx, objectID)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return Download{}, ErrObjectNotFound
		}
		return Download{}, fmt.Errorf("load artifact object: %w", err)
	}
	if record.ObjectID != objectID || record.Owner != owner || !record.Attached || record.Key == "" {
		return Download{}, ErrObjectNotFound
	}
	presigned, err := r.presigner.PresignGet(ctx, record.Key)
	if err != nil {
		return Download{}, fmt.Errorf("presign artifact object: %w", err)
	}
	return Download{
		Presigned: presigned,
		MediaType: record.MediaType,
		Filename:  record.Filename,
		Size:      record.Size,
		SHA256:    record.SHA256,
	}, nil
}

func validObjectID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
