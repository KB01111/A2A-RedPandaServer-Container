package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ArtifactStore persists the authoritative object metadata separately from
// S3. Newly uploaded objects are not resolvable until a task update attaches
// them in the same PostgreSQL transaction as the URL-bearing A2A event.
type ArtifactStore struct {
	pool *pgxpool.Pool
}

var _ artifact.ObjectRepository = (*ArtifactStore)(nil)

func NewArtifactStore(pool *pgxpool.Pool) (*ArtifactStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &ArtifactStore{pool: pool}, nil
}

func (s *ArtifactStore) SaveReadyObject(ctx context.Context, record artifact.ObjectRecord) error {
	if err := validateObjectRecord(record); err != nil {
		return err
	}
	var objectID string
	err := s.pool.QueryRow(ctx, `
INSERT INTO a2a_artifact_objects (
    object_id, tenant_id, owner_issuer, owner_subject, task_id, artifact_id,
    part_index, bucket, object_key, version_id, etag, media_type, filename,
    size_bytes, sha256_hex
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (object_id) DO UPDATE SET object_id = EXCLUDED.object_id
WHERE a2a_artifact_objects.tenant_id = EXCLUDED.tenant_id
  AND a2a_artifact_objects.owner_issuer = EXCLUDED.owner_issuer
  AND a2a_artifact_objects.owner_subject = EXCLUDED.owner_subject
  AND a2a_artifact_objects.task_id = EXCLUDED.task_id
  AND a2a_artifact_objects.artifact_id = EXCLUDED.artifact_id
  AND a2a_artifact_objects.part_index = EXCLUDED.part_index
  AND a2a_artifact_objects.bucket = EXCLUDED.bucket
  AND a2a_artifact_objects.object_key = EXCLUDED.object_key
  AND a2a_artifact_objects.version_id = EXCLUDED.version_id
  AND a2a_artifact_objects.etag = EXCLUDED.etag
  AND a2a_artifact_objects.media_type = EXCLUDED.media_type
  AND a2a_artifact_objects.filename = EXCLUDED.filename
  AND a2a_artifact_objects.size_bytes = EXCLUDED.size_bytes
  AND a2a_artifact_objects.sha256_hex = EXCLUDED.sha256_hex
  AND a2a_artifact_objects.state <> 'deleted'
RETURNING object_id`,
		record.ObjectID, record.Owner.Tenant, record.Owner.Issuer, record.Owner.Subject,
		string(record.TaskID), string(record.ArtifactID), record.PartIndex, record.Bucket,
		record.Key, record.VersionID, record.ETag, record.MediaType, record.Filename,
		record.Size, strings.ToLower(record.SHA256),
	).Scan(&objectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("artifact object identifier conflicts with different immutable metadata")
	}
	if err != nil {
		return fmt.Errorf("save artifact object: %w", err)
	}
	return nil
}

func (s *ArtifactStore) FindObject(ctx context.Context, objectID string) (artifact.ObjectRecord, error) {
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return artifact.ObjectRecord{}, artifact.ErrObjectNotFound
	}
	var record artifact.ObjectRecord
	record.ObjectID = objectID
	err = s.pool.QueryRow(ctx, `
SELECT tenant_id, owner_issuer, owner_subject, task_id, artifact_id, part_index,
       bucket, object_key, version_id, etag, media_type, filename, size_bytes,
       sha256_hex, state = 'attached'
FROM a2a_artifact_objects
WHERE object_id = $1 AND tenant_id = $2 AND owner_issuer = $3 AND owner_subject = $4
  AND state = 'attached'`, objectID, identity.Tenant, identity.Issuer, identity.Subject,
	).Scan(
		&record.Owner.Tenant, &record.Owner.Issuer, &record.Owner.Subject,
		&record.TaskID, &record.ArtifactID, &record.PartIndex, &record.Bucket,
		&record.Key, &record.VersionID, &record.ETag, &record.MediaType,
		&record.Filename, &record.Size, &record.SHA256, &record.Attached,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return artifact.ObjectRecord{}, artifact.ErrObjectNotFound
	}
	if err != nil {
		return artifact.ObjectRecord{}, fmt.Errorf("find artifact object: %w", err)
	}
	return record, nil
}

func attachArtifactObjects(ctx context.Context, tx pgx.Tx, identityOwner artifact.Owner, taskID a2a.TaskID, event a2a.Event) error {
	return attachObjectIDs(ctx, tx, identityOwner, taskID, artifactObjectIDs(event))
}

func attachTaskArtifactObjects(ctx context.Context, tx pgx.Tx, identityOwner artifact.Owner, task *a2a.Task) error {
	if task == nil {
		return nil
	}
	seen := make(map[string]struct{})
	objectIDs := make([]string, 0)
	for _, taskArtifact := range task.Artifacts {
		if taskArtifact == nil {
			continue
		}
		for _, part := range taskArtifact.Parts {
			appendArtifactObjectID(&objectIDs, seen, part)
		}
	}
	return attachObjectIDs(ctx, tx, identityOwner, task.ID, objectIDs)
}

func attachObjectIDs(ctx context.Context, tx pgx.Tx, identityOwner artifact.Owner, taskID a2a.TaskID, objectIDs []string) error {
	if len(objectIDs) == 0 {
		return nil
	}
	commandTag, err := tx.Exec(ctx, `
UPDATE a2a_artifact_objects
SET state = 'attached', attached_at = COALESCE(attached_at, clock_timestamp()), delete_after = 'infinity'
WHERE object_id = ANY($1::text[])
  AND tenant_id = $2 AND owner_issuer = $3 AND owner_subject = $4 AND task_id = $5
  AND state IN ('ready', 'attached')`, objectIDs, identityOwner.Tenant, identityOwner.Issuer,
		identityOwner.Subject, string(taskID))
	if err != nil {
		return fmt.Errorf("attach artifact objects: %w", err)
	}
	if commandTag.RowsAffected() != int64(len(objectIDs)) {
		return fmt.Errorf("attach artifact objects: one or more object references are missing or outside task ownership")
	}
	return nil
}

func artifactObjectIDs(event a2a.Event) []string {
	update, ok := event.(*a2a.TaskArtifactUpdateEvent)
	if !ok || update == nil || update.Artifact == nil {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, part := range update.Artifact.Parts {
		appendArtifactObjectID(&result, seen, part)
	}
	return result
}

func appendArtifactObjectID(result *[]string, seen map[string]struct{}, part *a2a.Part) {
	if part == nil || part.Metadata == nil {
		return
	}
	value, ok := part.Metadata[artifact.MetadataObjectID].(string)
	if !ok || value == "" {
		return
	}
	if _, duplicate := seen[value]; duplicate {
		return
	}
	seen[value] = struct{}{}
	*result = append(*result, value)
}

func validateObjectRecord(record artifact.ObjectRecord) error {
	for name, value := range map[string]string{
		"object ID": record.ObjectID, "issuer": record.Owner.Issuer,
		"tenant": record.Owner.Tenant, "subject": record.Owner.Subject,
		"task ID": string(record.TaskID), "artifact ID": string(record.ArtifactID),
		"bucket": record.Bucket, "object key": record.Key,
	} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("artifact %s is invalid", name)
		}
	}
	if record.PartIndex < 0 || record.Size < 0 || len(record.SHA256) != 64 {
		return fmt.Errorf("artifact object metadata is invalid")
	}
	return nil
}
