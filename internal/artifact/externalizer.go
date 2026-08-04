package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/s3store"
	"github.com/a2aproject/a2a-go/v2/a2a"
)

const (
	defaultInlinePartBytes     = int64(64 << 10)
	defaultInlineArtifactBytes = int64(256 << 10)
	defaultInlineTaskBytes     = int64(512 << 10)
	defaultMaxRawPartBytes     = int64(64 << 20)

	MetadataObjectID = "bridge.a2a/object-id"
	MetadataSHA256   = "bridge.a2a/sha256"
	MetadataSize     = "bridge.a2a/size"
)

// Owner is the authoritative identity scope attached to an artifact object.
type Owner struct {
	Issuer  string
	Tenant  string
	Subject string
}

// Policy bounds inline data and individual object uploads.
type Policy struct {
	InlinePartBytes     int64
	InlineArtifactBytes int64
	InlineTaskBytes     int64
	MaxRawPartBytes     int64
}

// ObjectRecord is the persistence hand-off after a successful object upload.
// It contains no presigned URL or credential material.
type ObjectRecord struct {
	ObjectID   string
	Owner      Owner
	TaskID     a2a.TaskID
	ArtifactID a2a.ArtifactID
	PartIndex  int
	Bucket     string
	Key        string
	VersionID  string
	ETag       string
	MediaType  string
	Filename   string
	Size       int64
	SHA256     string
	Attached   bool
}

// ExternalizeResult contains the safe event plus uploaded records. Objects may
// be non-empty when Err is non-nil so callers can reconcile partial uploads.
type ExternalizeResult struct {
	Event   *a2a.TaskArtifactUpdateEvent
	Objects []ObjectRecord
}

// Externalizer creates one per-execution Session. The session owns budgets and
// deterministic part ordinals, so Externalizer itself is concurrency-safe.
type Externalizer struct {
	store      s3store.ObjectStore
	publicBase *url.URL
	policy     Policy
}

// Session tracks inline budgets for one task execution. It is not safe for
// concurrent use.
type Session struct {
	externalizer   *Externalizer
	owner          Owner
	taskID         a2a.TaskID
	artifactInline map[a2a.ArtifactID]int64
	nextPart       map[a2a.ArtifactID]int
	taskInline     int64
}

func NewExternalizer(store s3store.ObjectStore, publicBaseURL string, policy Policy) (*Externalizer, error) {
	if store == nil {
		return nil, fmt.Errorf("artifact object store is required")
	}
	base, err := validatePublicBaseURL(publicBaseURL)
	if err != nil {
		return nil, err
	}
	policy, err = normalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	return &Externalizer{store: store, publicBase: base, policy: policy}, nil
}

// NewSession initializes budgets from the task's already persisted artifacts.
func (e *Externalizer) NewSession(owner Owner, taskID a2a.TaskID, existing []*a2a.Artifact) (*Session, error) {
	if err := validateOwner(owner); err != nil {
		return nil, err
	}
	if err := validateIdentifier("task", string(taskID)); err != nil {
		return nil, err
	}
	session := &Session{
		externalizer:   e,
		owner:          owner,
		taskID:         taskID,
		artifactInline: make(map[a2a.ArtifactID]int64),
		nextPart:       make(map[a2a.ArtifactID]int),
	}
	for _, artifact := range existing {
		if artifact == nil {
			return nil, fmt.Errorf("existing artifact is nil")
		}
		if err := validateIdentifier("artifact", string(artifact.ID)); err != nil {
			return nil, err
		}
		if _, exists := session.nextPart[artifact.ID]; exists {
			return nil, fmt.Errorf("existing task contains duplicate artifact ID %q", artifact.ID)
		}
		var inline int64
		for _, part := range artifact.Parts {
			if part == nil {
				continue
			}
			if raw, ok := part.Content.(a2a.Raw); ok {
				if int64(len(raw)) > e.policy.MaxRawPartBytes {
					return nil, fmt.Errorf("existing raw artifact part exceeds maximum %d", e.policy.MaxRawPartBytes)
				}
				inline += int64(len(raw))
			}
		}
		if inline > e.policy.InlineArtifactBytes {
			return nil, fmt.Errorf("existing artifact inline raw data exceeds maximum %d", e.policy.InlineArtifactBytes)
		}
		session.artifactInline[artifact.ID] = inline
		session.taskInline += inline
		session.nextPart[artifact.ID] = len(artifact.Parts)
	}
	if session.taskInline > e.policy.InlineTaskBytes {
		return nil, fmt.Errorf("existing task inline raw data exceeds maximum %d", e.policy.InlineTaskBytes)
	}
	return session, nil
}

// ExternalizeEvent replaces qualifying Raw parts with stable authenticated URL
// parts. It uploads before returning and never embeds a presigned URL.
func (s *Session) ExternalizeEvent(ctx context.Context, event *a2a.TaskArtifactUpdateEvent) (ExternalizeResult, error) {
	if event == nil || event.Artifact == nil {
		return ExternalizeResult{}, fmt.Errorf("artifact update event and artifact are required")
	}
	if event.TaskID != s.taskID {
		return ExternalizeResult{}, fmt.Errorf("artifact task ID does not match session task")
	}
	if err := validateIdentifier("artifact", string(event.Artifact.ID)); err != nil {
		return ExternalizeResult{}, err
	}
	artifactID := event.Artifact.ID
	taskInline := s.taskInline
	artifactInline := s.artifactInline[artifactID]
	nextPart := s.nextPart[artifactID]
	if !event.Append {
		taskInline -= artifactInline
		artifactInline = 0
		nextPart = 0
	}

	clonedEvent := *event
	clonedEvent.Metadata = maps.Clone(event.Metadata)
	clonedArtifact := *event.Artifact
	clonedArtifact.Extensions = append([]string(nil), event.Artifact.Extensions...)
	clonedArtifact.Metadata = maps.Clone(event.Artifact.Metadata)
	clonedArtifact.Parts = make(a2a.ContentParts, 0, len(event.Artifact.Parts))
	clonedEvent.Artifact = &clonedArtifact

	result := ExternalizeResult{Event: &clonedEvent}
	for _, sourcePart := range event.Artifact.Parts {
		partIndex := nextPart
		nextPart++
		part := clonePart(sourcePart)
		if part == nil {
			return result, fmt.Errorf("artifact part %d is nil", partIndex)
		}
		raw, isRaw := part.Content.(a2a.Raw)
		if !isRaw {
			clonedArtifact.Parts = append(clonedArtifact.Parts, part)
			continue
		}
		rawSize := int64(len(raw))
		if rawSize > s.externalizer.policy.MaxRawPartBytes {
			return result, fmt.Errorf("raw artifact part %d size %d exceeds maximum %d", partIndex, rawSize, s.externalizer.policy.MaxRawPartBytes)
		}
		shouldExternalize := rawSize >= s.externalizer.policy.InlinePartBytes ||
			artifactInline+rawSize > s.externalizer.policy.InlineArtifactBytes ||
			taskInline+rawSize > s.externalizer.policy.InlineTaskBytes
		if !shouldExternalize {
			artifactInline += rawSize
			taskInline += rawSize
			clonedArtifact.Parts = append(clonedArtifact.Parts, part)
			continue
		}

		digest := sha256.Sum256(raw)
		objectID, key, err := DeriveObjectLocation(s.owner, s.taskID, artifactID, partIndex, digest)
		if err != nil {
			return result, err
		}
		mediaType := strings.TrimSpace(part.MediaType)
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		stored, err := s.externalizer.store.Put(ctx, s3store.PutRequest{
			Key:         key,
			Body:        []byte(raw),
			ContentType: mediaType,
			Metadata: map[string]string{
				"object-id":     objectID,
				"scope-hash":    scopeHash(s.owner),
				"task-hash":     shortHash(string(s.taskID)),
				"artifact-hash": shortHash(string(artifactID)),
				"part-index":    strconv.Itoa(partIndex),
			},
		})
		if err != nil {
			return result, fmt.Errorf("externalize artifact part %d: %w", partIndex, err)
		}
		digestHex := hex.EncodeToString(digest[:])
		if stored.Key != key || stored.Size != rawSize || !strings.EqualFold(stored.SHA256, digestHex) {
			return result, fmt.Errorf("externalize artifact part %d: object store returned inconsistent metadata", partIndex)
		}
		result.Objects = append(result.Objects, ObjectRecord{
			ObjectID:   objectID,
			Owner:      s.owner,
			TaskID:     s.taskID,
			ArtifactID: artifactID,
			PartIndex:  partIndex,
			Bucket:     stored.Bucket,
			Key:        stored.Key,
			VersionID:  stored.VersionID,
			ETag:       stored.ETag,
			MediaType:  mediaType,
			Filename:   part.Filename,
			Size:       rawSize,
			SHA256:     digestHex,
		})
		urlPart := a2a.NewFileURLPart(a2a.URL(s.externalizer.objectURL(objectID)), mediaType)
		urlPart.Filename = part.Filename
		urlPart.Metadata = maps.Clone(part.Metadata)
		if urlPart.Metadata == nil {
			urlPart.Metadata = make(map[string]any, 3)
		}
		urlPart.Metadata[MetadataObjectID] = objectID
		urlPart.Metadata[MetadataSHA256] = digestHex
		urlPart.Metadata[MetadataSize] = rawSize
		clonedArtifact.Parts = append(clonedArtifact.Parts, urlPart)
	}
	s.artifactInline[artifactID] = artifactInline
	s.taskInline = taskInline
	s.nextPart[artifactID] = nextPart
	return result, nil
}

// DeriveObjectLocation deterministically derives an opaque object ID and a key
// that contains no raw issuer, tenant, or subject values.
func DeriveObjectLocation(owner Owner, taskID a2a.TaskID, artifactID a2a.ArtifactID, partIndex int, digest [sha256.Size]byte) (string, string, error) {
	if err := validateOwner(owner); err != nil {
		return "", "", err
	}
	if err := validateIdentifier("task", string(taskID)); err != nil {
		return "", "", err
	}
	if err := validateIdentifier("artifact", string(artifactID)); err != nil {
		return "", "", err
	}
	if partIndex < 0 {
		return "", "", fmt.Errorf("artifact part index must not be negative")
	}
	taskSegment := base64.RawURLEncoding.EncodeToString([]byte(taskID))
	artifactSegment := base64.RawURLEncoding.EncodeToString([]byte(artifactID))
	key := fmt.Sprintf("v1/t/%s/task/%s/artifact/%s/part/%06d-%s",
		scopeHash(owner), taskSegment, artifactSegment, partIndex, hex.EncodeToString(digest[:]))
	idDigest := sha256.Sum256([]byte(owner.Subject + "\x00" + key))
	return base64.RawURLEncoding.EncodeToString(idDigest[:]), key, nil
}

func normalizePolicy(policy Policy) (Policy, error) {
	if policy.InlinePartBytes == 0 {
		policy.InlinePartBytes = defaultInlinePartBytes
	}
	if policy.InlineArtifactBytes == 0 {
		policy.InlineArtifactBytes = defaultInlineArtifactBytes
	}
	if policy.InlineTaskBytes == 0 {
		policy.InlineTaskBytes = defaultInlineTaskBytes
	}
	if policy.MaxRawPartBytes == 0 {
		policy.MaxRawPartBytes = defaultMaxRawPartBytes
	}
	if policy.InlinePartBytes < 1 || policy.InlineArtifactBytes < policy.InlinePartBytes ||
		policy.InlineTaskBytes < policy.InlineArtifactBytes || policy.MaxRawPartBytes < policy.InlinePartBytes {
		return Policy{}, fmt.Errorf("artifact size policy is inconsistent")
	}
	return policy, nil
}

func validatePublicBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("public base URL must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("public base URL must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed, nil
}

func validateOwner(owner Owner) error {
	for name, value := range map[string]string{"issuer": owner.Issuer, "tenant": owner.Tenant, "subject": owner.Subject} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 512 || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("artifact owner %s is invalid", name)
		}
	}
	return nil
}

func validateIdentifier(name, value string) error {
	if value == "" || len(value) > 256 || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("artifact %s ID is invalid", name)
	}
	return nil
}

func (e *Externalizer) objectURL(objectID string) string {
	result := *e.publicBase
	result.Path = strings.TrimSuffix(result.Path, "/") + "/artifacts/" + objectID
	result.RawPath = ""
	return result.String()
}

func clonePart(source *a2a.Part) *a2a.Part {
	if source == nil {
		return nil
	}
	result := *source
	result.Metadata = maps.Clone(source.Metadata)
	if raw, ok := source.Content.(a2a.Raw); ok {
		result.Content = a2a.Raw(append([]byte(nil), raw...))
	}
	return &result
}

func scopeHash(owner Owner) string {
	digest := sha256.Sum256([]byte(owner.Issuer + "\x00" + owner.Tenant))
	return hex.EncodeToString(digest[:16])
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:16])
}
