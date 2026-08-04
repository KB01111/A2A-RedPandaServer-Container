package s3store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	checksumMetadataKey = "sha256"
	sizeMetadataKey     = "size"
)

// ObjectStore is the storage contract consumed by the artifact layer.
type ObjectStore interface {
	Put(context.Context, PutRequest) (Object, error)
	Delete(context.Context, string) error
	PresignGet(context.Context, string) (PresignedGet, error)
}

// PutRequest contains immutable object data and safe S3 user metadata.
type PutRequest struct {
	Key         string
	Body        []byte
	ContentType string
	Metadata    map[string]string
}

// Object describes a successfully uploaded and verified object.
type Object struct {
	Bucket    string
	Key       string
	VersionID string
	ETag      string
	Size      int64
	SHA256    string
	Metadata  map[string]string
}

// PresignedGet is a short-lived, GET-only URL. It must not be persisted.
type PresignedGet struct {
	URL       string
	ExpiresAt time.Time
}

type s3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type presignAPI interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

func (c *Client) Put(ctx context.Context, request PutRequest) (Object, error) {
	if err := validateObjectKey(request.Key); err != nil {
		return Object{}, err
	}
	if int64(len(request.Body)) > c.maxObjectBytes {
		return Object{}, fmt.Errorf("object size %d exceeds maximum %d", len(request.Body), c.maxObjectBytes)
	}
	metadata, err := normalizeMetadata(request.Metadata)
	if err != nil {
		return Object{}, err
	}
	digest := sha256.Sum256(request.Body)
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])
	digestHex := hex.EncodeToString(digest[:])
	metadata[checksumMetadataKey] = digestHex
	metadata[sizeMetadataKey] = strconv.FormatInt(int64(len(request.Body)), 10)
	contentType := strings.TrimSpace(request.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if len(contentType) > 255 || strings.ContainsAny(contentType, "\x00\r\n") {
		return Object{}, fmt.Errorf("invalid S3 object content type")
	}

	operationContext, cancel := c.operationContext(ctx)
	defer cancel()
	putOutput, err := c.api.PutObject(operationContext, &s3.PutObjectInput{
		Bucket:               aws.String(c.bucket),
		Key:                  aws.String(request.Key),
		Body:                 bytes.NewReader(request.Body),
		ContentLength:        aws.Int64(int64(len(request.Body))),
		ContentType:          aws.String(contentType),
		Metadata:             metadata,
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
		ChecksumSHA256:       aws.String(digestBase64),
		ServerSideEncryption: c.sse,
	})
	if err != nil {
		return Object{}, fmt.Errorf("put S3 object: %w", err)
	}

	headOutput, err := c.api.HeadObject(operationContext, &s3.HeadObjectInput{
		Bucket:       aws.String(c.bucket),
		Key:          aws.String(request.Key),
		ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return Object{}, fmt.Errorf("verify S3 object: %w", err)
	}
	if err := verifyHead(headOutput, int64(len(request.Body)), digestBase64, digestHex, c.sse); err != nil {
		return Object{}, fmt.Errorf("verify S3 object: %w", err)
	}
	versionID := aws.ToString(headOutput.VersionId)
	if versionID == "" {
		versionID = aws.ToString(putOutput.VersionId)
	}
	etag := aws.ToString(headOutput.ETag)
	if etag == "" {
		etag = aws.ToString(putOutput.ETag)
	}
	return Object{
		Bucket:    c.bucket,
		Key:       request.Key,
		VersionID: versionID,
		ETag:      etag,
		Size:      int64(len(request.Body)),
		SHA256:    digestHex,
		Metadata:  cloneMetadata(metadata),
	}, nil
}

func verifyHead(output *s3.HeadObjectOutput, size int64, digestBase64, digestHex string, sse types.ServerSideEncryption) error {
	if output == nil {
		return fmt.Errorf("empty HeadObject response")
	}
	if output.ContentLength == nil || *output.ContentLength != size {
		return fmt.Errorf("content length mismatch")
	}
	if checksum := aws.ToString(output.ChecksumSHA256); checksum != "" && checksum != digestBase64 {
		return fmt.Errorf("SHA-256 checksum mismatch")
	}
	if !strings.EqualFold(output.Metadata[checksumMetadataKey], digestHex) {
		return fmt.Errorf("SHA-256 metadata mismatch")
	}
	if output.Metadata[sizeMetadataKey] != strconv.FormatInt(size, 10) {
		return fmt.Errorf("size metadata mismatch")
	}
	if output.ServerSideEncryption != sse {
		return fmt.Errorf("server-side encryption mismatch")
	}
	return nil
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	operationContext, cancel := c.operationContext(ctx)
	defer cancel()
	if _, err := c.api.DeleteObject(operationContext, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}); err != nil {
		return fmt.Errorf("delete S3 object: %w", err)
	}
	return nil
}

func (c *Client) PresignGet(ctx context.Context, key string) (PresignedGet, error) {
	if err := validateObjectKey(key); err != nil {
		return PresignedGet{}, err
	}
	operationContext, cancel := c.operationContext(ctx)
	defer cancel()
	issuedAt := c.now()
	request, err := c.presigner.PresignGetObject(operationContext, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(c.presignTTL))
	if err != nil {
		return PresignedGet{}, fmt.Errorf("presign S3 object GET: %w", err)
	}
	parsed, err := url.ParseRequestURI(request.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (c.publicOrigin != nil && !sameOrigin(c.publicOrigin, parsed)) {
		return PresignedGet{}, fmt.Errorf("presign S3 object GET returned an invalid URL")
	}
	return PresignedGet{URL: request.URL, ExpiresAt: issuedAt.Add(c.presignTTL)}, nil
}

func validateObjectKey(key string) error {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) {
		return fmt.Errorf("S3 object key must contain between 1 and 1024 valid UTF-8 bytes")
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsAny(key, "\x00\r\n") {
		return fmt.Errorf("S3 object key contains unsafe characters")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("S3 object key contains an unsafe path segment")
		}
	}
	return nil
}

func normalizeMetadata(source map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(source)+2)
	for key, value := range source {
		key = strings.ToLower(strings.TrimSpace(key))
		if !metadataKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("invalid S3 metadata key")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("duplicate S3 metadata key %q", key)
		}
		if len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid S3 metadata value for %q", key)
		}
		result[key] = value
	}
	return result, nil
}

func cloneMetadata(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
