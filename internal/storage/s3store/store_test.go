package s3store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestNormalizeConfigDefaultsAndRejectsUnsafeInputs(t *testing.T) {
	valid := ClientConfig{
		Endpoint:  "https://minio.internal/base/",
		Region:    "us-east-1",
		Bucket:    "bridge-artifacts",
		AccessKey: "access",
		SecretKey: "secret",
	}
	normalized, endpoint, publicEndpoint, err := normalizeConfig(valid)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if normalized.MaxObjectBytes != defaultMaxObjectBytes || normalized.PresignTTL != defaultPresignTTL {
		t.Fatalf("defaults = %#v", normalized)
	}
	if normalized.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("SSE = %q", normalized.ServerSideEncryption)
	}
	if endpoint.String() != "https://minio.internal/base" || publicEndpoint.String() != endpoint.String() {
		t.Fatalf("endpoints = %q, %q", endpoint, publicEndpoint)
	}

	tests := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{name: "cleartext", mutate: func(c *ClientConfig) { c.Endpoint = "http://minio.internal" }},
		{name: "endpoint credentials", mutate: func(c *ClientConfig) { c.Endpoint = "https://user@minio.internal" }},
		{name: "public query", mutate: func(c *ClientConfig) { c.PublicEndpoint = "https://objects.example.test?bucket=x" }},
		{name: "invalid bucket", mutate: func(c *ClientConfig) { c.Bucket = "Bridge_Artifacts" }},
		{name: "missing access key", mutate: func(c *ClientConfig) { c.AccessKey = "" }},
		{name: "credential whitespace", mutate: func(c *ClientConfig) { c.SecretKey = " secret" }},
		{name: "unsupported SSE", mutate: func(c *ClientConfig) { c.ServerSideEncryption = types.ServerSideEncryptionAwsKms }},
		{name: "oversized presign TTL", mutate: func(c *ClientConfig) { c.PresignTTL = maximumPresignTTL + time.Second }},
		{name: "negative maximum", mutate: func(c *ClientConfig) { c.MaxObjectBytes = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if _, _, _, err := normalizeConfig(cfg); err == nil {
				t.Fatal("normalizeConfig() unexpectedly succeeded")
			}
		})
	}

	loopback := valid
	loopback.Endpoint = "http://127.0.0.1:9000"
	loopback.PublicEndpoint = "http://localhost:9000"
	loopback.AllowInsecureHTTP = true
	if _, _, _, err := normalizeConfig(loopback); err != nil {
		t.Fatalf("loopback development config error = %v", err)
	}
}

func TestPutSendsAndVerifiesSHA256MetadataAndSSE(t *testing.T) {
	body := []byte("artifact bytes")
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])
	api := &fakeS3API{
		putOutput: &s3.PutObjectOutput{ETag: aws.String("put-etag"), VersionId: aws.String("put-version")},
		headOutput: &s3.HeadObjectOutput{
			ChecksumSHA256:       aws.String(digestBase64),
			ContentLength:        aws.Int64(int64(len(body))),
			ETag:                 aws.String("head-etag"),
			VersionId:            aws.String("head-version"),
			Metadata:             map[string]string{checksumMetadataKey: digestHex, sizeMetadataKey: "14"},
			ServerSideEncryption: types.ServerSideEncryptionAes256,
		},
	}
	client := testClient(api, &fakePresigner{})
	metadata := map[string]string{"Scope-Hash": "scope", checksumMetadataKey: "caller-value"}
	object, err := client.Put(t.Context(), PutRequest{
		Key:         "v1/t/scope/object",
		Body:        body,
		ContentType: "application/pdf",
		Metadata:    metadata,
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if string(api.putBody) != string(body) {
		t.Fatalf("body = %q", api.putBody)
	}
	if got := aws.ToString(api.putInput.ChecksumSHA256); got != digestBase64 || api.putInput.ChecksumAlgorithm != types.ChecksumAlgorithmSha256 {
		t.Fatalf("checksum = %q, %q", got, api.putInput.ChecksumAlgorithm)
	}
	if api.putInput.ServerSideEncryption != types.ServerSideEncryptionAes256 || api.putInput.Metadata[checksumMetadataKey] != digestHex {
		t.Fatalf("put input = %#v", api.putInput)
	}
	if api.headInput.ChecksumMode != types.ChecksumModeEnabled {
		t.Fatalf("HeadObject checksum mode = %q", api.headInput.ChecksumMode)
	}
	if metadata[checksumMetadataKey] != "caller-value" {
		t.Fatal("Put() mutated caller metadata")
	}
	if object.Bucket != "bridge-artifacts" || object.Key != "v1/t/scope/object" || object.SHA256 != digestHex || object.Size != int64(len(body)) {
		t.Fatalf("object = %#v", object)
	}
	if object.ETag != "head-etag" || object.VersionID != "head-version" {
		t.Fatalf("verified identifiers = %#v", object)
	}
}

func TestPutRejectsOversizeAndVerificationMismatch(t *testing.T) {
	api := &fakeS3API{}
	client := testClient(api, &fakePresigner{})
	client.maxObjectBytes = 2
	if _, err := client.Put(t.Context(), PutRequest{Key: "safe/key", Body: []byte("abc")}); err == nil {
		t.Fatal("oversized Put() unexpectedly succeeded")
	}
	if api.putInput != nil {
		t.Fatal("oversized object reached S3")
	}

	digest := sha256.Sum256([]byte("ok"))
	api.headOutput = &s3.HeadObjectOutput{
		ContentLength:        aws.Int64(2),
		ChecksumSHA256:       aws.String(base64.StdEncoding.EncodeToString(digest[:])),
		Metadata:             map[string]string{checksumMetadataKey: "wrong"},
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	}
	client.maxObjectBytes = 10
	if _, err := client.Put(t.Context(), PutRequest{Key: "safe/key", Body: []byte("ok")}); err == nil || !strings.Contains(err.Error(), "metadata mismatch") {
		t.Fatalf("verification error = %v", err)
	}
}

func TestVerifyHeadRejectsEveryIntegrityBoundary(t *testing.T) {
	digest := sha256.Sum256([]byte("ok"))
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])
	digestHex := hex.EncodeToString(digest[:])
	valid := func() *s3.HeadObjectOutput {
		return &s3.HeadObjectOutput{
			ContentLength:        aws.Int64(2),
			ChecksumSHA256:       aws.String(digestBase64),
			Metadata:             map[string]string{checksumMetadataKey: digestHex, sizeMetadataKey: "2"},
			ServerSideEncryption: types.ServerSideEncryptionAes256,
		}
	}
	tests := []struct {
		name   string
		mutate func(*s3.HeadObjectOutput) *s3.HeadObjectOutput
	}{
		{name: "empty response", mutate: func(*s3.HeadObjectOutput) *s3.HeadObjectOutput { return nil }},
		{name: "size", mutate: func(output *s3.HeadObjectOutput) *s3.HeadObjectOutput {
			output.ContentLength = aws.Int64(3)
			return output
		}},
		{name: "checksum", mutate: func(output *s3.HeadObjectOutput) *s3.HeadObjectOutput {
			output.ChecksumSHA256 = aws.String("wrong")
			return output
		}},
		{name: "checksum metadata", mutate: func(output *s3.HeadObjectOutput) *s3.HeadObjectOutput {
			output.Metadata[checksumMetadataKey] = "wrong"
			return output
		}},
		{name: "size metadata", mutate: func(output *s3.HeadObjectOutput) *s3.HeadObjectOutput {
			output.Metadata[sizeMetadataKey] = "3"
			return output
		}},
		{name: "SSE", mutate: func(output *s3.HeadObjectOutput) *s3.HeadObjectOutput {
			output.ServerSideEncryption = ""
			return output
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyHead(test.mutate(valid()), 2, digestBase64, digestHex, types.ServerSideEncryptionAes256); err == nil {
				t.Fatal("verifyHead() unexpectedly succeeded")
			}
		})
	}
	withoutChecksumHeader := valid()
	withoutChecksumHeader.ChecksumSHA256 = nil
	if err := verifyHead(withoutChecksumHeader, 2, digestBase64, digestHex, types.ServerSideEncryptionAes256); err != nil {
		t.Fatalf("metadata-backed verification error = %v", err)
	}
}

func TestDeleteAndPresignUseBoundedInputs(t *testing.T) {
	presigner := &fakePresigner{response: &v4.PresignedHTTPRequest{URL: "https://objects.example.test/bucket/key?signature=value", Method: http.MethodGet}}
	api := &fakeS3API{deleteOutput: &s3.DeleteObjectOutput{}}
	client := testClient(api, presigner)
	now := time.Unix(2_000_000_000, 0).UTC()
	client.now = func() time.Time { return now }

	if err := client.Delete(t.Context(), "safe/key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if aws.ToString(api.deleteInput.Bucket) != "bridge-artifacts" || aws.ToString(api.deleteInput.Key) != "safe/key" {
		t.Fatalf("delete input = %#v", api.deleteInput)
	}
	presigned, err := client.PresignGet(t.Context(), "safe/key")
	if err != nil {
		t.Fatalf("PresignGet() error = %v", err)
	}
	if presigner.options.Expires != defaultPresignTTL || !presigned.ExpiresAt.Equal(now.Add(defaultPresignTTL)) {
		t.Fatalf("presign = %#v, options = %#v", presigned, presigner.options)
	}
	for _, key := range []string{"", "/absolute", "a/../b", "a\\b", "a//b"} {
		if _, err := client.PresignGet(t.Context(), key); err == nil {
			t.Fatalf("unsafe key %q unexpectedly accepted", key)
		}
	}
}

func TestPresignRejectsURLOutsideConfiguredPublicOrigin(t *testing.T) {
	presigner := &fakePresigner{response: &v4.PresignedHTTPRequest{URL: "https://attacker.example.test/object", Method: http.MethodGet}}
	client := testClient(&fakeS3API{}, presigner)
	client.publicOrigin, _ = url.Parse("https://objects.example.test")
	if _, err := client.PresignGet(t.Context(), "safe/key"); err == nil {
		t.Fatal("cross-origin presign unexpectedly accepted")
	}
}

func TestNewUsesExplicitCredentialsPathStyleAndDisablesProxy(t *testing.T) {
	body := []byte("abc")
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])
	var putRequest *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPut:
			putRequest = request.Clone(request.Context())
			_, _ = io.ReadAll(request.Body)
			response.Header().Set("ETag", "put-etag")
			response.WriteHeader(http.StatusOK)
		case http.MethodHead:
			response.Header().Set("Content-Length", "3")
			response.Header().Set("X-Amz-Checksum-Sha256", digestBase64)
			response.Header().Set("X-Amz-Meta-Sha256", digestHex)
			response.Header().Set("X-Amz-Meta-Size", "3")
			response.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
			response.WriteHeader(http.StatusOK)
		default:
			http.Error(response, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	client, err := New(ClientConfig{
		Endpoint:          server.URL,
		PublicEndpoint:    server.URL,
		Region:            "us-east-1",
		Bucket:            "bridge-artifacts",
		AccessKey:         "explicit-access",
		SecretKey:         "explicit-secret",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Put(t.Context(), PutRequest{Key: "path/object.bin", Body: body}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if putRequest == nil || putRequest.URL.Path != "/bridge-artifacts/path/object.bin" {
		t.Fatalf("path-style request = %#v", putRequest)
	}
	if authorization := putRequest.Header.Get("Authorization"); !strings.Contains(authorization, "Credential=explicit-access/") {
		t.Fatalf("Authorization = %q", authorization)
	}
	if putRequest.Header.Get("X-Amz-Server-Side-Encryption") != "AES256" {
		t.Fatalf("SSE header = %q", putRequest.Header.Get("X-Amz-Server-Side-Encryption"))
	}
	httpClient := newHTTPClient(ClientConfig{ConnectTimeout: time.Second, ResponseHeaderTimeout: time.Second, RequestTimeout: time.Second})
	transport := httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("S3 transport inherited an HTTP proxy")
	}
}

func TestNewRejectsRedirectsBeforeContactingTarget(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	client, err := New(ClientConfig{
		Endpoint: source.URL, PublicEndpoint: source.URL, Region: "us-east-1", Bucket: "bridge-artifacts",
		AccessKey: "access", SecretKey: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Put(t.Context(), PutRequest{Key: "safe/key", Body: []byte("abc")}); err == nil {
		t.Fatal("redirecting Put() unexpectedly succeeded")
	}
	if requests := targetRequests.Load(); requests != 0 {
		t.Fatalf("redirect target requests = %d, want 0", requests)
	}
}

func TestPresignUsesConfiguredPublicEndpoint(t *testing.T) {
	client, err := New(ClientConfig{
		Endpoint:       "https://minio.internal",
		PublicEndpoint: "https://objects.example.test/storage",
		Region:         "us-east-1",
		Bucket:         "bridge-artifacts",
		AccessKey:      "explicit-access",
		SecretKey:      "explicit-secret",
		UsePathStyle:   true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	presigned, err := client.PresignGet(t.Context(), "safe/key")
	if err != nil {
		t.Fatalf("PresignGet() error = %v", err)
	}
	parsed, err := url.Parse(presigned.URL)
	if err != nil {
		t.Fatalf("parse presign: %v", err)
	}
	if parsed.Host != "objects.example.test" || parsed.Path != "/storage/bridge-artifacts/safe/key" {
		t.Fatalf("presigned URL = %q", presigned.URL)
	}
	if parsed.Query().Get("X-Amz-Expires") != "300" || !strings.Contains(parsed.Query().Get("X-Amz-Credential"), "explicit-access/") {
		t.Fatalf("presigned query = %v", parsed.Query())
	}
}

func testClient(api s3API, presigner presignAPI) *Client {
	return newClient(ClientConfig{
		Bucket:               "bridge-artifacts",
		MaxObjectBytes:       defaultMaxObjectBytes,
		PresignTTL:           defaultPresignTTL,
		RequestTimeout:       defaultRequestTimeout,
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	}, api, presigner)
}

type fakeS3API struct {
	putInput     *s3.PutObjectInput
	putBody      []byte
	putOutput    *s3.PutObjectOutput
	putErr       error
	headInput    *s3.HeadObjectInput
	headOutput   *s3.HeadObjectOutput
	headErr      error
	deleteInput  *s3.DeleteObjectInput
	deleteOutput *s3.DeleteObjectOutput
	deleteErr    error
}

func (f *fakeS3API) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.putInput = input
	f.putBody, _ = io.ReadAll(input.Body)
	if f.putOutput == nil {
		f.putOutput = &s3.PutObjectOutput{}
	}
	return f.putOutput, f.putErr
}

func (f *fakeS3API) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.headInput = input
	return f.headOutput, f.headErr
}

func (f *fakeS3API) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deleteInput = input
	if f.deleteOutput == nil {
		f.deleteOutput = &s3.DeleteObjectOutput{}
	}
	return f.deleteOutput, f.deleteErr
}

type fakePresigner struct {
	input    *s3.GetObjectInput
	options  s3.PresignOptions
	response *v4.PresignedHTTPRequest
	err      error
}

func (f *fakePresigner) PresignGetObject(_ context.Context, input *s3.GetObjectInput, optionFns ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	f.input = input
	for _, option := range optionFns {
		option(&f.options)
	}
	if f.response == nil && f.err == nil {
		f.response = &v4.PresignedHTTPRequest{URL: "https://objects.example.test/object", Method: http.MethodGet}
	}
	return f.response, f.err
}

var _ ObjectStore = (*Client)(nil)
