package s3store

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	defaultMaxObjectBytes = int64(64 << 20)
	defaultPresignTTL     = 5 * time.Minute
	maximumPresignTTL     = 15 * time.Minute
	defaultRequestTimeout = 30 * time.Second
	defaultConnectTimeout = 3 * time.Second
	defaultHeaderTimeout  = 10 * time.Second
)

var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var metadataKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ClientConfig configures an S3-compatible object store without consulting the
// AWS default credential chain. Endpoint is used for service traffic while
// PublicEndpoint is used only when signing client-facing GET URLs.
type ClientConfig struct {
	Endpoint              string
	PublicEndpoint        string
	Region                string
	Bucket                string
	AccessKey             string
	SecretKey             string
	AllowInsecureHTTP     bool
	UsePathStyle          bool
	ServerSideEncryption  types.ServerSideEncryption
	MaxObjectBytes        int64
	PresignTTL            time.Duration
	RequestTimeout        time.Duration
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
}

// Client stores and signs objects in a single private bucket.
type Client struct {
	api            s3API
	presigner      presignAPI
	bucket         string
	maxObjectBytes int64
	presignTTL     time.Duration
	requestTimeout time.Duration
	sse            types.ServerSideEncryption
	publicOrigin   *url.URL
	now            func() time.Time
}

// New creates an S3 client with explicit static credentials, path-style
// addressing, bounded retries, no proxy, and no redirect following.
func New(cfg ClientConfig) (*Client, error) {
	normalized, endpoint, publicEndpoint, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	httpClient := newHTTPClient(normalized)
	credentialProvider := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
		normalized.AccessKey,
		normalized.SecretKey,
		"",
	))
	awsConfig := aws.Config{
		Region:      normalized.Region,
		Credentials: credentialProvider,
		HTTPClient:  httpClient,
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = 3
			})
		},
	}
	api := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint.String())
		options.UsePathStyle = normalized.UsePathStyle
	})
	publicAPI := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(publicEndpoint.String())
		options.UsePathStyle = normalized.UsePathStyle
	})
	client := newClient(normalized, api, s3.NewPresignClient(publicAPI))
	client.publicOrigin = publicEndpoint
	return client, nil
}

func newClient(cfg ClientConfig, api s3API, presigner presignAPI) *Client {
	return &Client{
		api:            api,
		presigner:      presigner,
		bucket:         cfg.Bucket,
		maxObjectBytes: cfg.MaxObjectBytes,
		presignTTL:     cfg.PresignTTL,
		requestTimeout: cfg.RequestTimeout,
		sse:            cfg.ServerSideEncryption,
		now:            time.Now,
	}
}

func normalizeConfig(cfg ClientConfig) (ClientConfig, *url.URL, *url.URL, error) {
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	cfg.PublicEndpoint = strings.TrimSpace(cfg.PublicEndpoint)
	cfg.Region = strings.TrimSpace(cfg.Region)
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	if cfg.Endpoint == "" || cfg.Region == "" || cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 endpoint, region, bucket, access key, and secret key are required")
	}
	if cfg.AccessKey != strings.TrimSpace(cfg.AccessKey) || cfg.SecretKey != strings.TrimSpace(cfg.SecretKey) ||
		strings.ContainsAny(cfg.AccessKey, "\x00\r\n") || strings.ContainsAny(cfg.SecretKey, "\x00\r\n") {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 credentials contain invalid whitespace or control characters")
	}
	if !bucketPattern.MatchString(cfg.Bucket) || strings.Contains(cfg.Bucket, "..") {
		return ClientConfig{}, nil, nil, fmt.Errorf("invalid S3 bucket name %q", cfg.Bucket)
	}
	endpoint, err := validateEndpoint(cfg.Endpoint, cfg.AllowInsecureHTTP)
	if err != nil {
		return ClientConfig{}, nil, nil, fmt.Errorf("invalid S3 endpoint: %w", err)
	}
	if cfg.PublicEndpoint == "" {
		cfg.PublicEndpoint = cfg.Endpoint
	}
	publicEndpoint, err := validateEndpoint(cfg.PublicEndpoint, cfg.AllowInsecureHTTP)
	if err != nil {
		return ClientConfig{}, nil, nil, fmt.Errorf("invalid S3 public endpoint: %w", err)
	}
	if cfg.ServerSideEncryption == "" {
		cfg.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	if cfg.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 server-side encryption must be AES256")
	}
	if cfg.MaxObjectBytes == 0 {
		cfg.MaxObjectBytes = defaultMaxObjectBytes
	}
	if cfg.MaxObjectBytes < 1 {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 maximum object size must be positive")
	}
	if cfg.PresignTTL == 0 {
		cfg.PresignTTL = defaultPresignTTL
	}
	if cfg.PresignTTL < time.Second || cfg.PresignTTL > maximumPresignTTL {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 presign TTL must be between 1 second and %s", maximumPresignTTL)
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	if cfg.ResponseHeaderTimeout == 0 {
		cfg.ResponseHeaderTimeout = defaultHeaderTimeout
	}
	if cfg.RequestTimeout < 1 || cfg.ConnectTimeout < 1 || cfg.ResponseHeaderTimeout < 1 {
		return ClientConfig{}, nil, nil, fmt.Errorf("S3 HTTP timeouts must be positive")
	}
	return cfg, endpoint, publicEndpoint, nil
}

func validateEndpoint(raw string, allowHTTP bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "https" && !allowHTTP {
		return nil, fmt.Errorf("must use HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed, nil
}

func newHTTPClient(cfg ClientConfig) *http.Client {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.requestTimeout)
}

func sameOrigin(expected, candidate *url.URL) bool {
	return strings.EqualFold(expected.Scheme, candidate.Scheme) &&
		strings.EqualFold(expected.Hostname(), candidate.Hostname()) &&
		effectivePort(expected) == effectivePort(candidate)
}

func effectivePort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "http" {
		return "80"
	}
	if value.Scheme == "https" {
		return "443"
	}
	return ""
}
