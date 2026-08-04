package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint        string
	PublicEndpoint  string
	Region          string
	Bucket          string
	AccessKeyFile   string
	SecretKeyFile   string
	UsePathStyle    bool
	ExternalizeAt   int64
	MaxObjectBytes  int64
	PresignTTL      time.Duration
	AllowPrivateIPs bool
}

func (c S3Config) Enabled() bool { return c.Endpoint != "" }

func loadS3Config(environment string) (S3Config, error) {
	endpoint := strings.TrimSpace(envOrDefault("S3_ENDPOINT", ""))
	keys := []string{"S3_PUBLIC_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY_FILE", "S3_SECRET_KEY_FILE", "S3_USE_PATH_STYLE", "S3_EXTERNALIZE_AT_BYTES", "S3_MAX_OBJECT_BYTES", "S3_PRESIGN_TTL"}
	if endpoint == "" {
		if key, ok := anyConfigured(keys...); ok {
			return S3Config{}, fmt.Errorf("%s requires S3_ENDPOINT", key)
		}
		return S3Config{}, nil
	}
	publicEndpoint := strings.TrimSpace(envOrDefault("S3_PUBLIC_ENDPOINT", endpoint))
	for key, raw := range map[string]string{"S3_ENDPOINT": endpoint, "S3_PUBLIC_ENDPOINT": publicEndpoint} {
		parsed, err := url.ParseRequestURI(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return S3Config{}, fmt.Errorf("%s must be an absolute HTTP(S) origin without credentials, path, query, or fragment", key)
		}
		if (environment == "staging" || environment == "production") && parsed.Scheme != "https" {
			return S3Config{}, fmt.Errorf("%s must use HTTPS in staging and production", key)
		}
	}
	bucket := strings.TrimSpace(envOrDefault("S3_BUCKET", ""))
	accessFile := strings.TrimSpace(envOrDefault("S3_ACCESS_KEY_FILE", ""))
	secretFile := strings.TrimSpace(envOrDefault("S3_SECRET_KEY_FILE", ""))
	if bucket == "" || accessFile == "" || secretFile == "" {
		return S3Config{}, fmt.Errorf("S3_BUCKET, S3_ACCESS_KEY_FILE, and S3_SECRET_KEY_FILE are required with S3_ENDPOINT")
	}
	if !validBucketName(bucket) {
		return S3Config{}, fmt.Errorf("S3_BUCKET is invalid")
	}
	if err := requireAbsolutePath("S3_ACCESS_KEY_FILE", accessFile); err != nil {
		return S3Config{}, err
	}
	if err := requireAbsolutePath("S3_SECRET_KEY_FILE", secretFile); err != nil {
		return S3Config{}, err
	}
	usePathStyle := true
	if value := strings.TrimSpace(envOrDefault("S3_USE_PATH_STYLE", "true")); value != "true" && value != "false" {
		return S3Config{}, fmt.Errorf("S3_USE_PATH_STYLE must be true or false")
	} else {
		usePathStyle = value == "true"
	}
	externalizeAt, err := parsePositiveInt64("S3_EXTERNALIZE_AT_BYTES", 64<<10, 64<<20)
	if err != nil {
		return S3Config{}, err
	}
	maxObjectBytes, err := parsePositiveInt64("S3_MAX_OBJECT_BYTES", 64<<20, 1<<30)
	if err != nil || maxObjectBytes < externalizeAt {
		return S3Config{}, fmt.Errorf("S3_MAX_OBJECT_BYTES must be at least S3_EXTERNALIZE_AT_BYTES and no more than 1 GiB")
	}
	presignTTL, err := parsePositiveDuration("S3_PRESIGN_TTL", "5m")
	if err != nil || presignTTL > 15*time.Minute {
		return S3Config{}, fmt.Errorf("S3_PRESIGN_TTL must be between zero and 15 minutes")
	}
	return S3Config{
		Endpoint:        strings.TrimSuffix(endpoint, "/"),
		PublicEndpoint:  strings.TrimSuffix(publicEndpoint, "/"),
		Region:          strings.TrimSpace(envOrDefault("S3_REGION", "us-east-1")),
		Bucket:          bucket,
		AccessKeyFile:   accessFile,
		SecretKeyFile:   secretFile,
		UsePathStyle:    usePathStyle,
		ExternalizeAt:   externalizeAt,
		MaxObjectBytes:  maxObjectBytes,
		PresignTTL:      presignTTL,
		AllowPrivateIPs: environment == "development" || environment == "test",
	}, nil
}

func validBucketName(value string) bool {
	if len(value) < 3 || len(value) > 63 || value[0] == '.' || value[0] == '-' || value[len(value)-1] == '.' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return !strings.Contains(value, "..")
}
