package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment     string
	Port            int
	PublicBaseURL   string
	AgentCardPath   string
	ShutdownTimeout time.Duration
	KeepAlive       time.Duration
	AgentInactivity time.Duration
	HTTPReadTimeout time.Duration
	MaxRequestBytes int64
}

func Load() (Config, error) {
	environment := strings.ToLower(strings.TrimSpace(envOrDefault("APP_ENV", "development")))
	switch environment {
	case "development", "test", "staging", "production":
	default:
		return Config{}, fmt.Errorf("APP_ENV must be development, test, staging, or production")
	}
	port, err := strconv.Atoi(envOrDefault("PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("PORT must be an integer between 1 and 65535")
	}

	publicBaseURL := envOrDefault("PUBLIC_BASE_URL", "http://localhost:"+strconv.Itoa(port))
	parsedURL, err := url.ParseRequestURI(publicBaseURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return Config{}, fmt.Errorf("PUBLIC_BASE_URL must be an absolute HTTP(S) URL")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || (parsedURL.Path != "" && parsedURL.Path != "/") {
		return Config{}, fmt.Errorf("PUBLIC_BASE_URL must not contain credentials, a path, query, or fragment")
	}
	if (environment == "staging" || environment == "production") && parsedURL.Scheme != "https" {
		return Config{}, fmt.Errorf("PUBLIC_BASE_URL must use HTTPS in staging and production")
	}

	shutdownTimeout, err := time.ParseDuration(envOrDefault("SHUTDOWN_TIMEOUT", "20s"))
	if err != nil || shutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("SHUTDOWN_TIMEOUT must be a positive duration")
	}
	keepAlive, err := time.ParseDuration(envOrDefault("A2A_KEEP_ALIVE_INTERVAL", "15s"))
	if err != nil || keepAlive <= 0 {
		return Config{}, fmt.Errorf("A2A_KEEP_ALIVE_INTERVAL must be a positive duration")
	}
	agentInactivity, err := time.ParseDuration(envOrDefault("A2A_AGENT_INACTIVITY_TIMEOUT", "5m"))
	if err != nil || agentInactivity <= 0 {
		return Config{}, fmt.Errorf("A2A_AGENT_INACTIVITY_TIMEOUT must be a positive duration")
	}
	httpReadTimeout, err := time.ParseDuration(envOrDefault("HTTP_READ_TIMEOUT", "30s"))
	if err != nil || httpReadTimeout <= 0 {
		return Config{}, fmt.Errorf("HTTP_READ_TIMEOUT must be a positive duration")
	}
	maxRequestBytes, err := strconv.ParseInt(envOrDefault("MAX_REQUEST_BODY_BYTES", "1048576"), 10, 64)
	if err != nil || maxRequestBytes <= 0 {
		return Config{}, fmt.Errorf("MAX_REQUEST_BODY_BYTES must be a positive integer")
	}

	return Config{
		Environment:     environment,
		Port:            port,
		PublicBaseURL:   publicBaseURL,
		AgentCardPath:   envOrDefault("AGENT_CARD_PATH", "config/agent-card.json"),
		ShutdownTimeout: shutdownTimeout,
		KeepAlive:       keepAlive,
		AgentInactivity: agentInactivity,
		HTTPReadTimeout: httpReadTimeout,
		MaxRequestBytes: maxRequestBytes,
	}, nil
}

func (c Config) Address() string {
	return ":" + strconv.Itoa(c.Port)
}

func envOrDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
