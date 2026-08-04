package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	OIDC            OIDCConfig
	Database        DatabaseConfig
}

type OIDCConfig struct {
	Issuer            string
	Audience          string
	TenantClaim       string
	AllowedAlgorithms []string
	RequiredScopes    []string
	ClockSkew         time.Duration
	HTTPTimeout       time.Duration
}

func (c OIDCConfig) Enabled() bool { return c.Issuer != "" }

type DatabaseConfig struct {
	URL               string
	PasswordFile      string
	MaxConnections    int32
	MinConnections    int32
	MaxConnectionLife time.Duration
	MaxConnectionIdle time.Duration
	HealthCheckPeriod time.Duration
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
	agentCardPath := "config/agent-card.json"
	if environment == "staging" || environment == "production" {
		agentCardPath = "/app/config/agent-card.json"
	}
	oidcConfig, err := loadOIDCConfig()
	if err != nil {
		return Config{}, err
	}
	databaseConfig, err := loadDatabaseConfig()
	if err != nil {
		return Config{}, err
	}

	return Config{
		Environment:     environment,
		Port:            port,
		PublicBaseURL:   publicBaseURL,
		AgentCardPath:   envOrDefault("AGENT_CARD_PATH", agentCardPath),
		ShutdownTimeout: shutdownTimeout,
		KeepAlive:       keepAlive,
		AgentInactivity: agentInactivity,
		HTTPReadTimeout: httpReadTimeout,
		MaxRequestBytes: maxRequestBytes,
		OIDC:            oidcConfig,
		Database:        databaseConfig,
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

func loadOIDCConfig() (OIDCConfig, error) {
	issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("OIDC_AUDIENCE"))
	if issuer == "" && audience == "" {
		return OIDCConfig{}, nil
	}
	if issuer == "" || audience == "" {
		return OIDCConfig{}, fmt.Errorf("OIDC_ISSUER and OIDC_AUDIENCE must be configured together")
	}
	parsedIssuer, err := url.ParseRequestURI(issuer)
	if err != nil || parsedIssuer.Host == "" || (parsedIssuer.Scheme != "http" && parsedIssuer.Scheme != "https") || parsedIssuer.User != nil || parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" {
		return OIDCConfig{}, fmt.Errorf("OIDC_ISSUER must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if parsedIssuer.Scheme != "https" && !isLoopbackHost(parsedIssuer.Hostname()) {
		return OIDCConfig{}, fmt.Errorf("OIDC_ISSUER must use HTTPS except for loopback development")
	}
	clockSkew, err := time.ParseDuration(envOrDefault("OIDC_CLOCK_SKEW", "1m"))
	if err != nil || clockSkew < 0 || clockSkew > 5*time.Minute {
		return OIDCConfig{}, fmt.Errorf("OIDC_CLOCK_SKEW must be between 0 and 5 minutes")
	}
	httpTimeout, err := time.ParseDuration(envOrDefault("OIDC_HTTP_TIMEOUT", "10s"))
	if err != nil || httpTimeout <= 0 {
		return OIDCConfig{}, fmt.Errorf("OIDC_HTTP_TIMEOUT must be a positive duration")
	}
	algorithms := splitCSV(envOrDefault("OIDC_ALLOWED_ALGORITHMS", "RS256"))
	allowedAlgorithms := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	for _, algorithm := range algorithms {
		if !allowedAlgorithms[algorithm] {
			return OIDCConfig{}, fmt.Errorf("OIDC_ALLOWED_ALGORITHMS contains unsafe or unsupported algorithm %q", algorithm)
		}
	}
	requiredScopes := splitCSV(envOrDefault("OIDC_REQUIRED_SCOPES", "a2a"))
	if len(requiredScopes) == 0 {
		return OIDCConfig{}, fmt.Errorf("OIDC_REQUIRED_SCOPES must contain at least one scope")
	}
	tenantClaim := strings.TrimSpace(envOrDefault("OIDC_TENANT_CLAIM", "tenant_id"))
	if tenantClaim == "" || strings.ContainsAny(tenantClaim, " \t\r\n") {
		return OIDCConfig{}, fmt.Errorf("OIDC_TENANT_CLAIM must be a non-empty claim name without whitespace")
	}
	return OIDCConfig{
		Issuer:            issuer,
		Audience:          audience,
		TenantClaim:       tenantClaim,
		AllowedAlgorithms: algorithms,
		RequiredScopes:    requiredScopes,
		ClockSkew:         clockSkew,
		HTTPTimeout:       httpTimeout,
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func loadDatabaseConfig() (DatabaseConfig, error) {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	passwordFile := strings.TrimSpace(os.Getenv("DATABASE_PASSWORD_FILE"))
	if databaseURL == "" {
		if passwordFile != "" {
			return DatabaseConfig{}, fmt.Errorf("DATABASE_PASSWORD_FILE requires DATABASE_URL")
		}
		return DatabaseConfig{}, nil
	}
	parsedURL, err := url.Parse(databaseURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql") {
		return DatabaseConfig{}, fmt.Errorf("DATABASE_URL must be an absolute PostgreSQL URL")
	}
	if parsedURL.User != nil {
		if _, hasPassword := parsedURL.User.Password(); hasPassword {
			return DatabaseConfig{}, fmt.Errorf("DATABASE_URL must not contain a password; use DATABASE_PASSWORD_FILE")
		}
	}
	if passwordFile != "" && !filepath.IsAbs(passwordFile) && !strings.HasPrefix(passwordFile, "/") {
		return DatabaseConfig{}, fmt.Errorf("DATABASE_PASSWORD_FILE must be an absolute path")
	}
	maxConnections, err := parseInt32("DATABASE_MAX_CONNECTIONS", 20, 1, 500)
	if err != nil {
		return DatabaseConfig{}, err
	}
	minConnections, err := parseInt32("DATABASE_MIN_CONNECTIONS", 2, 0, maxConnections)
	if err != nil {
		return DatabaseConfig{}, err
	}
	maxLife, err := parsePositiveDuration("DATABASE_MAX_CONNECTION_LIFETIME", "1h")
	if err != nil {
		return DatabaseConfig{}, err
	}
	maxIdle, err := parsePositiveDuration("DATABASE_MAX_CONNECTION_IDLE", "15m")
	if err != nil {
		return DatabaseConfig{}, err
	}
	healthPeriod, err := parsePositiveDuration("DATABASE_HEALTH_CHECK_PERIOD", "30s")
	if err != nil {
		return DatabaseConfig{}, err
	}
	return DatabaseConfig{
		URL:               databaseURL,
		PasswordFile:      passwordFile,
		MaxConnections:    maxConnections,
		MinConnections:    minConnections,
		MaxConnectionLife: maxLife,
		MaxConnectionIdle: maxIdle,
		HealthCheckPeriod: healthPeriod,
	}, nil
}

func splitCSV(value string) []string {
	var result []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseInt32(key string, fallback, minValue, maxValue int32) (int32, error) {
	value, err := strconv.ParseInt(envOrDefault(key, strconv.FormatInt(int64(fallback), 10)), 10, 32)
	if err != nil || value < int64(minValue) || value > int64(maxValue) {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minValue, maxValue)
	}
	return int32(value), nil
}

func parsePositiveDuration(key, fallback string) (time.Duration, error) {
	value, err := time.ParseDuration(envOrDefault(key, fallback))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return value, nil
}
