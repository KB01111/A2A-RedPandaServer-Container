package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCVerifier struct {
	claimsVerifier claimsVerifier
	issuer         string
	tenantClaim    string
	clockSkew      time.Duration
	now            func() time.Time
}

func NewOIDCVerifier(ctx context.Context, cfg config.OIDCConfig) (*OIDCVerifier, error) {
	issuerURL, err := validateOIDCConfig(cfg)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout:       cfg.HTTPTimeout,
		CheckRedirect: oidcRedirectPolicy(issuerURL.Scheme == "http"),
	}
	return newOIDCVerifier(ctx, cfg, httpClient)
}

func newOIDCVerifier(ctx context.Context, cfg config.OIDCConfig, sourceClient *http.Client) (*OIDCVerifier, error) {
	issuerURL, err := validateOIDCConfig(cfg)
	if err != nil {
		return nil, err
	}
	if sourceClient == nil {
		return nil, fmt.Errorf("OIDC HTTP client is required")
	}
	httpClient := *sourceClient
	httpClient.Timeout = cfg.HTTPTimeout
	httpClient.CheckRedirect = oidcRedirectPolicy(issuerURL.Scheme == "http")
	providerContext := oidc.ClientContext(ctx, &httpClient)
	provider, err := oidc.NewProvider(providerContext, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode OIDC provider metadata: %w", err)
	}
	allowLoopbackHTTP := issuerURL.Scheme == "http"
	if _, err := validateRemoteURL(metadata.JWKSURL, allowLoopbackHTTP, true); err != nil {
		return nil, fmt.Errorf("unsafe OIDC jwks_uri: %w", err)
	}
	verifier := provider.VerifierContext(providerContext, &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: append([]string(nil), cfg.AllowedAlgorithms...),
		// Expiry and nbf are checked below so the configured bounded skew can be
		// applied consistently in both directions.
		SkipExpiryCheck: true,
	})
	return &OIDCVerifier{
		claimsVerifier: oidcClaimsVerifier{verifier: verifier},
		issuer:         cfg.Issuer,
		tenantClaim:    cfg.TenantClaim,
		clockSkew:      cfg.ClockSkew,
		now:            time.Now,
	}, nil
}

func validateOIDCConfig(cfg config.OIDCConfig) (*url.URL, error) {
	if !cfg.Enabled() {
		return nil, fmt.Errorf("OIDC configuration is disabled")
	}
	issuerURL, err := validateRemoteURL(cfg.Issuer, true, false)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	if strings.TrimSpace(cfg.Audience) == "" || cfg.Audience != strings.TrimSpace(cfg.Audience) {
		return nil, fmt.Errorf("OIDC audience is required without surrounding whitespace")
	}
	if strings.TrimSpace(cfg.TenantClaim) == "" || strings.ContainsAny(cfg.TenantClaim, " \t\r\n") {
		return nil, fmt.Errorf("OIDC tenant claim is invalid")
	}
	if cfg.HTTPTimeout <= 0 {
		return nil, fmt.Errorf("OIDC HTTP timeout must be positive")
	}
	if cfg.ClockSkew < 0 || cfg.ClockSkew > 5*time.Minute {
		return nil, fmt.Errorf("OIDC clock skew must be between zero and five minutes")
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		return nil, fmt.Errorf("at least one OIDC signing algorithm is required")
	}
	allowed := map[string]bool{
		oidc.RS256: true, oidc.RS384: true, oidc.RS512: true,
		oidc.PS256: true, oidc.PS384: true, oidc.PS512: true,
		oidc.ES256: true, oidc.ES384: true, oidc.ES512: true,
	}
	seen := make(map[string]bool, len(cfg.AllowedAlgorithms))
	for _, algorithm := range cfg.AllowedAlgorithms {
		if !allowed[algorithm] || seen[algorithm] {
			return nil, fmt.Errorf("unsafe, unsupported, or duplicate OIDC signing algorithm %q", algorithm)
		}
		seen[algorithm] = true
	}
	return issuerURL, nil
}

func validateRemoteURL(raw string, allowLoopbackHTTP, allowQuery bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("must be an absolute HTTP(S) URL without credentials or fragment")
	}
	if !allowQuery && parsed.RawQuery != "" {
		return nil, fmt.Errorf("must not contain a query")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !allowLoopbackHTTP || !isLoopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("must use HTTPS except for a loopback development issuer")
		}
	default:
		return nil, fmt.Errorf("must use HTTP or HTTPS")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func oidcRedirectPolicy(allowLoopbackHTTP bool) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many OIDC redirects")
		}
		if _, err := validateRemoteURL(request.URL.String(), allowLoopbackHTTP, true); err != nil {
			return fmt.Errorf("unsafe OIDC redirect: %w", err)
		}
		return nil
	}
}

func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	claims := make(map[string]json.RawMessage)
	if err := v.claimsVerifier.VerifyClaims(ctx, rawToken, &claims); err != nil {
		return Identity{}, ErrInvalidToken
	}
	subject, err := requiredStringClaim(claims, "sub")
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	tenant, err := requiredStringClaim(claims, v.tenantClaim)
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	expiresAt, err := requiredNumericDate(claims, "exp")
	now := v.now()
	if err != nil || !now.Before(expiresAt.Add(v.clockSkew)) {
		return Identity{}, ErrInvalidToken
	}
	if notBefore, ok, err := optionalNumericDate(claims, "nbf"); err != nil || (ok && now.Add(v.clockSkew).Before(notBefore)) {
		return Identity{}, ErrInvalidToken
	}
	scopes, err := tokenScopes(claims)
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	return Identity{Issuer: v.issuer, Subject: subject, Tenant: tenant, Scopes: scopes}, nil
}

type claimsVerifier interface {
	VerifyClaims(context.Context, string, any) error
}

type oidcClaimsVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (v oidcClaimsVerifier) VerifyClaims(ctx context.Context, rawToken string, target any) error {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return err
	}
	return token.Claims(target)
}

func requiredStringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	raw, ok := claims[name]
	if !ok {
		return "", fmt.Errorf("missing claim")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("invalid claim")
	}
	return value, nil
}

func requiredNumericDate(claims map[string]json.RawMessage, name string) (time.Time, error) {
	value, ok, err := optionalNumericDate(claims, name)
	if err != nil || !ok {
		return time.Time{}, fmt.Errorf("invalid numeric date")
	}
	return value, nil
}

func optionalNumericDate(claims map[string]json.RawMessage, name string) (time.Time, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	var seconds json.Number
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, false, err
	}
	unixSeconds, err := seconds.Float64()
	const maxNumericDate = 253402300799 // 9999-12-31T23:59:59Z
	if err != nil {
		return time.Time{}, false, err
	}
	if math.IsNaN(unixSeconds) || math.IsInf(unixSeconds, 0) || unixSeconds < 0 || unixSeconds > maxNumericDate {
		return time.Time{}, false, fmt.Errorf("numeric date is outside the supported range")
	}
	wholeSeconds := int64(unixSeconds)
	nanoseconds := int64((unixSeconds - float64(wholeSeconds)) * float64(time.Second))
	return time.Unix(wholeSeconds, nanoseconds), true, nil
}

func tokenScopes(claims map[string]json.RawMessage) ([]string, error) {
	var result []string
	for _, name := range []string{"scope", "scp"} {
		raw, ok := claims[name]
		if !ok {
			continue
		}
		var scopeString string
		if json.Unmarshal(raw, &scopeString) == nil {
			result = append(result, strings.Fields(scopeString)...)
			continue
		}
		var scopeList []string
		if err := json.Unmarshal(raw, &scopeList); err != nil {
			return nil, err
		}
		result = append(result, scopeList...)
	}
	return result, nil
}
