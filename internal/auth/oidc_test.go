package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

type staticClaimsVerifier struct {
	claims map[string]any
	err    error
}

func (v staticClaimsVerifier) VerifyClaims(_ context.Context, _ string, target any) error {
	if v.err != nil {
		return v.err
	}
	data, err := json.Marshal(v.claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func TestOIDCVerifierValidatesClaimsAndSkew(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	base := map[string]any{
		"sub":       "user-1",
		"tenant_id": "tenant-1",
		"exp":       now.Add(10 * time.Minute).Unix(),
		"scope":     "a2a profile",
		"scp":       []string{"tasks.read"},
	}
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid"},
		{name: "fractional numeric date", mutate: func(c map[string]any) { c["exp"] = float64(now.Add(time.Minute).Unix()) + .5 }},
		{name: "expired within skew", mutate: func(c map[string]any) { c["exp"] = now.Add(-30 * time.Second).Unix() }},
		{name: "expired at skew boundary", mutate: func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, wantErr: true},
		{name: "not before within skew", mutate: func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }},
		{name: "not before outside skew", mutate: func(c map[string]any) {
			c["nbf"] = now.Add(time.Minute + time.Second).Unix()
		}, wantErr: true},
		{name: "missing expiry", mutate: func(c map[string]any) { delete(c, "exp") }, wantErr: true},
		{name: "missing subject", mutate: func(c map[string]any) { delete(c, "sub") }, wantErr: true},
		{name: "missing tenant", mutate: func(c map[string]any) { delete(c, "tenant_id") }, wantErr: true},
		{name: "invalid scopes", mutate: func(c map[string]any) { c["scope"] = 42 }, wantErr: true},
		{name: "negative expiry", mutate: func(c map[string]any) { c["exp"] = -1 }, wantErr: true},
		{name: "out of range expiry", mutate: func(c map[string]any) { c["exp"] = 1e100 }, wantErr: true},
		{name: "out of range not before", mutate: func(c map[string]any) { c["nbf"] = 1e100 }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := make(map[string]any, len(base))
			for key, value := range base {
				claims[key] = value
			}
			if test.mutate != nil {
				test.mutate(claims)
			}
			verifier := &OIDCVerifier{
				claimsVerifier: staticClaimsVerifier{claims: claims},
				issuer:         "https://issuer.example.test",
				tenantClaim:    "tenant_id",
				clockSkew:      time.Minute,
				now:            func() time.Time { return now },
			}
			identity, err := verifier.Verify(context.Background(), "signed-token")
			if test.wantErr {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("Verify() error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if identity.Issuer != "https://issuer.example.test" || identity.Subject != "user-1" || identity.Tenant != "tenant-1" || len(identity.Scopes) != 3 {
				t.Fatalf("identity = %#v", identity)
			}
		})
	}
}

func TestOIDCVerifierMapsVerifierErrorsToStableError(t *testing.T) {
	verifier := &OIDCVerifier{
		claimsVerifier: staticClaimsVerifier{err: errors.New("signature details")},
		tenantClaim:    "tenant_id",
		now:            time.Now,
	}
	if _, err := verifier.Verify(context.Background(), "secret"); !errors.Is(err, ErrInvalidToken) || strings.Contains(err.Error(), "signature") {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestOIDCVerifierEndToEndJWTValidation(t *testing.T) {
	provider := newTestOIDCProvider(t)
	trustedKey := generateRSAKey(t)
	provider.setKeys(map[string]*rsa.PublicKey{"trusted": &trustedKey.PublicKey})
	verifier := provider.newVerifier(t)

	now := time.Now().UTC()
	baseClaims := map[string]any{
		"iss":       provider.server.URL,
		"aud":       "bridge-a2a",
		"sub":       "user-1",
		"tenant_id": "tenant-1",
		"scope":     "a2a profile",
		"exp":       now.Add(10 * time.Minute).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
	}
	untrustedKey := generateRSAKey(t)
	tests := []struct {
		name      string
		claims    map[string]any
		key       *rsa.PrivateKey
		algorithm string
		wantValid bool
	}{
		{name: "valid", claims: cloneClaims(baseClaims), key: trustedKey, algorithm: oidc.RS256, wantValid: true},
		{name: "wrong issuer", claims: withClaim(baseClaims, "iss", "https://other.example.test"), key: trustedKey, algorithm: oidc.RS256},
		{name: "wrong audience", claims: withClaim(baseClaims, "aud", "other-audience"), key: trustedKey, algorithm: oidc.RS256},
		{name: "wrong signature", claims: cloneClaims(baseClaims), key: untrustedKey, algorithm: oidc.RS256},
		{name: "disallowed algorithm", claims: cloneClaims(baseClaims), algorithm: "HS256"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawToken := signTestJWT(t, test.key, []byte("not-an-rsa-key"), "trusted", test.algorithm, test.claims)
			identity, err := verifier.Verify(context.Background(), rawToken)
			if test.wantValid {
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				if identity.Issuer != provider.server.URL || identity.Subject != "user-1" || identity.Tenant != "tenant-1" {
					t.Fatalf("identity = %#v", identity)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want stable ErrInvalidToken", err)
			}
			if identity.Issuer != "" || identity.Subject != "" || identity.Tenant != "" || len(identity.Scopes) != 0 {
				t.Fatalf("identity = %#v, want zero value", identity)
			}
		})
	}
}

func TestOIDCVerifierJWKSRotationCacheAndOutage(t *testing.T) {
	provider := newTestOIDCProvider(t)
	firstKey := generateRSAKey(t)
	secondKey := generateRSAKey(t)
	unknownKey := generateRSAKey(t)
	provider.setKeys(map[string]*rsa.PublicKey{"first": &firstKey.PublicKey})
	verifier := provider.newVerifier(t)
	claims := map[string]any{
		"iss":       provider.server.URL,
		"aud":       "bridge-a2a",
		"sub":       "user-1",
		"tenant_id": "tenant-1",
		"scope":     "a2a",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}

	firstToken := signTestJWT(t, firstKey, nil, "first", oidc.RS256, claims)
	if _, err := verifier.Verify(context.Background(), firstToken); err != nil {
		t.Fatalf("verify first key: %v", err)
	}
	if requests := provider.keyRequestCount(); requests != 1 {
		t.Fatalf("JWKS requests after initial verification = %d, want 1", requests)
	}

	provider.setKeys(map[string]*rsa.PublicKey{"second": &secondKey.PublicKey})
	secondToken := signTestJWT(t, secondKey, nil, "second", oidc.RS256, claims)
	if _, err := verifier.Verify(context.Background(), secondToken); err != nil {
		t.Fatalf("verify rotated key: %v", err)
	}
	if requests := provider.keyRequestCount(); requests != 2 {
		t.Fatalf("JWKS requests after rotation = %d, want 2", requests)
	}

	provider.setOnline(false)
	if _, err := verifier.Verify(context.Background(), secondToken); err != nil {
		t.Fatalf("cached key during outage: %v", err)
	}
	if requests := provider.keyRequestCount(); requests != 2 {
		t.Fatalf("cached verification fetched JWKS: requests = %d", requests)
	}

	unknownToken := signTestJWT(t, unknownKey, nil, "unknown", oidc.RS256, claims)
	if _, err := verifier.Verify(context.Background(), unknownToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown key during outage error = %v", err)
	}
	if requests := provider.keyRequestCount(); requests != 3 {
		t.Fatalf("unknown key did not attempt refresh: requests = %d", requests)
	}
	if _, err := verifier.Verify(context.Background(), secondToken); err != nil {
		t.Fatalf("failed refresh discarded cached keys: %v", err)
	}
}

func TestNewOIDCVerifierRejectsIssuerMismatchAndUnsafeJWKS(t *testing.T) {
	t.Run("issuer mismatch", func(t *testing.T) {
		provider := newTestOIDCProvider(t)
		provider.setIssuerOverride(provider.server.URL + "/different")
		if _, err := newOIDCVerifier(context.Background(), provider.config(), provider.server.Client()); err == nil || !strings.Contains(err.Error(), "discover OIDC provider") {
			t.Fatalf("newOIDCVerifier() error = %v", err)
		}
	})

	t.Run("unsafe jwks downgrade", func(t *testing.T) {
		provider := newTestOIDCProvider(t)
		provider.setJWKSOverride("http://169.254.169.254/latest/meta-data")
		if _, err := newOIDCVerifier(context.Background(), provider.config(), provider.server.Client()); err == nil || !strings.Contains(err.Error(), "unsafe OIDC jwks_uri") {
			t.Fatalf("newOIDCVerifier() error = %v", err)
		}
	})
}

func TestNewOIDCVerifierBlocksPrivateDestinationInProductionMode(t *testing.T) {
	provider := newTestOIDCProvider(t)
	cfg := provider.config()
	cfg.AllowPrivateIPs = false
	if _, err := newOIDCVerifier(context.Background(), cfg, provider.server.Client()); err == nil || !strings.Contains(err.Error(), "private or special-use") {
		t.Fatalf("newOIDCVerifier() error = %v, want private-address rejection", err)
	}
}

func TestPublicOIDCAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{address: "8.8.8.8", want: true},
		{address: "2606:4700:4700::1111", want: true},
		{address: "127.0.0.1"},
		{address: "10.0.0.1"},
		{address: "169.254.169.254"},
		{address: "100.64.0.1"},
		{address: "198.18.0.1"},
		{address: "192.0.2.1"},
		{address: "::1"},
		{address: "fc00::1"},
		{address: "fe80::1"},
		{address: "2001:db8::1"},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := publicOIDCAddress(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("publicOIDCAddress(%q) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}

func TestNewOIDCVerifierEnforcesIssuerOrigin(t *testing.T) {
	t.Run("rejects HTTPS jwks_uri on a different host", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			targetRequests.Add(1)
		}))
		t.Cleanup(target.Close)

		provider := newTestOIDCProvider(t)
		provider.setJWKSOverride(urlWithHostname(t, target.URL, "localhost"))
		if _, err := newOIDCVerifier(context.Background(), provider.config(), provider.server.Client()); err == nil || !strings.Contains(err.Error(), "unsafe OIDC jwks_uri") {
			t.Fatalf("newOIDCVerifier() error = %v", err)
		}
		if requests := targetRequests.Load(); requests != 0 {
			t.Fatalf("different-host JWKS requests = %d, want 0", requests)
		}
	})

	t.Run("rejects discovery redirect to a different host", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			targetRequests.Add(1)
		}))
		t.Cleanup(target.Close)

		provider := newTestOIDCProvider(t)
		provider.setDiscoveryRedirect(urlWithHostname(t, target.URL, "localhost"))
		if _, err := newOIDCVerifier(context.Background(), provider.config(), provider.server.Client()); err == nil || !strings.Contains(err.Error(), "unsafe OIDC redirect") {
			t.Fatalf("newOIDCVerifier() error = %v", err)
		}
		if requests := targetRequests.Load(); requests != 0 {
			t.Fatalf("different-host discovery requests = %d, want 0", requests)
		}
	})

	t.Run("allows same-origin discovery path redirect", func(t *testing.T) {
		provider := newTestOIDCProvider(t)
		provider.setDiscoveryRedirect(provider.server.URL + "/redirected/openid-configuration")
		if _, err := newOIDCVerifier(context.Background(), provider.config(), provider.server.Client()); err != nil {
			t.Fatalf("newOIDCVerifier() error = %v", err)
		}
	})

	t.Run("rejects JWKS redirect to a different host", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			targetRequests.Add(1)
		}))
		t.Cleanup(target.Close)

		provider := newTestOIDCProvider(t)
		provider.setJWKSRedirect(urlWithHostname(t, target.URL, "localhost"))
		verifier := provider.newVerifier(t)
		key := generateRSAKey(t)
		token := signTestJWT(t, key, nil, "redirected", oidc.RS256, map[string]any{
			"iss":       provider.server.URL,
			"aud":       "bridge-a2a",
			"sub":       "user-1",
			"tenant_id": "tenant-1",
			"exp":       time.Now().Add(10 * time.Minute).Unix(),
		})
		if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify() error = %v, want stable ErrInvalidToken", err)
		}
		if requests := targetRequests.Load(); requests != 0 {
			t.Fatalf("different-host JWKS redirect requests = %d, want 0", requests)
		}
	})
}

func TestSameOriginRequiresMatchingSchemeHostAndPort(t *testing.T) {
	issuer := parseTestURL(t, "https://issuer.example.test/tenant")
	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "same origin", candidate: "https://issuer.example.test/keys", want: true},
		{name: "implicit default port", candidate: "https://issuer.example.test:443/keys", want: true},
		{name: "scheme downgrade", candidate: "http://issuer.example.test/keys"},
		{name: "different host", candidate: "https://keys.example.test/keys"},
		{name: "different port", candidate: "https://issuer.example.test:8443/keys"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sameOrigin(issuer, parseTestURL(t, test.candidate)); got != test.want {
				t.Fatalf("sameOrigin() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNewOIDCVerifierAllowsLoopbackHTTPIssuer(t *testing.T) {
	provider := newLoopbackTestOIDCProvider(t)
	key := generateRSAKey(t)
	provider.setKeys(map[string]*rsa.PublicKey{"loopback": &key.PublicKey})
	verifier := provider.newVerifier(t)
	token := signTestJWT(t, key, nil, "loopback", oidc.RS256, map[string]any{
		"iss":       provider.server.URL,
		"aud":       "bridge-a2a",
		"sub":       "user-1",
		"tenant_id": "tenant-1",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestValidateOIDCConfigRejectsUnsafeInputs(t *testing.T) {
	valid := config.OIDCConfig{
		Issuer:            "https://issuer.example.test/tenant",
		Audience:          "bridge-a2a",
		TenantClaim:       "tenant_id",
		AllowedAlgorithms: []string{oidc.RS256},
		ClockSkew:         time.Minute,
		HTTPTimeout:       time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*config.OIDCConfig)
	}{
		{name: "non HTTP scheme", mutate: func(c *config.OIDCConfig) { c.Issuer = "file:///tmp/issuer" }},
		{name: "non loopback cleartext", mutate: func(c *config.OIDCConfig) { c.Issuer = "http://issuer.example.test" }},
		{name: "userinfo", mutate: func(c *config.OIDCConfig) { c.Issuer = "https://user@issuer.example.test" }},
		{name: "query", mutate: func(c *config.OIDCConfig) { c.Issuer = "https://issuer.example.test?tenant=one" }},
		{name: "empty audience", mutate: func(c *config.OIDCConfig) { c.Audience = "" }},
		{name: "unsafe algorithm", mutate: func(c *config.OIDCConfig) { c.AllowedAlgorithms = []string{"HS256"} }},
		{name: "duplicate algorithm", mutate: func(c *config.OIDCConfig) { c.AllowedAlgorithms = []string{oidc.RS256, oidc.RS256} }},
		{name: "excessive skew", mutate: func(c *config.OIDCConfig) { c.ClockSkew = 6 * time.Minute }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			cfg.AllowedAlgorithms = append([]string(nil), valid.AllowedAlgorithms...)
			test.mutate(&cfg)
			if _, err := validateOIDCConfig(cfg); err == nil {
				t.Fatal("validateOIDCConfig() unexpectedly succeeded")
			}
		})
	}
	if _, err := validateOIDCConfig(valid); err != nil {
		t.Fatalf("valid configuration error = %v", err)
	}
}

type testOIDCProvider struct {
	t                 *testing.T
	server            *httptest.Server
	mu                sync.Mutex
	keys              map[string]*rsa.PublicKey
	online            bool
	keyRequests       int
	issuerOverride    string
	jwksOverride      string
	discoveryRedirect string
	jwksRedirect      string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	provider := &testOIDCProvider{t: t, online: true, keys: make(map[string]*rsa.PublicKey)}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func newLoopbackTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	provider := &testOIDCProvider{t: t, online: true, keys: make(map[string]*rsa.PublicKey)}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *testOIDCProvider) config() config.OIDCConfig {
	return config.OIDCConfig{
		Issuer:            p.server.URL,
		Audience:          "bridge-a2a",
		TenantClaim:       "tenant_id",
		AllowedAlgorithms: []string{oidc.RS256},
		ClockSkew:         time.Minute,
		HTTPTimeout:       2 * time.Second,
		AllowPrivateIPs:   true,
	}
}

func (p *testOIDCProvider) newVerifier(t *testing.T) *OIDCVerifier {
	t.Helper()
	verifier, err := newOIDCVerifier(context.Background(), p.config(), p.server.Client())
	if err != nil {
		t.Fatalf("newOIDCVerifier() error = %v", err)
	}
	return verifier
}

func (p *testOIDCProvider) serveHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		p.mu.Lock()
		redirect := p.discoveryRedirect
		p.mu.Unlock()
		if redirect != "" {
			http.Redirect(response, request, redirect, http.StatusFound)
			return
		}
		p.writeDiscovery(response)
	case "/redirected/openid-configuration":
		p.writeDiscovery(response)
	case "/jwks":
		p.mu.Lock()
		p.keyRequests++
		redirect := p.jwksRedirect
		online := p.online
		keyIDs := make([]string, 0, len(p.keys))
		for keyID := range p.keys {
			keyIDs = append(keyIDs, keyID)
		}
		sort.Strings(keyIDs)
		keys := make([]map[string]string, 0, len(keyIDs))
		for _, keyID := range keyIDs {
			key := p.keys[keyID]
			keys = append(keys, rsaJWK(keyID, key))
		}
		p.mu.Unlock()
		if redirect != "" {
			http.Redirect(response, request, redirect, http.StatusFound)
			return
		}
		if !online {
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(map[string]any{"keys": keys}); err != nil {
			p.t.Errorf("encode JWKS response: %v", err)
		}
	default:
		http.NotFound(response, request)
	}
}

func (p *testOIDCProvider) writeDiscovery(response http.ResponseWriter) {
	p.mu.Lock()
	issuer := p.issuerOverride
	jwksURL := p.jwksOverride
	p.mu.Unlock()
	if issuer == "" {
		issuer = p.server.URL
	}
	if jwksURL == "" {
		jwksURL = p.server.URL + "/jwks"
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                p.server.URL + "/authorize",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              jwksURL,
		"id_token_signing_alg_values_supported": []string{oidc.RS256},
	}); err != nil {
		p.t.Errorf("encode discovery response: %v", err)
	}
}

func (p *testOIDCProvider) setKeys(keys map[string]*rsa.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = keys
}

func (p *testOIDCProvider) setOnline(online bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.online = online
}

func (p *testOIDCProvider) setIssuerOverride(issuer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuerOverride = issuer
}

func (p *testOIDCProvider) setJWKSOverride(jwksURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksOverride = jwksURL
}

func (p *testOIDCProvider) setDiscoveryRedirect(redirect string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discoveryRedirect = redirect
}

func (p *testOIDCProvider) setJWKSRedirect(redirect string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksRedirect = redirect
}

func (p *testOIDCProvider) keyRequestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyRequests
}

func parseTestURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return parsed
}

func urlWithHostname(t *testing.T, rawURL, hostname string) string {
	t.Helper()
	parsed := parseTestURL(t, rawURL)
	parsed.Host = hostname + ":" + parsed.Port()
	return parsed.String()
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func rsaJWK(keyID string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": oidc.RS256,
		"kid": keyID,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, hmacKey []byte, keyID, algorithm string, claims map[string]any) string {
	t.Helper()
	header := encodeJWTPart(t, map[string]any{"alg": algorithm, "kid": keyID, "typ": "JWT"})
	payload := encodeJWTPart(t, claims)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	var signature []byte
	switch algorithm {
	case oidc.RS256:
		if key == nil {
			t.Fatal("RSA key is required")
		}
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("sign JWT: %v", err)
		}
	case "HS256":
		mac := hmac.New(sha256.New, hmacKey)
		_, _ = mac.Write([]byte(signingInput))
		signature = mac.Sum(nil)
	default:
		t.Fatalf("unsupported test algorithm %q", algorithm)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJWTPart(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT part: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func cloneClaims(claims map[string]any) map[string]any {
	result := make(map[string]any, len(claims))
	for name, value := range claims {
		result[name] = value
	}
	return result
}

func withClaim(claims map[string]any, name string, value any) map[string]any {
	result := cloneClaims(claims)
	result[name] = value
	return result
}
