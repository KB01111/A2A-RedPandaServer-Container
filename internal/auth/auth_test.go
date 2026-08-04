package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type verifierFunc func(context.Context, string) (Identity, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (Identity, error) {
	return f(ctx, token)
}

func testAuthenticator(t *testing.T, verify verifierFunc) *Authenticator {
	t.Helper()
	authenticator, err := NewAuthenticator(verify, "https://issuer.example.test/", []string{"a2a"})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	return authenticator
}

func TestMiddlewareAuthenticatesAndRemovesCredentials(t *testing.T) {
	authenticator := testAuthenticator(t, func(_ context.Context, token string) (Identity, error) {
		if token != "good-token" {
			return Identity{}, ErrInvalidToken
		}
		return Identity{Issuer: "https://issuer.example.test/", Subject: "user-1", Tenant: "tenant-1", Scopes: []string{"a2a"}}, nil
	})

	called := false
	handler := authenticator.Middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		identity, ok := IdentityFromContext(request.Context())
		if !ok || identity.Subject != "user-1" || identity.Tenant != "tenant-1" {
			t.Fatalf("identity = %#v, %v", identity, ok)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if value := request.Header.Get(name); value != "" {
				t.Errorf("%s leaked to downstream handler: %q", name, value)
			}
		}
		response.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/message:send", strings.NewReader("body"))
	request.Header.Set("Authorization", "Bearer good-token")
	request.Header.Set("Proxy-Authorization", "Basic secret")
	request.Header.Set("Cookie", "session=secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("response = %d, called = %v", response.Code, called)
	}
}

func TestMiddlewareRejectsInvalidCredentialsWithoutCallingNext(t *testing.T) {
	authenticator := testAuthenticator(t, func(_ context.Context, _ string) (Identity, error) {
		return Identity{}, ErrInvalidToken
	})
	tests := []struct {
		name    string
		headers []string
		status  int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "basic", headers: []string{"Basic secret"}, status: http.StatusUnauthorized},
		{name: "malformed", headers: []string{"Bearer"}, status: http.StatusUnauthorized},
		{name: "duplicate", headers: []string{"Bearer first", "Bearer second"}, status: http.StatusUnauthorized},
		{name: "comma combined", headers: []string{"Bearer first, Bearer second"}, status: http.StatusUnauthorized},
		{name: "comma without spaces", headers: []string{"Bearer first,second"}, status: http.StatusUnauthorized},
		{name: "tab separator", headers: []string{"Bearer\ttoken"}, status: http.StatusUnauthorized},
		{name: "trailing whitespace", headers: []string{"Bearer token "}, status: http.StatusUnauthorized},
		{name: "padding without content", headers: []string{"Bearer =="}, status: http.StatusUnauthorized},
		{name: "oversized", headers: []string{"Bearer " + strings.Repeat("x", 16*1024)}, status: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := authenticator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			request := httptest.NewRequest(http.MethodPost, "/message:send", nil)
			for _, value := range test.headers {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || called {
				t.Fatalf("status = %d, called = %v", response.Code, called)
			}
			if response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Fatalf("auth headers = %#v", response.Header())
			}
			if strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("response leaked credential: %s", response.Body.String())
			}
		})
	}
}

func TestMiddlewareRejectsMissingScope(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) {
		return Identity{Issuer: "https://issuer.example.test/", Subject: "user", Tenant: "tenant", Scopes: []string{"profile"}}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/message:send", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	authenticator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("response = %d, headers = %#v", response.Code, response.Header())
	}
}

func TestMiddlewareRejectsMismatchedVerifiedIssuer(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) {
		return Identity{
			Issuer:  "https://different-issuer.example.test",
			Subject: "user",
			Tenant:  "tenant",
			Scopes:  []string{"a2a"},
		}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/message:send", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	authenticator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("response = %d, headers = %#v", response.Code, response.Header())
	}
}

func TestIdentityInterceptorSetsCanonicalTenantAndOwner(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) { return Identity{}, nil })
	identity := Identity{Issuer: "https://issuer", Subject: "same-sub", Tenant: "tenant-a", Scopes: []string{"a2a"}}
	ctx := WithIdentity(context.Background(), identity)
	callCtx := &a2asrv.CallContext{}
	payload := &a2a.GetTaskRequest{ID: "task-1"}
	_, _, err := authenticator.CallInterceptor().Before(ctx, callCtx, &a2asrv.Request{Payload: payload})
	if err != nil {
		t.Fatalf("Before() error = %v", err)
	}
	if payload.Tenant != identity.Tenant {
		t.Fatalf("tenant = %q", payload.Tenant)
	}
	if callCtx.User == nil || callCtx.User.Name == identity.Subject || !strings.Contains(callCtx.User.Name, identity.Tenant) {
		t.Fatalf("user = %#v", callCtx.User)
	}
	if callCtx.User.Attributes["subject"] != identity.Subject || callCtx.User.Attributes["tenant"] != identity.Tenant {
		t.Fatalf("attributes = %#v", callCtx.User.Attributes)
	}
}

func TestIdentityInterceptorRejectsTenantMismatch(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) { return Identity{}, nil })
	ctx := WithIdentity(context.Background(), Identity{Subject: "user", Tenant: "tenant-a"})
	_, _, err := authenticator.CallInterceptor().Before(ctx, &a2asrv.CallContext{}, &a2asrv.Request{
		Payload: &a2a.ListTasksRequest{Tenant: "tenant-b"},
	})
	if !errors.Is(err, a2a.ErrUnauthorized) {
		t.Fatalf("Before() error = %v, want unauthorized", err)
	}
}

func TestIdentityInterceptorInjectsTenantIntoEveryRequestType(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) { return Identity{}, nil })
	identity := Identity{Issuer: "https://issuer", Subject: "user", Tenant: "canonical-tenant", Scopes: []string{"a2a"}}
	tests := []struct {
		name    string
		payload any
	}{
		{name: "send message", payload: &a2a.SendMessageRequest{}},
		{name: "get task", payload: &a2a.GetTaskRequest{}},
		{name: "list tasks", payload: &a2a.ListTasksRequest{}},
		{name: "cancel task", payload: &a2a.CancelTaskRequest{}},
		{name: "subscribe task", payload: &a2a.SubscribeToTaskRequest{}},
		{name: "extended card", payload: &a2a.GetExtendedAgentCardRequest{}},
		{name: "create push config", payload: &a2a.PushConfig{}},
		{name: "get push config", payload: &a2a.GetTaskPushConfigRequest{}},
		{name: "list push configs", payload: &a2a.ListTaskPushConfigRequest{}},
		{name: "delete push config", payload: &a2a.DeleteTaskPushConfigRequest{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			callCtx := &a2asrv.CallContext{}
			_, _, err := authenticator.CallInterceptor().Before(
				WithIdentity(context.Background(), identity),
				callCtx,
				&a2asrv.Request{Payload: test.payload},
			)
			if err != nil {
				t.Fatalf("Before() error = %v", err)
			}
			if tenant := requestTenant(test.payload); tenant != identity.Tenant {
				t.Fatalf("tenant = %q, want %q", tenant, identity.Tenant)
			}
			if callCtx.User == nil || !callCtx.User.Authenticated {
				t.Fatalf("user = %#v", callCtx.User)
			}
		})
	}
}

func TestOwnerKeyIsStableAndUnambiguous(t *testing.T) {
	identity := Identity{Issuer: "https://issuer", Tenant: "tenant", Subject: "subject"}
	if first, second := OwnerKey(identity), OwnerKey(identity); first != second {
		t.Fatalf("owner key is unstable: %q != %q", first, second)
	}
	identities := []Identity{
		identity,
		{Issuer: "https://issuer/tenant", Tenant: "", Subject: "subject"},
		{Issuer: "https://issuer", Tenant: "tenant/subject", Subject: ""},
		{Issuer: "https://issuer", Tenant: "ten", Subject: "antsubject"},
	}
	seen := make(map[string]bool, len(identities))
	for _, candidate := range identities {
		key := OwnerKey(candidate)
		if seen[key] {
			t.Fatalf("owner key collision for %#v: %q", candidate, key)
		}
		seen[key] = true
	}
}

func TestConfigureAgentCardPublishesOIDCDiscovery(t *testing.T) {
	authenticator := testAuthenticator(t, func(context.Context, string) (Identity, error) { return Identity{}, nil })
	card := &a2a.AgentCard{}
	authenticator.ConfigureAgentCard(card)
	data, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(data)
	for _, expected := range []string{`"openIdConnectSecurityScheme"`, `"openIdConnectUrl":"https://issuer.example.test/.well-known/openid-configuration"`, `"schemes":{"oidc":["a2a"]}`} {
		if !strings.Contains(jsonText, expected) {
			t.Errorf("Agent Card JSON %s does not contain %s", jsonText, expected)
		}
	}
	card.SecurityRequirements[0]["oidc"][0] = "mutated"
	if authenticator.requiredScopes[0] != "a2a" {
		t.Fatalf("Agent Card scopes alias authenticator configuration: %#v", authenticator.requiredScopes)
	}
}
