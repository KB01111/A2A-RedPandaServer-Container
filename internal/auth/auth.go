package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

var ErrInvalidToken = errors.New("invalid access token")

type Identity struct {
	Issuer  string
	Subject string
	Tenant  string
	Scopes  []string
}

type Verifier interface {
	Verify(context.Context, string) (Identity, error)
}

type Authenticator struct {
	verifier       Verifier
	issuer         string
	requiredScopes []string
}

func NewAuthenticator(verifier Verifier, issuer string, requiredScopes []string) (*Authenticator, error) {
	if verifier == nil {
		return nil, fmt.Errorf("token verifier is required")
	}
	if issuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}
	if len(requiredScopes) == 0 {
		return nil, fmt.Errorf("at least one required scope is required")
	}
	return &Authenticator{
		verifier:       verifier,
		issuer:         issuer,
		requiredScopes: append([]string(nil), requiredScopes...),
	}, nil
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		rawToken, err := bearerToken(request.Header.Values("Authorization"))
		if err != nil {
			writeAuthError(response, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer authentication is required")
			return
		}
		identity, err := a.verifier.Verify(request.Context(), rawToken)
		if err != nil || identity.Issuer != a.issuer || identity.Subject == "" || identity.Tenant == "" {
			writeAuthError(response, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer authentication is required")
			return
		}
		for _, required := range a.requiredScopes {
			if !slices.Contains(identity.Scopes, required) {
				writeAuthError(response, http.StatusForbidden, "PERMISSION_DENIED", "required scope is missing")
				return
			}
		}

		request = request.Clone(WithIdentity(request.Context(), identity))
		request.Header.Del("Authorization")
		request.Header.Del("Proxy-Authorization")
		request.Header.Del("Cookie")
		next.ServeHTTP(response, request)
	})
}

func (a *Authenticator) CallInterceptor() a2asrv.CallInterceptor {
	return identityInterceptor{}
}

func (a *Authenticator) ConfigureAgentCard(card *a2a.AgentCard) {
	const schemeName = a2a.SecuritySchemeName("oidc")
	card.SecuritySchemes = a2a.NamedSecuritySchemes{
		schemeName: a2a.OpenIDConnectSecurityScheme{
			Description:      "OIDC bearer token issued for the Bridge A2A audience",
			OpenIDConnectURL: strings.TrimSuffix(a.issuer, "/") + "/.well-known/openid-configuration",
		},
	}
	card.SecurityRequirements = a2a.SecurityRequirementsOptions{
		a2a.SecurityRequirements{
			schemeName: a2a.SecuritySchemeScopes(append([]string(nil), a.requiredScopes...)),
		},
	}
}

type identityInterceptor struct {
	a2asrv.PassthroughCallInterceptor
}

func (identityInterceptor) Before(
	ctx context.Context,
	callCtx *a2asrv.CallContext,
	request *a2asrv.Request,
) (context.Context, any, error) {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return ctx, nil, a2a.ErrUnauthenticated
	}
	if tenant := requestTenant(request.Payload); tenant != "" && tenant != identity.Tenant {
		return ctx, nil, a2a.ErrUnauthorized
	}
	setRequestTenant(request.Payload, identity.Tenant)
	callCtx.User = a2asrv.NewAuthenticatedUser(OwnerKey(identity), map[string]any{
		"issuer":  identity.Issuer,
		"subject": identity.Subject,
		"tenant":  identity.Tenant,
		"scopes":  append([]string(nil), identity.Scopes...),
	})
	return ctx, nil, nil
}

// OwnerKey returns an unambiguous stable identity key for SDK components whose
// ownership contract exposes only one string.
func OwnerKey(identity Identity) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(identity.Issuer), identity.Issuer, len(identity.Tenant), identity.Tenant, len(identity.Subject), identity.Subject)
}

func requestTenant(payload any) string {
	switch value := payload.(type) {
	case *a2a.SendMessageRequest:
		return value.Tenant
	case *a2a.GetTaskRequest:
		return value.Tenant
	case *a2a.ListTasksRequest:
		return value.Tenant
	case *a2a.CancelTaskRequest:
		return value.Tenant
	case *a2a.SubscribeToTaskRequest:
		return value.Tenant
	case *a2a.GetExtendedAgentCardRequest:
		return value.Tenant
	case *a2a.PushConfig:
		return value.Tenant
	case *a2a.GetTaskPushConfigRequest:
		return value.Tenant
	case *a2a.ListTaskPushConfigRequest:
		return value.Tenant
	case *a2a.DeleteTaskPushConfigRequest:
		return value.Tenant
	default:
		return ""
	}
}

func setRequestTenant(payload any, tenant string) {
	switch value := payload.(type) {
	case *a2a.SendMessageRequest:
		value.Tenant = tenant
	case *a2a.GetTaskRequest:
		value.Tenant = tenant
	case *a2a.ListTasksRequest:
		value.Tenant = tenant
	case *a2a.CancelTaskRequest:
		value.Tenant = tenant
	case *a2a.SubscribeToTaskRequest:
		value.Tenant = tenant
	case *a2a.GetExtendedAgentCardRequest:
		value.Tenant = tenant
	case *a2a.PushConfig:
		value.Tenant = tenant
	case *a2a.GetTaskPushConfigRequest:
		value.Tenant = tenant
	case *a2a.ListTaskPushConfigRequest:
		value.Tenant = tenant
	case *a2a.DeleteTaskPushConfigRequest:
		value.Tenant = tenant
	}
}

func bearerToken(values []string) (string, error) {
	if len(values) != 1 {
		return "", ErrInvalidToken
	}
	value := values[0]
	if len(value) > 16*1024 {
		return "", ErrInvalidToken
	}
	separator := strings.IndexByte(value, ' ')
	if separator <= 0 || !strings.EqualFold(value[:separator], "Bearer") {
		return "", ErrInvalidToken
	}
	token := value[separator:]
	for len(token) > 0 && token[0] == ' ' {
		token = token[1:]
	}
	if !validBearerCredential(token) {
		return "", ErrInvalidToken
	}
	return token, nil
}

// validBearerCredential implements the b64token character set from RFC 6750.
// In particular, it rejects commas and horizontal tabs so combined or malformed
// Authorization fields cannot be interpreted as a single credential.
func validBearerCredential(value string) bool {
	if value == "" {
		return false
	}
	padding := false
	content := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '=' {
			if !content {
				return false
			}
			padding = true
			continue
		}
		if padding {
			return false
		}
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			content = true
			continue
		}
		switch character {
		case '-', '.', '_', '~', '+', '/':
			content = true
			continue
		default:
			return false
		}
	}
	return content
}

func writeAuthError(response http.ResponseWriter, status int, code, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		response.Header().Set("WWW-Authenticate", `Bearer realm="bridge-a2a", error="invalid_token"`)
	}
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"error": map[string]any{
			"code":    status,
			"status":  code,
			"message": message,
		},
	})
}

type identityContextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	identity.Scopes = append([]string(nil), identity.Scopes...)
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	identity.Scopes = append([]string(nil), identity.Scopes...)
	return identity, ok
}
