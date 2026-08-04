package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
)

func TestRequiredA2ARoutes(t *testing.T) {
	testServer := newTestServer(t)

	cardResponse := request(t, testServer.Client(), http.MethodGet, testServer.URL+"/.well-known/agent-card.json", nil)
	defer closeBody(t, cardResponse.Body)
	if cardResponse.StatusCode != http.StatusOK {
		t.Fatalf("agent card status = %d, want 200", cardResponse.StatusCode)
	}
	var card a2a.AgentCard
	decodeJSON(t, cardResponse.Body, &card)
	if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != "https://a2a.example.com" {
		t.Fatalf("agent card interface = %#v", card.SupportedInterfaces)
	}
	if !card.Capabilities.Streaming {
		t.Fatal("agent card does not advertise streaming")
	}

	sendBody := marshalJSON(t, a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
	})
	sendResponse := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:send", sendBody)
	defer closeBody(t, sendResponse.Body)
	if sendResponse.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(sendResponse.Body)
		t.Fatalf("message send status = %d, body = %s", sendResponse.StatusCode, data)
	}
	if contentType := sendResponse.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("message send Content-Type = %q", contentType)
	}
	var sendResult a2a.StreamResponse
	decodeJSON(t, sendResponse.Body, &sendResult)
	task, ok := sendResult.Event.(*a2a.Task)
	if !ok || task.ID == "" || task.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("message send result = %#v", sendResult.Event)
	}

	getResponse := request(t, testServer.Client(), http.MethodGet, testServer.URL+"/tasks/"+string(task.ID), nil)
	defer closeBody(t, getResponse.Body)
	if getResponse.StatusCode != http.StatusOK {
		t.Fatalf("get task status = %d", getResponse.StatusCode)
	}

	listResponse := request(t, testServer.Client(), http.MethodGet, testServer.URL+"/tasks?pageSize=10", nil)
	defer closeBody(t, listResponse.Body)
	if listResponse.StatusCode != http.StatusOK {
		t.Fatalf("list tasks status = %d", listResponse.StatusCode)
	}

	streamBody := marshalJSON(t, a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("stream me")),
	})
	streamResponse := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:stream", streamBody)
	defer closeBody(t, streamResponse.Body)
	if streamResponse.StatusCode != http.StatusOK {
		t.Fatalf("message stream status = %d", streamResponse.StatusCode)
	}
	if contentType := streamResponse.Header.Get("Content-Type"); !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("message stream Content-Type = %q", contentType)
	}
	streamData, err := io.ReadAll(streamResponse.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if events := bytes.Count(streamData, []byte("data:")); events < 3 {
		t.Fatalf("stream emitted %d events, want at least 3: %s", events, streamData)
	}

	subscribeResponse := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/tasks/"+string(task.ID)+":subscribe", nil)
	defer closeBody(t, subscribeResponse.Body)
	if subscribeResponse.StatusCode == http.StatusMethodNotAllowed || subscribeResponse.StatusCode == http.StatusNotFound {
		t.Fatalf("subscribe route status = %d", subscribeResponse.StatusCode)
	}

	cancelResponse := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/tasks/"+string(task.ID)+":cancel", nil)
	defer closeBody(t, cancelResponse.Body)
	if cancelResponse.StatusCode == http.StatusMethodNotAllowed || cancelResponse.StatusCode == http.StatusNotFound {
		t.Fatalf("cancel route status = %d", cancelResponse.StatusCode)
	}
}

func TestMalformedMessageReturnsProtocolError(t *testing.T) {
	testServer := newTestServer(t)
	response := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:send", strings.NewReader(`{"message":`))
	defer closeBody(t, response.Body)
	if response.StatusCode < 400 || response.StatusCode >= 500 {
		t.Fatalf("malformed message status = %d, want 4xx", response.StatusCode)
	}
}

func TestProtocolVersionIsRequired(t *testing.T) {
	for _, version := range []string{"", "0.3", "2.0"} {
		t.Run("version_"+version, func(t *testing.T) {
			testServer := newTestServer(t)
			message := marshalJSON(t, a2a.SendMessageRequest{
				Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/message:send", message)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if version != "" {
				req.Header.Set(a2a.SvcParamVersion, version)
			}
			response, err := testServer.Client().Do(req)
			if err != nil {
				t.Fatalf("send request: %v", err)
			}
			defer closeBody(t, response.Body)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("unsupported version status = %d, want 400", response.StatusCode)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if !bytes.Contains(body, []byte("VERSION_NOT_SUPPORTED")) {
				t.Fatalf("unsupported version body = %s", body)
			}
		})
	}
}

func TestProtocolVersionQueryParameter(t *testing.T) {
	testServer := newTestServer(t)
	body := marshalJSON(t, a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/message:send?A2A-Version=1.0", body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := testServer.Client().Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("query version status = %d, body = %s", response.StatusCode, data)
	}
}

func TestConflictingProtocolVersionsAreRejected(t *testing.T) {
	testServer := newTestServer(t)
	body := marshalJSON(t, a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/message:send?A2A-Version=0.3", body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.SvcParamVersion, string(a2a.Version))
	response, err := testServer.Client().Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("conflicting version status = %d, want 400", response.StatusCode)
	}
}

func TestNormalizeExtensions(t *testing.T) {
	var got []string
	handler := normalizeServiceParameters(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		got = request.Header.Values(a2a.SvcParamExtensions)
		response.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/?A2A-Extensions=https%3A%2F%2Ffour.example", nil)
	req.Header.Add(a2a.SvcParamExtensions, "https://one.example, https://two.example")
	req.Header.Add(a2a.SvcParamExtensions, "https://three.example")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	want := []string{"https://one.example", "https://two.example", "https://three.example", "https://four.example"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("extensions = %#v, want %#v", got, want)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	testServer := newTestServerWithMaxBody(t, 128)
	response := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:send", strings.NewReader(strings.Repeat("x", 129)))
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", response.StatusCode)
	}
}

func TestProductionRequiresExplicitTaskStore(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Environment = "production"
	_, err := New(cfg, Dependencies{Dispatcher: orchestrator.LoopbackDispatcher{}})
	if err == nil || !strings.Contains(err.Error(), "task store is required") {
		t.Fatalf("New() error = %v, want task store requirement", err)
	}
}

func TestProductionRequiresAuthentication(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Environment = "production"
	_, err := New(cfg, Dependencies{
		Dispatcher: orchestrator.LoopbackDispatcher{},
		TaskStore:  taskstore.NewInMemory(nil),
	})
	if err == nil || !strings.Contains(err.Error(), "authentication is required") {
		t.Fatalf("New() error = %v, want authentication requirement", err)
	}
}

func TestAuthenticatedServerKeepsAgentCardPublicAndProtectsA2A(t *testing.T) {
	testServer := newAuthenticatedTestServer(t)

	cardResponse, err := testServer.Client().Get(testServer.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(t, cardResponse.Body)
	if cardResponse.StatusCode != http.StatusOK {
		t.Fatalf("agent card status = %d", cardResponse.StatusCode)
	}
	cardBody, err := io.ReadAll(cardResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cardBody, []byte("openIdConnectSecurityScheme")) || !bytes.Contains(cardBody, []byte("https://issuer.example.test/.well-known/openid-configuration")) {
		t.Fatalf("Agent Card security = %s", cardBody)
	}

	message := marshalJSON(t, a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))})
	unauthenticated := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:send", message)
	defer closeBody(t, unauthenticated.Body)
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.StatusCode)
	}

	message = marshalJSON(t, a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/message:send", message)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.SvcParamVersion, string(a2a.Version))
	req.Header.Set("Authorization", "Bearer valid")
	response, err := testServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("authenticated status = %d, body = %s", response.StatusCode, body)
	}
}

func TestAuthenticationRunsBeforeRequestBodyBuffering(t *testing.T) {
	testServer := newAuthenticatedTestServerWithMaxBody(t, 8)
	response := request(t, testServer.Client(), http.MethodPost, testServer.URL+"/message:send", strings.NewReader(strings.Repeat("x", 1024)))
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want authentication before 413", response.StatusCode)
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	return newTestServerWithMaxBody(t, 1<<20)
}

func newTestServerWithMaxBody(t *testing.T, maxRequestBytes int64) *httptest.Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.MaxRequestBytes = maxRequestBytes
	handler, err := New(cfg, Dependencies{Dispatcher: orchestrator.LoopbackDispatcher{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

type testVerifier struct{}

func (testVerifier) Verify(_ context.Context, token string) (auth.Identity, error) {
	if token != "valid" {
		return auth.Identity{}, auth.ErrInvalidToken
	}
	return auth.Identity{
		Issuer:  "https://issuer.example.test",
		Subject: "user-1",
		Tenant:  "tenant-1",
		Scopes:  []string{"a2a"},
	}, nil
}

func newAuthenticatedTestServer(t *testing.T) *httptest.Server {
	return newAuthenticatedTestServerWithMaxBody(t, 1<<20)
}

func newAuthenticatedTestServerWithMaxBody(t *testing.T, maxRequestBytes int64) *httptest.Server {
	t.Helper()
	authenticator, err := auth.NewAuthenticator(testVerifier{}, "https://issuer.example.test", []string{"a2a"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig(t)
	cfg.MaxRequestBytes = maxRequestBytes
	handler, err := New(cfg, Dependencies{
		Dispatcher:     orchestrator.LoopbackDispatcher{},
		Authentication: authenticator,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	testServer := httptest.NewServer(handler)
	t.Cleanup(testServer.Close)
	return testServer
}

func newTestConfig(t *testing.T) config.Config {
	t.Helper()
	cardPath := filepath.Join(t.TempDir(), "agent-card.json")
	card := `{
  "capabilities":{"streaming":true},
  "defaultInputModes":["text/plain"],
  "defaultOutputModes":["text/plain"],
  "description":"test agent",
  "name":"test agent",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":[{"url":"http://wrong.invalid","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
  "version":"test"
}`
	if err := os.WriteFile(cardPath, []byte(card), 0o600); err != nil {
		t.Fatalf("write agent card: %v", err)
	}
	return config.Config{
		Environment:     "test",
		Port:            8080,
		PublicBaseURL:   "https://a2a.example.com/",
		AgentCardPath:   cardPath,
		ShutdownTimeout: time.Second,
		MaxRequestBytes: 1 << 20,
	}
}

func request(t *testing.T, client *http.Client, method, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(a2a.SvcParamVersion, string(a2a.Version))
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	return response
}

func marshalJSON(t *testing.T, value any) io.Reader {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return bytes.NewReader(data)
}

func decodeJSON(t *testing.T, reader io.Reader, target any) {
	t.Helper()
	if err := json.NewDecoder(reader).Decode(target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func closeBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}
