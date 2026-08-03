package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	"github.com/a2aproject/a2a-go/v2/a2a"
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

func TestNormalizeExtensions(t *testing.T) {
	var got []string
	handler := normalizeServiceParameters(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		got = request.Header.Values(a2a.SvcParamExtensions)
		response.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add(a2a.SvcParamExtensions, "https://one.example, https://two.example")
	req.Header.Add(a2a.SvcParamExtensions, "https://three.example")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	want := []string{"https://one.example", "https://two.example", "https://three.example"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("extensions = %#v, want %#v", got, want)
	}
}

func newTestServer(t *testing.T) *httptest.Server {
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
	handler, err := New(config.Config{
		Environment:     "test",
		Port:            8080,
		PublicBaseURL:   "https://a2a.example.com/",
		AgentCardPath:   cardPath,
		ShutdownTimeout: time.Second,
	}, Dependencies{Dispatcher: orchestrator.LoopbackDispatcher{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
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
