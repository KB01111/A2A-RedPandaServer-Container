package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAgentCardRejectsUnservedInterfaces(t *testing.T) {
	tests := []struct {
		name       string
		interfaces string
		wantError  string
	}{
		{name: "null", interfaces: "[null]", wantError: "null supported interface"},
		{name: "JSON-RPC", interfaces: `[{"url":"https://example.com","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]`, wantError: "unsupported transport"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "card.json")
			card := `{
  "capabilities":{"streaming":true},
  "defaultInputModes":["text/plain"],
  "defaultOutputModes":["text/plain"],
  "description":"test",
  "name":"test",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":` + test.interfaces + `,
  "version":"1"
}`
			if err := os.WriteFile(path, []byte(card), 0o600); err != nil {
				t.Fatalf("write card: %v", err)
			}
			_, err := loadAgentCard(path, "https://a2a.example.com")
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("loadAgentCard() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestLoadAgentCardRequiresDefaultModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card.json")
	card := `{
  "capabilities":{},
  "description":"test",
  "name":"test",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":[{"url":"https://example.com","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
  "version":"1"
}`
	if err := os.WriteFile(path, []byte(card), 0o600); err != nil {
		t.Fatalf("write card: %v", err)
	}
	_, err := loadAgentCard(path, "https://a2a.example.com")
	if err == nil || !strings.Contains(err.Error(), "default input and output modes") {
		t.Fatalf("loadAgentCard() error = %v", err)
	}
}

func TestLoadAgentCardRejectsUnconfiguredCapabilities(t *testing.T) {
	for _, capability := range []string{"pushNotifications", "extendedAgentCard"} {
		t.Run(capability, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "card.json")
			card := `{
  "capabilities":{"streaming":true,"` + capability + `":true},
  "defaultInputModes":["text/plain"],
  "defaultOutputModes":["text/plain"],
  "description":"test",
  "name":"test",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":[{"url":"https://example.com","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
  "version":"1"
}`
			if err := os.WriteFile(path, []byte(card), 0o600); err != nil {
				t.Fatalf("write card: %v", err)
			}
			_, err := loadAgentCard(path, "https://a2a.example.com")
			if err == nil || !strings.Contains(err.Error(), "not configured") {
				t.Fatalf("loadAgentCard() error = %v", err)
			}
		})
	}
}

func TestLoadAgentCardRejectsUnconfiguredExtensionsAndSecurity(t *testing.T) {
	tests := []struct {
		name         string
		capabilities string
		topLevel     string
		want         string
	}{
		{name: "extension", capabilities: `"streaming":true,"extensions":[{"uri":"https://extension.example"}]`, want: "capabilities"},
		{name: "security", capabilities: `"streaming":true`, topLevel: `,"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}},"securityRequirements":[{"bearer":[]}]`, want: "security"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "card.json")
			card := `{
  "capabilities":{` + test.capabilities + `}` + test.topLevel + `,
  "defaultInputModes":["text/plain"],
  "defaultOutputModes":["text/plain"],
  "description":"test",
  "name":"test",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":[{"url":"https://example.com","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
  "version":"1"
}`
			if err := os.WriteFile(path, []byte(card), 0o600); err != nil {
				t.Fatalf("write card: %v", err)
			}
			_, err := loadAgentCard(path, "https://a2a.example.com")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadAgentCard() error = %v, want %q", err, test.want)
			}
		})
	}
}
