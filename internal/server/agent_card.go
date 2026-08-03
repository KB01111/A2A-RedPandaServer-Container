package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func loadAgentCard(path, publicBaseURL string) (*a2a.AgentCard, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent card: %w", err)
	}

	var card a2a.AgentCard
	if err := json.Unmarshal(data, &card); err != nil {
		return nil, fmt.Errorf("decode agent card: %w", err)
	}
	if card.Name == "" || card.Version == "" || len(card.Skills) == 0 {
		return nil, fmt.Errorf("agent card requires name, version, and at least one skill")
	}
	if len(card.SupportedInterfaces) == 0 {
		card.SupportedInterfaces = []*a2a.AgentInterface{
			a2a.NewAgentInterface(strings.TrimRight(publicBaseURL, "/"), a2a.TransportProtocolHTTPJSON),
		}
	}
	for _, agentInterface := range card.SupportedInterfaces {
		if agentInterface.ProtocolBinding == a2a.TransportProtocolHTTPJSON {
			agentInterface.URL = strings.TrimRight(publicBaseURL, "/")
			agentInterface.ProtocolVersion = a2a.Version
		}
	}
	return &card, nil
}
