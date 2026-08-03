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
	if card.Name == "" || card.Description == "" || card.Version == "" || len(card.Skills) == 0 {
		return nil, fmt.Errorf("agent card requires name, description, version, and at least one skill")
	}
	if len(card.DefaultInputModes) == 0 || len(card.DefaultOutputModes) == 0 {
		return nil, fmt.Errorf("agent card requires non-empty default input and output modes")
	}
	for index, skill := range card.Skills {
		if skill.ID == "" || skill.Name == "" || skill.Description == "" || len(skill.Tags) == 0 {
			return nil, fmt.Errorf("agent card skill %d requires id, name, description, and tags", index)
		}
	}
	if !card.Capabilities.Streaming {
		return nil, fmt.Errorf("agent card must advertise the mounted streaming transport")
	}
	if card.Capabilities.PushNotifications || card.Capabilities.ExtendedAgentCard || len(card.Capabilities.Extensions) > 0 {
		return nil, fmt.Errorf("agent card advertises capabilities that are not configured")
	}
	if len(card.SecuritySchemes) > 0 || len(card.SecurityRequirements) > 0 {
		return nil, fmt.Errorf("agent card advertises security that is not configured")
	}
	if len(card.SupportedInterfaces) == 0 {
		card.SupportedInterfaces = []*a2a.AgentInterface{
			a2a.NewAgentInterface(strings.TrimRight(publicBaseURL, "/"), a2a.TransportProtocolHTTPJSON),
		}
	}
	for _, agentInterface := range card.SupportedInterfaces {
		if agentInterface == nil {
			return nil, fmt.Errorf("agent card contains a null supported interface")
		}
		if agentInterface.ProtocolBinding != a2a.TransportProtocolHTTPJSON {
			return nil, fmt.Errorf("agent card advertises unsupported transport %q", agentInterface.ProtocolBinding)
		}
		agentInterface.URL = strings.TrimRight(publicBaseURL, "/")
		agentInterface.ProtocolVersion = a2a.Version
	}
	return &card, nil
}
