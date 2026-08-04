package redpanda

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestNewClientValidatesAndConstructsProducerAndConsumer(t *testing.T) {
	tlsConfig := &tls.Config{}
	client, err := NewClient(ClientConfig{
		Brokers:         []string{"redpanda.internal:9092"},
		TLSConfig:       tlsConfig,
		SCRAM:           &SCRAMConfig{Username: "bridge", Password: "secret"},
		DeliveryTimeout: 5 * time.Second,
		GroupID:         "bridge-results",
		Topics:          []string{"a2a.results"},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.Close()
	if tlsConfig.MinVersion != 0 {
		t.Fatalf("NewClient() mutated caller TLS config: MinVersion = %d", tlsConfig.MinVersion)
	}
}

func TestNewClientRejectsInvalidConfig(t *testing.T) {
	tests := map[string]ClientConfig{
		"no brokers":      {},
		"scheme":          {Brokers: []string{"kafka://broker:9092"}},
		"missing port":    {Brokers: []string{"broker"}},
		"partial scram":   {Brokers: []string{"broker:9092"}, SCRAM: &SCRAMConfig{Username: "bridge"}},
		"topics no group": {Brokers: []string{"broker:9092"}, Topics: []string{"results"}},
		"group no topics": {Brokers: []string{"broker:9092"}, GroupID: "group"},
		"duplicate topic": {Brokers: []string{"broker:9092"}, GroupID: "group", Topics: []string{"results", "results"}},
		"bad timeout":     {Brokers: []string{"broker:9092"}, DeliveryTimeout: -time.Second},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(config); err == nil {
				t.Fatal("NewClient() error = nil, want rejection")
			}
		})
	}
}

func TestTopicsValidate(t *testing.T) {
	valid := Topics{Commands: "a2a.commands", Results: "a2a.results", DeadLetter: "a2a.dlq"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	valid.Results = valid.Commands
	if err := valid.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("Validate() error = %v, want distinct topics error", err)
	}
}
