package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type RedpandaConfig struct {
	Brokers            []string
	SecurityProtocol   string
	SASLMechanism      string
	Username           string
	PasswordFile       string
	CAFile             string
	ClientCertFile     string
	ClientKeyFile      string
	TopicPrefix        string
	ConsumerGroup      string
	ClientID           string
	ProduceTimeout     time.Duration
	ResultIdleTimeout  time.Duration
	MaxMessageBytes    int
	AllowAutoTopic     bool
	AllowPrivateBroker bool
}

func (c RedpandaConfig) Enabled() bool        { return len(c.Brokers) > 0 }
func (c RedpandaConfig) CommandTopic() string { return c.TopicPrefix + ".agent-commands.v1" }
func (c RedpandaConfig) ResultTopic() string  { return c.TopicPrefix + ".agent-results.v1" }
func (c RedpandaConfig) DLQTopic() string     { return c.TopicPrefix + ".agent-dlq.v1" }

func loadRedpandaConfig(environment string) (RedpandaConfig, error) {
	const brokerKey = "REDPANDA_BROKERS"
	brokers := splitCSV(strings.TrimSpace(envOrDefault(brokerKey, "")))
	keys := []string{
		"REDPANDA_SECURITY_PROTOCOL", "REDPANDA_SASL_MECHANISM", "REDPANDA_USERNAME",
		"REDPANDA_PASSWORD_FILE", "REDPANDA_CA_FILE", "REDPANDA_CLIENT_CERT_FILE",
		"REDPANDA_CLIENT_KEY_FILE", "REDPANDA_TOPIC_PREFIX", "REDPANDA_CONSUMER_GROUP",
		"REDPANDA_CLIENT_ID", "REDPANDA_PRODUCE_TIMEOUT", "REDPANDA_RESULT_IDLE_TIMEOUT",
		"REDPANDA_MAX_MESSAGE_BYTES", "REDPANDA_ALLOW_AUTO_TOPIC_CREATION",
	}
	if len(brokers) == 0 {
		if key, ok := anyConfigured(keys...); ok {
			return RedpandaConfig{}, fmt.Errorf("%s requires %s", key, brokerKey)
		}
		return RedpandaConfig{}, nil
	}
	for _, broker := range brokers {
		host, port, err := net.SplitHostPort(broker)
		if err != nil || strings.TrimSpace(host) == "" {
			return RedpandaConfig{}, fmt.Errorf("REDPANDA_BROKERS entries must be host:port without a URL scheme")
		}
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return RedpandaConfig{}, fmt.Errorf("REDPANDA_BROKERS contains an invalid port")
		}
	}
	protocolDefault := "PLAINTEXT"
	if environment == "staging" || environment == "production" {
		protocolDefault = "SASL_SSL"
	}
	protocol := strings.ToUpper(strings.TrimSpace(envOrDefault("REDPANDA_SECURITY_PROTOCOL", protocolDefault)))
	if protocol != "PLAINTEXT" && protocol != "SASL_SSL" {
		return RedpandaConfig{}, fmt.Errorf("REDPANDA_SECURITY_PROTOCOL must be PLAINTEXT or SASL_SSL")
	}
	if environment == "staging" || environment == "production" {
		if protocol != "SASL_SSL" {
			return RedpandaConfig{}, fmt.Errorf("REDPANDA_SECURITY_PROTOCOL must be SASL_SSL in staging and production")
		}
	}
	if protocol == "PLAINTEXT" {
		for _, broker := range brokers {
			host, _, _ := net.SplitHostPort(broker)
			if !IsLoopbackHost(host) {
				return RedpandaConfig{}, fmt.Errorf("PLAINTEXT Redpanda brokers must be loopback development endpoints")
			}
		}
	}
	username := strings.TrimSpace(envOrDefault("REDPANDA_USERNAME", ""))
	passwordFile := strings.TrimSpace(envOrDefault("REDPANDA_PASSWORD_FILE", ""))
	mechanism := strings.ToUpper(strings.TrimSpace(envOrDefault("REDPANDA_SASL_MECHANISM", "SCRAM-SHA-256")))
	if protocol == "SASL_SSL" {
		if mechanism != "SCRAM-SHA-256" || username == "" || passwordFile == "" {
			return RedpandaConfig{}, fmt.Errorf("SASL_SSL requires SCRAM-SHA-256, REDPANDA_USERNAME, and REDPANDA_PASSWORD_FILE")
		}
	}
	caFile := strings.TrimSpace(envOrDefault("REDPANDA_CA_FILE", ""))
	certFile := strings.TrimSpace(envOrDefault("REDPANDA_CLIENT_CERT_FILE", ""))
	keyFile := strings.TrimSpace(envOrDefault("REDPANDA_CLIENT_KEY_FILE", ""))
	if (certFile == "") != (keyFile == "") {
		return RedpandaConfig{}, fmt.Errorf("REDPANDA_CLIENT_CERT_FILE and REDPANDA_CLIENT_KEY_FILE must be configured together")
	}
	for key, value := range map[string]string{
		"REDPANDA_PASSWORD_FILE":    passwordFile,
		"REDPANDA_CA_FILE":          caFile,
		"REDPANDA_CLIENT_CERT_FILE": certFile,
		"REDPANDA_CLIENT_KEY_FILE":  keyFile,
	} {
		if err := requireAbsolutePath(key, value); err != nil {
			return RedpandaConfig{}, err
		}
	}
	topicPrefix := strings.TrimSpace(envOrDefault("REDPANDA_TOPIC_PREFIX", "bridge-a2a"))
	if !validKafkaName(topicPrefix) {
		return RedpandaConfig{}, fmt.Errorf("REDPANDA_TOPIC_PREFIX contains invalid characters")
	}
	group := strings.TrimSpace(envOrDefault("REDPANDA_CONSUMER_GROUP", "bridge-a2a-results-v1"))
	if !validKafkaName(group) {
		return RedpandaConfig{}, fmt.Errorf("REDPANDA_CONSUMER_GROUP contains invalid characters")
	}
	produceTimeout, err := parsePositiveDuration("REDPANDA_PRODUCE_TIMEOUT", "10s")
	if err != nil {
		return RedpandaConfig{}, err
	}
	idleTimeout, err := parsePositiveDuration("REDPANDA_RESULT_IDLE_TIMEOUT", "4m")
	if err != nil {
		return RedpandaConfig{}, err
	}
	maxBytes, err := parsePositiveInt64("REDPANDA_MAX_MESSAGE_BYTES", 8<<20, 64<<20)
	if err != nil {
		return RedpandaConfig{}, err
	}
	allowAuto, err := strconv.ParseBool(envOrDefault("REDPANDA_ALLOW_AUTO_TOPIC_CREATION", "false"))
	if err != nil || ((environment == "staging" || environment == "production") && allowAuto) {
		return RedpandaConfig{}, fmt.Errorf("REDPANDA_ALLOW_AUTO_TOPIC_CREATION must be false in staging and production")
	}
	return RedpandaConfig{
		Brokers:            brokers,
		SecurityProtocol:   protocol,
		SASLMechanism:      mechanism,
		Username:           username,
		PasswordFile:       passwordFile,
		CAFile:             caFile,
		ClientCertFile:     certFile,
		ClientKeyFile:      keyFile,
		TopicPrefix:        topicPrefix,
		ConsumerGroup:      group,
		ClientID:           strings.TrimSpace(envOrDefault("REDPANDA_CLIENT_ID", "bridge-a2a-server")),
		ProduceTimeout:     produceTimeout,
		ResultIdleTimeout:  idleTimeout,
		MaxMessageBytes:    int(maxBytes),
		AllowAutoTopic:     allowAuto,
		AllowPrivateBroker: environment == "development" || environment == "test",
	}, nil
}

func validKafkaName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
