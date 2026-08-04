package redpanda

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

const (
	defaultClientID        = "a2a-redpanda-bridge"
	defaultDeliveryTimeout = 30 * time.Second
	defaultMaxPollRecords  = 100
)

type SCRAMConfig struct {
	Username string
	Password string
}

type ClientConfig struct {
	Brokers                []string
	ClientID               string
	TLSConfig              *tls.Config
	SCRAM                  *SCRAMConfig
	DeliveryTimeout        time.Duration
	GroupID                string
	Topics                 []string
	SessionTimeout         time.Duration
	RebalanceTimeout       time.Duration
	MaxMessageBytes        int
	AllowAutoTopicCreation bool
}

// NewClient constructs a franz-go client with safe producer defaults. If a
// group is configured, auto-commit is disabled and rebalances are held while
// records are durably ingested.
func NewClient(config ClientConfig) (*kgo.Client, error) {
	config = normalizeClientConfig(config)
	if err := validateClientConfig(config); err != nil {
		return nil, err
	}

	options := []kgo.Opt{
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordDeliveryTimeout(config.DeliveryTimeout),
	}
	if config.MaxMessageBytes > 0 {
		options = append(options,
			kgo.ProducerBatchMaxBytes(int32(config.MaxMessageBytes)),
			kgo.BrokerMaxReadBytes(int32(config.MaxMessageBytes)),
			kgo.FetchMaxBytes(int32(config.MaxMessageBytes)),
		)
	}
	if config.AllowAutoTopicCreation {
		options = append(options, kgo.AllowAutoTopicCreation())
	}
	if config.TLSConfig != nil {
		tlsConfig := config.TLSConfig.Clone()
		if tlsConfig.MinVersion == 0 || tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		options = append(options, kgo.DialTLSConfig(tlsConfig))
	}
	if config.SCRAM != nil {
		mechanism := scram.Auth{User: config.SCRAM.Username, Pass: config.SCRAM.Password}.AsSha256Mechanism()
		options = append(options, kgo.SASL(mechanism))
	}
	if config.GroupID != "" {
		options = append(options,
			kgo.ConsumerGroup(config.GroupID),
			kgo.ConsumeTopics(config.Topics...),
			kgo.DisableAutoCommit(),
			kgo.BlockRebalanceOnPoll(),
		)
		if config.SessionTimeout > 0 {
			options = append(options, kgo.SessionTimeout(config.SessionTimeout))
		}
		if config.RebalanceTimeout > 0 {
			options = append(options, kgo.RebalanceTimeout(config.RebalanceTimeout))
		}
	}
	return kgo.NewClient(options...)
}

func Ping(ctx context.Context, client *kgo.Client) error {
	if client == nil {
		return errors.New("redpanda client is required")
	}
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("ping redpanda: %w", err)
	}
	return nil
}

func normalizeClientConfig(config ClientConfig) ClientConfig {
	if config.ClientID == "" {
		config.ClientID = defaultClientID
	}
	if config.DeliveryTimeout == 0 {
		config.DeliveryTimeout = defaultDeliveryTimeout
	}
	return config
}

func validateClientConfig(config ClientConfig) error {
	if len(config.Brokers) == 0 {
		return errors.New("at least one Redpanda broker is required")
	}
	for _, broker := range config.Brokers {
		if err := validateBroker(broker); err != nil {
			return err
		}
	}
	if strings.TrimSpace(config.ClientID) != config.ClientID || config.ClientID == "" {
		return errors.New("client ID is invalid")
	}
	if config.DeliveryTimeout <= 0 {
		return errors.New("delivery timeout must be positive")
	}
	if config.SessionTimeout < 0 || config.RebalanceTimeout < 0 {
		return errors.New("consumer timeouts cannot be negative")
	}
	if config.MaxMessageBytes < 0 || int64(config.MaxMessageBytes) > int64(^uint32(0)>>1) {
		return errors.New("maximum message bytes must fit a positive int32")
	}
	if config.SCRAM != nil {
		if config.SCRAM.Username == "" || config.SCRAM.Password == "" {
			return errors.New("SCRAM username and password are required")
		}
		if strings.TrimSpace(config.SCRAM.Username) != config.SCRAM.Username {
			return errors.New("SCRAM username is invalid")
		}
	}
	if config.GroupID == "" && len(config.Topics) != 0 {
		return errors.New("consumer group is required when topics are configured")
	}
	if config.GroupID != "" {
		if strings.TrimSpace(config.GroupID) != config.GroupID || len(config.Topics) == 0 {
			return errors.New("consumer group and at least one topic are required")
		}
		seen := make(map[string]struct{}, len(config.Topics))
		for _, topic := range config.Topics {
			if err := validateTopic(topic); err != nil {
				return err
			}
			if _, duplicate := seen[topic]; duplicate {
				return fmt.Errorf("duplicate consumer topic %q", topic)
			}
			seen[topic] = struct{}{}
		}
	}
	return nil
}

func validateBroker(broker string) error {
	if broker == "" || strings.TrimSpace(broker) != broker {
		return fmt.Errorf("invalid Redpanda broker %q", broker)
	}
	if strings.Contains(broker, "://") {
		return fmt.Errorf("Redpanda broker %q must not include a URL scheme", broker)
	}
	host, port, err := net.SplitHostPort(broker)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("invalid Redpanda broker %q: expected host:port", broker)
	}
	return nil
}

func validateTopic(topic string) error {
	if topic == "" || strings.TrimSpace(topic) != topic || strings.ContainsAny(topic, "\x00\r\n\t ") {
		return fmt.Errorf("invalid Redpanda topic %q", topic)
	}
	return nil
}
