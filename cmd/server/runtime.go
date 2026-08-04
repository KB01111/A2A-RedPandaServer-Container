package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/redpanda"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/secretfile"
	appserver "github.com/KB01111/A2A-RedPandaServer-Container/internal/server"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/postgres"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/storage/s3store"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
)

type applicationRuntime struct {
	dependencies appserver.Dependencies
	pool         *pgxpool.Pool
	closeClients []func()
	workers      []func(context.Context) error
	waitGroup    sync.WaitGroup
}

func buildApplicationRuntime(ctx context.Context, cfg config.Config, logger *slog.Logger) (_ *applicationRuntime, resultErr error) {
	if err := validateRuntimeConfiguration(cfg); err != nil {
		return nil, err
	}
	runtime := &applicationRuntime{dependencies: appserver.Dependencies{Logger: logger}}
	defer func() {
		if resultErr != nil {
			runtime.close()
		}
	}()

	if cfg.OIDC.Enabled() {
		verifier, err := auth.NewOIDCVerifier(ctx, cfg.OIDC)
		if err != nil {
			return nil, fmt.Errorf("initialize OIDC verifier: %w", err)
		}
		runtime.dependencies.Authentication, err = auth.NewAuthenticator(verifier, cfg.OIDC.Issuer, cfg.OIDC.RequiredScopes)
		if err != nil {
			return nil, fmt.Errorf("initialize authentication: %w", err)
		}
	}

	if cfg.Database.URL != "" {
		pool, err := postgres.OpenPool(ctx, postgres.PoolConfig{
			DatabaseURL:       cfg.Database.URL,
			PasswordFile:      cfg.Database.PasswordFile,
			ApplicationName:   "bridge-a2a-server",
			MaxConns:          cfg.Database.MaxConnections,
			MinConns:          cfg.Database.MinConnections,
			MaxConnLifetime:   cfg.Database.MaxConnectionLife,
			MaxConnIdleTime:   cfg.Database.MaxConnectionIdle,
			HealthCheckPeriod: cfg.Database.HealthCheckPeriod,
		})
		if err != nil {
			return nil, err
		}
		runtime.pool = pool
		if err := postgres.VerifySchema(ctx, pool); err != nil {
			return nil, fmt.Errorf("verify database schema: %w", err)
		}
	}

	storeOptions := make([]postgres.StoreOption, 0, 1)
	if cfg.Webhook.Enabled {
		if err := runtime.configureWebhooks(cfg, logger, &storeOptions); err != nil {
			return nil, err
		}
	}
	if runtime.pool != nil {
		store, err := postgres.NewStore(runtime.pool, storeOptions...)
		if err != nil {
			return nil, err
		}
		runtime.dependencies.TaskStore = store
	}

	if cfg.S3.Enabled() {
		if err := runtime.configureArtifacts(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.Redpanda.Enabled() {
		if err := runtime.configureRedpanda(ctx, cfg); err != nil {
			return nil, err
		}
	} else {
		runtime.dependencies.Dispatcher = orchestrator.LoopbackDispatcher{}
	}
	return runtime, nil
}

func (runtime *applicationRuntime) configureWebhooks(cfg config.Config, logger *slog.Logger, storeOptions *[]postgres.StoreOption) error {
	keyring, err := secretfile.ReadAES256Keyring(cfg.Webhook.CredentialKeysFile)
	if err != nil {
		return err
	}
	cipher, err := webhook.NewCredentialCipher(keyring.CurrentKeyID, keyring.Keys)
	if err != nil {
		return fmt.Errorf("initialize webhook credential cipher: %w", err)
	}
	privateKey, err := secretfile.ReadEd25519PrivateKey(cfg.Webhook.SigningKeyFile)
	if err != nil {
		return err
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("webhook signing key did not produce an Ed25519 public key")
	}
	publicDigest := sha256.Sum256(publicKey)
	policy := webhook.TargetPolicy{
		AllowHTTP: cfg.Webhook.AllowPrivateTargets, AllowPrivateNetworks: cfg.Webhook.AllowPrivateTargets,
	}
	repository, err := postgres.NewWebhookRepository(runtime.pool)
	if err != nil {
		return err
	}
	sink, err := postgres.NewWebhookEventSink(cipher, policy)
	if err != nil {
		return err
	}
	*storeOptions = append(*storeOptions, postgres.WithTaskEventSink(sink))
	pushStore, err := postgres.NewPushConfigStore(runtime.pool, cipher, policy)
	if err != nil {
		return err
	}
	pushSender, err := webhook.NewPushSender(webhook.PushSenderConfig{
		Repository: repository, CredentialCipher: cipher, TargetPolicy: policy,
	})
	if err != nil {
		return err
	}
	runtime.dependencies.PushConfigStore = pushStore
	runtime.dependencies.PushSender = pushSender
	signer := webhook.Ed25519Signer{KeyID: hex.EncodeToString(publicDigest[:8]), PrivateKey: privateKey}
	hostname, _ := os.Hostname()
	for index := 0; index < cfg.Webhook.WorkerCount; index++ {
		worker, err := webhook.NewWorker(webhook.WorkerConfig{
			Repository: repository, CredentialCipher: cipher, Signer: signer,
			HTTP:      webhook.HTTPClientConfig{Policy: policy, Timeout: cfg.Webhook.DeliveryTimeout},
			WorkerID:  hostname + "-" + strconv.Itoa(os.Getpid()) + "-webhook-" + strconv.Itoa(index),
			BatchSize: cfg.Webhook.BatchSize, LeaseDuration: cfg.Webhook.LeaseDuration,
			MaxAttempts: cfg.Webhook.MaxAttempts, MaxRetryAge: cfg.Webhook.MaxRetryAge,
			BaseBackoff: 2 * time.Second, MaxBackoff: 6 * time.Hour,
		})
		if err != nil {
			return err
		}
		runtime.workers = append(runtime.workers, worker.Run)
	}
	logger.Info("webhook delivery configured", "workers", cfg.Webhook.WorkerCount, "signing_key_id", signer.KeyID)
	return nil
}

func (runtime *applicationRuntime) configureArtifacts(cfg config.Config) error {
	accessKey, err := secretfile.ReadString(cfg.S3.AccessKeyFile, "S3 access key", 16<<10)
	if err != nil {
		return err
	}
	secretKey, err := secretfile.ReadString(cfg.S3.SecretKeyFile, "S3 secret key", 16<<10)
	if err != nil {
		return err
	}
	client, err := s3store.New(s3store.ClientConfig{
		Endpoint: cfg.S3.Endpoint, PublicEndpoint: cfg.S3.PublicEndpoint,
		Region: cfg.S3.Region, Bucket: cfg.S3.Bucket, AccessKey: accessKey,
		SecretKey: secretKey, AllowInsecureHTTP: cfg.S3.AllowPrivateIPs,
		UsePathStyle: cfg.S3.UsePathStyle, MaxObjectBytes: cfg.S3.MaxObjectBytes,
		PresignTTL: cfg.S3.PresignTTL,
	})
	if err != nil {
		return fmt.Errorf("initialize S3 artifact client: %w", err)
	}
	repository, err := postgres.NewArtifactStore(runtime.pool)
	if err != nil {
		return err
	}
	externalizer, err := artifact.NewExternalizer(client, cfg.PublicBaseURL, artifact.Policy{
		InlinePartBytes:     cfg.S3.ExternalizeAt,
		InlineArtifactBytes: cfg.S3.ExternalizeAt * 4,
		InlineTaskBytes:     cfg.S3.ExternalizeAt * 8,
		MaxRawPartBytes:     cfg.S3.MaxObjectBytes,
	})
	if err != nil {
		return err
	}
	resolver, err := artifact.NewResolver(repository, client)
	if err != nil {
		return err
	}
	runtime.dependencies.ArtifactPipeline = &orchestrator.ArtifactPipeline{Externalizer: externalizer, Recorder: repository}
	runtime.dependencies.ArtifactResolver = resolver
	return nil
}

func (runtime *applicationRuntime) configureRedpanda(ctx context.Context, cfg config.Config) error {
	tlsConfig, scramConfig, err := redpandaSecurity(cfg.Redpanda)
	if err != nil {
		return err
	}
	topics := redpanda.Topics{
		Commands: cfg.Redpanda.CommandTopic(), Results: cfg.Redpanda.ResultTopic(), DeadLetter: cfg.Redpanda.DLQTopic(),
	}
	client, err := redpanda.NewClient(redpanda.ClientConfig{
		Brokers: cfg.Redpanda.Brokers, ClientID: cfg.Redpanda.ClientID,
		TLSConfig: tlsConfig, SCRAM: scramConfig, DeliveryTimeout: cfg.Redpanda.ProduceTimeout,
		GroupID: cfg.Redpanda.ConsumerGroup, Topics: []string{topics.Results},
		MaxMessageBytes:        cfg.Redpanda.MaxMessageBytes,
		AllowAutoTopicCreation: cfg.Redpanda.AllowAutoTopic,
	})
	if err != nil {
		return fmt.Errorf("initialize Redpanda client: %w", err)
	}
	runtime.closeClients = append(runtime.closeClients, client.Close)
	if err := redpanda.Ping(ctx, client); err != nil {
		return err
	}
	validation := redpanda.ValidationPolicy{MaxEnvelopeBytes: cfg.Redpanda.MaxMessageBytes}
	brokerPublisher, err := redpanda.NewPublisher(client, topics, validation)
	if err != nil {
		return err
	}
	store, err := postgres.NewRedpandaStore(runtime.pool, cfg.Redpanda.ResultIdleTimeout)
	if err != nil {
		return err
	}
	durablePublisher, err := redpanda.NewDurablePublisher(store, topics, validation)
	if err != nil {
		return err
	}
	dispatcher, err := redpanda.NewDispatcher(redpanda.DispatcherConfig{
		Publisher: durablePublisher, Results: store, ExecutionResolver: store,
		Validation: validation,
	})
	if err != nil {
		return err
	}
	runtime.dependencies.Dispatcher = dispatcher
	commandWorker, err := redpanda.NewCommandWorker(redpanda.CommandWorkerConfig{
		Repository: store, Publisher: brokerPublisher,
		WorkerID: "command-" + strconv.Itoa(os.Getpid()),
	})
	if err != nil {
		return err
	}
	ingestor, err := redpanda.NewResultIngestor(redpanda.IngestorConfig{
		Consumer: client, Store: store, DeadLetterPublisher: brokerPublisher,
		ResultsTopic: topics.Results, Validation: validation,
	})
	if err != nil {
		return err
	}
	runtime.workers = append(runtime.workers, commandWorker.Run, ingestor.Run)
	return nil
}

func redpandaSecurity(cfg config.RedpandaConfig) (*tls.Config, *redpanda.SCRAMConfig, error) {
	if cfg.SecurityProtocol == "PLAINTEXT" {
		return nil, nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		contents, err := secretfile.ReadPublicString(cfg.CAFile, "Redpanda CA certificate", 1<<20)
		if err != nil {
			return nil, nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(contents)) {
			return nil, nil, fmt.Errorf("Redpanda CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if cfg.ClientCertFile != "" {
		certificatePEM, err := secretfile.ReadPublicString(cfg.ClientCertFile, "Redpanda client certificate", 1<<20)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := secretfile.ReadString(cfg.ClientKeyFile, "Redpanda client key", 1<<20)
		if err != nil {
			return nil, nil, err
		}
		certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
		if err != nil {
			return nil, nil, fmt.Errorf("load Redpanda client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	password, err := secretfile.ReadString(cfg.PasswordFile, "Redpanda password", 64<<10)
	if err != nil {
		return nil, nil, err
	}
	return tlsConfig, &redpanda.SCRAMConfig{Username: cfg.Username, Password: password}, nil
}

func validateRuntimeConfiguration(cfg config.Config) error {
	durableFeature := cfg.Redpanda.Enabled() || cfg.S3.Enabled() || cfg.Webhook.Enabled
	if durableFeature && (cfg.Database.URL == "" || !cfg.OIDC.Enabled()) {
		return fmt.Errorf("Redpanda, S3, and webhook features require DATABASE_URL and OIDC authentication")
	}
	if cfg.Environment == "staging" || cfg.Environment == "production" {
		if cfg.Database.URL == "" || !cfg.OIDC.Enabled() || !cfg.Redpanda.Enabled() || !cfg.S3.Enabled() || !cfg.Webhook.Enabled {
			return fmt.Errorf("%s requires OIDC, PostgreSQL, Redpanda, S3, and webhook configuration", cfg.Environment)
		}
	}
	return nil
}

func (runtime *applicationRuntime) start(ctx context.Context) <-chan error {
	errorsChannel := make(chan error, len(runtime.workers))
	for _, run := range runtime.workers {
		runtime.waitGroup.Add(1)
		go func(worker func(context.Context) error) {
			defer runtime.waitGroup.Done()
			if err := worker(ctx); err != nil && ctx.Err() == nil {
				errorsChannel <- err
			}
		}(run)
	}
	return errorsChannel
}

func (runtime *applicationRuntime) wait() {
	runtime.waitGroup.Wait()
}

func (runtime *applicationRuntime) close() {
	for index := len(runtime.closeClients) - 1; index >= 0; index-- {
		runtime.closeClients[index]()
	}
	if runtime.pool != nil {
		runtime.pool.Close()
	}
}
