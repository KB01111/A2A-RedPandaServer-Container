# Bridge A2A Server

Production-oriented Agent2Agent (A2A) protocol server packaged as a standalone
OCI image for rootless Podman and systemd/Quadlet deployments behind 1Panel
OpenResty.

The service is intentionally stateless at the container boundary. PostgreSQL,
Redpanda, S3-compatible object storage, OpenTelemetry, Prometheus, and the agent
workers are external services.

Implementation is being delivered in independently reviewed phases on GitHub.

## Local protocol server

The current protocol core requires Go 1.25 or newer and uses the official
`a2a-go/v2/a2asrv` HTTP+JSON server:

```powershell
go run ./cmd/server
```

The default development configuration serves the Agent Card at
`/.well-known/agent-card.json` and the A2A v1.0 REST operations at the paths
listed in the deployment specification. See [docs/architecture.md](docs/architecture.md)
for the SDK boundary and planned production adapters.

`.env.example` documents variables loaded by the container runtime. When
running the binary directly, export overrides in the shell environment.

## Durable development wiring

Set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `DATABASE_URL` to exercise the durable,
authenticated path. Credentials are read from mounted files such as
`DATABASE_PASSWORD_FILE`; passwords, passfiles, service files, and password
environment variables outside that explicit path are rejected. OIDC policy
variables without a complete issuer/audience pair also fail startup.
Apply schema migrations separately before starting the server:

```powershell
go run ./cmd/migrate
go run ./cmd/server
```

Add the Redpanda, S3, and webhook variables from `.env.example` to exercise the
complete production data path. Redpanda commands use a PostgreSQL outbox;
results are persisted before consumer offsets are committed. Large raw
artifact parts move to the private S3 bucket and resolve through authenticated
stable application URLs. Push notifications are transactionally enqueued and
delivered by leased, signed webhook workers.

The webhook signing file accepts one Ed25519 PKCS#8 `PRIVATE KEY` PEM block (or
a base64-encoded 64-byte private key). The credential keyring is strict JSON:

```json
{
  "currentKeyId": 1,
  "keys": {
    "1": "base64-encoded-32-byte-AES-key"
  }
}
```

The local in-memory task store and loopback dispatcher remain available only
when the corresponding external services are omitted in development or tests.
Staging and production require OIDC, PostgreSQL, Redpanda, S3, and webhook
configuration. See [docs/architecture.md](docs/architecture.md) for the SDK,
durability, encryption, and tenant-isolation contracts.
