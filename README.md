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
