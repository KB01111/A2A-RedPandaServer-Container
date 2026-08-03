# Bridge A2A Server

Production-oriented Agent2Agent (A2A) protocol server packaged as a standalone
OCI image for rootless Podman and systemd/Quadlet deployments behind 1Panel
OpenResty.

The service is intentionally stateless at the container boundary. PostgreSQL,
Redpanda, S3-compatible object storage, OpenTelemetry, Prometheus, and the agent
workers are external services.

Implementation is being delivered in independently reviewed phases on GitHub.

