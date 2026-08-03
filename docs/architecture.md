# Architecture

## SDK decision

The server uses the official `github.com/a2aproject/a2a-go/v2/a2asrv`
implementation, pinned in `go.mod`. The SDK owns A2A v1.0 request validation,
HTTP+JSON route binding, SSE framing, task transitions, task-store coordination,
capability checks, and Agent Card serving. The module's `v2` major version is
the Go SDK version; the implemented A2A protocol version is `1.0`.

Application code wraps the SDK at the boundaries where the deployment has
project-specific requirements:

- configuration and Agent Card URL projection;
- OIDC authentication and tenant authorization;
- PostgreSQL task persistence;
- Redpanda command/result orchestration;
- S3-backed artifact handling;
- webhook delivery policy;
- health, metrics, tracing, and structured logging.

This keeps protocol semantics in the maintained reference SDK without coupling
infrastructure adapters to its HTTP transport.

The SDK does not itself enforce the `A2A-Version` service parameter. The HTTP
stack therefore requires `A2A-Version: 1.0` for protocol calls and normalizes
comma-separated `A2A-Extensions` values before handing requests to `a2asrv`.

## Runtime boundary

The server is a stateless protocol and orchestration process. Agent workers,
PostgreSQL, Redpanda, S3-compatible storage, OpenResty, and the observability
stack run separately. The development loopback dispatcher is deterministic and
exists only for the protocol-core phase and local tests; the production wiring
will replace it with the Redpanda dispatcher before the first release.
