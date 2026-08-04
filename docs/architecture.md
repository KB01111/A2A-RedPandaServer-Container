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

## Authentication and tenant boundary

OIDC authentication wraps the A2A transport rather than running only as an SDK
interceptor. This is deliberate: the SDK snapshots HTTP headers into request
metadata before calling the executor. The outer middleware verifies a signed
JWT, removes `Authorization`, `Proxy-Authorization`, and `Cookie`, and places a
small verified identity in the request context. An SDK interceptor then sets
the authenticated A2A user and injects the authoritative tenant claim into the
typed request. A client-supplied tenant that differs from the signed claim is
rejected.

The accepted token profile is a signed JWT access token with the configured
issuer, audience, asymmetric signing algorithm, `sub`, tenant, `exp`, and
required scopes. Opaque tokens are not accepted. Discovery is performed once
at startup and the long-lived verifier uses the provider's cached remote key
set. An identity-provider outage therefore does not make liveness dependent on
a network call for every request, although a previously unseen signing key
still fails closed while the key endpoint is unavailable.

## PostgreSQL task ownership

The PostgreSQL adapter implements the SDK's `taskstore.Store` contract without
changing A2A wire behavior. Every read and write is scoped by both the verified
tenant and subject from `context.Context`; request JSON is never an authority
source. Cross-scope lookups return not-found so they cannot be used as an
existence oracle. Task IDs remain globally unique because the SDK's in-process
event, work, and push stores are keyed only by task ID.

The full canonical task is stored as JSONB with indexed projections for tenant,
owner, context, state, status time, and update time. Updates use row locking and
the SDK task version for optimistic concurrency. List operations use a
repeatable-read snapshot and opaque keyset cursors.

Schema changes are forward-only, checksummed, and protected by a PostgreSQL
advisory lock. `cmd/migrate` owns DDL. The server only verifies that the schema
is current and fails startup when it is behind; production deployments should
use separate migration and runtime database roles.

## Runtime boundary

The server is a stateless protocol and orchestration process. Agent workers,
PostgreSQL, Redpanda, S3-compatible storage, OpenResty, and the observability
stack run separately. The development loopback dispatcher is deterministic and
exists only for the protocol-core phase and local tests; the production wiring
will replace it with the Redpanda dispatcher before the first release. Until
then, the executable refuses staging and production startup and the server
constructor requires an explicit non-memory task store in those environments.
