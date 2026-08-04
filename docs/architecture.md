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

Discovery redirects and the discovered JWKS endpoint must remain on the exact
issuer origin (scheme, host, and effective port). In staging and production the
OIDC dialer also rejects private, loopback, link-local, and special-use IP
destinations at connection time. Cleartext loopback issuers and private
destinations are enabled only for development and test environments.

## PostgreSQL task ownership

The PostgreSQL adapter implements the SDK's `taskstore.Store` contract without
changing A2A wire behavior. Every read and write is scoped by the verified OIDC
issuer, tenant, and subject from `context.Context`; request JSON is never an
authority source. Cross-scope lookups return not-found so they cannot be used
as an existence oracle. Task IDs remain globally unique because the SDK's
in-process event, work, and push stores are keyed only by task ID.

The full canonical task is stored as JSONB with indexed projections for tenant,
owner, context, state, status time, and update time. Updates use row locking and
the SDK task version for optimistic concurrency. List operations use a
repeatable-read snapshot and opaque keyset cursors.

Schema changes are forward-only, checksummed, and protected by a PostgreSQL
advisory lock. `cmd/migrate` owns DDL. The server only verifies that the schema
is current and fails startup when it is behind; production deployments should
use separate migration and runtime database roles and must not run migrations
concurrently with application processes. Database passwords are accepted only
through the explicit bounded secret file; URI parameters and PostgreSQL
password/service environment fallbacks are rejected.

## Runtime boundary

The server is a stateless protocol and orchestration process. Agent workers,
PostgreSQL, Redpanda, S3-compatible storage, OpenResty, and the observability
stack run separately. The deterministic loopback dispatcher is available only
when Redpanda is omitted in development or tests. Staging and production fail
startup unless OIDC, PostgreSQL, Redpanda, S3, and webhook delivery are all
configured.

## Durable Redpanda orchestration

The bridge uses three fixed, versioned topics derived from
`REDPANDA_TOPIC_PREFIX`:

- `.agent-commands.v1` for execute and cancel commands;
- `.agent-results.v1` for artifacts, heartbeats, and terminal results;
- `.agent-dlq.v1` for malformed result records.

Every record uses a strict `bridge.a2a.redpanda/v1` JSON envelope. Event,
execution, command, tenant, task, context, sequence, deadline, principal, and
trace fields are validated before publication or ingestion. Record keys and
identifiers are domain-separated, length-prefixed SHA-256 digests. The same
tenant/task key keeps one task's records on one partition.

Commands first commit to the PostgreSQL outbox. A leased worker publishes them
with franz-go's idempotent producer defaults and all-ISR acknowledgements.
Result consumers disable auto-commit and hold rebalances while processing each
poll: a valid record commits to the PostgreSQL result inbox before its Kafka
offset is committed; an invalid record commits to the DLQ before its source
offset is committed. Broker-position, event-ID, and execution-sequence
constraints make replay idempotent. Delivery is therefore at least once; the
database identities provide business-level deduplication rather than claiming
end-to-end exactly-once semantics.

TLS 1.2+, SCRAM-SHA-256, bounded message sizes, manual offset commits, and
automatic-topic-creation-off are the production defaults. Topic creation and
retention are operator-owned infrastructure concerns.

## Artifact boundary

Raw artifact parts remain inline only within configured per-part,
per-artifact, and per-task budgets. Larger parts are uploaded to the private
S3/MinIO bucket with deterministic owner-scoped keys, SHA-256 metadata,
verified size/checksum, and SSE-S3 (`AES256`). Task events contain stable
application URLs such as `/artifacts/{opaque-id}`, never presigned URLs.

An uploaded object begins in `ready`. Its metadata changes to `attached` in the
same PostgreSQL transaction that stores the URL-bearing task version; the
create path also scans the initial task snapshot. Missing or cross-owner object
references roll the task write back. The authenticated resolver compares the
exact issuer, tenant, and subject, then returns a fresh GET-only presign with a
maximum 15-minute lifetime. Invalid, unattached, absent, and cross-owner IDs
all return not-found.

The AWS SDK is constructed from an explicit `aws.Config` and static credentials
read from mounted files. It never consults the default AWS credential chain,
proxy environment, IMDS, SSO, or shared profile files.

## Push notifications and webhook delivery

The official SDK's `WithPushNotifications` option remains the protocol entry
point. Push configurations are owner-scoped and encrypted with versioned
AES-256-GCM key material. Callback URLs must use HTTPS in production and may
not contain user information, query parameters, or fragments; notification
tokens and Basic/Bearer credentials stay encrypted.

Each task version inserts its webhook event into the PostgreSQL outbox inside
the task transaction. A domain-separated deterministic delivery ID makes the
SDK's subsequent `SendPush` call idempotently converge on that row. Workers
claim leases before network I/O, deliver concurrently, and finish with
lease-token compare-and-swap updates. Redirects and proxy discovery are
disabled, TLS 1.2+ is required, DNS results are validated again at dial time,
and private/special-use targets are blocked outside development/test. Requests
carry an Ed25519 signature plus a stable delivery ID. Retryable network errors,
408, 425, 429, and 5xx responses use bounded exponential backoff with jitter;
other 4xx responses are terminal. Attempts and total retry age are bounded.
