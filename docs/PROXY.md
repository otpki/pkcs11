# Direct Go PKCS #11 proxy

The `proxy` package lets an application use a PKCS #11 module over the network.
It is useful when many application replicas need to share an HSM without each
replica opening its own unbounded set of native sessions.

The proxy is a Go client and broker. It is not a replacement `.so` or `.dll`.
Both sides are configured with normal Go values.

```text
application replicas
        |
        | TCP/TLS requests
        v
proxy broker
        |
        | bounded physical session pool
        v
PKCS #11 module and HSM
```

`proxy.Client` implements `raw.Module`, so the rest of the `pkcs11` package can
keep doing token selection, vendor routing, object lookup, signing, KEM, health,
and recovery above the network transport.

## Important rules

The design is built around a few rules:

1. A network connection never owns an HSM session.
2. A virtual session does not consume a physical session until work needs one.
3. Each broker route owns a bounded physical session pool.
4. Multipart operations pin a physical session only while PKCS #11 requires it.
5. Session objects also pin a physical session while they exist.
6. Logical client login is separate from physical HSM login.
7. Normal remote logout never calls physical `C_Logout`.
8. A logical client is bound to one authenticated principal and one broker process.
9. Non-idempotent operations are not retried with a new request ID.
10. Vendor parameters cross the network as logical values, not native pointers.
11. Queues, sessions, clients, handles, frames, and replay state are all bounded.
12. Remote asynchronous sessions are rejected because pointer ownership after `CKR_PENDING` cannot be made safe generically.

## Main types

| Type | Purpose |
| --- | --- |
| `proxy.Target` | Application-side endpoint, route, TLS, retry, and codec settings. |
| `proxy.Source` | A `pkcs11.ModuleSource` returned by `proxy.RemoteModule`. |
| `proxy.Client` | Network implementation of `raw.Module`. |
| `proxy.Server` | Broker that owns local HSM clients. |
| `proxy.TargetConfig` | One broker route and its local HSM settings. |
| `proxy.SessionBudget` | Limits for physical and virtual resources. |
| `proxy.LoginPolicy` | Logical login and physical login policy. |
| `proxy.Authenticator` | Converts a transport identity into a stable principal. |
| `proxy.OperationAuthorizer` | Decides what a principal may do on a target. |
| `proxy.ActivationStatus` | Secret-free physical activation state. |
| `proxy.RouteInfo` | Published route ID, revision, and token metadata. |
| `proxy.ErrTargetLost` | The client's pinned broker or target can no longer be used. |
| `proxy.ParameterCodec` | Vendor parameter transport format. |

## Authentication and authorization

Transport authentication and HSM login are different things.

The server gets a stable principal from either:

- `ServerConfig.Authenticator`, or
- the SHA-256 digest of a verified client certificate.

`TargetConfig.Authorize` then decides what that principal may do. Authorization
runs before the request consumes HSM queue or session capacity.

Client-activated targets have one extra authorization step. The caller selected
to perform physical activation is checked with:

```text
Operation = proxy.AuthorizationOperationActivateTarget
PhysicalActivation = true
```

This prevents any authenticated workload from automatically becoming the one
that submits a PIN to the HSM.

Authorization data is intentionally small. It does not include the PIN, bearer
credential, key material, plaintext, ciphertext, or attribute values.

### Logical client identity

`proxy.Open` creates a random `ClientID`. The first authenticated request binds
that ID to a principal. Reusing the same client ID under another principal is
rejected.

Deduplication is also scoped by principal, so one workload cannot replay another
workload's retained response.

`SecurityContextID` is required when a target uses TLS, an auth provider, or a
custom dialer. Change it when the trust roots, certificates, workload auth
policy, or dial behavior change. It is not a secret.

Plaintext mode is meant for isolated development only. Without mTLS or a custom
transport authenticator, all clients share the anonymous transport principal.
Use a logical authenticator if you need workload separation in that setup.

### Development certificates

The CLI can create a small development mTLS tree:

```sh
pkcs11-proxy pki init --dir ./pki --host 10.0.0.5 --client alice --client bob
pkcs11-proxy pki issue server --dir ./pki --name broker2 --host 10.0.0.6
pkcs11-proxy pki issue client --dir ./pki --name carol
```

This writes `ca.pem`, `ca.key`, `server.pem`, `server.key`, and client
certificates under `clients/`. Use `tls.client_ca_file` to require client
certificates.

These certificates are for development, not production PKI.

## Virtual and physical sessions

A remote `C_OpenSession` creates a virtual session handle. It does not open a
native HSM session.

For a normal one-shot operation, the broker:

```text
accept request
    ↓
wait in bounded queue
    ↓
borrow physical session
    ↓
ensure required login state
    ↓
resolve virtual handles
    ↓
call local PKCS #11 module
    ↓
release physical session
    ↓
return response
```

### Multipart operations

Operations such as `C_SignInit` / `C_SignUpdate` / `C_SignFinal` must stay on
the same native session. The broker pins that physical lease until the operation
finishes, is cancelled, errors out, expires, or the virtual session closes.

The same rule applies to other multipart and message APIs.

### Session objects

Objects created with `CKA_TOKEN=false` belong to a native session. The broker
keeps the physical lease pinned while those objects exist.

Virtual object handles are local to one logical client. A handle from another
client, a closed session, or an old target epoch is rejected before it reaches
the HSM.

Because a physical session may later be reused by another logical client, the
broker keeps provenance for session objects. A client only sees session objects
it created. Token objects remain shared token state.

## Login and activation

A broker process is one physical PKCS #11 application serving many logical
applications. Forwarding every remote `C_Login` and `C_Logout` directly would
mix those clients together, so the proxy separates logical login from physical
login.

### Physical login modes

| Mode | PIN source | Automatic relogin | Typical use |
| --- | --- | --- | --- |
| `PhysicalLoginServerManaged` | `LoginPolicy.PhysicalPIN` | Yes | Broker owns the HSM credential. |
| `PhysicalLoginClientActivated` | Authorized remote login | No | Application owns the HSM credential. |
| `PhysicalLoginProtectedPath` | HSM trusted input path | Provider dependent | PIN pad or local trusted input. |

### Client-activated login

In client-activated mode, the broker config does not contain the HSM PIN.
`TargetConfig.Client.PIN` is rejected for broker targets.

A typical policy looks like this:

```go
Login: proxy.LoginPolicy{
    Mode:             proxy.PhysicalLoginClientActivated,
    PhysicalUserType: raw.CKU_USER,
    AllowedUserTypes: []uint{raw.CKU_USER},
    Authenticate:     auditLogicalLogin,
}
```

If several pods try to activate at once, only one of their PINs is sent to the
HSM. The others wait for that activation result.

```text
pod A PIN --\
pod B PIN ----> activation coordinator ----> one physical C_Login
pod C PIN --/
```

This avoids multiplying PIN attempts when an application scales out.

Once the target is active, later logical clients do not cause another physical
login. They still need transport authentication, target authorization, and a
logical login grant.

### Verifying later client PINs

Some HSMs return `CKR_USER_ALREADY_LOGGED_IN` without checking a later PIN. If
every client must prove it knows the accepted PIN, enable
`LoginPolicy.VerifyClientPIN`.

After a successful activation, the broker stores an HMAC-SHA-256 of the accepted
PIN under a random per-target key. Later PINs are compared in memory. A wrong PIN
is rejected without consuming an HSM retry.

The broker clears that verifier when activation is lost and updates it after a
successful `C_SetPIN`.

If the PIN can be changed outside the broker, `PINRotationInterval` can allow an
old verifier to be replaced. After the interval, one mismatching PIN may trigger
a fresh physical activation. Set this carefully because every failed rotation
attempt can consume an HSM PIN retry. A value of zero disables this behavior.

### What the broker keeps

Client-activated mode does not keep the plaintext PIN in target state, session
state, logs, metrics, traces, audit records, or replay state.

The request copy, authentication callback copy, and physical-login `Secret` are
cleared after use. The broker keeps only login state and, when enabled, the
in-memory verifier described above.

### Losing activation

Because the broker does not retain the PIN, it cannot silently relogin after a
restart or other loss of physical login state.

Activation may be lost after events such as:

- broker or HSM restart
- module reinitialization
- control-session loss
- token failover that clears login state
- `CKR_USER_NOT_LOGGED_IN` from the provider

The target becomes inactive and private operations return
`proxy.ErrActivationRequired` with `CKR_USER_NOT_LOGGED_IN`. A client must
activate the target again.

If an inactive broker receives `CKR_USER_ALREADY_LOGGED_IN`, it returns
`proxy.ErrActivationInconclusive`. That HSM response does not prove the supplied
PIN was correct.

### Logical login and logout

Remote `C_Login` and `C_LoginUser` create a grant for one logical client. A
client without a current grant cannot use private operations even if the HSM is
physically logged in for another client.

Remote `C_Logout` only clears that logical client's grants, private handles,
session objects, and active operations. It never calls the physical HSM's
`C_Logout` during normal application use.

### Maintenance operations

Token initialization, PIN administration, SO login, and other process-wide
operations are disabled by default. They require an enabled
`MaintenancePolicy`, an authorization callback, and the exclusive maintenance
lock.

An SO target also requires `MaxClients=1`. In practice, keep maintenance traffic
on a separate target from normal application traffic.

## Object handles

The protocol never sends a native `CK_OBJECT_HANDLE` over the network.

The broker maps native handles to client-local virtual handles. These mappings
are invalidated when the object, session, client, target generation, or broker
epoch ends.

## Retries and unknown outcomes

Every request has a random request ID.

Idempotent calls can be retried normally. Non-idempotent calls reuse the same
request ID across transport attempts. The broker keeps a bounded execution
ledger keyed by:

```text
principal + client ID + request ID
```

A duplicate request can receive the original result instead of running the HSM
operation again.

The ledger fingerprint records the method and argument shape, but not secret
values or payloads. It does not keep offline hashes of PINs, keys, labels, or
plaintext.

Execution history and response retention are separate. Even if the stored
response bytes are evicted, the broker remembers that the operation ran until
the retry horizon ends. A follower then gets `proxy.ErrOutcomeUnknown` instead
of silently running the operation a second time.

This protects against reconnect ambiguity inside one broker process. It does not
make mutations exactly-once across a broker crash. Durable exactly-once behavior
would need an external operation ledger and provider-specific reconciliation.

## Vendor mechanism parameters

Standard parameters are encoded as architecture-independent values. This covers
common types such as RSA-PSS, RSA-OAEP, AES-CTR, AES-GCM, ECDH1, EdDSA, and
PKCS #11 3.2 signing context structures.

`raw.UnsafeParameter` is rejected by the proxy because a native memory image
cannot safely cross a process or architecture boundary.

Vendors with pointer-bearing custom parameters can provide a
`proxy.ParameterCodec`. The client sends logical fields, and the broker rebuilds
the native parameter for its own host ABI.

Codec IDs and versions are checked during the handshake. Client and server must
agree exactly.

## Multiple HSMs

An application can create independent remote modules for different routes or
brokers:

```go
hsmA, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: proxy.RemoteModule(targetA),
    Token:  selectorA,
})

hsmB, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: proxy.RemoteModule(targetB),
    Token:  selectorB,
})
```

Their client IDs, sessions, handles, login grants, vendor sets, retries, and
target generations are independent.

## Token discovery

There are two ways to publish routes:

- `targets[]` names each route explicitly.
- `discovery[]` lists modules and creates one route for each token found.

You cannot configure both at the same time.

Example discovery config:

```yaml
discovery:
  - module: "/opt/vendor/lib/libpkcs11.so"
    name_prefix: "vendor-"
    vendors: []
    overrides:
      - name: "partition-alpha"
        token_serial: "0102"
        sessions:
          max_physical_total: 4
```

Discovery reads token-present slots and token metadata. It does not open
sessions or probe every mechanism just to build the route list.

The broker reconciles discovery at startup and before route listings. A new
token appears on the next listing. A removed token is unpublished while old
in-flight work drains.

Important route rules:

- The default route ID is the trimmed token serial.
- If serial is empty, the token label is used.
- `name_prefix` helps avoid collisions between modules.
- An override name is used exactly as written.
- If two tokens resolve to the same route ID, both are skipped until config separates them.
- Discovery route revisions are stable digests of the route and resolved config.
- Overrides must select exactly one token at startup.
- A module with no tokens is valid and publishes an empty set.

The top-level `sessions.*` and `activation.*` values act as templates for
discovered routes. An override can patch individual fields.

## Active-active broker replicas

Several broker processes can serve the same HSM or HSM HA cluster. They do not
share proxy state.

```text
              HSM / HSM HA cluster
                 /             \
            proxy A           proxy B
          local state       local state
```

Each replica has its own physical sessions, logical clients, virtual handles,
pinned operations, login grants, deduplication state, and epoch.

### Client pinning

A `proxy.Target` can list several broker addresses:

```go
proxy.Target{
    Endpoints:  []string{"proxy-a.internal:9443", "proxy-b.internal:9443"},
    ServerName: "pkcs11-proxy.internal",
}
```

`Open` rendezvous-hashes the client ID across those endpoints, probes them in
that order, and picks the first active compatible broker. After that, the
logical client stays pinned to that endpoint, server ID, and epoch for its
lifetime.

Only transport unavailability moves the initial probe to another endpoint.
Authentication, protocol, version, and codec failures are treated as real
errors rather than failover signals.

Adding a replica affects new clients only. Existing clients are not moved.

### Fencing

Each broker process has a random `ServerID` and epoch. Requests include the
identity selected during `Open`. If the client reaches the wrong broker, an old
process, or a changed target, the request fails with `proxy.ErrTargetLost`
instead of continuing against unrelated state.

This is important because virtual sessions and object handles are intentionally
process-local.

### Draining

When a broker starts draining, it stops accepting new logical clients. Existing
clients keep working until they close or the drain timeout expires.

After the timeout, remaining clients are forced off and see
`proxy.ErrTargetLost`. A fresh `Open` can then choose another replica.

### Capacity planning

Budgets are per broker process. If two replicas each allow eight physical HSM
sessions, the HSM may see up to sixteen from the proxy fleet.

Size replica budgets against the HSM's real global limits.

## CLI configuration

`pkcs11-proxy serve` accepts scalar settings through YAML, flags, or environment
variables. The precedence is:

```text
flag > environment > YAML > built-in default
```

A flag has the same name as its YAML key, for example `--otel.endpoint`.
Environment variables use the `PKCS11_PROXY_` prefix, for example
`PKCS11_PROXY_OTEL_ENDPOINT`.

`targets[]` and `discovery[]` are YAML-only because they are structured lists.

See `cmd/pkcs11-proxy/pkcs11-proxy.example.yaml` for a commented example. The
CLI reference under `docs/cli/` is generated from the command source.

## Container image

The published broker image contains the proxy binary, not every vendor's PKCS
#11 middleware. Mount or install the required middleware into the runtime image
according to that vendor's licensing and deployment rules.

The public build works without access to the private vendor module. Maintainer
builds include private integrations when the private submodule is present.

## Test mode

For development without an HSM, use the in-memory test module.

```sh
pkcs11-proxy serve --test --insecure
```

The test token uses PIN `1234`. You can also use `module: "test"` or
`test:<name>:<token-count>` in configuration.

Test mode is for development and CI. It is not a software HSM replacement.

## Kubernetes

A common deployment is one broker Deployment or StatefulSet close to the HSM,
with applications listing all broker replicas in `proxy.Target.Endpoints`.

The broker owns the HSM session budget. Application pods can scale without each
opening their own native session pool.

For graceful updates:

1. readiness should fail when a broker starts draining
2. new application clients should stop selecting that replica
3. existing clients should finish or hit the configured drain timeout
4. clients that lose their pin should open a new logical client

Do not assume a Kubernetes Service can move an existing logical client between
broker processes. Proxy state is deliberately process-local.

## Observability

The library emits OpenTelemetry metrics, spans, and logs through the global OTel
providers. The CLI can export them over OTLP/HTTP.

### Metrics

Important proxy metrics include:

| Metric | What it tells you |
| --- | --- |
| `pkcs11_proxy_physical_sessions` | Physical HSM sessions in use. |
| `pkcs11_proxy_pinned_sessions` | Sessions held for multipart work or session objects. |
| `pkcs11_proxy_queue_depth` | Requests waiting for HSM capacity. |
| `pkcs11_proxy_dedup_entries` | Entries in the request replay ledger. |
| `pkcs11_proxy_requests_total` | Request outcomes by method and route. |
| `pkcs11_proxy_request_duration_seconds` | Request latency. |
| `pkcs11_proxy_transport_errors_total` | Client or server transport failures. |
| `pkcs11_proxy_target_lost_total` | Clients losing their pinned broker or target. |

Metrics are per process. Fleet-wide aggregation belongs in the telemetry
backend.

The root `pkcs11` package also emits managed-operation metrics through
`pkcs11.OTelHooks()`.

### Health and Prometheus endpoint

`health.listen` starts a separate HTTP listener with:

- `GET /healthz` for process liveness
- `GET /readyz` for broker readiness and per-route health details
- `GET /metrics` for Prometheus

`/healthz` stays simple on purpose. A broken HSM does not make the process itself
dead.

`/readyz` returns 503 when the broker is draining. Route health is included in
the response body so operators can see a bad token without necessarily taking
all unrelated routes out of service.

The listener is unauthenticated and serves operational metadata. It must bind to
loopback unless `health.allow_remote` is enabled.

Example Kubernetes probes:

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 9464 }
readinessProbe:
  httpGet: { path: /readyz, port: 9464 }
```

### Application logging

The CLI sends `slog` records through a bounded non-blocking queue. A slow stderr
writer should not stall HSM requests. Queue overflow is counted and reported.

Relevant settings are:

```yaml
logging:
  level: "info"
  format: "text"
  queue_size: 8192
```

### Signed audit log

Setting `audit.path` enables an append-only JSONL audit log. Event records are
batched into Merkle trees and sealed by signed checkpoints.

A checkpoint contains the Merkle root, covered sequence range, and a hash of the
previous checkpoint. This detects changes inside a sealed batch and breaks the
checkpoint chain if sealed batches are removed or reordered.

The audit log records security events such as client creation, login grants,
activation, failed activation, maintenance, authorization failures, fencing,
and draining. It does not record credentials or cryptographic payloads.

Records after the latest checkpoint form an unsealed tail. A clean shutdown
seals pending records. A crash can leave a tail that verification reports as
unsealed rather than pretending it was signed.

The default audit key is an Ed25519 seed stored at `<audit.path>.key`, with a
public key written beside it for offline verification.

Useful commands:

```sh
pkcs11-proxy audit verify audit.log --key audit.key.pub
pkcs11-proxy audit inspect audit.log --tail 20
pkcs11-proxy audit prove audit.log --seq 42 --key audit.key.pub
```

Library users can provide their own `ServerConfig.Audit` sink instead.

### Dev UI

The optional dev UI shows broker state without requiring a full telemetry stack.
It includes route health, activation state, session and queue usage, clients,
recent request outcomes, and audit status.

It is read-only and intentionally omits PINs and key material. It still exposes
operational metadata, so it binds to loopback unless `dev_ui.allow_remote` is
enabled.

## Suggested alerts

Useful signals include:

- physical sessions approaching `sessions.max_physical_total`
- queue depth approaching `sessions.max_queued`
- pinned sessions approaching `sessions.max_pinned`
- deduplication entries approaching their limit
- rising unauthorized requests
- rising transport errors
- rising `target_lost` events
- repeated stale-generation or revision errors
- audit gaps or audit writer failures
- log queue drops

## Raw API coverage

The generated proxy client implements the synchronous `raw.Module` surface,
including PKCS #11 3.0 message APIs and PKCS #11 3.2 KEM, signature-first
verification, session validation, and authenticated wrapping.

Module lifecycle calls are logical on the client side:

- `Initialize` initializes one logical client.
- `Finalize` closes that client's sessions and grants.
- `CloseAllSessions` affects only that client.
- `Destroy` drains and removes only that client.
- The broker owns actual local module initialization and finalization.

Remote asynchronous sessions are the main deliberate exception.
