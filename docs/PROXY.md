# Direct Go PKCS #11 proxy

The `proxy` package exposes any local managed PKCS #11 target through the same
`raw.Module` contract used by a native module. It is intended for Kubernetes and
other horizontally scaled applications that must reach a non-network HSM
without allowing each application replica to open an independent, unbounded set
of native HSM sessions.

The proxy is a **Go library**, not a `.so`, `.dll`, side-loaded configuration
file, or globally mutable client runtime. Both sides are configured with normal
Go values:

```text
stateless application replicas
        |
        | one framed request and response per TCP/TLS connection
        v
proxy.Server route
        |
        | bounded queue and managed physical-session pool
        v
local PKCS #11 module and HSM
```

The application can use either API (raw or pkcs11):

```text
pkcs11.Client -> proxy.Source -> proxy.Client -> network -> proxy.Server
raw.Module    -> proxy.Client -> network -> proxy.Server
```

`proxy.Client` implements the complete `raw.Module` interface. The managed root
client therefore continues to provide token selection, vendor routing, object
re-resolution, signers, decrypters, KEM, certificates, health, retry policy,
and hooks above the remote transport.

## Design principles

The implementation follows these rules:

1. A remote socket is never the owner of an HSM session.
1. Opening a virtual PKCS #11 session does not open a physical HSM session.
1. One server target owns one authoritative combined physical session budget.
1. Multipart operations and session objects pin a physical lease only while
   PKCS #11 semantics require affinity.
1. Client login is logical and isolated. physical HSM login is coordinated by the server from an explicitly
   selected credential source.
1. Normal logical logout never calls physical `C_Logout`.
1. Every logical client is permanently bound to one authenticated network
   principal.
1. Every logical client is permanently bound to one proxy process. Replicas are
   active-active against the HSM but never share or migrate PKCS #11 state.
1. Non-idempotent operations are never blindly replayed with a new request ID.
1. Vendor parameters cross the network semantically and are marshaled for the
   server's host's ABI immediately before the native HSM call.
1. Capacity is bounded at every layer: sockets, queued requests, physical
   sessions, pinned sessions, clients, virtual sessions, object mappings,
   message size, and deduplication memory.
1. The protocol does not transmit native pointers, native session handles, or
   native object handles.
1. Remote asynchronous sessions fail closed because provider-owned pointer
   lifetimes after `CKR_PENDING` cannot be safely virtualized generically.

## Packages and primary types

| Type                        | Role                                                                                                      |
| --------------------------- | --------------------------------------------------------------------------------------------------------- |
| `proxy.Target`              | Immutable application side route, TLS, retry, and codec configuration.                                    |
| `proxy.Source`              | `pkcs11.ModuleSource` produced by `proxy.RemoteModule`.                                                   |
| `proxy.Client`              | Request scoped network implementation of `raw.Module`.                                                    |
| `proxy.Server`              | Multi route broker that owns local managed HSM clients.                                                   |
| `proxy.TargetConfig`        | One broker route and its local HSM, login, quota, and codec policy.                                       |
| `proxy.SessionBudget`       | Authoritative physical and virtual resource limits.                                                       |
| `proxy.LoginPolicy`         | Logical-client authentication plus server-managed, client-activated, or protected-path physical login.    |
| `proxy.Authenticator`       | Transport peer authentication and stable principal derivation.                                            |
| `proxy.OperationAuthorizer` | Per-target authorization, including the exact physical activation transition.                             |
| `proxy.ActivationStatus`    | Secret-free inactive/activating/active state and generation.                                              |
| `proxy.RouteInfo`           | Broker-published route descriptor: route ID, revision, and bound token metadata.                          |
| `proxy.ListRoutes`          | Server-scoped route catalog lookup clients may call before choosing `Target.Route` and `Target.Revision`. |
| `proxy.ErrTargetLost`       | Sentinel for an unrecoverable pinned replica: wrong server, stale epoch, vanished route, or unreachable.  |
| `proxy.ServerState`         | `ServerActive`/`ServerDraining` lifecycle state reported by describe and `Server.State()`.                |
| `proxy.ParameterCodec`      | Architecture-independent vendor parameter transport.                                                      |
| `pkcs11.RawSessionLease`    | Long-lived managed physical lease used internally by the broker.                                          |

## Transport authentication, target authorization, and principal binding

Transport authentication and HSM login are separate.

The server determines a stable principal in one of two ways:

1. `ServerConfig.Authenticator` validates `RequestIdentity` and returns a stable,
   non-secret principal string
2. when a verified client certificate is present, the server uses the SHA-256
   digest of the leaf certificate.

Authentication answers **who the peer is**. `TargetConfig.Authorize` is a
separate callback that answers **what that principal may do**. It runs for every
request before HSM queue or session capacity is consumed. When a client-activated
target is inactive, the exact leader selected to submit a PIN also receives a
second authorization request with:

```text
Operation = proxy.AuthorizationOperationActivateTarget
PhysicalActivation = true
```

This prevents an authenticated but non-privileged workload from winning the
shared activation transition. Authorization requests contain no PIN, bearer
token, key material, plaintext, ciphertext, or attribute values.

A random logical `ClientID` is created by `proxy.Open`. The first authenticated
request binds that ID to the principal. Any later request-scoped connection
that presents the same client ID under a different principal is rejected with
`client_identity_mismatch`. Deduplication keys also include the principal, so a
second workload cannot replay another workload's retained response.

`SecurityContextID` is required when the client uses TLS, an `AuthProvider`, or
a custom `Dialer`. It must change whenever opaque trust roots, certificates,
workload-token policy, routing, or dial behavior changes. It is non-secret and
exists to prevent the process-wide managed registry from sharing a logical
remote module across different security contexts.

Plaintext `AllowInsecure` mode is intended only for isolated tests. Without an
`Authenticator` or verified mTLS, all connections have the anonymous transport
principal, so each target must use a separate `LogicalAuthenticator`.

### Development mTLS tree

`pkcs11-proxy pki` mints a throwaway Ed25519 CA plus server and client leaf
certificates for `tls.*` configuration — development tooling only, keys land
on disk 0600, nothing replaces a production CA:

```sh
# CA + server cert (SANs from --host) + client certs under ./pki
pkcs11-proxy pki init --dir ./pki --host 10.0.0.5 --client alice --client bob

# Additional leaves under the same CA
pkcs11-proxy pki issue server --dir ./pki --name broker2 --host 10.0.0.6
pkcs11-proxy pki issue client --dir ./pki --name carol
```

Layout: `ca.pem`/`ca.key`, `server.pem`/`server.key` (leaf + chain), and
`clients/<name>.{pem,key}`. Point the broker at them with `tls.cert_file`,
`tls.key_file`, and `tls.client_ca_file` — the last enables mTLS and makes the
client certificate digest the workload principal. The same generator is
available in the dev UI's _dev mTLS tree_ panel, which produces the bundle in
memory and returns PEM files for browser download without touching disk.

## Virtual and physical sessions

### Virtual session creation

Remote `C_OpenSession` validates flags and quotas, then allocates a virtual
handle. It does not acquire a physical HSM session.

```text
C_OpenSession
    -> validate logical client and target generation
    -> reserve virtual-session count
    -> allocate client-local virtual handle
    -> return
```

The virtual handle is meaningful only to the logical client that created it. It
is never a native handle and never crosses into the local HSM module.

### Ordinary calls

A stateless single-part call borrows a physical session only for the duration of
the broker request:

```text
request
    -> bounded admission queue
    -> acquire managed physical lease
    -> ensure physical login when needed
    -> resolve virtual object handles
    -> execute local raw.Module method
    -> translate returned handles
    -> release physical lease
    -> response
```

### Multipart operations

Calls such as `C_SignInit`/`Update`/`Final` must use the same native session.
The broker pins a physical lease to the virtual session from initialization
until finalization, cancellation, replacement, error cleanup, session close, or
idle expiration.

The same rule applies to message APIs and other stateful operation families.

### Session objects

An object created with `CKA_TOKEN=false` belongs to a native session. The broker
keeps that physical lease pinned while any such object remains and maps the
object through a client-local virtual handle.

Token objects are not pinned merely because they lack an application locator.
The broker may retain the native token-object handle for the current target
epoch, while durable managed operations continue to prefer unique ID, ID,
label, class, and key type re-resolution where possible.

Closing a virtual session destroys its session objects, cancels unfinished
operations, invalidates its handles, and releases its pinned lease. Using a
handle from another client, closed session, or target epoch fails instead of
reaching the HSM.

## Login, physical activation, and logout

PKCS #11 ordinary login is commonly application-wide across all sessions in one
process. The server process is one physical Cryptoki application while serving
many isolated logical applications. Directly forwarding every remote
`C_Login`/`C_Logout` would therefore be unsafe.

The proxy supports three explicit physical-login modes:

| Mode                           | PIN source                                       | Automatic recovery           | Typical use                                        |
| ------------------------------ | ------------------------------------------------ | ---------------------------- | -------------------------------------------------- |
| `PhysicalLoginServerManaged`   | `LoginPolicy.PhysicalPIN`                        | Yes                          | Server account owns the HSM credential.            |
| `PhysicalLoginClientActivated` | First authorized remote `C_Login` while inactive | No, a client must reactivate | Client application owns PIN auditing and approval. |
| `PhysicalLoginProtectedPath`   | HSM trusted input path; nil PIN                  | Provider-dependent           | PIN pad, local console, or another protected path. |

### Client-activated physical login

A client-activated target contains no HSM PIN in server configuration.
`TargetConfig.Client.PIN` is rejected for every broker target because the local
managed client runs with `LoginNone`. physical credentials belong only in
`LoginPolicy.PhysicalPIN` for server-managed mode or in the activating client's
`C_Login` request for client-activated mode:

```go
Login: proxy.LoginPolicy{
    Mode:             proxy.PhysicalLoginClientActivated,
    PhysicalUserType: raw.CKU_USER,
    Authenticate:     auditLogicalLogin,
    AllowedUserTypes: []uint{raw.CKU_USER},
}
```

### Multiple pods activating simultaneously

All pods may race to activate the same target. They do not race at the HSM:

```text
pod A PIN --\
pod B PIN ----> one activation coordinator ---> one physical C_Login
pod C PIN --/                |
                              +--> all followers receive the same result
```

Only the leader's PIN reaches the HSM. Followers wait using their own contexts;
their PINs may still be independently audited by `LoginPolicy.Authenticate`, but
are wiped without being sent to Cryptoki. This prevents horizontal scaling from
multiplying PIN attempts or exhausting the token's retry counter. If the
selected leader is denied `AuthorizationOperationActivateTarget`, that denial is
returned only to that caller; followers re-contend for leadership, no PIN reaches
the HSM, and the failed-PIN cooldown is not started.

Once active, later logical clients do not cause another physical login. They
still need transport authentication, target authorization, and either
`LoginPolicy.Authenticate` or `TrustTransportIdentity`. If every pod must prove
knowledge of the PIN independently, `Authenticate` must validate an
application-side verifier; the already-logged-in HSM cannot reliably validate a
second PIN because it may return `CKR_USER_ALREADY_LOGGED_IN` without checking
it.

### PIN memory and audit boundary

In client-activated mode the PIN is never placed in:

- `TargetConfig` or `ServerConfig`;
- target/client/session/object state;
- activation status or statistics;
- the request replay response ledger;
- logs, traces, metrics, or error messages;
- recovery state for a future physical session.

The protocol request is wiped after dispatch. `LoginPolicy.Authenticate`
receives a separate short-lived copy that is wiped when the callback returns.
The physical-login path creates another `pkcs11.Secret`, destroys it immediately
after `C_Login`, and does not retain it for relogin.

The client application remains responsible for PIN acquisition, approval,
auditing, and policy. The proxy is responsible for transport confidentiality,
peer authentication, target authorization, one-at-a-time physical submission,
zeroization, and preserving only the resulting login state.

### Activation loss and fail-closed recovery

Because no PIN is retained, client-activated login cannot recover transparently
from:

- proxy or HSM restart;
- module reinitialization;
- control-session/device loss;
- token failover that clears login state;
- a provider returning `CKR_USER_NOT_LOGGED_IN` after activation.

The target becomes `ActivationInactive`, increments its activation generation,
and old logical grants become stale. Private operations fail with both
`proxy.ErrActivationRequired` and `CKR_USER_NOT_LOGGED_IN`. The application must
perform another audited `Activate`/`C_Login` with a fresh PIN.

`Server.TargetStats` exposes the secret-free activation state, generation,
last successful activating principal, and timestamps. It never exposes the credential.

If an inactive client-activated server receives `CKR_USER_ALREADY_LOGGED_IN`,
the proxy returns `proxy.ErrActivationInconclusive` and remains inactive. That
HSM response does not prove the supplied PIN was correct.

### Logical login

A remote `C_Login` or `C_LoginUser` establishes a grant only for the requesting
logical client. The grant can be authenticated by:

- `LoginPolicy.Authenticate`, which validates/audits the client credential or
  application policy; or
- `TrustTransportIdentity`, after verified mTLS or `ServerConfig.Authenticator`
  has authenticated the workload.

A client without a current logical grant receives `CKR_USER_NOT_LOGGED_IN` for
private operations even when the physical HSM is active for another client.
Client-activated grants are bound to the current activation generation.

### Logout

Normal remote `C_Logout` revokes only the logical client's grants, private
handle mappings, session objects, and active operations. It does **not** invoke
physical `C_Logout`, so one pod cannot deactivate every other pod.

Physical sessions close when the target drains or the server shuts down. Token
administration remains a separate maintenance boundary.

### SO and maintenance operations

`C_InitToken`, `C_InitPIN`, `C_SetPIN`, SO identity, and other destructive or
application-wide transitions are denied by default. They require:

```text
MaintenancePolicy.Enabled = true
MaintenancePolicy.Authorize != nil
exclusive maintenance lock
```

An SO physical target also requires `MaxClients=1`. Normal application traffic
should use a separate non-maintenance target.

## Object-handle virtualization

The wire protocol never exposes a native `CK_OBJECT_HANDLE`.

## Retry, deduplication, and unknown outcomes

Every request has a random request ID.

Idempotent calls can be attempted again normally. Non-idempotent calls use the
same request ID across transport attempts. The server maintains a bounded
ledger keyed by:

```text
principal + client ID + request ID
```

The first request is the leader. A concurrent or later duplicate with the same
secret-independent operation fingerprint waits for or receives the retained
response. The fingerprint contains the method and argument schema, but not
argument values, request authentication bytes, PINs, labels, key material, or
vendor payloads. Reusing an ID for a different method or schema is rejected.
reusing it for the same method with different values returns the
first retained result rather than performing a second HSM mutation.

When the connection fails after a non-idempotent request may have reached the
server, the client retries only with that same ID. If the server can no longer
prove the original outcome, for example, because the target token changed, the
client returns `proxy.ErrOutcomeUnknown`. Callers must reconcile the operation
rather than generating a fresh request blindly.

Stateful signature operations, key generation, object creation/destruction,
PIN changes, and similar mutations are never claimed to be exactly-once across
a broker process crash. Durable exactly-once semantics would require an
external durable operation ledger and provider-specific reconciliation.

## Vendor mechanism parameters

Standard parameter types are encoded semantically:

- RSA-PSS
- RSA-OAEP
- AES-CTR
- AES-GCM
- ECDH1
- EdDSA
- PKCS #11 3.2 sign/hash-sign additional context
- byte and unsigned-integer selectors

`raw.UnsafeParameter` is rejected because a native pointer-bearing memory image
cannot safely cross a process or architecture boundary.

A vendor module can implement `proxy.VendorCodecProvider` and return
`ParameterCodec` values. The codec transports logical data, not ABI bytes. The
broker decodes the parameter into the same Go type expected by the local vendor
module, and the local raw backend marshals it according to the broker host's
`raw.NativeABI`.

Codec IDs and versions are part of the handshake. Client and server descriptor
sets must match exactly, preventing silent interpretation under different
schemas. The repository includes codecs for the currently pointer-bearing IBM
ML-KEM and YubiHSM wrap parameters; ordinary byte-based Utimaco parameters are
already architecture-independent.

## Multiple HSMs from one process

Each high-level client has its own immutable `proxy.Source`:

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

Targets may use the same endpoint set and different routes, or entirely
different brokers. Their registry identities, client IDs, epochs, sessions,
login grants, object maps, vendor candidates, codecs, retries, and recovery
generations are independent.

## Active-active replicas

Two or more `pkcs11-proxy` processes can serve the same HSM (or HSM HA cluster)
with no leader, no shared datastore, and no load balancer. Each replica owns
its own ephemeral virtualization state: logical clients, virtual sessions and
handles, pinned physical leases, multipart state, the dedup ledger, login
grants, and the target epoch are all process-local and are never replicated.

```text
                    HSM / HSM HA cluster
                           |
             +-------------+-------------+
             |                           |
          proxy-A                     proxy-B
       local session pool          local session pool
       local client state          local client state
             ^                           ^
             |                           |
        logical clients             logical clients
```

### Client pinning

`proxy.Target` accepts a list of directly reachable replica addresses:

```go
proxy.Target{
    Endpoints:  []string{"proxy-a.internal:9443", "proxy-b.internal:9443"},
    ServerName: "pkcs11-proxy.internal", // TLS identity, independent of address
    ...
}
```

`Open` generates the random `ClientID`, ranks the endpoints by rendezvous
hashing (`SHA-256(clientID ‖ endpoint)`), and probes them in that order with
`@describe`. Only transport-level unavailability advances to the next endpoint;
authentication, protocol, codec, and version failures fail immediately. The
first replica that answers and reports `AcceptingNewClients` wins; the client
then pins `endpoint + ServerID + Epoch` forever:

- every request, including every same-request-ID retry, dials only the pinned
  endpoint;
- `client.Endpoint()` and `client.ServerID()` expose the pin for diagnostics;
- `ServerName` remains a separate TLS concern — endpoints may be bare IPs
  sharing one certificate identity.

Different `ClientID`s rank endpoints differently, so new logical clients
distribute approximately evenly across replicas. Scaling up is graceful by
construction: add a replica to the configuration and only _new_ `Open` calls
can select it. There is no rebalancing of existing clients.

### Fencing

Each process generates a random `ServerID` at startup, and each target carries
its existing random `Epoch` per generation. `describe` returns both; every
established request then carries them. A replica rejects a request whose
`ServerID` names another process with `wrong_server` before any client state is
touched, and a stale `Epoch` still fails with `target_epoch_mismatch`. On the
client, `wrong_server`, `target_epoch_mismatch`, `target_not_found`, and
`revision_mismatch` — as well as transport exhaustion against the pinned
endpoint — all satisfy `errors.Is(err, proxy.ErrTargetLost)`. If the lost call
was non-idempotent and may have run, `errors.Is(err, proxy.ErrOutcomeUnknown)`
also holds.

A pinned replica dying is the failure boundary: the logical PKCS #11
application behind it is gone, exactly as if its own process had died. The
client library never silently retries against another replica. Recovery is a
fresh `Open` — new `ClientID`, new pin — followed by whatever application-level
state the caller recreates (sessions, login, token-object re-discovery via
durable attributes like `CKA_ID`/`CKA_LABEL`; session objects are
unrecoverable by design).

### Scaling down and draining

`Server.Drain()` flips a replica to `ServerDraining`: `describe` then reports
`AcceptingNewClients: false`, so endpoint selection skips it, while existing
clients keep working until they close or idle-expire. `Server.LogicalClients()`
is the drain countdown and `Server.WaitDrained(ctx)` blocks until it reaches
zero.

In `pkcs11-proxy`, SIGINT/SIGTERM runs that sequence automatically — drain, log
the remaining logical-client count, wait up to `drain_timeout` (default 5m),
then shut down — so the same behavior falls out of systemd `SIGTERM`,
Kubernetes pod termination, or a manual stop. The dashboard shows each
replica's state and `server_id` in the header. Operational order for removing
a replica:

1. signal it (it starts draining);
2. wait for `LogicalClients() == 0` or the drain timeout;
3. remove it from client endpoint configuration;
4. stop the process.

### Per-replica budgets and administration

Session budgets are intentionally per-process — there is no distributed
semaphore. Divide the HSM's usable session capacity across replicas by hand:
e.g. an HSM that tolerates ~80 proxy-owned sessions gets
`max_physical_total: 40` on each of two replicas, `~25` on three, with headroom
left for administration.

For the same reason, normal HA replicas should keep `Maintenance.Enabled =
false` (the default) so `C_InitToken`, `C_InitPIN`, `C_SetPIN`, and SO
operations are unavailable through horizontally-scaled instances; run
maintenance from a separate dedicated process. Server-managed login
(`PhysicalPIN`/`PhysicalLoginServerManaged`) is the straightforward HA mode:
each replica performs its own independent physical `C_Login`. Client-activated
login also works — each client activates whichever replica it pinned — but each
replica's activation state is independent by design.

## Configuration reference

Every broker option is one name on three surfaces: the flag
`--otel.endpoint`, the YAML key `otel.endpoint`, and the environment variable
`PKCS11_PROXY_OTEL_ENDPOINT` (precedence: flag > env > config > default). The
generated CLI reference at [cli/pkcs11-proxy_serve.md](cli/pkcs11-proxy_serve.md)
doubles as the complete configuration reference — every flag, its default, and
its description. It regenerates via `go generate ./cmd/pkcs11-proxy` (checked
in CI); `cmd/pkcs11-proxy/pkcs11-proxy.example.yaml` is the annotated YAML
counterpart. The `targets` list is the only YAML-only option. An unknown key
in the YAML file fails startup naming it.

## Container image

The root `Dockerfile` builds with `golang:1.27-alpine` and cross-compiles the
cgo backend through `zig cc` against a pinned glibc floor (2.28) — musl-only
build host, glibc output. The runtime is Chainguard's `glibc-dynamic` image: a
minimal glibc rootfs with no shell or package manager, plus copied
ca-certificates and a static busybox (`wget`/`nc`/`sh`) for healthchecks. The
cgo backend is required because the broker dlopens vendor PKCS#11 middleware,
so the purego fallback is deliberately not used. Vendor `.so` files are not
baked into the image; mount them plus the YAML at runtime:

```sh
docker build -t pkcs11-proxy .
docker run --rm -p 9443:9443 \
  -v "$PWD/pkcs11-proxy.yaml:/etc/pkcs11-proxy/pkcs11-proxy.yaml:ro" \
  -v /opt/hsm/vendor-pkcs11.so:/opt/hsm/vendor-pkcs11.so:ro \
  -v pkcs11-audit:/var/lib/pkcs11-proxy \
  pkcs11-proxy
```

Entrypoint is `pkcs11-proxy serve`; the default command reads
`/etc/pkcs11-proxy/pkcs11-proxy.yaml`. The broker's default listen is
`127.0.0.1:9443` — inside a container set `listen: 0.0.0.0:9443` (or pass
`--listen`). A persistent volume at `/var/lib/pkcs11-proxy` keeps the signed
audit log and its key off the container layer. SIGTERM triggers the drain
sequence, so `docker stop` and Kubernetes pod termination scale down cleanly.
The image runs as uid 65532 (nonroot) and bakes a `HEALTHCHECK` that
TCP-probes port 9443 — adjust to your `listen:` port. Both `linux/amd64` and
`linux/arm64` are published per release as one manifest.

Test mode works with no mounts at all:

```sh
docker run --rm -p 9443:9443 pkcs11-proxy --test --insecure --listen 0.0.0.0:9443
```

## Test mode (no HSM required)

`pkcs11-proxy serve --test` replaces the configured targets with synthetic routes
backed by `internal/testmock`, an in-memory `raw.Module` implementation — no
HSM, vendor middleware, or C toolchain needed:

```sh
pkcs11-proxy serve --test --insecure --dev_ui.enabled
```

That serves three routes — `test-alpha` and `test-beta` on two tokens of one
shared virtual HSM, `test-gamma` on a second virtual HSM — so the route catalog
and dev dashboard show multi-token and multi-module layout at once. Every test
token accepts the user PIN `1234`; the workload credential must still be
non-empty but is not validated.

A custom topology can also bind individual routes to the test module from
YAML — `module: "test"` or `module: "test:<hsm-name>:<token-count>"` — which
mixes freely with real modules in the same broker.

`examples/proxy/testclient` lists routes, activates a token, and runs a digest:

```sh
go run ./examples/proxy/testclient
```

The test module implements real sessions, token-scope login, objects,
SHA-2 digests, ECDSA/RSA sign/verify, AES key generation, AES-CBC
encrypt/decrypt, and random generation; everything else returns
`CKR_FUNCTION_NOT_SUPPORTED`. It is a development fixture, not a security
boundary — never point it at real keys or production traffic.

## Kubernetes deployment

Both sides scale horizontally, and the same code runs identically on bare
metal, VMs, Compose, Kubernetes, Nomad, or systemd — no membership protocol,
leader election, shared datastore, or load balancer is required.

Brokers run as independent replicas that each own a per-process slice of the
HSM session budget (see "Per-replica budgets"). The client library is the
placement mechanism: give `Target.Endpoints` the directly reachable addresses
of every replica and each new logical client rendezvous-pins one of them:

```yaml
# application-side configuration
pkcs11_proxy:
  endpoints:
    - pkcs11-proxy-0.pkcs11-proxy.pki.svc:9443
    - pkcs11-proxy-1.pkcs11-proxy.pki.svc:9443
  server_name: pkcs11-proxy.pki.svc
```

Any addressing works — StatefulSet pod DNS names, plain service IPs, node
addresses — the client only needs to dial each address directly. Do not put a
load-balanced address in the endpoint list: an LB would break the pin (every
request dials its endpoint and must land on the same process).

Pod termination runs the drain sequence: SIGTERM → `ServerDraining` → new
clients skip the pod → existing clients finish → exit at `drain_timeout` or
sooner. Removing a replica is the four-step order in "Scaling down" above.

ErrTargetLost surfaced to an application means "recreate the proxy client" —
for the managed `pkcs11` layer that is a fresh `pkcs11.Open` followed by
re-establishing sessions, login, and object references through durable token
attributes.

## Observability

The proxy emits three telemetry layers, all through non-secret metadata only:
never PINs, request authentication bytes, plaintext, ciphertext, signatures,
wrapped keys, mechanism payloads, object values, or HSM key material.

### Metrics conformance (§30)

The proxy library instruments through the global OpenTelemetry meter
(`github.com/otpki/pkcs11/proxy`). With no SDK installed the calls are no-ops;
`pkcs11-proxy` installs OTLP/HTTP exporters when `otel.endpoint` is
configured, and any embedder can install its own SDK.

| Metric                                  | Type      | Labels                                                                | Emitted by |
| --------------------------------------- | --------- | --------------------------------------------------------------------- | ---------- |
| `pkcs11_proxy_clients`                  | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_virtual_sessions`         | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_physical_sessions`        | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_pinned_sessions`          | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_queue_depth`              | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_dedup_entries`            | gauge     | `server_id`, `target`                                                 | server     |
| `pkcs11_proxy_requests_total`           | counter   | `server_id`/`endpoint`, `target`/`route`, `method`, `outcome`, `role` | both       |
| `pkcs11_proxy_request_duration_seconds` | histogram | same as above                                                         | both       |
| `pkcs11_proxy_transport_errors_total`   | counter   | `role`, `endpoint`/`route` (client); none (server)                    | both       |
| `pkcs11_proxy_target_lost_total`        | counter   | `role`, `route`                                                       | client     |

All values are **per-process** — each replica exports its own gauges labeled
with `server_id`; fleet aggregation is the collector's job. The same numbers
are mirrored in-process via `Server.Counters()` and the dev UI, so they are
visible without an OTel stack.

The root `pkcs11` package emits the managed-operation counterparts through
`pkcs11.OTelHooks()` — a `Hooks` adapter producing
`pkcs11_operations_total{operation, vendor, read_write, outcome}`,
`pkcs11_operation_duration_seconds`, one `pkcs11.<op>` span per native call,
and a log record per operation. The broker attaches it automatically when a
route's `Client.Hooks` is unset, so native HSM calls get the same coverage
without any embedder wiring.

`outcome` is the protocol error code (`ok`, `wrong_server`, `unauthorized`,
`revision_mismatch`, `ckr`, …); request spans (`pkcs11.proxy <method>` server
side, `pkcs11.proxy.client <method>` client side) carry the §29 identity set:
`pkcs11.server_id`, `pkcs11.target_epoch`, `pkcs11.client_id`,
`pkcs11.request_id`, `pkcs11.target`, `pkcs11.method`. Every request also emits
an OTel log record with the same fields (debug severity on success, warn on
rejection).

### Application logging

`pkcs11-proxy` routes `slog` through a bounded non-blocking handler
(`internal/obslog`): records queue for a dedicated writer goroutine so a slow
stderr can never stall a request, and drops are counted plus announced with a
downstream warning. Configure with `logging.level` (`debug|info|warn|error`),
`logging.format` (`text|json`), `logging.queue_size`.

### Signed audit log

`audit.path` enables an append-only JSONL audit log. Event records are
unsigned leaf lines; every `audit.batch_size` records (default 64) — or every
`audit.checkpoint_interval` (default 30s), whichever comes first — the writer
seals the batch with a signed `checkpoint` line carrying the Merkle root over
the leaf hashes (`SHA-256(0x00‖line)` leaves, `SHA-256(0x01‖L‖R)` nodes, odd
nodes promoted), the sealed `seq` range, and a hash chain to the previous
checkpoint. One Ed25519 signature therefore attests a whole batch; any
modification, removal, or reordering inside a sealed range breaks its root,
and removing or reordering whole checkpoints breaks the chain. Records are
also sealed on clean shutdown.

Covered security events: `client_established`, `client_destroyed`,
`client_expired`, `login_grant`, `logout`, `activation`,
`activation_failure`, `maintenance`, `auth_failure`, `fence_rejection`,
`drain_rejection`, `stale_generation`, `drain`. Records contain only `seq`,
timestamp, event type, route, method, logical-client ID, principal, and
outcome code — never credentials or payloads.

Records written after the newest checkpoint are an **unsealed tail**: a
graceful shutdown seals them, but a crash or truncation can leave them without
attestation — verification reports them rather than rejecting the log. Note
that a log truncated exactly to a checkpoint boundary verifies clean, just as
any prefix of an append-only chain does.

Key management: `audit.key_file` (default `<path>.key`) holds a hex Ed25519
seed created `0600` on first run; the public key is written to
`<key_file>.pub` for verifiers. The writer is non-blocking with a bounded
queue (`audit.queue_size`); forced drops are recorded as an `audit_gap` leaf
so the loss is itself inside the verifiable record set. Every committed line
is fsynced. An existing log is resumed on restart — the checkpoint chain
continues across process lifetimes and an unsealed tail merges into the next
batch.

Verify, inspect, and extract inclusion proofs offline:

```sh
# Replay the file: contiguous seqs, recomputed Merkle roots, signature chain
pkcs11-proxy audit verify audit.log --key audit.key.pub

# Decode the newest 20 records (checkpoint lines excluded)
pkcs11-proxy audit inspect audit.log --tail 20

# Emit a Merkle inclusion proof for one record and verify it
pkcs11-proxy audit prove audit.log --seq 42 --key audit.key.pub
```

A proof binds one record to a signed checkpoint root so a third party can
verify inclusion without the full log; chain continuity across checkpoints
still requires `audit verify` over the file.

For library users the same events are delivered through
`ServerConfig.Audit` (`proxy.AuditSink`), so embedders can implement their own
signed or remote sink.

### Dev UI

`/dev/` now also reports the §30 request counters (`requests_total`,
`transport_errors_total`, `auth_failures_total`, `fence_rejections_total`,
`drain_rejections_total`, `stale_generations_total`), a requests/s + errors/s
sparkline, whether OTLP export is enabled, the TLS mode (`insecure`, `tls`,
`mtls`), the log queue depth/drops, and the audit log's key ID plus
written/sealed/pending counts. Each route card shows the token's capability
surface — mechanism count plus the routable algorithm names — from the managed
client's `Capabilities()` snapshot.

Two more panels answer "who holds the token" and "what just happened" without
an OTel stack:

- **Logical clients** (`Server.ClientInfos()`): one row per established
  logical client — client id, route, principal, establishing method, age, last
  activity, authenticated flag, virtual sessions, objects, and in-flight
  requests.
- **Requests**: the method × outcome breakdown (`Server.MethodOutcomes()`,
  same dimensions as `pkcs11_proxy_requests_total`) plus the last 256
  completed requests (`Server.RecentRequests()`) — method, outcome, latency,
  and client. The ring is a rolling window, not a log.

When audit is enabled the dashboard shows a dedicated panel: recent records
(`GET /dev/api/audit/events?tail=N`, served from the writer's in-memory tail),
and a **verify chain** button (`GET /dev/api/audit/verify`) that replays the
whole log against the public key and reports records/checkpoints/unsealed
counts.

### Alerting guidance

```text
pkcs11_proxy_physical_sessions near the sessions.max_physical_total budget
pkcs11_proxy_queue_depth near sessions.max_queued
pkcs11_proxy_pinned_sessions near sessions.max_pinned
pkcs11_proxy_dedup_entries near the dedup budget
pkcs11_proxy_requests_total{outcome="unauthorized"} rising
pkcs11_proxy_transport_errors_total rising (replica/network loss)
pkcs11_proxy_target_lost_total rising (clients losing pinned replicas)
stale_generations_total rising (epoch/revision churn — config drift)
audit audit_gap records present, or audit_failed > 0
log_dropped > 0 (log queue saturation)
```

## Supported raw surface and concessions

The generated proxy client implements every method in `raw.Module`, including
PKCS #11 3.0 message operations and PKCS #11 3.2 KEM, signature-first verify,
session validation, and authenticated wrapping.

The server handles module lifecycle logically:

- remote `Initialize` initializes one logical client;
- remote `Finalize` closes only that logical client's sessions and grants;
- remote `CloseAllSessions` affects only that logical client;
- remote `Destroy` drains and removes only that logical client; and
- the broker owns actual local module initialization/finalization.
