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

| Type                        | Role                                                                                                   |
|-----------------------------|--------------------------------------------------------------------------------------------------------|
| `proxy.Target`              | Immutable application side route, TLS, retry, and codec configuration.                                 |
| `proxy.Source`              | `pkcs11.ModuleSource` produced by `proxy.RemoteModule`.                                                |
| `proxy.Client`              | Request scoped network implementation of `raw.Module`.                                                 |
| `proxy.Server`              | Multi route broker that owns local managed HSM clients.                                                |
| `proxy.TargetConfig`        | One broker route and its local HSM, login, quota, and codec policy.                                    |
| `proxy.SessionBudget`       | Authoritative physical and virtual resource limits.                                                    |
| `proxy.LoginPolicy`         | Logical-client authentication plus server-managed, client-activated, or protected-path physical login. |
| `proxy.Authenticator`       | Transport peer authentication and stable principal derivation.                                         |
| `proxy.OperationAuthorizer` | Per-target authorization, including the exact physical activation transition.                          |
| `proxy.ActivationStatus`    | Secret-free inactive/activating/active state and generation.                                           |
| `proxy.ParameterCodec`      | Architecture-independent vendor parameter transport.                                                   |
| `pkcs11.RawSessionLease`    | Long-lived managed physical lease used internally by the broker.                                       |


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
|--------------------------------|--------------------------------------------------|------------------------------|----------------------------------------------------|
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

Targets may use the same endpoint and different routes, or entirely different
brokers. Their registry identities, client IDs, epochs, sessions, login grants,
object maps, vendor candidates, codecs, retries, and recovery generations are
independent.

## Kubernetes deployment

The stateless client application may scale horizontally. The server should scale only
in a way that preserves one authoritative physical session budget.

The default production shape is:

```text
one active broker per HSM or partition
one stable Service/VIP
optional passive replacement
application Deployment scales independently
```

A broker may run as:

- a service on the host physically attached to the HSM
- a pod pinned to that host
- a one-replica StatefulSet
- an active/passive pair with leader election and drain before handoff
- a DaemonSet only when every node has a different independent HSM.

Do not run multiple active brokers against the same finite HSM merely behind a
load-balanced Service. Each process would own a separate local pool, multiplying
the actual session limit. Active-active requires an external distributed permit
service and coordinated login/maintenance ownership. this package intentionally
does not pretend a process-local semaphore solves that problem.

## Observability

The local managed client still emits the configured root `Hooks` around HSM
operations. Broker deployments should additionally export `TargetStats`:

```go
stats, ok := server.TargetStats("production-hsm-a")
```

Useful alerts include:

```text
PhysicalOpened near MaxPhysical
PhysicalActive near MaxPhysical
PinnedSessions near MaxPinned
QueuedRequests near MaxQueued
rapid session rotation or broken-session replacement
DedupBytes near MaxDedupBytes
repeated revision or epoch mismatches
logical authentication failures
PIN incorrect or locked errors
ErrOutcomeUnknown returned to clients
```

Never log PINs, request authentication bytes, plaintext, ciphertext, signatures,
wrapped keys, mechanism payloads, object values, or HSM key material.

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

