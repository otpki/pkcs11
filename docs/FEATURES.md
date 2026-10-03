# Feature reference

This is a reference for what the driver can do. It does not mean every HSM
supports every item. A token still needs to advertise the required mechanism,
or a selected `VendorModule` needs to provide a tested vendor-specific route.

## Raw PKCS #11 coverage

The `raw` package exposes the full function table from the pinned OASIS PKCS #11
3.2 headers.

### Core Cryptoki operations

Supported operations include:

- module initialization, finalization, and module information
- slot, token, interface, and mechanism discovery
- token and PIN initialization
- session open, close, login, logout, cancellation, and state handling
- object create, copy, destroy, search, size, and attribute access
- encrypt and decrypt, including multipart forms
- digest, sign, and verify, including multipart forms
- sign-recover and verify-recover
- combined digest/encrypt and sign/encrypt style operations
- key generation, wrapping, unwrapping, and derivation
- random generation and seeding

### PKCS #11 3.0

The raw API also includes the 3.0 additions:

- interface enumeration and selection
- `C_LoginUser`
- `C_SessionCancel`
- message encrypt, decrypt, sign, and verify APIs

The driver checks the selected interface version before using 3.x function-table
entries.

### PKCS #11 3.2

3.2 support includes:

- `C_EncapsulateKey` and `C_DecapsulateKey`
- signature-first verification
- session validation flags
- asynchronous completion, lookup, and join APIs
- authenticated wrap and unwrap with associated data

## Managed client

`Client` represents one selected token. It adds the application-level behavior
that is normally tedious to build around raw Cryptoki:

- explicit module opening and conservative module discovery
- token selection by slot, serial, label, model, manufacturer, or policy
- separate bounded read-only and read/write session pools
- eager, lazy, manual, or disabled login
- token-wide or provider-specific login coordination
- protected authentication paths
- context-specific login for `CKA_ALWAYS_AUTHENTICATE`
- idle-session cleanup and module-generation invalidation
- bounded retries for operations known to be replay-safe
- relogin, session replacement, module reinitialization, and token refresh
- optional module-wide call serialization
- optional per-session OS-thread affinity
- object and attribute caching with sensitive-value exclusions
- health checks, runtime validation, and hotplug watching
- tracing, metrics, and audit hooks that omit cryptographic payloads
- managed raw escape hatches for operations not yet modeled by the high-level API

Normal callers do not manage sessions directly. `WithRawSession` and
`VendorSession.Call` provide scoped raw access while keeping the managed
lifecycle, locking, hooks, and recovery behavior.

## Objects and keys

The managed API supports:

- durable object locators using `CKA_UNIQUE_ID`, `CKA_ID`, label, class, and key type
- exact-one object lookup
- public/private pair lookup
- object re-resolution after session replacement or failover
- object enumeration and common metadata
- attribute reads and writes
- public, private, and secret-key policy
- typed algorithm templates plus expert raw attributes
- secret-key generation
- asymmetric and PQC key-pair generation
- key destruction
- wrapping and authenticated wrapping
- unwrapping and authenticated unwrapping
- X.509 certificate import, replacement, lookup, parsing, and key association

Private and secret keys default to persistent, private, sensitive, and
non-extractable objects. Applications can override those defaults when needed.

## Go crypto support

The managed API includes:

- token-backed `crypto.Signer`
- managed signing and verification
- `crypto.Decrypter` for RSA private keys
- RSA-PSS and RSA PKCS #1 v1.5 signatures
- RSA-OAEP, PKCS #1 v1.5, and raw RSA encryption where supported
- ECDSA P-256, P-384, and P-521 with DER signature conversion
- Ed25519 and Ed448 public-key loading and signing routes
- AES-128, AES-192, and AES-256 key generation
- AES-GCM
- AES-CBC with padding
- AES-CTR
- provider-generated GCM IV handling when declared by a vendor module
- SHA-family token-side digests
- HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
- token RNG and optional external seeding
- public-key loading into standard Go types when possible
- `OpaquePublicKey` when Go has no matching standard key type

Normal callers describe the algorithm they want. Numeric mechanism overrides
are still available for expert use.

## Post-quantum and stateful signatures

PQC uses the same routing and object model as the rest of the driver.

### Standard PKCS #11 3.2 families

High-level routing covers:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- all standardized SHA2 and SHAKE SLH-DSA parameter sets
- HSS/LMS
- XMSS and XMSSMT
- direct-message PQC signing
- prehash signing with an explicit hash mechanism
- signing context and hedge controls
- KEM encapsulation and decapsulation into token-resident secrets
- signature-first verification

### Vendor and pre-standard algorithms

A vendor module can add algorithms such as vendor Dilithium, Kyber, Falcon,
SPHINCS+, composite, or hybrid schemes when it defines and tests the necessary
mechanisms, key types, parameters, and object behavior.

External ML-DSA `mu` is also available as a vendor extension. PKCS #11 3.2 does
not assign a standard mechanism for it, so the driver validates the 64-byte
input and delegates only when the selected vendor module provides the route.

### Stateful key safety

HSS/LMS/XMSS/XMSSMT signing consumes persistent key state. Managed signing
therefore:

- uses a read/write session when the route requires one
- marks the operation as non-replayable
- does not repeat an ambiguous signing attempt
- exposes provider-specific remaining-signature metadata when available

A vendor can represent a logical key pair with one resident object. The public
API still returns `KeyPair`. The vendor module owns the unusual object model.

## Mechanism parameters and ABI control

Typed standard parameters include:

- RSA-PSS
- RSA-OAEP, including labels
- AES-CTR
- AES-GCM, including provider IV write-back
- ECDH1
- EdDSA context and prehash parameters
- PQC signing context
- PQC hash-sign context

Pointer-bearing vendor parameters should implement
`raw.NativeParameterMarshaler` and use `raw.NativeStructBuilder`. The builder
handles the active LP64 or Windows LLP64 layout and keeps referenced buffers
alive for the native call.

Use `raw.ParameterMarshaler` for pointer-free opaque records.
`raw.UnsafeParameter` is the last-resort escape hatch and leaves memory layout,
lifetime, concurrency, and secrecy to the caller.

## Vendor modules

A `VendorModule` can provide:

- module names, environment variables, and install paths
- provider fingerprint matching and product variants
- proprietary mechanism, key type, attribute, and parameter-set aliases
- provider lifecycle, session, login, buffer, and recovery behavior
- route, mechanism, and template normalization
- proprietary object metadata and algorithm inference
- unusual key-pair models
- custom generate, sign, verify, KEM, or public-key-load operations
- capability augmentation
- provider-specific conformance tests and fixtures

The root driver copies mutable inputs before calling vendor code. Vendor modules
cannot replace the process-wide module lifecycle or session pool. Exact native
calls still run through a scoped `VendorSession`.

## Discovery and diagnostics

Operational tooling includes:

- canonical module-path deduplication
- finite discovery from explicit paths, generic environment variables, vendor hints, and conservative system paths
- deterministic discovery ordering
- file-identity deduplication
- device fingerprints from standard module, slot, token, interface, and mechanism data
- vendor selection diagnostics with match scores and reasons
- hotplug and token-replacement watching
- polling fallback when slot events are unavailable
- selected-token refresh with session, cache, and login invalidation
- non-destructive health checks
- runtime module and mechanism SHA-256 evidence
- optional caller-supplied cryptographic probes using existing keys
- signed hardware-evidence binding to runtime metadata

Discovery is intentionally conservative. It does not recursively load every
shared library it can find.

## Conformance and validation

The repository includes portable and vendor-specific conformance support:

- manifest-driven test definitions
- standard high-level cases shared by providers
- provider-specific extension cases for proprietary behavior
- public simulator and container fixtures where redistributable
- licensed fixture hooks for private providers
- cgo and PureGo parity coverage
- generated ABI validation against pinned headers

Repository ABI validation may require a C compiler. Applications using the
PureGo backend do not need one at runtime.

## Deliberate limitations

A few boundaries are intentional:

- Native PKCS #11 modules are not sandboxed.
- There is no software private-key fallback.
- Application-provided native mutex and `CK_NOTIFY` callbacks are not currently exposed.
- Go context cancellation cannot reliably interrupt a native call already running.
- A no-cgo build still loads native vendor code dynamically.
- Simulator success does not prove behavior on a physical HSM or cloud service.

## Network proxy

The `proxy` package implements `raw.Module` remotely, so it works under both the
raw and managed APIs.

The broker supports:

- immutable application and server configuration
- multiple HSM routes in one process
- one TCP/TLS connection per request
- stable workload-principal binding
- virtual sessions that do not consume physical sessions until used
- bounded queues, clients, sessions, handles, frames, and deduplication state
- server-managed, client-activated, and protected-path physical login
- coordinated client activation without storing the client PIN for recovery
- logical login and logout isolated per remote client
- multipart and session-object affinity
- virtual session and object handles
- target revision and epoch fencing
- bounded same-request replay for ambiguous transport failures
- `proxy.ErrOutcomeUnknown` when the original result cannot be proven
- architecture-independent parameter transport
- vendor parameter codecs
- graceful drain and target statistics
- the synchronous PKCS #11 3.2 `raw.Module` surface

Remote asynchronous sessions are intentionally unsupported because a generic
proxy cannot safely own provider-retained pointers across requests after
`CKR_PENDING`.

See [`PROXY.md`](PROXY.md) for the full design and deployment guide.
