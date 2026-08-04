# Feature reference

This document describes the functionality implemented by the driver. It is a
capability reference for the software, not a claim that every listed operation
is available on every token. A concrete HSM must advertise the required
mechanism and flags, or the selected `VendorModule` must provide and test a
provider-specific route.

## Native PKCS #11 coverage

The raw package exposes every entry in the pinned OASIS PKCS #11 3.2 function
table. Function order, minimum interface version, names, and native argument
counts are generated from the pinned `pkcs11f.h` header.

### Base Cryptoki operations

Implemented base operations include:

- module initialization, legacy initialization, finalization, and information
- slot, token, and mechanism enumeration
- token and PIN initialization
- session open, close, close-all, information, operation-state save/restore,
  login, logout, function status, cancellation, and slot-event waiting
- object create, copy, destroy, size, attribute read/write, and search
- single-part and multipart encrypt/decrypt
- single-part and multipart digest
- single-part and multipart sign/verify
- sign-recover and verify-recover
- combined digest/encrypt, decrypt/digest, sign/encrypt, and decrypt/verify
- symmetric key generation, asymmetric key-pair generation, wrapping,
  unwrapping, and derivation
- seed and random generation.

### PKCS #11 3.0 additions

Implemented 3.0 operations include:

- interface enumeration and selection
- username-aware `C_LoginUser`
- `C_SessionCancel`
- the message encrypt, decrypt, sign, and verify APIs, including begin/next/final
  multipart forms.

The driver checks the selected function-table version before reading 3.x slots.
Provider conformance must additionally verify that a module returning a 3.x
table supplies callable implementations and appropriate mechanism flags.

### PKCS #11 3.2 additions

Implemented 3.2 operations include:

- `C_EncapsulateKey` and `C_DecapsulateKey`
- signature-first verification initialization, single-part, update, and final
- session validation flags
- asynchronous completion, ID lookup, and join
- authenticated wrap and unwrap with associated data.

## High-level managed client

`Client` represents one selected token. It supports:

- explicit module opening and conservative automatic module discovery
- token selection by slot, serial number, label, model, manufacturer, and
  configured selector policy
- standard-first mechanism and template routing
- separate bounded read-only and read/write session pools
- eager, lazy, manual, or disabled login
- token-wide or provider-declared per-session login coordination
- protected authentication paths and context-specific login for
  `CKA_ALWAYS_AUTHENTICATE` keys
- idle-session retirement and module-generation invalidation
- bounded retry and exponential backoff for complete replay-safe operations
- re-login, session replacement, module reinitialization, and token
  rediscovery
- optional module-wide call serialization and per-session OS-thread affinity
- object and attribute caching with sensitive-attribute exclusions
- health checks, runtime validation, hotplug watching, and explicit refresh
- metrics, tracing, and audit hooks that exclude cryptographic payloads
- managed raw module/session escape hatches for operations not yet modeled.

Sessions remain internal for ordinary use. `WithRawSession` and
`VendorSession.Call` preserve module lifetime, serialization, thread affinity,
hooks, and recovery classification while exposing the exact `raw.Ctx` and
session handle for the callback lifetime.

## Object and key management

The high-level API supports:

- durable object references using `CKA_UNIQUE_ID`, `CKA_ID`, label, class, key
  type, and inferred algorithm
- exact-one lookup and public/private pair lookup
- automatic object re-resolution after session replacement or failover
- object enumeration and common policy metadata
- attribute reads and writes
- configurable public, private, and secret-key policy
- template policies plus expert raw attributes
- algorithm invariants protecting class, key type, and parameter set
- secret-key and asymmetric/PQC key-pair generation
- key destruction
- wrapping, authenticated wrapping, unwrapping, and authenticated unwrapping
- ECDH derivation through the raw API and conformance runner
- X.509 certificate import, replacement, lookup, parsing, and association with a
  key through `CKA_ID`.

Private and secret keys default to persistent, private, sensitive,
non-extractable objects. Applications may override policy and remain responsible
for the resulting security properties.

## Go crypto interfaces and operations

The managed API provides:

- `crypto.Signer` backed by a token-resident private key
- context-aware direct signing and verification
- `crypto.Decrypter` for RSA private keys
- RSA-PSS and PKCS #1 v1.5 signatures
- RSA-OAEP, PKCS #1 v1.5, and raw RSA encryption routes where supported
- ECDSA P-256, P-384, and P-521 with Go DER signature conversion
- Ed25519 and Ed448 public-key loading and signing routes
- AES-128, AES-192, and AES-256 generation
- AES-GCM, AES-CBC with padding, and AES-CTR
- provider-generated GCM IV handling where declared by a vendor module
- SHA-family token-side digest operations
- HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
- token RNG and optional external RNG seeding
- public-key loading into standard Go key types or `OpaquePublicKey` when the
  standard library has no corresponding key type.

Mechanism overrides remain available for expert use, but normal callers express
algorithm intent rather than numeric mechanism IDs.

## Post-quantum and stateful signatures

PQC is part of the main routing and object model, not a separate driver.

### Standardized PKCS #11 3.2 families

Implemented high-level routing includes:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- all standardized SHA2 and SHAKE SLH-DSA 128/192/256, small/fast parameter
  sets
- HSS/LMS
- XMSS and XMSSMT
- direct-message PQC signing
- external-prehash signing with an explicit hash mechanism
- context and hedge controls represented by PKCS #11 3.2 additional-context
  structures
- KEM encapsulation and decapsulation returning token-resident shared-secret
  objects
- signature-first verification.

### Vendor and pre-standard families

The router can represent vendor-supplied Dilithium, Kyber, Falcon,
SPHINCS-plus, composite, and hybrid families when a supplied `VendorModule`
defines and tests the necessary key types, parameter sets, mechanisms, and
operation behavior.

External ML-DSA `mu` is supported as a vendor extension because PKCS #11 3.2
does not assign a standard mechanism for that operation. The driver validates a
64-byte input and delegates only when the selected vendor module exposes the
semantics.

### Stateful-signature safety

HSS/LMS/XMSS/XMSSMT signatures consume persistent key state. Managed signing:

- obtains a read/write session when the selected route requires it
- marks the complete operation non-replayable
- does not retry an ambiguous signature attempt
- exposes provider-specific remaining-signature metadata where available.

A vendor may model a logical key pair as one resident object. The root API keeps
returning `KeyPair`, while the provider module owns the unusual resident object
model and temporary public/verification carriers.

## Mechanism parameters and native ABI control

Typed standard parameters include:

- RSA-PSS
- RSA-OAEP with optional label
- AES-CTR
- AES-GCM, including provider write-back of generated IV data
- ECDH1 derivation
- EdDSA context/prehash parameters
- PQC sign additional context
- PQC hash-sign additional context.

Provider packages can implement `raw.NativeParameterMarshaler` with
`raw.NativeStructBuilder`. The builder uses the active LP64 or Windows LLP64
layout, creates explicit pointer relocations, and lets the raw package copy and
pin all referenced byte buffers.

`raw.ParameterMarshaler` remains appropriate for pointer-free opaque native
records. `raw.UnsafeParameter` is the final escape hatch and transfers layout,
alignment, allocation, lifetime, concurrency, and secrecy responsibility to the
caller.

## Vendor modules

A vendor module may contribute:

- native library names, environment variables, and installation directories
- standard-fingerprint matching and product/firmware variants
- semantic aliases for mechanisms, key types, attributes, and parameter sets
- initialization, finalization, session, login, output-buffer, GCM, and recovery
  behavior
- route, mechanism, and template normalization
- proprietary object metadata and algorithm inference
- nonstandard key-pair models
- complete custom generate, sign, verify, KEM, or public-key-load operations
- capability augmentation
- provider-owned native conformance tests and fixtures.

The root driver clones definitions and mutable operation inputs before invoking
a vendor module. A vendor module cannot replace the process-wide session pool or
module lifecycle; custom raw calls run through a scoped managed `VendorSession`.

## Discovery, monitoring, and diagnostics

Implemented operational features include:

- canonical module-path deduplication
- finite discovery from explicit paths, generic environment variables,
  supplied vendor hints, and conservative system directories
- deterministic candidate ordering and file-identity deduplication
- device fingerprints from standard module, interface, slot, token, and
  mechanism information
- dynamic vendor selection with diagnostic scores and reasons
- hotplug/token replacement watching through nonblocking
  `C_WaitForSlotEvent`, with snapshot polling fallback
- selected-token refresh with session/cache/login invalidation
- non-destructive health checks
- runtime module and mechanism SHA-256 evidence
- optional caller-supplied existing-key cryptographic probes
- signed hardware-evidence binding to exact runtime metadata.

Broad in-process discovery is diagnostic functionality, not sandboxing. Loading
a native module executes trusted native code in the host process.

## Conformance and validation

The repository includes:

- generated-function inventory and native-argument-count checks
- host C ABI comparisons against the pinned OASIS headers
- Windows amd64 and arm64 LLP64/one-byte-pack compile-time assertions
- dynamic mock PKCS #11 modules for legacy, 3.0, 3.2, output-buffer, session,
  thread-affinity, and lifecycle behavior
- build-tag tests proving cgo-default, no-cgo-fallback, and forced-PureGo
  selection
- a source-separation scan that confines `import "C"` and cgo directives to the
  cgo backend
- vendor separation tests
- reusable `vendortest.Module` provider contracts
- provider-specific routing, parameter, template, object-model, and cleanup
  tests
- provider-owned public, licensed, or hardware-template fixtures.

Tests run the same disposable mock modules through the default cgo backend and
the PureGo backend. They may invoke a local C compiler to build those modules
and compare C header layouts. That is a repository validation dependency; a
consumer building the PureGo fallback does not need a C compiler.

## Deliberate limitations

- Native PKCS #11 modules are not sandboxed. Invalid function pointers or vendor
  memory corruption can terminate the process.
- The driver does not provide software cryptographic fallback for private-key
  operations.
- The driver does not currently expose application-provided native mutex or
  `CK_NOTIFY` callbacks. It uses `CKF_OS_LOCKING_OK`, provider-declared legacy
  initialization, and nil session notification callbacks.
- A context cancellation cannot portably interrupt a native call already in
  progress. Cancellation still bounds acquisition, retry, and subsequent work.
- A Go executable built without cgo still dynamically loads vendor native code,
  it is not a wholly static cryptographic appliance.
- Simulator success is not equivalent to physical-HSM or cloud-service
  validation.

## Direct Go network proxy

The `proxy` package provides a complete remote implementation of `raw.Module`
and can therefore be used under either the raw or managed API. Supported broker
features include:

- fully programmatic, immutable, revisioned client and server configuration;
- multiple independent HSM routes in one broker and multiple remote clients in
  one application process
- one TCP/TLS connection per request, with no persistent application socket
- stable authenticated-principal binding for every logical client ID
- virtual sessions that consume no physical session until work is executed
- one combined read-only/read/write physical HSM session budget
- bounded connections, queue, clients, virtual sessions, pinned sessions,
  object handles, frames, dedup entries, and dedup bytes
- one reserved control session and three explicit physical-login modes:
  server-managed PIN, client-supplied activation, and protected authentication
  path
- target-wide client activation that collapses concurrent pods onto one physical
  PIN attempt and wipes every request, callback, and `Secret` copy afterward
- activation-generation invalidation plus fail-closed
  `proxy.ErrActivationRequired` recovery when a broker that retained no PIN loses
  physical login
- separate transport `Authenticator`, per-target `OperationAuthorizer`, and
  logical `LoginPolicy.Authenticate` hooks
- isolated logical login/logout and context-specific authentication
- multipart-operation and session-object physical affinity with idle cleanup
- client-local virtual object and session handles
- immutable revision and random target-epoch invalidation
- bounded same-request replay for non-idempotent transport failures and
  explicit `proxy.ErrOutcomeUnknown` when the result cannot be proved
- strict architecture-independent JSON framing and semantic parameter values
- vendor-contributed versioned parameter codecs
- target statistics and graceful request/session drain
- the complete synchronous PKCS #11 3.2 `raw.Module` surface.

Remote asynchronous sessions are deliberately rejected because generic
cross-request retention of provider-owned pointers after `CKR_PENDING` cannot
be made safe. Local cgo and PureGo modules retain the full asynchronous API.

See `PROXY.md` for the complete contract.
