# otpki/pkcs11

`pkcs11` is a Go driver/client for PKCS #11 through version 3.2. The
root package provides a single token oriented `Client`. This client owns the module
lifecycle, token selection, login, session pools, caching, recovery, algorithm
routing, and optional HSM vendor adaptation.

This project deliberately separates the driver code from the provider code.

| Package                                      | Purpose                                                                                                                      |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `github.com/otpki/pkcs11`                    | High-level token API: keys, signers, ciphers, KEM, objects, certificates, health, discovery, and managed raw escape hatches. |
| `github.com/otpki/pkcs11/raw`                | Complete low-level PKCS #11 3.2 ABI.                                                                                         |
| `github.com/otpki/pkcs11/proxy`              | Direct Go remote module and multi target HSM broker.                                                                         |
| `github.com/otpki/pkcs11/vendors/<provider>` | One isolated `VendorModule` implementation, public/vendor ABI definitions, tests, and optional simulator fixture.   |
| `github.com/otpki/pkcs11/vendorkit`          | Helpers for vendor modules.                                                                                                  |
| `github.com/otpki/pkcs11/vendortest`         | Reusable contract tests for vendor modules.                                                                                  |
| `github.com/otpki/pkcs11/conformance`        | Manifest-driven portable and provider-extended conformance runner.                                                           |

The root driver imports no concrete vendor package. Applications explicitly choose
which vendor implementations they are going to need by passing them into a config.
Vendor implementations can live in this repository, another Go module, or the consuming
application.

The ABI boundary has one shared Cryptoki implementation and two "transports". A normal
cgo-enabled build uses a C bridge as the default. When cgo is disabled, `ebitengine/purego`
is used to call the ABI.

## Requirements

- Go 1.26 or newer
- A PKCS11 middleware built for the target OS and architecture.
- Any native dependencies required by that module

Backend selection is automatic:

```sh
# Default when a C toolchain is available.
CGO_ENABLED=1 go build ./...

# Real native fallback without cgo or a target C compiler.
CGO_ENABLED=0 go build ./...

# Force PureGo while cgo is available, useful for parity testing.
CGO_ENABLED=1 go build -tags pkcs11_purego ./...
```

Native loading is enabled on Linux, macOS, and Windows for amd64 and arm64 under
both transports. Other targets compile the public packages, but `raw.Open`
returns `raw.ErrNativeUnavailable` until their byte order, calling convention,
and ABI layout are validated. The selected "transport" is available through
`raw.ActiveNativeBackend()`.

Removing cgo from the Go executable does not make the vendor library portable.
For example, a glibc-only Linux module still requires glibc, and an amd64-only
simulator still requires an amd64 runtime or emulation.

## PKCS #11 3.2 and PQC

PQC is part of the main driver. Standard routing covers:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- every standardized SLH-DSA parameter set
- HSS/LMS, XMSS, and XMSSMT
- direct, prehash, context, and hedged signing where the provider supports it
- KEM encapsulation/decapsulation
- signature-first verification
- authenticated wrapping

```go
signer, pair, err := client.GenerateSigner(ctx,
    pkcs11.KeyPairOptions{
        Algorithm: pkcs11.AlgorithmMLDSA65,
        Label:     "issuing-ca-mldsa",
        ID:        []byte("issuing-ca-mldsa-v1"),
    },
    pkcs11.SignerConfig{},
)
if err != nil {
    return err
}

signature, err := signer.Sign(
    rand.Reader,
    []byte("message"),
    pkcs11.PQCDirect(nil, pkcs11.HedgePreferred),
)
_ = pair
_ = signature
```

Routing is standard-first:

1. Build the portable PKCS #11 3.2 route.
2. Use it when the token advertises the required mechanism and flags.
3. Otherwise ask only the dynamically selected `VendorModule` for a documented
   provider fallback.
4. Return unsupported when neither route exists.

## Login, recovery, and caching

- `LoginLazy` is the normal service mode.
- `LoginEager` authenticates during `Open`.
- `LoginManual` requires `Activate`.
- `LoginNone` never logs in.

The driver uses separate internal read-only and read/write pools, coordinates
per-token or per-session login, retires idle or invalid sessions, re-finds
objects through stable locators, and invalidates caches after mutation,
rediscovery, or recovery. Only complete operations explicitly classified as
replay-safe are retried.

Use a durable `CKA_ID` for keys that must survive session replacement or HSM
failover. Labels are supported but must be unique.

## Automatic module discovery

Production services should configure an explicit trusted module path. For
controlled setup or diagnostics, supplied vendor modules contribute finite
search hints:

```go
modules := []pkcs11.VendorModule{utimaco.New()}

candidates, err := pkcs11.ModuleCandidates(
    pkcs11.DefaultDetectionConfig(),
    modules...,
)

client, err := pkcs11.OpenAuto(ctx, pkcs11.Config{
    Token:   selector,
    PIN:     pinProvider,
    Vendors: modules,
})
```

## Complete control without a "public" session API

The normal API intentionally hides sessions. Use `WithRawSession` for an exact
operation that is not yet modeled by the root API or a vendor module:

```go
err := client.WithRawSession(ctx, pkcs11.RawSessionOptions{
    ReadWrite: true,
    Operation: "custom-operation",
    // Set only when replaying the complete callback is safe.
    Idempotent: false,
}, func(module *raw.Ctx, session raw.SessionHandle) error {
    return module.SeedRandom(session, []byte("seed"))
})
```

The module and session handle are valid only during the callback. Do not retain
them or start asynchronous work that outlives it. A read/write raw callback
conservatively invalidates the object cache.

Vendor implementations receive an even narrower `VendorSession` capability so
provider code retains managed serialization, OS-thread affinity, hooks, durable
object resolution, and lifetime protection.

## Vendor modules

A `VendorModule` owns all vendor specific concerns:

- fingerprint matching and product variants
- discovery environment variables, module names, and installation paths
- proprietary mechanisms, key types, attributes, parameter sets, and typed
  parameter encoders
- lifecycle, session, login, buffer, thread-affinity, and recovery facts
- mechanism and template normalization
- edge case object models and operation sequences
- its native conformance tests and optional container fixture.

The root package contains no provider filename catalog and no provider switch
statements. Adding a vendor should require a new package, not edits scattered
through the driver.

## Remote HSM access and bounded proxying

The `proxy` package lets the same managed or raw API reach a local HSM through
a direct Go broker. The client opens one TCP/TLS connection per PKCS #11 call.
the server owns the persistent physical HSM session pool, bounded queue,
multipart/session-object affinity, virtual handles, request replay ledger, and
coordinated physical login state.

```go
remote := proxy.RemoteModule(proxy.Target{
    ConfigID:          "key-storage-config-6f97",
    Revision:          "database-row-version-42",
    Endpoint:          "pkcs11-proxy.pki.svc.cluster.local:9443",
    Route:             "production-hsm-a",
    SecurityContextID: "pki-workload-mtls-v3",
    TLS:               clientTLS,
    Vendors:           []pkcs11.VendorModule{utimaco.New()},
})

client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: remote,
    Token:  selector,
    Login:  pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
    PIN:    logicalActivationProvider,
})
```

Remote configuration is immutable and can come directly from a database. No
environment variable, client configuration file, persistent socket, or native
proxy shim is required. One server route is the authoritative governor for a
finite HSM session budget even when, for example, a Kubernetes application 
scales to many replicas.

The server does not have to be provisioned with the HSM PIN. In
`proxy.PhysicalLoginClientActivated` mode the client application supplies a
short-lived PIN through the ordinary managed `PINProvider` and `Client.Activate`
(or through raw `C_Login`). Exactly one concurrent caller performs physical
`C_Login` while other pods wait for that result. The PIN is wiped after the call and
is never retained for recovery, so a lost activation fails closed and requires
a fresh audited client activation. Transport authentication and target
authorization remain separate requirements.
