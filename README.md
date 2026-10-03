# otpki/pkcs11

`pkcs11` is a Go client for PKCS #11 through version 3.2. The main package gives
applications a token-oriented API and handles the lower-level work such as
sessions, login, retries, caching, recovery, and vendor-specific routing.

The repository is split into a few layers:

| Package | Use it for |
| --- | --- |
| `github.com/otpki/pkcs11` | Normal application code. Keys, signers, encryption, KEM, objects, certificates, discovery, and health. |
| `github.com/otpki/pkcs11/raw` | Direct access to the PKCS #11 3.2 API. |
| `github.com/otpki/pkcs11/proxy` | Remote access to an HSM through the Go proxy. |
| `github.com/otpki/pkcs11/vendors/<provider>` | Public vendor integrations. |
| `github.com/otpki/pkcs11/vendorkit` | Helpers for writing vendor integrations. |
| `github.com/otpki/pkcs11/vendortest` | Shared tests for vendor integrations. |
| `github.com/otpki/pkcs11/conformance` | Portable and vendor-specific conformance tests. |

The root package does not import concrete vendor packages. Your application
chooses which vendor modules it trusts and passes them in through configuration.
Those modules may live in this repository, another Go module, or your own app.

## Requirements

- Go 1.27 or newer
- PKCS #11 middleware for the target OS and architecture
- Any native libraries required by that middleware

The native backend is chosen at build time:

```sh
# Default when cgo is available.
CGO_ENABLED=1 go build ./...

# Use PureGo instead of a C toolchain.
CGO_ENABLED=0 go build ./...

# Force PureGo while cgo is available. Useful for parity testing.
CGO_ENABLED=1 go build -tags pkcs11_purego ./...
```

Both backends support Linux, macOS, and Windows on amd64 and arm64. Other
targets can compile the public packages, but native loading stays disabled until
their ABI has been validated.

PureGo removes the C build dependency from the Go application. It does not make
the vendor library portable. A Linux-only or amd64-only PKCS #11 library still
needs a compatible runtime.

## Development

Contributors only need `just` and `curl` on `PATH`.

```sh
just tools   # install the pinned development tools under .tool/
just check   # format, lint, tidy, generate, and check for generated diffs
```

The same tool versions are used in CI.

## Opening a token

A `Client` represents one selected token. In production, prefer an explicit
module path and a stable token selector.

```go
client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: pkcs11.LocalModule("/opt/vendor/lib/libpkcs11.so"),
    Token: pkcs11.TokenSelector{
        Label: "production",
    },
    PIN: pinProvider,
    Vendors: []pkcs11.VendorModule{
        softhsm.NewV2(),
    },
})
if err != nil {
    return err
}
defer client.Close()
```

`LoginLazy` is the normal service mode. `LoginEager` logs in during `Open`,
`LoginManual` waits for `Activate`, and `LoginNone` never logs in.

Use a durable `CKA_ID` for keys that need to survive session replacement or HSM
failover. Labels are also supported, but they must be unique if they are used as
locators.

## PKCS #11 3.2 and PQC

PQC support is part of the normal driver. Standard routing includes:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- all standardized SLH-DSA parameter sets
- HSS/LMS, XMSS, and XMSSMT
- direct, prehash, context, and hedged signing where the provider supports it
- KEM encapsulation and decapsulation
- signature-first verification
- authenticated wrapping

Example:

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

Routing prefers the standard PKCS #11 mechanism. A vendor module is asked for a
fallback only when the standard route is unavailable or the provider needs a
documented compatibility workaround.

## Raw access

Normal application code does not need to manage sessions directly. When you do
need an operation that is not modeled by the managed API, use
`WithRawSession`:

```go
err := client.WithRawSession(ctx, pkcs11.RawSessionOptions{
    ReadWrite:  true,
    Operation:  "custom-operation",
    Idempotent: false,
}, func(module *raw.Ctx, session raw.SessionHandle) error {
    return module.SeedRandom(session, []byte("seed"))
})
```

The module and session handle are valid only inside the callback. Do not save
them or start work that outlives the callback.

If you need the complete unmanaged Cryptoki API, use the `raw` package.

## Vendor modules

A `VendorModule` contains provider-specific behavior such as:

- module discovery hints and fingerprint matching
- proprietary mechanisms, key types, attributes, and parameter sets
- provider-specific login, session, and recovery behavior
- mechanism and template normalization
- unusual object models or operation sequences
- vendor conformance tests and simulator fixtures

Adding a provider should normally mean adding one provider package, not adding
vendor switches throughout the driver. See
[`docs/VENDOR_MODULES.md`](docs/VENDOR_MODULES.md) for the extension model.

## Module discovery

Production services should configure an explicit module path. Discovery is
mainly useful for setup tools and diagnostics.

```go
modules := []pkcs11.VendorModule{softhsm.NewV2()}

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

Only the vendor modules supplied by the caller contribute vendor-specific search
hints.

## Remote HSM access

The `proxy` package lets applications use a local HSM through a Go broker. The
application keeps using the same managed or raw APIs, while the broker owns the
physical HSM session pool.

```go
remote := proxy.RemoteModule(proxy.Target{
    ConfigID:          "key-storage-config-6f97",
    Revision:          "database-row-version-42",
    Endpoints:         []string{"pkcs11-proxy-0.pki.svc:9443", "pkcs11-proxy-1.pki.svc:9443"},
    Route:             "production-hsm-a",
    SecurityContextID: "pki-workload-mtls-v3",
    TLS:               clientTLS,
    Vendors:           []pkcs11.VendorModule{softhsm.NewV2()},
})

client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: remote,
    Token:  selector,
    Login:  pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
    PIN:    logicalActivationProvider,
})
```

In client-activated mode, the broker does not store the HSM PIN in its config.
One authorized client performs the physical login and concurrent callers wait
for that result. The PIN is discarded after the call. If physical login state
is lost, a client must activate the target again.

The broker also supports bounded queues, virtual sessions and handles,
active-active proxy replicas, OpenTelemetry, health endpoints, and a signed
audit log. See [`docs/PROXY.md`](docs/PROXY.md).

## Installing the proxy

GitHub releases include DEB, RPM, Arch, and Alpine packages for amd64 and arm64,
alongside the existing standalone binaries. Linux packages include a config and
a service that is enabled for boot but not started during installation. macOS
and Windows remain binary-only.

See [release packages](packaging/README.md) for installation, configuration,
upgrades, and removal.

## Public and private vendor builds

The public module and public proxy build do not require access to private vendor
source. Private integrations live in `github.com/otpki/pkcs11-private-vendors`.
Maintainer builds include that module when its submodule is present.

```sh
just build
# or

go run build.go
```

The binary is written to `dist/pkcs11-proxy` (`.exe` on Windows).

If `pkcs11-private-vendors/go.mod` is missing, the build uses only public
vendors. An empty, uninitialized submodule also counts as missing. If the
private module exists but is broken, the build fails instead of silently
falling back.

Run `pkcs11-proxy vendors` to see which vendor modules were compiled into a
binary.

## Native client for other applications

Applications that load a PKCS#11 shared library can use the small Rust client in
[`native/`](native/README.md). Releases include `.so`, `.dylib` and `.dll` builds
for amd64 and arm64. Linux packages also install the library and a separate
`/etc/pkcs11-proxy/client.yaml`. It connects to the proxy and does not load vendor
middleware locally. It exposes a PKCS#11 3.2 subset and keeps the older
2.40/3.0/3.1 interfaces for existing applications. See the native client guide for configuration and the
deliberately limited set of supported functions.

## More documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains the main package boundaries.
- [`docs/FEATURES.md`](docs/FEATURES.md) is the capability reference.
- [`docs/SECURITY.md`](docs/SECURITY.md) covers important trust and secret-handling rules.
- [`docs/VENDOR_MODULES.md`](docs/VENDOR_MODULES.md) explains vendor integrations.
- [`docs/PROXY.md`](docs/PROXY.md) covers the remote HSM proxy.
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) explains broker setup and tuning.
- [`examples/`](examples/) contains runnable examples.
- [`docs/cli/`](docs/cli/pkcs11-proxy.md) contains generated CLI documentation.
