# Vendor modules

The root `pkcs11` package is vendor-neutral. Provider-specific behavior enters
through one interface:

```go
pkcs11.VendorModule
```

A vendor module can live in this repository, in another Go module, or directly
in an application. The application decides which modules it trusts:

```go
client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: pkcs11.LocalModule(modulePath),
    Token:  pkcs11.TokenSelector{Label: "production"},
    PIN:    pinProvider,
    Vendors: []pkcs11.VendorModule{
        softhsm.NewV2(),
        yubihsm.New(),
    },
})
```

An empty `Vendors` slice is valid and gives standards-only behavior.

For production services, prefer the smallest vendor set you actually need.
`vendors/all` is mainly useful for diagnostics and broad conformance runs.

## How a vendor is selected

The driver follows this flow:

```text
load PKCS #11 module
    ↓
read standard module, slot, token, interface, and mechanism data
    ↓
ask only the caller-supplied VendorModules to match that fingerprint
    ↓
select the strongest match, or use standards-only behavior
    ↓
prefer standard PKCS #11 routes
    ↓
ask the selected vendor module for a fallback when needed
    ↓
normalize the final mechanism and template
    ↓
run through the normal managed session, login, and recovery path
```

There is no global vendor registry and no side-effect import mechanism.

## Two implementation styles

### Declarative modules

Use `vendorkit.New` or `vendorkit.MustNew` when the integration is mostly static
metadata and behavior flags:

```go
package acmehsm

import (
    pkcs11 "github.com/otpki/pkcs11"
    "github.com/otpki/pkcs11/vendorkit"
)

const ID pkcs11.AdapterFamily = "acme-hsm"

func New() pkcs11.VendorModule {
    return vendorkit.MustNew(pkcs11.VendorDefinition{
        ID:       ID,
        Name:     "Acme HSM",
        Priority: 100,
        Source:   "Acme PKCS #11 SDK 4.2 integration guide",
        Match: pkcs11.VendorMatchSpec{
            Manufacturers:      []string{"acme"},
            Models:             []string{"acme hsm"},
            ModulePaths:        []string{"acmepkcs11"},
            MinimumTextMatches: 1,
        },
        Discovery: pkcs11.VendorDiscovery{
            EnvironmentVariables: []string{"ACME_PKCS11_MODULE"},
            ModuleNames: map[string][]string{
                "linux":   {"libacmepkcs11.so"},
                "darwin":  {"libacmepkcs11.dylib"},
                "windows": {"acmepkcs11.dll"},
            },
        },
        Behavior: pkcs11.VendorBehavior{
            LoginScope:    pkcs11.VendorLoginToken,
            NetworkBacked: true,
        },
        Conformance: pkcs11.VendorConformance{
            Notes: "requires an Acme HSM or licensed simulator",
        },
    })
}
```

`vendorkit.Module` validates the definition and returns defensive copies. One
instance can be shared across clients.

### Behavioral modules

Embed `pkcs11.VendorBase` when the provider needs custom routing or operations:

```go
type Module struct {
    pkcs11.VendorBase
}

func New() pkcs11.VendorModule { return &Module{} }

func (*Module) Definition() pkcs11.VendorDefinition {
    return pkcs11.VendorDefinition{/* immutable static data */}
}

func (*Module) AdaptRoute(device pkcs11.Device, route pkcs11.Route) (pkcs11.Route, error) {
    // Keep a working standard route. Only translate documented fallbacks.
    return route, nil
}
```

`VendorBase` supplies conservative no-op behavior, so an out-of-tree module only
needs to implement the hooks it actually uses.

## Decorating an existing module

If you only need to add deployment-specific identifiers, decorate an existing
module instead of forking all of its behavior:

```go
module := vendorkit.MustDecorate(softhsm.NewV2(), func(def *pkcs11.VendorDefinition) {
    def.Source = "deployment-specific vendor catalog"
    if def.Catalog.Mechanisms == nil {
        def.Catalog.Mechanisms = make(map[string]pkcs11.NumericID)
    }
    def.Catalog.Mechanisms["company-approved-operation"] = 0x80001234
})
```

Decoration changes only the immutable definition. If runtime behavior changes,
write a real module implementation.

## `VendorDefinition`

`Definition` is called during validation, discovery, sorting, and selection. It
must be fast, deterministic, concurrency-safe, and immutable from the caller's
point of view.

If you store one definition internally, return it through
`pkcs11.CloneVendorDefinition`.

### Identity

- `ID` is the stable machine identifier. Avoid changing it after release.
- `Name` is the normal human-readable name.
- `Priority` breaks ties. It should not compensate for weak matching rules.
- `Source` records where the provider-specific facts came from.

`Source` may point to public documentation, a licensed SDK version, or other
reviewed interoperability evidence.

### Matching

`VendorMatchSpec` can match standard fingerprint fields such as:

- module, slot, and token manufacturer
- library description
- token model
- slot description
- canonical module path
- required mechanisms

`MinimumTextMatches` helps avoid weak matches from generic names such as
`cryptoki.dll`. `MatchAllText` requires all configured text categories.

Use `MatchFunc` only when simple matching is not enough. A custom matcher should
be pure. It receives a copied fingerprint, must not call the native module, and
must not mutate global state.

Use `Variant` for stable subproduct names instead of adding provider-specific
conditionals to the root package.

You can test matching without opening a native library:

```go
match, err := pkcs11.MatchVendorModule(acmehsm.New(), fingerprint)
if err != nil || !match.Matched {
    t.Fatalf("Acme fingerprint was not recognized: match=%#v err=%v", match, err)
}
```

`vendortest.Module` also exercises definition stability and matching behavior.

### Discovery

`VendorDiscovery` owns provider-specific module search hints:

- `EnvironmentVariables`
- `ModuleNames` by operating system
- `SearchDirectories` by operating system

The root package only knows generic variables such as `PKCS11_MODULE` and
generic library locations.

Keep discovery finite. Do not recursively load arbitrary shared libraries from a
filesystem. Production services should still use an explicit trusted module
path when possible.

### Catalog

`VendorCatalog` maps human-readable aliases to proprietary numeric IDs for:

- mechanisms
- key types
- attributes
- parameter sets

Aliases are normalized to lowercase.

Keep native structure layouts out of the catalog. Typed parameter encoders
belong in provider code.

`CatalogLevel` records where proprietary ABI facts came from:

- `standard-only` means no proprietary values are compiled in
- `public` means the values came from redistributable material or approved interoperability work
- `vendor-sdk-required` means private or licensed data is still needed

### Native parameters

For pointer-bearing native records, implement `raw.NativeParameterMarshaler`
and use `raw.NativeStructBuilder`. Describe the target Cryptoki layout instead
of casting Go structs directly.

The shared raw marshaller handles LP64 and Windows LLP64 layouts and keeps
referenced memory alive for the call.

For pointer-free records, `raw.ParameterMarshaler` may be enough.
`raw.UnsafeParameter` should be a last resort.

### Behavior flags

`VendorBehavior` describes provider-wide facts that affect the generic driver,
such as:

- login scope
- whether the provider is network-backed
- module-wide call serialization
- OS-thread affinity
- legacy initialization behavior
- output-buffer behavior
- GCM conventions
- recovery constraints

Prefer these declarative flags when they accurately describe the provider. Use
custom hooks only for behavior that cannot be represented this way.

## Runtime hooks

### `AdaptRoute`

`AdaptRoute` runs after the generic router has tried the standard PKCS #11 path.
Use it for things such as:

- replacing an unavailable standard mechanism with a vendor mechanism
- selecting a proprietary key type
- adding a typed vendor parameter
- changing template expectations
- requiring a read/write session
- disabling replay for a stateful operation

Do not replace a working standard route without a documented reason.

`Route.VendorData` can carry small immutable provider-owned state to later hooks.
The root package does not interpret it.

### `NormalizeMechanism`

This is the last mechanism hook before the raw ABI call. Use it for low-level
provider translation that is independent of the high-level algorithm decision.

Examples include replacing a standard GCM mechanism with a provider mechanism
or validating a provider-specific OAEP restriction.

Return a copy. Do not mutate caller-owned values.

### `NormalizeTemplate`

This is the last object-template hook before the raw call. It is a good place to
handle documented provider differences such as:

- removing an unsupported attribute
- copying a parameter set into a proprietary attribute
- mapping a KEM usage flag to `CKA_DERIVE`

The root driver checks algorithm invariants before this hook. Do not silently
change the requested object class or key algorithm.

### `TranslateError`

Use `TranslateError` when a provider reports a standard condition through a
vendor-defined return value.

For example, a vendor-specific "not logged in" error should become
`CKR_USER_NOT_LOGGED_IN` so the normal login and recovery logic can react to it.

Use `pkcs11.TranslateVendorError` to keep the original vendor error available
for diagnostics while exposing the standard result to normal callers.

If a vendor error has no standard equivalent, return it unchanged.

### `ClassifyError`

The root driver first calculates a conservative recovery action. A vendor module
may strengthen that action for a known provider-specific failure.

It must not weaken an existing standard action.

Recovery and replay are separate. Fixing the session pool does not mean a failed
mutation is safe to run again.

### Object metadata

`ObjectAttributes` lists proprietary attributes needed for discovery or
algorithm inference.

`InferAlgorithm` can map proprietary object metadata to a public `Algorithm`.
Return `false` when the evidence is not strong enough.

`KeyPairModel` describes providers with unusual object models. For example,
`SingleObject` can represent a stateful signing key whose public and private
halves are one resident object.

### Custom operations

The custom operation hooks include:

- `GenerateSecretKey`
- `GenerateKeyPair`
- `LoadPublicKey`
- `Sign`
- `Verify`
- `Encapsulate`
- `Decapsulate`

They return a `handled` value. Return `handled=false, err=nil` to fall back to
the generic path.

Use these hooks only when the normal mechanism and template pipeline cannot
represent the provider's required sequence or object model.

### `VendorSession`

Custom operations receive a `VendorSession`, not a long-lived native handle. It
provides:

- the operation context and current device
- read/write state
- durable object resolution
- scoped raw calls
- broken-session marking
- object-cache invalidation

The `raw.Ctx` and session handle passed to `VendorSession.Call` are valid only
inside that callback. Do not store them or use them from a goroutine that
outlives the call.

### `FinalizeEncryption`

Use this for provider-specific output formatting after a successful encryption.
For example, a provider may prepend a generated IV to the ciphertext instead of
returning it separately.

### `AugmentCapabilities`

The root derives capabilities from live mechanisms first. A vendor can then add
high-level operations that are implemented through a provider-specific path.

Do not advertise a capability without real mechanism or provider evidence.

## Suggested provider layout

A full provider is easier to maintain when its implementation, tests, and
fixtures stay together:

```text
vendors/acme/
    module.go
    constants.go
    params.go
    module_test.go
    params_test.go
    module_contract_test.go
    README.md
    conformance/
        profile.go
        integration_test.go
        suite.go
        fixture.go
        docker-*/
```

The root package must not import provider packages. The repository has tests that
check this boundary.

## Tests for a shipped module

### Contract test

Every provider should run the shared contract test:

```go
func TestModuleContract(t *testing.T) {
    vendortest.Module(t, New())
}
```

It checks definition stability, defensive copies, discovery hygiene, matching,
provenance, and conformance metadata.

### Matching tests

Cover positive and negative fingerprints, neighboring providers, platform
paths, missing metadata, and every product variant returned by custom matching.

### Routing and ABI tests

For each proprietary feature, check that:

- a usable standard mechanism still wins
- the vendor fallback is chosen only when needed
- required mechanism flags are enforced
- native parameter bytes or layouts are exact
- caller templates are not mutated
- translated templates contain only documented changes
- read/write and replay requirements are correct
- capability augmentation matches the real implementation

Where relevant, test both LP64 and LLP64 layouts.

### Operation tests

Use a fake `VendorSession` to exercise custom lifecycle behavior without an HSM.
Include cleanup paths, object resolution, broken-session handling, and cache
invalidation.

### Conformance tests

Providers with an executable runtime should build a profile from
`conformance.HardwareMatrix` and call `conformance.Test` from an integration
test.

Cases are classified as:

- `required` for supported behavior that must pass
- `optional` for capability-dependent behavior
- `forbidden` for behavior the provider must reject
- `disabled` for intentionally untested or future coverage

Do not mark a hardware feature required until it has been run against the exact
provider version and configuration you claim to support.

### Vendor-specific conformance cases

Use the shared portable case kinds whenever possible. Add a
`conformance.CaseExtension` only for proprietary behavior that cannot be
expressed by the common suite.

Namespace custom kinds, for example:

```text
vendor:acme:backup-key
```

## Proxy parameter codecs

Pointer-free or already-semantic vendor parameters may cross the proxy without
extra work.

Pointer-bearing `raw.NativeParameterMarshaler` values need a
`proxy.ParameterCodec`. The codec sends logical fields over the network and
rebuilds the native structure on the HSM host.

In-tree vendor modules can implement `proxy.VendorCodecProvider` so their codecs
are added automatically to client and server configuration.

Codec ID and version are protocol contracts. Bump the version when the payload
meaning changes, and test client/server mismatch behavior.

Never send client-side pointers or platform-sized native structure images over
the network. See [`PROXY.md`](PROXY.md) for the proxy design.
