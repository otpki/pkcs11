# Vendor module architecture

The root `pkcs11` package is intentionally vendor-neutral. It knows how to
manage a PKCS #11 module, select a token, pool and recover sessions, coordinate
login, build standard 3.2 routes, and execute high-level operations. It does not
import Utimaco, AWS, Thales, IBM, or any other provider package.

All provider-specific behavior enters through one compile-time plugin contract:

```go
pkcs11.VendorModule
```

A vendor module can live:

- in this repository under `vendors/<provider>`;
- in a separate public or private Go module; or
- directly in the consuming application.

The application explicitly chooses the modules it trusts:

```go
client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module: pkcs11.LocalModule(modulePath),
    Token:  pkcs11.TokenSelector{Label: "production"},
    PIN:    pinProvider,
    Vendors: []pkcs11.VendorModule{
        utimaco.New(),
        thales.NewLuna(),
    },
})
```

An empty `Vendors` slice is valid and gives standards-only PKCS #11 behavior.
The convenience package `vendors/all` is useful for diagnostic tools and broad
conformance runs, but production services should normally pass only the
providers they expect.

## Selection and operation flow

For each token-present slot, the driver performs this sequence:

```text
load and initialize the native PKCS #11 module
        ↓
collect standard CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, interface, path,
and mechanism information
        ↓
score only the VendorModule implementations supplied by the caller
        ↓
select the strongest match, or the generic standards-only fallback
        ↓
probe the selected module's finite proprietary mechanism catalog when needed
        ↓
derive standard capabilities and let the selected module augment them
        ↓
build a standard PKCS #11 3.2 route for each requested operation
        ↓
use the advertised standard route when available
        ↓ standard unavailable
ask the selected VendorModule to adapt the route
        ↓
normalize copied mechanisms/templates immediately before the raw ABI call
        ↓
execute through managed sessions, login, hooks, recovery, and cache rules
```

The root driver never searches a global registry and never imports a vendor
package for side effects. Two applications in the same process may supply
different candidate sets, although a native library still has one shared
process-wide initialization lifecycle.

## Choosing an implementation style

### Declarative modules

Use `vendorkit.New` or `vendorkit.MustNew` when the provider needs only static
metadata and low-level behavior facts:

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
        Source:   "Acme PKCS #11 SDK 4.2 public integration guide",
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
            LoginScope:   pkcs11.VendorLoginToken,
            NetworkBacked: true,
        },
		Conformance: pkcs11.VendorConformance{
			Notes: "requires an Acme HSM or licensed simulator",
        },
    })
}
```

`vendorkit.Module` embeds `VendorBase`, validates the definition at
construction, and returns defensive definition snapshots. It is safe to share
one instance among clients.

### Behavioral modules

Implement a type that embeds `pkcs11.VendorBase` when the provider needs custom
route, template, mechanism, object-model, or operation behavior:

```go
type Module struct {
    pkcs11.VendorBase
}

func New() pkcs11.VendorModule { return &Module{} }

func (*Module) Definition() pkcs11.VendorDefinition {
    return pkcs11.VendorDefinition{/* immutable static data */}
}

func (*Module) AdaptRoute(device pkcs11.Device, route pkcs11.Route) (pkcs11.Route, error) {
    // Leave an advertised standard mechanism untouched. Translate only a
    // documented fallback route owned by this provider.
    return route, nil
}
```

Embedding `VendorBase` is strongly recommended. It provides conservative no-op
implementations and allows the root interface to grow without forcing every
out-of-tree provider to add boilerplate methods immediately.

### Adding licensed identifiers without forking behavior

A consumer can decorate a shipped module exactly once during startup:

```go
module := vendorkit.MustDecorate(utimaco.New(), func(def *pkcs11.VendorDefinition) {
    def.Source = "licensed Utimaco SDK 6.4 header reviewed internally"
    if def.Catalog.Mechanisms == nil {
        def.Catalog.Mechanisms = make(map[string]pkcs11.NumericID)
    }
    def.Catalog.Mechanisms["company-approved-operation"] = 0x80001234
})

client, err := pkcs11.Open(ctx, pkcs11.Config{
    Module:  pkcs11.LocalModule(modulePath),
    Vendors: []pkcs11.VendorModule{module}, // do not also pass utimaco.New()
})
```

`Decorate` delegates every operational method to the base module and replaces
only its immutable definition. Use a normal module implementation when behavior
must change; definition decoration must not be used to hide operational logic.

## `VendorDefinition`

`Definition` is called during validation, discovery, sorting, and selection. It
must be cheap, deterministic, concurrency-safe, and immutable from the caller's
perspective. Use `pkcs11.CloneVendorDefinition` when returning a stored value.

### Identity and provenance

- `ID` is the stable machine identifier. Changing it breaks forced selection,
  preferred-family filters, tests, and persisted diagnostics.
- `Name` is the operator-facing default name. A custom matcher may return a more
  specific detected product name and variant.
- `Priority` is only a tie-breaker. Do not use a high priority to compensate for
  weak matching rules.
- `Source` identifies the public documentation, licensed SDK version, or
  independently derived interoperability evidence used by the implementation.

### Matching

`VendorMatchSpec` supports ordinary substring-based matching against standard
fingerprint fields:

- module, slot, and token manufacturer strings;
- library description;
- token model;
- slot description;
- canonical module path; and
- required mechanisms.

`MinimumTextMatches` prevents broad names such as `cryptoki.dll` from selecting
a provider on their own. `MatchAllText` requires every configured text category.

Use `MatchFunc` only when one provider package contains multiple product
variants or needs a relationship that declarative matching cannot express. A
custom matcher must be pure: it receives a defensive `Fingerprint`, must not
call the module, and must not mutate global state. Return `Variant` for stable
subproduct diagnostics rather than creating root-package conditionals.

`MatchVendorModule` exposes the same pure matching operation used by discovery.
Provider packages should use it in unit tests to prove that representative
fingerprints select the intended module without loading a native library:

```go
match, err := pkcs11.MatchVendorModule(acmehsm.New(), fingerprint)
if err != nil || !match.Matched {
    t.Fatalf("Acme fingerprint was not recognized: match=%#v err=%v", match, err)
}
```

The reusable `vendortest.Module` contract test synthesizes a fingerprint from
the declarative definition and also exercises `Definition` concurrently. Add
provider-specific table tests for product variants, firmware differences, and
ambiguous fingerprints.

### Discovery

`VendorDiscovery` owns all provider filenames and installation hints:

- `EnvironmentVariables` contains provider-specific module-path variables;
- `ModuleNames` maps `GOOS` to shared-library basenames; and
- `SearchDirectories` maps `GOOS` to conventional install directories.

The root package contains only generic variables (`PKCS11_MODULE`,
`PKCS11_MODULE_PATH`, and `CRYPTOKI_LIBRARY`) and generic library directories.
It never contains provider product names.

Discovery hints are finite and must point only to plausible module basenames.
The driver does not recursively load every shared library in a directory.
Production systems should still configure an explicit trusted module path.

### Catalog

`VendorCatalog` maps semantic aliases to proprietary numeric identifiers:

- mechanisms;
- key types;
- attributes; and
- parameter sets.

Aliases are normalized to lowercase. Generic aliases such as
`ml-dsa-key-pair-gen` are consumed by the standard-first router. Namespaced
aliases such as `acme-backup-key` can be used by diagnostics or a provider's
public helpers. Do not place parameter structure layouts in the catalog; use
typed encoders in the provider package.

`CatalogLevel` is diagnostic provenance:

- `standard-only`: no proprietary numeric ABI is compiled in;
- `public`: identifiers came from redistributable/public material or approved
  independently written interoperability code; and
- `vendor-sdk-required`: the package detects and supports standard behavior,
  but unpublished values must be supplied by a licensed/private module.

### Native parameter encoders

Vendor parameter encoders feed the one shared ABI marshaller. A cgo-enabled
build stores the resulting native byte image in C-owned memory; a no-cgo build
stores the same image in pinned Go memory and invokes it through PureGo.
Provider code must therefore describe the target Cryptoki ABI rather than
relying on Go struct layout or a cgo-only C type. In particular, it must not
assume that Go `uint` has the same width as `CK_ULONG` or that Windows uses Unix
LP64 alignment.

Use `raw.NativeParameterMarshaler` for pointer-bearing vendor records:

```go
type Parameters struct {
    Flags uint
    Data  []byte
}

func (p Parameters) MarshalPKCS11Native(
    abi raw.NativeABI,
) (raw.NativeParameterLayout, error) {
    builder := raw.NewNativeStructBuilder(abi)
    builder.AddULong(p.Flags)
    builder.AddPointer(p.Data)
    builder.AddULong(uint(len(p.Data)))
    return builder.Layout(), nil
}
```

`NativeStructBuilder` applies Unix LP64 or Windows LLP64/one-byte Cryptoki
packing and returns pointer relocations. The cgo backend materializes that
layout in C-owned memory; the PureGo backend copies and pins the root record and
every referenced byte slice. Both retain the completed parameter graph for the
full operation, including multipart operations whose provider may keep a
parameter pointer after `C_*Init` returns.

Use `raw.ParameterMarshaler` only for pointer-free records whose returned bytes
already have the correct target ABI representation. Use `raw.UnsafeParameter`
only when the caller owns native memory; it bypasses copying, pinning, alignment,
width conversion, cleanup, and secrecy handling.

Parameter encoders require golden byte/layout tests for Linux LP64 and Windows
LLP64. A provider with architecture-specific records should test every claimed
platform and should reject unsupported ABI combinations rather than guessing.

### Behavior

`VendorBehavior` contains provider implementation facts needed before an
operation hook runs. These are not application tuning knobs.

| Field | Use |
| --- | --- |
| `SerializeCalls` | Serialize all calls when the module is not safely concurrent. |
| `LegacyInitialize` | Use a nil `C_Initialize` argument when OS-locking initialization is rejected. |
| `SkipFinalize` | Avoid `C_Finalize` for a module known to make it unsafe. |
| `ForceSerialSessions` | Limit each pool to one session. |
| `LockSessionToOSThread` | Execute every call for one native session on one permanently locked thread. |
| `ReadWriteSessionsOnly` | Route read-only work through the read/write pool. |
| `MaxSessions` | Apply a provider cap below the token-advertised/default cap. |
| `LoginScope` | Select automatic, token-wide, or per-session login coordination. |
| `ProtectedPathOnEmptyPIN` | Permit empty PIN data for a protected authentication path. |
| `RejectNullOutputProbe` | Use bounded real-buffer growth when a module rejects PKCS #11 nil-output sizing probes. |
| `AllowUnadvertisedMechanism` | Permit only this module's documented catalog aliases when the token omits them from its mechanism list. |
| `NetworkBacked` | Enable conservative recovery classification for remote providers. |
| `GCMIVMode` / `GCMIVSize` | Describe caller-generated, parameter-returned, or ciphertext-prefixed GCM IVs. |

Add a behavior flag only when it changes generic lifecycle/session execution
before a provider hook can run. Prefer a narrowly scoped hook for algorithm or
object behavior.

Module-wide behavior is monotonic for a shared native library. If any selected
token requires call serialization, legacy initialization, skipped finalization,
or real-buffer output probing, that restriction is promoted to the process-wide
module registry entry and remains enabled until the library is unloaded. This
prevents one client selecting a less restrictive token from weakening another
client's safety requirements.

## Operational hooks

Every hook receives defensive copies of public data. A module must not retain
mutable references to a `Device`, `Route`, mechanism, template, or option slice.

### `AdaptRoute`

This runs after the generic router has attempted standard PKCS #11 3.2. Typical
uses are:

- replacing an unavailable standard ML-DSA mechanism with a proprietary one;
- encoding a vendor parameter record;
- selecting a nonstandard key type;
- omitting `CKA_PARAMETER_SET` because the parameter set is carried elsewhere;
- forcing a read/write session; and
- disabling replay for stateful or ambiguous operations.

Do not replace a usable standard route unless the provider has a documented
incompatibility and `PreferVendorIdentifiers` is justified. Record reasons in
`Route.Reasons` for diagnostics.

`Route.VendorData` is opaque module-owned state passed to later hooks. Keep it
immutable and small. The root driver never interprets it.

### `NormalizeMechanism`

This is the final mechanism boundary before `raw`. Use it for provider ABI
translation that is independent of higher-level algorithm selection, such as:

- replacing standard AES-GCM with a vendor GCM mechanism;
- validating an OAEP restriction; or
- allocating a correctly shaped typed parameter.

Return a copy. Never mutate the caller's mechanism or pointed-to slices.

### `NormalizeTemplate`

This is the final object template boundary. Use it for documented differences
such as:

- removing attributes a cloud provider rejects;
- mirroring a standard parameter set into a proprietary attribute;
- translating KEM usage attributes into `CKA_DERIVE`; or
- returning an intentionally empty public template.

The root validates algorithm invariants before this point. A module must not
silently change the requested object class or key algorithm.

### `ClassifyError`

The root first computes a conservative standard `RecoveryAction`. A module may
strengthen it, for example from no recovery to session replacement for a known
network error. It must never weaken a non-zero standard action. Error
classification and operation replay are separate: recovery can repair the pool
while a non-idempotent operation still returns its original error.

### Object discovery and inference

`ObjectAttributes` declares proprietary attributes required to identify keys.
The root requests them with standard metadata. Unsupported and sensitive
attributes are tolerated according to PKCS #11 partial-read behavior.

`InferAlgorithm` receives all collected metadata and can map proprietary key
types/encodings to a public `Algorithm`. Return `false` when the evidence is
insufficient; never guess between parameter sets.

`KeyPairModel` describes exceptional logical models. `SingleObject` allows a
stateful provider object to represent both public and private halves while the
application still uses `KeyPair`.

### Custom operation hooks

`GenerateSecretKey`, `GenerateKeyPair`, `LoadPublicKey`, `Sign`, `Verify`,
`Encapsulate`, and `Decapsulate` return a `handled` result. Return
`handled=false, err=nil` to use the generic path. Return `handled=true` whenever
the module attempted or definitively owns the operation, including on error.

Use custom hooks only when the operation cannot be expressed as the standard
sequence. Ordinary proprietary mechanism numbers usually need only
`AdaptRoute`, `NormalizeMechanism`, and `NormalizeTemplate`.

### `VendorSession`

Custom hooks receive a `VendorSession`, not a public session handle. It provides:

- the operation context and current device snapshot;
- read/write state;
- `Resolve` for durable object lookup;
- `Call` for exact raw operations while preserving module serialization,
  OS-thread affinity, hooks, and lifetime protection;
- `MarkBroken` when the native session cannot be reused; and
- `InvalidateObjects` after an opaque mutation.

The `raw.Ctx` and `raw.SessionHandle` passed to `Call` are valid only during the
callback. Do not store them, start a goroutine that outlives the callback, or
call the module directly from a different thread.

### `FinalizeEncryption`

Use this only to translate provider output conventions after successful
encryption, such as suppressing a separate IV when the provider prefixes it to
the ciphertext.

### `AugmentCapabilities`

The root derives capabilities from standard and catalog mechanisms first. A
module can then add high-level operations implemented through an exceptional
contract, such as derive-based KEM. It must not mark an operation supported
without concrete live mechanism evidence.

## Provider package layout

A full provider is easiest to maintain when every provider-owned artifact lives
together:

```text
vendors/acme/
    doc.go or package comment
    module.go                 VendorModule implementation
    constants.go              public/licensed numeric ABI facts
    params.go                 typed parameter encoders
    module_test.go            matching, route, template, error tests
    params_test.go            byte-exact ABI vectors
    module_contract_test.go   vendortest.Module(t, New())
    README.md                 setup, behavior, support, update process
    conformance/
        profile.go            Go-native profile built from HardwareMatrix
        integration_test.go   runs cases as standard Go subtests
        suite.go              namespaced custom cases, only when required
        fixture.go            optional simulator/container preparation
        docker-*/             provider-owned runtime recipes
```

The root package must not import this directory. `vendor_separation_test.go`
enforces the boundary.

## Required tests for a shipped module

Every module in this repository must have all of the following.

### Static contract test

```go
func TestModuleContract(t *testing.T) {
    vendortest.Module(t, New())
}
```

The reusable test validates definition stability, defensive copies, discovery
hygiene, matching, provenance, and conformance metadata. Provider-local profile
tests validate Go-native suites, expected adapter IDs, and matrix completeness.

### Matching tests

Test positive and negative fingerprints, ambiguous neighboring providers,
redacted metadata, platform paths, and every variant name returned by a custom
matcher.

### Route and ABI tests

For each proprietary feature, test:

- standard mechanism wins when advertised;
- vendor fallback is selected only when needed;
- required mechanism flags and missing-mechanism errors;
- exact parameter bytes or native layout on LP64 and LLP64 where applicable;
- template input is not mutated;
- resulting template contains only documented translations;
- replay/read-write requirements; and
- capability augmentation.

### Operation tests

Use a fake `VendorSession` to exercise custom object lifecycles, cleanup errors,
stable locator use, broken-session marking, and cache invalidation without
hardware.

### Conformance tests

Providers with an executable runtime define a Go profile from
`conformance.HardwareMatrix`, then call `conformance.Test` from an integration
test. Classify each case as:

- `required`: part of the support contract and must pass;
- `optional`: genuinely capability-dependent, but malformed behavior still
  fails;
- `forbidden`: the provider must reject the operation; or
- `disabled`: documented future/destructive/parameter-dependent coverage.

Hardware-only providers record their prerequisites in `VendorConformance` but
do not copy an unexecuted matrix into the repository. Promote cases to required
only after running the exact client, model, firmware, policy, and configuration.

### Vendor-specific conformance cases

Portable high-level behavior must use the central case kinds. Add a
`conformance.CaseExtension` only for a proprietary ABI diagnostic or operation
that cannot be expressed portably. Kinds must be namespaced, for example:

```text
vendor:acme:backup-key
```

Keep the extension beside the provider package and opt into it from the native
integration test:

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, Profile(),
        conformance.WithVendorModules(acme.New()),
        conformance.WithCaseExtensions(acmeconformance.New()),
    )
}
```

## Proxy parameter codecs

A vendor parameter that already uses a semantic byte encoding needs no extra
proxy support. A pointer-free `raw.ParameterMarshaler` can also cross the wire
as opaque bytes. Pointer-bearing `raw.NativeParameterMarshaler` values must be
paired with a `proxy.ParameterCodec` that transports logical fields and rebuilds
the native layout on the HSM host.

In-tree vendor modules may implement `proxy.VendorCodecProvider`; their codecs
are merged automatically into `proxy.Target` and `proxy.TargetConfig`. Codec ID
and version are protocol contracts: change the version whenever payload meaning
changes, and test a deliberate client/server mismatch. Never encode client-side
pointers or platform-sized native structure images. See `PROXY.md`.
