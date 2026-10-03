# Architecture

This document explains the main boundaries in the repository. Start here if you
are trying to decide where a change belongs.

## Main packages

The packages have different jobs:

- `pkcs11` is the managed, token-oriented API used by most applications.
- `raw` maps closely to Cryptoki and exposes the full PKCS #11 3.2 API.
- `proxy` implements `raw.Module` over the network.
- `vendors/<provider>` contains provider-specific behavior.
- `vendorkit` and `vendortest` help build and test vendor modules.

A useful rule is: application intent belongs in `pkcs11`, exact PKCS #11 calls
belong in `raw`, and provider quirks belong in a `VendorModule`.

## What `Client` owns

A `Client` represents one selected token. It manages:

- native module lifecycle
- interface and token selection
- read-only and read/write session pools
- login and protected authentication paths
- module and session locking
- optional OS-thread affinity
- algorithm and template routing
- object lookup and caching
- retries, recovery, and rediscovery
- health, tracing, metrics, and audit hooks

Applications usually work with keys, signers, ciphers, KEMs, certificates, and
objects instead of native session handles.

## Native ABI layer

The `raw` package implements Cryptoki once and has two native call backends:

```text
                    raw PKCS #11 implementation
                ABI encoding and lifetime handling
                              |
                 generated function invocation
                    /                     \
               cgo backend           PureGo backend
```

With cgo enabled, the cgo backend is the default. With cgo disabled, or with the
`pkcs11_purego` build tag, supported platforms use Ebitengine PureGo.

Both paths use the same generated function inventory and the same explicit ABI
layouts. The main difference is where native-call memory lives and how the
function pointer is invoked.

The module still runs as native code inside the process. PureGo does not sandbox
it or make an incompatible vendor library portable.

## Module lifecycle

Native libraries are shared by canonical path. The process keeps one module
reference and coordinates initialization and finalization around it:

```text
load library
    ↓
select interface
    ↓
C_Initialize
    ↓
clients use sessions and operations
    ↓
last client closes
    ↓
C_Finalize when safe
    ↓
unload library
```

Operation leases cover the full lifetime of multipart operations. The module
cannot be reinitialized or unloaded between calls such as `C_SignInit` and
`C_Sign`.

A generation number invalidates pooled sessions and cached native handles after
module reinitialization, token refresh, or rediscovery. Native handles are never
assumed to remain valid across those events.

## Vendor selection

The application passes its allowed vendor modules in `Config.Vendors`. The
driver builds a standard fingerprint from the module, slot, token, interface,
and mechanism information, then asks those modules to match it.

The strongest match wins. If nothing matches, the driver uses the generic
standards-only behavior. `StrictStandard` keeps the detected identity for
diagnostics but disables vendor-specific behavior.

Vendor definitions are treated as immutable. The driver copies maps, slices,
mechanisms, templates, and device data before handing them to vendor hooks.

## Operation routing

High-level operations use a standard-first path:

```text
application intent
    ↓
portable algorithm route
    ↓
standard mechanism available? ── yes ──> use it
    |
    no
    ↓
ask the selected vendor module for a fallback
    ↓
normalize mechanism and template
    ↓
run through a managed session
```

A vendor hook should only replace the generic operation when the provider's
object model or call sequence cannot be represented by the normal path.

`Route.Execution` carries important execution rules, such as whether the
operation needs a read/write session or must not be replayed.

## Vendor operations

Custom provider operations receive a `VendorSession`. They do not get the
session pool itself or a reusable native handle.

`VendorSession` provides:

- the current context and device
- read/write state
- durable object resolution
- scoped raw calls with the normal locking and hooks
- broken-session marking
- object-cache invalidation

The raw module and session passed to `VendorSession.Call` exist only for that
callback.

## Discovery

The root package knows only generic environment variables and generic library
locations. Provider-specific filenames and install locations belong in
`VendorDefinition.Discovery`.

`ModuleCandidates` only uses hints from vendor modules the caller supplied. This
keeps native library loading explicit and lets private or out-of-tree providers
work the same way as in-tree providers.
