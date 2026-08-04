# Architecture

## Root responsibilities

A `Client` represents one selected token. It owns:

- shared native module initialization/finalization
- interface negotiation and token selection
- read-only and read/write session pools
- login coordination and protected authentication paths
- lifecycle locks, optional call serialization, and OS-thread affinity
- standard PKCS #11 3.2 routing and templates
- object lookup, cache invalidation, and durable locator recovery
- retry classification and rediscovery
- tracing, metrics, and audit hooks
- health/runtime validation.

The root API expresses application intent. `raw` expresses exact Cryptoki
calls. `VendorModule` is the only bridge for provider-specific behavior.

## Native ABI boundary

The raw package has one Cryptoki implementation and two build-selected native
transports:

```text
                         shared raw implementation
    module / info / session / object / crypto / key / message / 3.2
             explicit ABI layouts, marshalling, outputs, lifetimes
                                  |
                    generated function ID + uintptr arguments
                         /                         \
            cgo native transport            PureGo native transport
            p11x_open/close                  Dlopen/Dlsym/Dlclose
            calloc/free                     pinned byte blocks
            generated typed switch          purego.SyscallN
```

Selection remains automatic:

```text
CGO_ENABLED=1
    cgo transport, unless pkcs11_purego is forced

CGO_ENABLED=0, or -tags pkcs11_purego
    PureGo transport on supported targets
```

`raw.Ctx` exists once. All 104 base/3.0/3.2 methods, structure encoders,
nested-template handling, output-buffer behavior, and multipart mechanism
ownership are backend-neutral. Build-selected files are limited to native
loading, allocation, invocation, and any future callback transport.

Both transports use the pinned OASIS 3.2 headers as their authoritative source.
`internal/cmd/gencalls` emits one Go function inventory and one generic typed C
dispatcher. The cgo switch casts shared `uintptr` arguments to the exact OASIS C
types. PureGo installs the corresponding table addresses in the same generated
order.

The shared native arena writes identical explicit byte layouts for Unix LP64
and Windows LLP64/one-byte Cryptoki packing. With cgo, those byte images live in
C-owned `calloc` blocks. With PureGo, they live in byte-only Go blocks pinned for
the complete provider-visible lifetime. Secrets are cleared before release, and
multipart mechanism graphs remain retained until completion, cancellation,
session closure, finalization, or destruction.

Architecture tests reject backend-specific `Ctx` methods so the duplicate raw
operation surface cannot be reintroduced accidentally.

Neither transport sandboxes the native module. The module still runs in-process
and must match the target OS, architecture, data model, and native dependencies.
Fatal native faults, invalid function tables, and indefinitely blocked calls
remain outside portable Go recovery.

## Module lifecycle

Native libraries are deduplicated by canonical path. One process-wide
`moduleRef` coordinates:

```text
acquire module reference
    ↓
load library and select interface
    ↓
C_Initialize (OS locking preferred; documented legacy fallback)
    ↓
clients obtain operation leases and session handles
    ↓
last client closes pools
    ↓
C_Finalize when owned and safe
    ↓
unload library
```

Operation leases cover complete multipart operations, not merely individual C
calls. Reinitialization and unload cannot invalidate a session between
`C_SignInit` and `C_Sign`.

A module generation number invalidates pooled sessions and cached handles after
reinitialization, rediscovery, or refresh. Stale native handles are never
assumed portable between sessions or failover events.

## Vendor selection

The application supplies candidate implementations in `Config.Vendors`.
Selection uses only standard fingerprint information:

- canonical module path;
- selected interface name/version/flags;
- `CK_INFO`;
- `CK_SLOT_INFO`;
- `CK_TOKEN_INFO`; and
- mechanism inventory and mechanism information.

Each candidate owns its matching rules. The strongest match is selected;
otherwise the generic standards-only adapter is used. `StrictStandard` retains
the detected identity for diagnostics but disables provider behavior and
catalog aliases.

A vendor definition is immutable. The driver clones maps and slices before use,
and provider hooks receive defensive `Device`, `Route`, mechanism, and template
copies.

## Standard-first routing

For each high-level operation:

```text
Intent
    ↓
portable algorithm specification
    ↓
advertised standard mechanism available?
    ├── yes: build standard Route
    └── no: resolve selected vendor catalog alias
                    ↓
             VendorModule.AdaptRoute
    ↓
application policy + algorithm template
    ↓
VendorModule.NormalizeMechanism / NormalizeTemplate
    ↓
managed raw call
```

A vendor package may implement a custom operation hook only when the provider's
object model or call sequence cannot be represented by the generic path. The
`handled` return distinguishes “not mine” from a completed or failed custom
operation.

`Route.Execution` tells the root whether an adapted route requires read/write
sessions or forbids replay. `Route.VendorData` is opaque immutable state owned
by the selected module.

## Managed provider operations

Custom hooks receive `VendorSession`, not the session pool or a reusable raw
handle. It provides:

- the operation context and selected device;
- read/write state;
- durable object resolution;
- a scoped raw call preserving serialization, thread affinity, tracing, and
  lifetime protection;
- broken-session marking; and
- object-cache invalidation.

The raw context and handle supplied to `VendorSession.Call` are valid only
inside that callback.

## Discovery ownership

The root contains only generic environment variables and generic library
locations. Each `VendorDefinition.Discovery` supplies provider-specific:

- environment variable names;
- module basenames by `GOOS`; and
- conventional installation directories by `GOOS`.

`ModuleCandidates` considers only the vendor modules passed by the caller. This
keeps the trusted native loading surface explicit and makes out-of-tree modules
first-class.

