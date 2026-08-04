# Pinned Cryptoki C boundary

This directory contains the authoritative OASIS PKCS #11 3.2 C headers and the
small C portion of the default cgo transport. The public and shared raw
implementation lives in Go above this directory.

## Files

```text
oasis/3.2/
    pinned pkcs11.h, pkcs11f.h, and pkcs11t.h

platform.h
    declaration macros and Windows one-byte Cryptoki packing

bridge.h / bridge.c
    loader context, interface negotiation, version-safe table accessors

calls_gen.h
    generated generic typed dispatcher for all 104 function-table entries

loader_unix.c / loader_windows.c
    platform dynamic-loader implementations

abi_layout_test.c
    compile-time function-table layout assertions
```

The shared Go code passes a generated function ID and up to ten native scalar or
pointer arguments to `p11x_dispatch`. Each generated switch case selects the
correct base, 3.0, or 3.2 table type, validates the function pointer, casts every
argument to the type declared in `pkcs11f.h`, and invokes it.

There are intentionally no handwritten or generated per-operation cgo wrappers
used by Go. Cryptoki behavior, marshalling, output handling, and operation
lifetimes are implemented once in ordinary `raw/*.go` files.

## Generation

From the repository root:

```sh
go generate ./...
go run ./internal/cmd/gencalls -check
```

`gencalls` generates both:

```text
raw/function_table_gen.go
raw/internal/cryptoki/calls_gen.h
```

from the same pinned function inventory. `genconst` separately generates Go
constants and return-value names from `pkcs11t.h`.

## ABI validation

`raw/abi_layout_test.go` compares the shared explicit Go layouts with C
`sizeof`/`offsetof` probes. `abi_layout_test.c` verifies table extension and
packing assumptions, including forced Windows LLP64/one-byte packing builds.
