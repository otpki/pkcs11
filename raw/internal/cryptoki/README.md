# Pinned Cryptoki C boundary

This directory contains the pinned OASIS PKCS #11 3.2 C headers and the small C
layer used by the default cgo backend. The actual PKCS #11 behavior lives in the
shared Go implementation under `raw/`.

## Files

```text
oasis/3.2/
    pinned pkcs11.h, pkcs11f.h, and pkcs11t.h

platform.h
    declaration helpers and Windows Cryptoki packing

bridge.h / bridge.c
    module loading, interface selection, and table access

calls_gen.h
    generated dispatcher for the PKCS #11 function table

loader_unix.c / loader_windows.c
    platform-specific dynamic loading

abi_layout_test.c
    compile-time ABI and table layout checks
```

The Go code passes a generated function ID plus native arguments to
`p11x_dispatch`. The generated C switch selects the correct function-table type,
checks the function pointer, casts the arguments using the pinned headers, and
calls the provider.

There are no per-operation cgo wrappers. Marshalling, output handling, and
operation lifetimes are implemented once in Go and shared with the PureGo
backend.

## Generation

From the repository root:

```sh
go generate ./...
go run ./internal/cmd/gencalls -check
```

`gencalls` generates:

```text
raw/function_table_gen.go
raw/internal/cryptoki/calls_gen.h
```

`genconst` separately generates Go constants and return-value names from
`pkcs11t.h`.

## ABI validation

`raw/abi_layout_test.go` compares the Go layouts with C `sizeof` and `offsetof`
probes. `abi_layout_test.c` checks function-table extension and packing rules,
including Windows LLP64 and one-byte Cryptoki packing.
