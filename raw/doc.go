// Package raw exposes the low-level PKCS #11 API through version 3.2.
// Callers work directly with slots, sessions, object handles, mechanisms, and
// attributes. The parent pkcs11 package adds the managed application API.
//
// Cryptoki behavior and ABI encoding are shared by both native backends. cgo is
// used by default when available. Supported no-cgo builds use PureGo.
//
// Native modules are trusted in-process code. A bad function table, blocked
// native call, or native crash cannot be recovered safely by Go.
//
// Prefer typed parameter values and NativeParameterMarshaler for custom native
// structures. UnsafeParameter leaves native memory layout and lifetime to the
// caller.
package raw
