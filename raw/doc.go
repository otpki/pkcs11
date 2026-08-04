// Package raw exposes the complete low-level PKCS #11 API through version 3.2.
// It is intentionally close to Cryptoki: callers work with slots, sessions,
// object handles, mechanisms, attributes, and explicit operation ordering.
// The parent pkcs11 package adds token selection, managed sessions, login,
// caching, retries, vendor routing, crypto.Signer, and other application-level
// abstractions.
//
// Cryptoki semantics are implemented once. Build-selected native transports are
// limited to library/interface loading, provider-visible allocation, and typed
// function-pointer invocation. cgo is the default when enabled; disabling cgo
// selects the Ebitengine PureGo transport on supported platforms. The
// pkcs11_purego build tag forces PureGo for parity testing.
//
// Both transports use the same explicit ABI layouts, attribute and mechanism
// encoders, output-buffer limits, and multipart lifetime manager. The cgo
// transport stores native byte images in C-owned memory; PureGo stores them in
// pinned byte-only Go blocks.
//
// Native modules are trusted code in the process. Destroy must not race with
// calls; Ctx enforces this for calls made through the same value, while the
// managed parent package additionally coordinates process-wide module sharing.
// Fatal native faults, invalid function tables, and indefinitely blocked calls
// cannot be recovered portably.
//
// Standard mechanism parameters are represented by typed Go values. Vendor
// packages should prefer NativeParameterMarshaler and NativeStructBuilder for
// pointer-bearing ABI records. UnsafeParameter bypasses layout and lifetime
// management and should be used only when the caller owns suitable native
// memory for the complete operation.
package raw
