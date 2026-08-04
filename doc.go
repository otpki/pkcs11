//go:generate go run ./internal/cmd/gencalls
//go:generate go run ./internal/cmd/genconst
//go:generate go run ./internal/cmd/genproxy

// Package pkcs11 provides a managed, token-oriented PKCS #11 client through
// version 3.2.
//
// Client owns native module lifecycle, token selection, login, internal session
// pools, caches, retries, recovery, algorithm routing, and automatic selection
// among the HSM VendorModule implementations supplied by the application.
// Standard operations are expressed as key, signer, cipher, KEM,
// object, certificate, and health methods rather than session-handle calls.
//
// Native calls use the generated cgo bridge by default when cgo is enabled.
// When cgo is disabled, the same public API automatically falls back to an
// Ebitengine PureGo backend on supported platforms. The pkcs11_purego build tag
// can force that fallback for parity testing.
//
// Package raw exposes the complete unmanaged Cryptoki ABI. WithRawModule,
// WithRawSession, and RawSessionLease are explicit infrastructure escape hatches
// that preserve the managed lifecycle while allowing exact raw calls.
// Proprietary identifiers and typed parameter helpers live in vendors/<vendor>
// packages.
//
// Package proxy provides a direct Go remote raw.Module and a bounded broker for
// exposing local HSMs to stateless applications without a native proxy shim.
package pkcs11
