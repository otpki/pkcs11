// Package pkcs11 provides a managed, token-oriented PKCS #11 3.2 client.
//
// Client handles module lifecycle, token selection, login, session pools,
// caching, recovery, algorithm routing, and the VendorModules supplied by the
// application. Most callers work with keys, signers, ciphers, KEMs, objects,
// certificates, and health checks instead of native session handles.
//
// Package raw exposes the full low-level Cryptoki API. Package proxy provides
// the same raw.Module interface over the network.
//
// Native calls use cgo by default when it is enabled. Supported no-cgo builds
// use the PureGo backend. The pkcs11_purego build tag can also force PureGo for
// backend parity tests.
//
//go:generate go run ./internal/cmd/gencalls
//go:generate go run ./internal/cmd/genconst
//go:generate go run ./internal/cmd/genproxy
package pkcs11
