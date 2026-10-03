// Package proxy exposes a local PKCS #11 target through a Go network broker.
//
// Client implements raw.Module, so both the raw API and the managed pkcs11
// client can use a remote HSM without a native proxy library. Each request uses
// its own TCP or TLS connection.
//
// Server owns the physical HSM session budget. It provides virtual sessions and
// handles, bounded queueing, multipart affinity, logical login, physical login
// coordination, request deduplication, and target fencing.
//
// Standard and vendor parameters cross the network as semantic values and are
// marshaled for the broker host ABI. Remote asynchronous sessions are not
// supported because provider-owned pointer lifetimes cannot be safely carried
// across requests.
//
// See docs/PROXY.md for deployment and protocol details.
package proxy
