// Package proxy exposes a local managed PKCS #11 target through a direct Go
// network broker.
//
// Client implements raw.Module, so both the low-level raw API and the managed
// pkcs11.Client API can use a remote target without a native proxy shared
// library, environment variables, or client-side configuration file. Target
// values are immutable and may be constructed directly from database records.
// A Client opens one TCP or TLS connection for one request and response and
// retains no socket between calls.
//
// Server is the authoritative owner of the finite HSM. It multiplexes virtual
// logical clients and sessions onto a bounded managed physical-session pool,
// applies queue backpressure, preserves multipart and session-object affinity,
// virtualizes object handles, separates transport authentication from target
// authorization, supports server-managed, client-activated, and protected-path
// physical login, retains a control session without retaining client-supplied
// PINs, avoids normal physical logout, and bounds replay data for ambiguous
// non-idempotent transport failures.
//
// Standard PKCS #11 mechanism parameters use architecture-independent semantic
// wire values. Vendor modules can contribute ParameterCodec implementations for
// proprietary pointer-bearing parameters; native ABI marshaling occurs only on
// the broker host. The generated client covers the complete raw.Module surface.
// Remote asynchronous sessions are intentionally unsupported because generic
// cross-request ownership of provider-retained pointers after CKR_PENDING cannot
// be proven safe.
//
// See the repository's PROXY.md for deployment, security, authentication, authorization, quota, login,
// configuration-rollout, retry, vendor-codec, observability, and testing
// guidance.
package proxy
