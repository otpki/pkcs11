# Security

This package sits directly on a native cryptographic boundary. Most of the
important rules are simple, but they are worth making explicit.

## Found a security problem?

Please do not open a public issue. Report it privately through
[GitHub's vulnerability reporting](https://github.com/otpki/pkcs11/security/advisories/new)
so a fix can land before the details are public.

Tell us what you found, how to trigger it, and which side of the boundary it
sits on: the driver, the proxy, a vendor module, or a specific HSM. Crashes,
panics, and races in ordinary use are not usually security issues, a regular
issue is fine for those. When in doubt, report privately anyway. We would
rather read a few false alarms than miss a real one.

## Trust the native module

A PKCS #11 module is native code loaded into your process. It can create
threads, block forever, corrupt memory, or crash the process. Use explicit,
trusted module paths in production.

A `VendorModule` is also trusted Go code. It is not sandboxed. Only pass vendor
implementations you expect and have reviewed.

## cgo and PureGo have the same trust boundary

PureGo removes a C build dependency. It does not turn the PKCS #11 library into
safe Go code. Both backends call native function pointers in the same process.

The two backends share ABI encoding and PKCS #11 behavior. cgo keeps native
call buffers in C allocations. PureGo uses pinned byte buffers.

For pointer-bearing vendor parameters, prefer `NativeParameterMarshaler`.
`UnsafeParameter` leaves layout and lifetime management to the caller.

## Treat PINs as short-lived secrets

PIN providers return mutable `Secret` values. The driver clears the working
copies it controls after use, including pinned native credential buffers.

Go cannot guarantee that no old copy remains in runtime memory, logs, crash
dumps, or a caller-owned buffer. Prefer short-lived secrets from an external
secret manager and never place PINs in logs, test definitions, or diagnostics.

Built-in hooks do not record PINs, key material, plaintext, ciphertext, wrapped
keys, or mechanism parameters. Custom hooks and vendor modules should follow the
same rule.

## Raw callbacks are scoped

`WithRawSession` and `VendorSession.Call` expose native handles only during the
callback. Do not save those handles, use them after the callback, or move a
thread-affine session to another OS thread.

`raw.UnsafeParameter` is a lower-level escape hatch. The caller owns its memory,
layout, alignment, concurrency, lifetime, and secrecy rules.

## Recovery is not the same as replay

The driver may recover a broken session or module without repeating the failed
operation. Only operations explicitly marked replay-safe are retried.

Operations such as key generation, object mutation, unwrap, decapsulation, RNG
seeding, PIN changes, and stateful signatures are not blindly replayed after an
ambiguous failure.

A vendor module may request stronger recovery, but it cannot weaken a standard
recovery action.

## Key defaults and caches

Private and secret keys default to token-resident, private, sensitive, and
non-extractable. Applications may override those attributes, but then own the
resulting policy.

The default cache excludes secret values, private components, seed material,
stateful counters, and vendor-defined attributes. Mutating operations, raw
write callbacks, refresh, and recovery invalidate relevant caches.

## Proxy security boundary

With the network proxy, the broker and its local PKCS #11 middleware become part
of the HSM trust boundary. Production deployments should use mTLS or a custom
`ServerConfig.Authenticator` that returns a stable workload principal.

Authentication and authorization are separate:

- `ServerConfig.Authenticator` identifies the peer.
- `TargetConfig.Authorize` decides what that principal may do on a target.
- `LoginPolicy.Authenticate` can validate or audit logical login credentials.

Authorization callbacks never receive PINs, bearer credentials, key material,
or cryptographic payloads.

### Physical login modes

The proxy supports three sources for the physical HSM credential:

- **Server managed:** `LoginPolicy.PhysicalPIN` provides a fresh PIN when needed.
- **Client activated:** an authorized client supplies the PIN for activation.
- **Protected path:** the broker passes no PIN and relies on the HSM's trusted input path.

In client-activated mode, the server does not keep the PIN for later recovery.
Concurrent activation attempts are collapsed so only one PIN reaches the HSM.
When `VerifyClientPIN` is enabled, later clients are checked against an in-memory
HMAC of the accepted PIN, not by spending another HSM PIN attempt.

If physical login state is lost, the target returns
`proxy.ErrActivationRequired` until a client activates it again. Providers that
require a retained PIN for per-session login are not compatible with this mode.

Normal remote `C_Logout` only logs out the logical client. It does not call the
physical HSM's `C_Logout`, because that could affect other clients using the
same broker.

Token initialization, PIN administration, and SO operations require an explicit
`MaintenancePolicy` and exclusive maintenance access.

### Network retries

Non-idempotent requests keep the same request ID across transport retries. The
server keeps a bounded execution ledger so a reconnect can receive the original
result instead of repeating the HSM operation.

The replay fingerprint intentionally excludes secret values and payloads. If
the broker can no longer prove the original result, the client returns
`proxy.ErrOutcomeUnknown`. The caller must reconcile the operation instead of
blindly trying it again.

The proxy rejects native pointer images and `raw.UnsafeParameter`. Standard and
registered vendor parameters are sent as semantic values and marshaled for the
broker host's ABI.

Each active broker replica owns its own physical session budget and activation
state. Running several replicas against one HSM increases total HSM session use,
so size each replica's limits with the combined fleet in mind.
