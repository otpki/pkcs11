# Security

## Native library trust

A PKCS #11 module is native code loaded into the process. It can execute
constructors, create threads, block indefinitely, corrupt memory, or terminate
the process. Configure explicit trusted paths in production.

A `VendorModule` is also trusted executable Go code. It receives defensive
metadata copies and scoped access to managed sessions, but it is not sandboxed.
Applications should pass only provider implementations they review and expect.

## Native transports and memory

Selecting PureGo instead of cgo removes a build dependency, it does not turn the
PKCS #11 module into safe Go code. Both transports call native function pointers
in the same process. A malformed function table, invalid pointer, blocking
middleware call, or native `SIGSEGV`/`SIGILL` can still terminate or compromise
the process.

Cryptoki semantics and ABI encoding are shared. The cgo transport places the
encoded byte graphs in C-owned allocations, the PureGo transport places the same
layouts in byte-only Go blocks pinned with `runtime.Pinner`. 

Typed vendor parameters should use `NativeParameterMarshaler`.
`UnsafeParameter` remains entirely caller-owned under either transport. The
driver intentionally supplies no abi-to-Go mutex or session-notification
callbacks.

## Secret handling

PIN providers return mutable `Secret` buffers. The driver destroys its working
copies after authentication and clears pinned native credential buffers before
unpinning them. Go cannot guarantee that compilers, runtimes, logs, crash dumps,
or prior copies contain no remnants. Prefer short-lived secrets from an
external secret manager and never put PINs in test definitions or diagnostics.

Hooks and reports intentionally omit plaintext, ciphertext, wrapped keys,
mechanism parameters, PINs, and key material. Provider modules and custom hooks
must preserve this rule.

## Raw and vendor callbacks

`WithRawSession` and `VendorSession.Call` expose a native module and session
handle only for the callback lifetime. Never retain them, call from a goroutine
that outlives the callback, or move a thread-affine session to another OS
thread.

`raw.UnsafeParameter` transfers allocation, layout, lifetime, alignment,
thread-safety, and secrecy responsibility to the caller.

## Retries

Recovery does not imply replay. Only operations explicitly classified as safe
are repeated. Key generation, mutation, unwrap, decapsulation, RNG seeding, and
stateful signatures are not blindly replayed after ambiguous failures. A vendor
module may strengthen recovery but cannot weaken a non-zero standard action.

## Key policy and caching

Private and secret keys default to token-resident, private, sensitive, and
non-extractable. Applications can override attributes and remain responsible
for their policy.

The default cache excludes secret values, private components, seed material,
stateful counters, and vendor-defined attributes. Caches are invalidated after
mutations, raw write callbacks, refresh, and recovery.

## Network proxy security boundary

The direct Go proxy makes the broker and its local PKCS #11 middleware part of
the HSM trust boundary. Production deployments should use mutually
authenticated TLS or a `ServerConfig.Authenticator` that returns a stable
principal. A logical client ID is bound to that principal for its lifetime.
request IDs and retained responses are also principal-scoped.

Authentication and authorization are distinct. `ServerConfig.Authenticator`
establishes who the peer is. `TargetConfig.Authorize` decides whether that
principal may perform each target operation and separately controls the exact
inactive-to-active physical login transition.
`LoginPolicy.Authenticate` validates or audits every logical login credential.
PINs, bearer credentials, key material, and operation payloads are not included
in authorization requests.

Physical HSM credentials have an explicit source selected by
`LoginPolicy.Mode`:

- server-managed mode obtains a fresh short-lived secret from
  `LoginPolicy.PhysicalPIN`
- client-activated mode stores no HSM PIN in server configuration and uses the
  PIN supplied by the one authenticated and authorized remote login selected as
  activation leader. Server targets reject `TargetConfig.Client.PIN` so a
  physical credential cannot be silently hidden in the nested client config
- protected-path mode passes a nil PIN and relies on the token's trusted input
  path.

In client-activated mode, concurrent pods collapse onto one physical
`C_Login`/`C_LoginUser` attempt. Other callers wait for the same result rather
than consuming additional HSM PIN attempts. Request, callback, and `Secret`
copies are wiped after use. The broker retains only login state, timestamps,
principal, and activation generation, never the PIN or a PIN verifier. Because
no credential is available for automatic relogin, control-session, HSM, module,
broker, or failover login loss causes a
`proxy.ErrActivationRequired` result until another audited client supplies a
fresh PIN. Providers requiring per-session physical login are rejected in this
mode because safely supporting future sessions would require retaining the PIN.

Ordinary remote logout is virtual. It revokes one logical client's grants,
private handles, session objects, and operations but never calls physical
`C_Logout`, which would affect every physical session in the broker process.
Token initialization, PIN administration, and SO use are disabled unless an
exclusive `MaintenancePolicy` authorizes the exact method.

The protocol rejects native pointer images and `raw.UnsafeParameter`. Standard
and registered vendor parameters are transported semantically and marshaled
only for the broker host ABI.

A dropped connection after a non-idempotent operation may leave the result
ambiguous. The server can replay a bounded retained response only for the same
principal, client ID, request ID, target revision, epoch, and
secret-independent fingerprint. The fingerprint deliberately
excludes request values so the ledger never retains an offline hash of a PIN,
bearer credential, key value, or plaintext. When proof is unavailable, the client returns
`proxy.ErrOutcomeUnknown` rather than issuing a new HSM mutation.

One active server should own the physical session budget and activation state
for one HSM or partition. Multiple independent active server multiply the
actual HSM session usage and can race physical login. they require an external
distributed permit and ownership design.
