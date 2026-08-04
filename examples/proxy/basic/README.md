# Basic proxy example

This example exposes one local Utimaco PKCS #11 token through the Go proxy and
uses it remotely through both supported APIs:

- the managed `pkcs11.Client`; and
- the complete low-level `raw.Module` interface implemented by `proxy.Client`.

The [`server`](server/main.go) runs beside the native PKCS #11 library and owns
the physical HSM login. The [`client`](client/main.go) needs no native library,
vendor configuration file, or HSM network middleware.

## Credential model

This basic example uses **server-managed physical login**. Two credentials have
different purposes:

| Variable | Process | Purpose |
| --- | --- | --- |
| `PKCS11_PIN` | Server only | The real HSM user PIN used for physical `C_Login`. |
| `PKCS11_PROXY_CLIENT_PIN` | Server and client | A separate logical credential authorizing this remote client. |

The remote client PIN is never substituted for the HSM PIN. Logical logout
revokes only that remote client's grant and does not physically log every other
client out of the shared token.

## Start the server

The server loads the native module, selects the token, logs in eagerly, and
owns the authoritative physical-session budget shared by all remote clients.

```sh
PKCS11_MODULE=/opt/utimaco/lib/libcs_pkcs11_R3.so \
PKCS11_TOKEN_LABEL=example-token \
PKCS11_PIN=physical-hsm-pin \
PKCS11_PROXY_CLIENT_PIN=logical-client-secret \
go run ./examples/proxy/basic/server
```

Optional server settings:

```sh
export PKCS11_PROXY_ADDRESS=127.0.0.1:9443
export PKCS11_PROXY_ROUTE=example-hsm
export PKCS11_PROXY_REVISION=example-v1
```

The configured `SessionBudget` bounds physical sessions, pinned multipart
operations, queued requests, logical clients, virtual sessions, object mappings,
and replay-ledger memory. Opening a remote virtual session does not immediately
consume a physical HSM session.

## Run the client

Use the same route, revision, token label, and logical client credential. The
client process does **not** receive `PKCS11_MODULE` or the physical HSM PIN.

```sh
PKCS11_TOKEN_LABEL=example-token \
PKCS11_PROXY_CLIENT_PIN=logical-client-secret \
go run ./examples/proxy/basic/client
```

## What the client demonstrates

The managed portion:

1. constructs an immutable `proxy.Target`;
2. passes `proxy.RemoteModule(target)` directly to `pkcs11.Open`;
3. authenticates lazily with the logical client credential;
4. performs a remote SHA-256 digest;
5. inspects the selected standard or Utimaco ML-DSA route;
6. generates, signs, and verifies with an ML-DSA-65 key; and
7. destroys the example key objects.

The raw portion calls `proxy.Open`, initializes the remote module, opens a
virtual session, performs logical `C_Login`, requests token random bytes, and
explicitly closes every raw resource.

## Utimaco behavior

Both programs supply `utimaco.New()` explicitly:

- On the client, it fingerprints the remote token and performs the same
  standard-first mechanism routing used with a local module.
- On the server, it supplies the physical session/login behavior and any
  broker-side provider integration required by the local module.

If the token does not advertise standard PKCS #11 3.2 ML-DSA, the Utimaco
adapter can select the documented QuantumProtect fallback. Current Utimaco
parameter records marshal to architecture-independent `[]byte`, so they cross
the proxy without a custom codec. `raw.UnsafeParameter` cannot cross the proxy.

## Security note

The programs use plaintext localhost to keep the example self-contained.
Production deployments should configure verified mTLS or a strong
`ServerConfig.Authenticator`, use a secret manager for the broker-owned HSM
credential, and apply `TargetConfig.Authorize` for target-level operation policy.
