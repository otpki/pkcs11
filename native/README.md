# Native PKCS#11 client

Load this library as a PKCS#11 module to connect an application to a remote
`pkcs11-proxy` server.

## Quick start

1. Download the library for the application’s OS and architecture.
2. Copy `client.example.yaml` and set the proxy endpoint, route, and CA file.
3. Set the config path before starting the application:

```sh
export PKCS11_CLIENT_CONFIG=/absolute/path/client.yaml
pkcs11-tool --module /path/to/libpkcs11_proxy_client.so --list-slots
```

Applications can also configure the module path directly. Use the architecture
of the application process. Alpine requires the musl library; other Linux
distributions use glibc.

Linux packages install the library at
`/usr/lib/pkcs11-proxy/libpkcs11_proxy_client.so` and the config at
`/etc/pkcs11-proxy/client.yaml`. macOS and Windows libraries are standalone
downloads; configure their full path in the application.

## Configuration

Environment variables override YAML values. Set them before launching the app.

| Setting | Environment variable | Notes |
| --- | --- | --- |
| `endpoint` | `PKCS11_CLIENT_ENDPOINT` | Proxy `host:port`; default `127.0.0.1:9443`. |
| `route` | `PKCS11_CLIENT_ROUTE` | Required if the proxy has multiple routes. |
| `revision` | `PKCS11_CLIENT_REVISION` | Optional route revision. |
| `ca_file` | `PKCS11_CLIENT_CA_FILE` | CA certificate for TLS; TLS is enabled by default. |
| `cert_file`, `key_file` | `PKCS11_CLIENT_CERT_FILE`, `PKCS11_CLIENT_KEY_FILE` | Optional mutual TLS credentials; use together. |
| `server_name` | `PKCS11_CLIENT_SERVER_NAME` | Optional TLS name override. |
| `auth` | `PKCS11_CLIENT_AUTH` | Workload credential, not the token PIN. |
| `timeout_seconds` | `PKCS11_CLIENT_TIMEOUT_SECONDS` | RPC timeout; default 30 seconds. |
| `insecure` | `PKCS11_CLIENT_INSECURE` | Plaintext testing only. |

The token PIN is supplied by the application through `C_Login`. Do not put it
in the config file.

## Supported interface

The library exposes PKCS#11 3.2 and legacy 3.1, 3.0, and 2.40 interfaces. It
supports common session, object, key, crypto, and random-number operations;
unsupported calls return `CKR_FUNCTION_NOT_SUPPORTED`. Actual mechanisms and
operations depend on the proxy and HSM. This is a subset, not full PKCS#11
3.2 conformance.

## Build

From the repository root with a stable Rust toolchain:

```sh
cargo test --manifest-path native/Cargo.toml
cargo build --release --manifest-path native/Cargo.toml
```
