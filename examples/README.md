# Examples

Every directory is a standalone program. Start with `basic`, then choose the
lowest-level or operational feature you need.

| Example                                          | What it demonstrates                                                                                                                                            |
|--------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`basic`](basic)                                 | Managed client configuration, diagnostics, health, random, digest, RSA signing and encryption, AES-GCM, HMAC, object lookup, attributes, wrapping, and cleanup. |
| [`signatures`](signatures)                       | RSA, ECDSA, and Ed25519 through `crypto.Signer` plus managed verification.                                                                                      |
| [`advanced`](advanced)                           | Hooks, manual login, pool lifecycle, runtime validation, hotplug watching, raw callbacks, and long-lived raw session leases.                                    |
| [`raw`](raw)                                     | Direct `raw.Module` use: initialization, slots, sessions, login, RNG, digest, key generation, AES-GCM, object search, and explicit cleanup.                     |
| [`proxy/basic/client`](proxy/client)             | A remote Utimaco target through the managed and raw APIs, including vendor-routed ML-DSA.                                                                       |
| [`proxy/basic/server`](proxy/server)             | A Utimaco HSM server with separate logical and physical credentials.                                                                                            |
| [`proxy/clientactivated`](proxy/clientactivated) | Client-owned HSM activation plus independent workload authorization.                                                                                            |
| [`detect`](detect)                               | Middleware discovery, safe probing, and opening a detected module.                                                                                              |
| [`pqc`](pqc)                                     | Standard ML-DSA signing modes and ML-KEM encapsulation/decapsulation.                                                                                           |
| [`customvendor`](customvendor)                   | An application-owned vendor module built with `vendorkit`.                                                                                                      |
| [`vendors`](vendors)                             | Standards-only, single-provider, all-provider, and decorated vendor-module composition.                                                                         |

Most programs expect these environment variables:

```sh
export PKCS11_MODULE=/absolute/path/to/vendor-pkcs11.so
export PKCS11_TOKEN_LABEL='example-token'
export PKCS11_TOKEN_SERIAL='optional-more-stable-selector'
export PKCS11_PIN='user-pin'
```

The examples create token objects. Use a disposable token or simulator first.
Not every token supports every mechanism; each program fails at the first
unsupported operation so the exact capability gap is visible.

The programs work with either native backend:

```sh
CGO_ENABLED=1 go build ./examples/...
CGO_ENABLED=0 go build ./examples/...
CGO_ENABLED=1 go build -tags pkcs11_purego ./examples/...
```
