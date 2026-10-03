# Examples

Each directory is a standalone program. Start with `basic`, then move to the
example closest to what you are building.

| Example | What it shows |
| --- | --- |
| [`basic`](basic) | Normal managed-client setup, health, RNG, digests, RSA, AES-GCM, HMAC, objects, attributes, wrapping, and cleanup. |
| [`signatures`](signatures) | RSA, ECDSA, and Ed25519 through `crypto.Signer` and managed verification. |
| [`advanced`](advanced) | Hooks, manual login, pool behavior, runtime validation, hotplug, and raw callbacks. |
| [`raw`](raw) | Direct `raw.Module` use with explicit sessions and cleanup. |
| [`proxy/pinauth/client`](proxy/pinauth/client) | Client-owned HSM activation with separate workload authorization. |
| [`detect`](detect) | Module discovery and safe probing. |
| [`pqc`](pqc) | ML-DSA signing and ML-KEM encapsulation/decapsulation. |
| [`customvendor`](customvendor) | An application-owned vendor module built with `vendorkit`. |
| [`vendors`](vendors) | Different ways to compose vendor modules. |

Most examples use these environment variables:

```sh
export PKCS11_MODULE=/absolute/path/to/vendor-pkcs11.so
export PKCS11_TOKEN_LABEL='example-token'
export PKCS11_TOKEN_SERIAL='optional-more-stable-selector'
export PKCS11_PIN='user-pin'
```

The examples create token objects. Use a disposable token or simulator first.
A program exits when the token does not support an operation it needs, which
makes capability gaps easy to see.

You can build the examples with either native backend:

```sh
CGO_ENABLED=1 go build ./examples/...
CGO_ENABLED=0 go build ./examples/...
CGO_ENABLED=1 go build -tags pkcs11_purego ./examples/...
```
