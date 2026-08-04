# Client-activated proxy

This example separates the three security decisions involved in remote HSM
access:

- `server/main.go` authenticates the workload, authorizes target operations,
  and runs in `PhysicalLoginClientActivated` mode without any configured HSM PIN.
- `client/main.go` supplies a workload credential through `proxy.Target.Auth`
  and obtains the HSM PIN only when `pkcs11.Client.Activate` requests it.
- Utimaco behavior is selected explicitly on both sides with `utimaco.New()`.

Start the broker without `PKCS11_PIN`:

```sh
PKCS11_MODULE=/opt/utimaco/lib/libcs_pkcs11_R3.so \
PKCS11_TOKEN_LABEL=example-token \
PKCS11_PROXY_AUTH_TOKEN=development-workload-token \
go run ./examples/proxy/clientactivated/server
```

Start the application separately. Only this process receives the HSM PIN:

```sh
PKCS11_TOKEN_LABEL=example-token \
PKCS11_PROXY_AUTH_TOKEN=development-workload-token \
PKCS11_PIN=1234 \
go run ./examples/proxy/clientactivated/client
```

Plaintext localhost and bearer authentication keep the example self-contained.
Use verified mTLS and production policy/audit integrations in a deployment.
