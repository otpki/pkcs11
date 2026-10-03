## pkcs11-proxy

PKCS #11 proxy broker

### Synopsis

Run a PKCS #11 proxy broker.

The proxy opens one or more local PKCS #11 modules and makes their tokens
available to remote clients. Each target has a route name. Clients can call
proxy.ListRoutes to find the available routes before connecting.

The first client login activates a token with its PIN. Later clients must use
the same PIN. The server does not store a plaintext PIN. By default, any
authenticated client can use every operation.

Settings use the same names in flags, PKCS11_PROXY_* environment variables,
and YAML. Precedence is flag, environment, YAML, then default. targets[] and
discovery are YAML-only. Discovery can publish one route per reported token.

Use --test for an in-memory HSM with PIN "1234". This is useful for trying the
proxy and dashboard without a real HSM.

logging.* controls logs, audit.* controls the signed audit log, and otel.*
controls OpenTelemetry export. health.listen serves /healthz, /readyz, and
/metrics for local monitoring.

Use the pki subcommand to create development mTLS certificates. Use audit to
verify or inspect audit logs.

### Examples

```
  # Run with the example configuration
  pkcs11-proxy serve --config ./pkcs11-proxy.yaml

  # Serve the read-only dev dashboard alongside the broker
  pkcs11-proxy serve --config ./pkcs11-proxy.yaml --dev_ui.enabled

  # Dev mode: three synthetic routes on in-memory test modules (PIN "1234")
  pkcs11-proxy serve --test --insecure --dev_ui.enabled

  # Mint a development mTLS tree: CA + server + client certs under ./pki
  pkcs11-proxy pki init --dir ./pki --host 10.0.0.5 --client alice

  # Offline-verify a signed audit log, inspect records, prove one entry
  pkcs11-proxy audit verify audit.log --key audit.log.key.pub
  pkcs11-proxy audit inspect audit.log --tail 10
  pkcs11-proxy audit prove audit.log --seq 7 --key audit.log.key.pub
```

### Options

```
  -h, --help   help for pkcs11-proxy
```

### SEE ALSO

* [pkcs11-proxy audit](pkcs11-proxy_audit.md)	 - Verify and inspect signed audit logs
* [pkcs11-proxy pki](pkcs11-proxy_pki.md)	 - Create a development mTLS tree (CA, server certs, client certs)
* [pkcs11-proxy serve](pkcs11-proxy_serve.md)	 - Run the proxy broker
* [pkcs11-proxy vendors](pkcs11-proxy_vendors.md)	 - List the vendor modules compiled into this binary

