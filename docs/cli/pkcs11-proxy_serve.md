## pkcs11-proxy serve

Run the proxy broker

### Synopsis

Run the proxy broker.

Most settings use the same dotted name in flags and YAML, with a matching
PKCS11_PROXY_* environment variable. Precedence is flag, environment, YAML,
then default. targets[] and discovery are YAML-only.

```
pkcs11-proxy serve [flags]
```

### Options

```
      --activation.failure_cooldown duration           PIN-guessing cooldown after a failed activation (default 1s)
      --activation.pin_rotation_interval duration      minimum age of the last physical login before a mismatched PIN may lead a fresh activation (0 disables out-of-band PIN rotation)
      --audit.batch_size int                           records sealed by one signed Merkle checkpoint (default 64)
      --audit.checkpoint_interval duration             max time records sit unsealed at low volume (default 30s)
      --audit.key_file string                          Ed25519 audit signing key (default <path>.key)
      --audit.path string                              JSONL audit log, appended across restarts (empty disables audit)
      --audit.queue_size int                           number of buffered audit events before recording a gap (default 4096)
      --config string                                  YAML config file (default ./pkcs11-proxy.yaml, env PKCS11_PROXY_CONFIG)
      --dev_ui.allow_remote                            allow the dev dashboard on non-loopback addresses
      --dev_ui.enabled                                 serve the read-only dev dashboard
      --dev_ui.listen string                           dev dashboard bind address (default "127.0.0.1:9463")
      --drain_timeout duration                         time existing clients have to finish after SIGTERM (default 5m0s)
      --health.allow_remote                            allow health endpoints on non-loopback addresses
      --health.listen string                           address for /healthz, /readyz, and /metrics (empty disables)
  -h, --help                                           help for serve
      --insecure                                       permit plaintext TCP when no TLS certificate is configured (development)
      --listen string                                  broker listen address clients dial (proxy.Target.Endpoints) (default "127.0.0.1:9443")
      --logging.format string                          log format (text or json) (default "text")
      --logging.level string                           minimum slog level (debug, info, warn, or error) (default "info")
      --logging.queue_size int                         number of buffered log records before dropping (default 8192)
      --otel.endpoint string                           OTLP/HTTP collector host:port or URL (empty disables export)
      --otel.insecure                                  plaintext OTLP transport
      --otel.metric_interval duration                  periodic metric export cadence (default 15s)
      --otel.service_name string                       OTel resource service.name attribute (default "pkcs11-proxy")
      --sessions.client_drain_idle_timeout duration    idle grace before a connected client is evicted once draining starts (default 5s)
      --sessions.max_clients int                       cap on concurrently retained logical clients (default 256)
      --sessions.max_objects_per_client int            cap on virtual object handles per client (default 1024)
      --sessions.max_physical_read_write int           cap on physical sessions opened read/write (default 4)
      --sessions.max_physical_total int                cap on native HSM sessions per route (control + pool + in-flight + pinned) (default 8)
      --sessions.max_pinned int                        cap on physical leases held across network calls (default 2)
      --sessions.max_queued int                        maximum requests waiting for physical capacity (default 64)
      --sessions.max_virtual_sessions_per_client int   cap on virtual sessions per client (no physical session until used) (default 16)
      --sessions.queue_timeout duration                max wait for physical capacity before a request fails busy (default 5s)
      --shutdown_timeout duration                      maximum shutdown time after draining (default 30s)
      --test                                           serve in-memory test routes with PIN "1234" instead of targets[]
      --tls.cert_file string                           PEM server certificate (requires key_file)
      --tls.client_ca_file string                      PEM CA that additionally requires client certificates (mTLS)
      --tls.key_file string                            PEM server private key (requires cert_file)
```

### SEE ALSO

* [pkcs11-proxy](pkcs11-proxy.md)	 - PKCS #11 proxy broker

