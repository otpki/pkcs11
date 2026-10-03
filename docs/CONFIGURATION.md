# Configure pkcs11-proxy

Start with the [small HSM example](../cmd/pkcs11-proxy/pkcs11-proxy.example.yaml).
It needs a listening address, TLS certificates, and the token to expose. Leave
session limits and other tuning settings out until you have a reason to change
them. The [full reference](../cmd/pkcs11-proxy/pkcs11-proxy.reference.yaml) shows
every scalar setting with a comment beside it.

## What you are configuring

The **broker** is the `pkcs11-proxy` process. It loads the vendor's PKCS #11
**module**, which is usually a `.so`, `.dylib`, or `.dll`. That module talks to
one or more **tokens**. A token is a key store, often an HSM partition. A **slot**
is the module's numbered place for a token. It is not necessarily a separate
physical HSM.

A **route** gives one token a name, such as `signing`. An application selects that
name to choose its token. A **logical client** is one remote `proxy.Client`, not
one TCP connection. Reuse it for the life of the application instead of creating
one for each signature.

A **physical session** is a real PKCS #11 session opened by the broker. A
**virtual session** is a handle the application gets from the broker. Many
virtual sessions can share the physical pool. Some operations need a physical
session to stay assigned between requests. That session is called **pinned**.

This proxy speaks its own Go protocol. `pkcs11-tool` can test the native vendor
module on the broker host, but it cannot connect directly to the broker's TCP
port. Applications use the repository's `proxy` package.

## First start

Copy the small example to `pkcs11-proxy.yaml`. Set the module path to the library
installed on the broker host, choose the token's label or serial, and use server
and client certificates from your PKI. Then run:

```sh
pkcs11-proxy serve --config ./pkcs11-proxy.yaml
```

The application needs the broker address, its route name, a client certificate,
and trust in the server certificate. Static `targets` routes use revision `v1`.
Discovery routes have a generated revision. Read their `ID` and `Revision` from
`proxy.ListRoutes` instead of hardcoding them.

The HSM PIN does not belong in this YAML. The application supplies it when it
logs in. The first successful client login activates the physical token. Later
clients are checked against an in-memory verifier of that accepted PIN.

## Choose tokens

For a fixed deployment, `targets` is easiest:

```yaml
targets:
  - name: signing
    module: /opt/vendor/lib/libpkcs11.so
    token_serial: "0102"
```

`name` is the public route name. It defaults to `hsm`, so set distinct names when
you publish more than one route. `module` is the local vendor library path.
`token_label`, `token_serial`, and `slot_id` select the token. Multiple selectors
must all match. With no selector, the first matching token is used. Avoid that
in production because the ordering can change.

`vendors` chooses compiled vendor adapters by ID or name. An empty list enables
all adapters in that binary. Run `pkcs11-proxy vendors` to see the available
ones. This setting does not install middleware. The client must support every
parameter codec the broker advertises. Extra client codecs are allowed, so
matching adapter sets are convenient rather than required.

Use `discovery` instead when the token list changes:

```yaml
discovery:
  - module: /opt/vendor/lib/libpkcs11.so
    name_prefix: site-a-
    refresh_interval: 5s
    overrides:
      - name: signing
        token_serial: "0102"
        sessions:
          max_physical_total: 4
```

Do not set `targets` and `discovery` together. Discovery normally builds names
from token serials, falling back to labels. `name_prefix` keeps tokens from
different modules from getting the same name. An override's `name` is used as
written, without the prefix.

Each override must select exactly one token at startup using exactly one of
`token_serial`, `token_label`, or `slot_id`. Its `sessions` and `activation`
sections override only the listed settings for that token. Other settings
inherit the global values. Static target entries do not accept these per-token
sections.

`discovery[].refresh_interval` defaults to `5s`. A route-list request checks for
changes only when that interval has passed. This is not a background poll.
Lower it when token changes need to appear sooner and callers list routes often.
Raise it when enumeration is expensive. Zero means `5s`. A negative value checks
on every listing. No setting makes an old logical client move to a new token
silently. A changed route can require that client to reopen.

## Network and shutdown

| Setting              | Default          | What it changes                                                                                                                           |
| -------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `listen`             | `127.0.0.1:9443` | Where applications connect. Use a private interface or a container bind address for remote clients. Protect the port with network policy. |
| `tls.cert_file`      | Empty            | Server certificate in PEM format. Required with `tls.key_file`. Include the names clients actually use to connect.                        |
| `tls.key_file`       | Empty            | Server private key. Restrict file access to the broker's OS account.                                                                      |
| `tls.client_ca_file` | Empty            | Require client certificates trusted by this CA. The verified certificate identifies the workload.                                         |
| `insecure`           | `false`          | Permit plaintext when no server key pair is configured. Development only. Configured TLS still takes precedence.                          |
| `test`               | `false`          | Replace configured targets with fake demo tokens. Never enable it in a real-key deployment.                                               |
| `drain_timeout`      | `5m`             | How long existing clients have to finish after shutdown is requested. Raise for longer jobs.                                              |
| `shutdown_timeout`   | `30s`            | Time allowed for cleanup after draining. Raise only when normal cleanup genuinely needs it.                                               |

Server-only TLS encrypts the connection but does not prove who the client is.
The standalone command's non-mTLS identity is derived from caller-supplied bytes.
Those bytes are an identifier, not a validated bearer credential. For real HSM
access, require mTLS. The CLI also has no per-route role policy: permitted
clients share the configured routes, subject to PIN checks and the disabled
maintenance operations. Embed the broker and configure `TargetConfig.Authorize`
when workloads need different permissions.

A client CA without a server certificate and key is rejected, even with
`insecure: true`. The server must not silently ignore a requested security check.

Queue and shutdown deadlines do not forcibly interrupt a native library call.
Configure the vendor SDK's own connection and operation timeouts. Also give
systemd or your container platform enough stop time for draining and cleanup.

## Sessions and queueing

These defaults are for the command, not the Go library's zero-value
`SessionBudget`. Limits apply separately to each route on each broker replica.
Two replicas with an eight-session limit can use sixteen sessions on the same
HSM. Include other applications and routes when sizing against the provider's
limit.

| Setting                                    | CLI default | When to change it                                                                                                                                                                              |
| ------------------------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sessions.max_physical_total`              | `8`         | Real HSM sessions, including idle, active, pinned, and one reserved control session. Raise only when requests wait for capacity and the HSM can handle more concurrency. Keep it at least two. |
| `sessions.max_physical_read_write`         | `4`         | Read/write sessions within that total. Raise for concurrent key creation or object updates. It is not extra capacity on top of the total.                                                      |
| `sessions.max_pinned`                      | `2`         | Physical sessions held between requests for multipart operations or session objects. Raise for those workloads, but leave capacity for other work.                                             |
| `sessions.max_queued`                      | `64`        | Requests allowed to wait for physical capacity. Raise to absorb short bursts, not sustained overload. Larger queues usually mean longer waits, not more throughput.                            |
| `sessions.max_clients`                     | `256`       | Logical clients retained per route. Raise for more long-lived app instances, not because one app makes many calls.                                                                             |
| `sessions.max_virtual_sessions_per_client` | `16`        | Session handles one app may hold. Raise when it deliberately opens more concurrent sessions. These are not sixteen permanently reserved HSM sessions.                                          |
| `sessions.max_objects_per_client`          | `1024`      | Object-handle mappings one app may retain. Raise when that app legitimately works with more objects. It does not limit the number of keys stored on the HSM.                                   |
| `sessions.queue_timeout`                   | `5s`        | Maximum wait to borrow HSM capacity. Lower for fast failure, or raise for tolerable short bursts. It is not a native-operation timeout.                                                        |
| `sessions.client_drain_idle_timeout`       | `5s`        | During shutdown, how long an idle client may remain. Raise for clients that pause between steps but still need time to finish. Normal idle expiry is separate.                                 |

At the defaults, one of the eight physical sessions is reserved for shared login
state. At most seven remain for work. Up to two may be pinned, and up to four
may be read/write. Those categories overlap. They are not additional pools.

Explicit zero or negative session values do not disable limits. They invoke
library fallback rules: total `16`, queued `256`, clients `4096`, virtual sessions
per client `64`, and object handles per client `4096`. The read/write fallback
is the physical total. The pinned fallback is half the non-control capacity,
rounded down with a minimum of one. Both listed session timeouts fall back to
`5s`. A read/write limit above the total is also clamped to the total. Omit these
fields instead of using zero unless you deliberately want those library rules.

## Object-search caching

`find_cache.ttl` defaults to `15s`. It reuses a completed object search made on
the same physical session. This can avoid repeated network-HSM enumeration when
the broker resolves keys. It does not cache private key material or make the
first search faster.

Changes made through the broker and login-state changes invalidate the cache.
Changes made by another tool or broker may remain invisible until the TTL
expires. Lower the TTL for frequently changing keys. Raise it only when the
object list is stable and stale results are acceptable. Zero uses `15s`.
A negative duration, such as `-1s`, disables this cache.

The cache keeps at most 256 completed searches per wrapped module, and caches
only searches with at most 4096 handles. Larger searches still run normally.
The limits prevent a series of unique searches from growing the cache forever.
They are internal bounds, not more YAML settings to tune. Embedders sharing
one module source should use a consistent cache policy because module sharing
is keyed by the underlying source, not by the TTL.

## Login and PIN changes

`activation.failure_cooldown` defaults to `1s`. After a failed physical login,
the broker waits before letting another activation attempt reach the HSM.
Raise it to slow attempts that could spend a token's limited PIN retries.
Zero uses `1s`. A negative value disables that cooldown.

**This is not a rate limit for every PIN check.** Once the token is active,
later PINs are checked in memory. The current implementation has no separate
attempt budget for those checks. Require trusted clients and add a bounded
login-attempt policy before using the broker with untrusted or mutually
distrustful workloads. Do not rely on the HSM's lockout policy to protect
software verification.

`activation.pin_rotation_interval` defaults to `0s`, which disables automatic
acceptance of an externally changed PIN. Leave it there when PIN changes go
through a controlled restart or another coordinated procedure. Negative values
are invalid.

With a positive interval, a mismatching PIN can trigger a physical logout and
fresh login once the last physical attempt is old enough. This lets an
application use a PIN changed directly on the HSM, but it affects the whole
shared token. A wrong replacement can leave the route inactive and consume an
HSM PIN retry. The rotation caller must pass activation authorization before
the logout occurs. This interval does not replace the failure cooldown or a
software PIN-attempt limit.

## Health and the development dashboard

`dev_ui.enabled` defaults to `false`. Enable it for troubleshooting.
`dev_ui.listen` defaults to `127.0.0.1:9463`. `dev_ui.allow_remote` defaults to
`false` and must be enabled before binding a non-loopback address.

`health.listen` defaults to empty, which disables the health listener. Set a
separate address such as `127.0.0.1:9464` for `/healthz`, `/readyz`, and `/metrics`.
`health.allow_remote` defaults to `false` and controls whether a non-loopback
bind is allowed.

Neither listener has authentication. `allow_remote` only permits the bind.
It does not add TLS, passwords, or access control. Use a private network,
a firewall, or a protected reverse proxy. Treat client IDs and topology as
operational data, even though PINs and key payloads are not displayed.

## Application logs and audit records

`logging.level` defaults to `info`. Use `debug` temporarily while investigating,
then return to `info`. The other usual levels are `warn` and `error`.
`logging.format` defaults to `text`. Use `json` for a log collector.
`logging.queue_size` defaults to `8192` records. A larger queue can absorb a
short burst but uses more memory. A full queue drops records instead of
blocking HSM work. Zero or negative queue size uses the default.

`audit.path` defaults to empty, which disables the signed security-event log.
Set it to a file in a private, writable directory. Audit records are not a
complete log of cryptographic operations, and signatures do not encrypt their
contents.

`audit.key_file` defaults to `<audit.path>.key`. It contains the Ed25519 signing
seed. Its public key is written next to it as `.pub`. Back up the signing key,
and preserve a trusted copy of the public key separately from the log. Use one
writer per log file and do not share a newly created key path between processes.

`audit.queue_size` defaults to `4096` events. Overflow drops events and the
writer tries to record a gap. It does not stop HSM work. Zero or negative size
uses the default. The current drop counters are reset after a warning or gap
record, so they should not be treated as lifetime loss totals.

`audit.batch_size` defaults to `64` records per signed checkpoint. A larger
batch reduces signing frequency but leaves more records waiting for a
signature. It does not combine disk writes: each record is still written and
synced separately. Zero or negative batch size uses the default.

`audit.checkpoint_interval` defaults to `30s`. It seals a partially filled
batch when traffic is low. Lower it to shorten that unsigned window, at the
cost of more checkpoints. Zero uses `30s`. A negative value disables timed
sealing, but batch-size and clean-shutdown sealing still apply.

There is a restart caveat: the current writer parses an existing log without
fully verifying its signatures, and adopts an unsigned tail for later sealing.
Do not treat append-on-restart as an integrity check. Preserve and independently
verify the old log with a trusted public key before recovery. Preserve unsigned
crash tails separately rather than silently treating them as trusted records.
An external checkpoint record is also needed to detect removal of a complete
suffix, or replacement of the entire local log and key.

## OpenTelemetry

`otel.endpoint` defaults to empty, which disables OTLP push export. The local
Prometheus endpoint can still export metrics when `health.listen` is set.
Use a bare collector address such as `collector.internal:4318`. This is
OTLP over HTTP, not the collector's OTLP/gRPC listener. URL paths are not
supported by the current endpoint setup.

`otel.insecure` defaults to `false`. A bare endpoint uses TLS unless this is
true. An `http://` prefix also enables plaintext. In the current implementation,
`https://` does not override `otel.insecure: true`, so avoid conflicting values.
This is separate from the broker's top-level `insecure` setting.

`otel.service_name` defaults to `pkcs11-proxy`. It is the service name shown in
your telemetry backend. Keep it consistent across replicas of the same service.
`otel.metric_interval` defaults to `15s`. A shorter interval gives fresher
metrics with more export traffic. Use a positive duration.

The request counters keep up to 4096 distinct route/method/outcome combinations.
New combinations share an overflow bucket once that table fills. Unusually
long labels are replaced with a marker. This prevents rejected requests with
invented route names from growing the in-process counter table forever.

## Tune one bottleneck at a time

If requests wait for physical sessions, compare queue wait with native HSM call
time before raising the session total. If the HSM is already saturated, more
sessions and a longer queue can make latency worse. If one application is the
only source of work, also check its client-side connection pool before raising
broker limits. The default remote client keeps four pooled connections.

If key lookup is slow, compare the first search with repeated searches on a warm
session. Check how often sessions are replaced, how many distinct templates you
search for, and whether other tools are changing keys. A longer TTL does not
help a search that never repeats on the same session.

If audit or application logs drop records, fix the slow destination first.
Increasing the queue only buys time. Do not weaken audit sync or signing rules
as an undocumented performance tweak.

These settings are separate resource limits, not a total process-memory budget.
The proxy also rejects excessive caller-requested random-data and search-batch
sizes. Batches, decoded frames, retained replies, and provider-sized outputs
still need to be considered together when load testing. No timeout or queue
setting can make an uncooperative native library safely interruptible.
