# PKCS #11 proxy broker

Remote PKCS #11 access with route-per-token, active-active replicas,
Merkle-sealed audit logging, and OpenTelemetry export.

## Install

Download the binary for your platform, verify it against the single
`checksums.txt`, then place it on `PATH`:

```sh
sha256sum -c checksums.txt --ignore-missing   # or: shasum -a 256 -c checksums.txt
./pkcs11-proxy_<os>_<arch> --version
```

| Platform        | Asset                            | Runs on                                                                                               |
| --------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Linux x86_64    | `pkcs11-proxy_linux_amd64`       | glibc ≥ 2.28: RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 11+, Amazon Linux 2023+, Fedora 28+, SLES 15+ |
| Linux aarch64   | `pkcs11-proxy_linux_arm64`       | same floor — ARM servers, Graviton, Ampere                                                            |
| macOS arm64     | `pkcs11-proxy_darwin_arm64`      | macOS 13+ (Ventura and later), Apple Silicon                                                          |
| macOS x86_64    | `pkcs11-proxy_darwin_amd64`      | macOS 13+, Intel                                                                                      |
| Windows x86_64  | `pkcs11-proxy_windows_amd64.exe` | Windows 10+ / Server 2016+ — best-effort, compile-verified                                            |
| Windows aarch64 | `pkcs11-proxy_windows_arm64.exe` | Windows 11 ARM64 — best-effort, compile-verified                                                      |

Notes:

- All binaries use the cgo backend. Linux builds are dynamically linked
  against glibc ≥ 2.28 so vendor PKCS#11 middleware can be dlopen'd; whatever
  shared libraries the vendor module itself needs (libssl, etc.) must be
  installed on the host.
- No binary ships vendor middleware — point `module:` in the YAML at your
  vendor `.so`/`.dll`.
- The dev dashboard binds loopback only unless `dev_ui.allow_remote` is set.

## Container image

Multiarch (`linux/amd64` + `linux/arm64`), published to the org registry:

```
$REGISTRY_URL/otpki-pkcs11-proxy:<tag>    # and :latest
```

Chainguard `glibc-dynamic` runtime — glibc, ca-certificates, and busybox
`wget`/`nc`/`sh` for healthchecks; no shell package manager, runs as uid 65532. Mount your config, vendor middleware, and an audit volume:

```sh
docker run -d --name pkcs11-proxy -p 9443:9443 \
  -v "$PWD/pkcs11-proxy.yaml:/etc/pkcs11-proxy/pkcs11-proxy.yaml:ro" \
  -v /opt/hsm/vendor-pkcs11.so:/opt/hsm/vendor-pkcs11.so:ro \
  -v pkcs11-audit:/var/lib/pkcs11-proxy \
  $REGISTRY_URL/otpki-pkcs11-proxy:<tag>

# hardware-free smoke test
docker run --rm -p 9443:9443 $REGISTRY_URL/otpki-pkcs11-proxy:<tag> \
  --test --insecure --listen 0.0.0.0:9443
```

The default config path is `/etc/pkcs11-proxy/pkcs11-proxy.yaml`; override by
passing args (they replace the default `--config` CMD). The baked-in
`HEALTHCHECK` TCP-probes port 9443 — adjust if `listen:` moves. The image
contains no vendor PKCS#11 middleware; mount it read-only and reference it in
`module:` paths.

## Quick start

```sh
# Hardware-free smoke test: three synthetic routes, dev dashboard on :9463
pkcs11-proxy serve --test --insecure --dev_ui.enabled --listen 0.0.0.0:9443

# Real deployment
pkcs11-proxy serve --config /etc/pkcs11-proxy/pkcs11-proxy.yaml

# Development mTLS tree and audit tooling
pkcs11-proxy pki init --dir ./pki --host <broker-ip> --client alice
pkcs11-proxy audit verify audit.log --key audit.log.key.pub
```

## Changes
