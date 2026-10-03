Official release binaries include both public vendors and the private vendors
from the pinned private module. GitHub's generated source archives contain only
the public source tree.

# PKCS #11 proxy server

A remote PKCS #11 broker with route-per-token discovery, active-active replicas,
signed audit logs, and OpenTelemetry support.

## Install

Download the binary for your platform and verify it with `checksums.txt`:

```sh
sha256sum -c checksums.txt --ignore-missing
# macOS alternative:
shasum -a 256 -c checksums.txt

./pkcs11-proxy_<os>_<arch> --version
```

| Platform | Asset | Minimum runtime |
| --- | --- | --- |
| Linux x86_64 | `pkcs11-proxy_linux_amd64` | glibc 2.28+ |
| Linux aarch64 | `pkcs11-proxy_linux_arm64` | glibc 2.28+ |
| macOS arm64 | `pkcs11-proxy_darwin_arm64` | macOS 13+ |
| macOS x86_64 | `pkcs11-proxy_darwin_amd64` | macOS 13+ |
| Windows x86_64 | `pkcs11-proxy_windows_amd64.exe` | Windows 10+ / Server 2016+ |
| Windows aarch64 | `pkcs11-proxy_windows_arm64.exe` | Windows 11 ARM64 |

Release binaries use the cgo backend. Linux binaries are dynamically linked so
they can load normal vendor PKCS #11 middleware. Any libraries required by that
middleware must also be installed on the host.

The release does not include vendor middleware. Point `module:` at the vendor's
installed `.so`, `.dylib`, or `.dll`.

## Container image

The multi-architecture image is published as:

```text
$REGISTRY_URL/otpki-pkcs11-proxy:<tag>
```

It uses the Chainguard `glibc-dynamic` runtime and runs as uid 65532. Mount the
config, vendor middleware, and any persistent audit storage you need.

```sh
docker run -d --name pkcs11-proxy -p 9443:9443 \
  -v "$PWD/pkcs11-proxy.yaml:/etc/pkcs11-proxy/pkcs11-proxy.yaml:ro" \
  -v /opt/hsm/vendor-pkcs11.so:/opt/hsm/vendor-pkcs11.so:ro \
  -v pkcs11-audit:/var/lib/pkcs11-proxy \
  $REGISTRY_URL/otpki-pkcs11-proxy:<tag>

# Hardware-free smoke test
docker run --rm -p 9443:9443 $REGISTRY_URL/otpki-pkcs11-proxy:<tag> \
  --test --insecure --listen 0.0.0.0:9443
```

The default config path is
`/etc/pkcs11-proxy/pkcs11-proxy.yaml`.

## Quick start

```sh
# In-memory test routes and dev dashboard
pkcs11-proxy serve --test --insecure --dev_ui.enabled --listen 0.0.0.0:9443

# Real config
pkcs11-proxy serve --config /etc/pkcs11-proxy/pkcs11-proxy.yaml

# Development certificates and audit tools
pkcs11-proxy pki init --dir ./pki --host <broker-ip> --client alice
pkcs11-proxy audit verify audit.log --key audit.log.key.pub
```

## Changes
