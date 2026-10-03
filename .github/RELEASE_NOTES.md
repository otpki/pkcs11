Official proxy server binaries include both public vendors and the private vendors
from the pinned private module. GitHub's generated source archives contain only
the public source tree.

# PKCS #11 proxy server

A remote PKCS #11 broker with route-per-token discovery, active-active replicas,
signed audit logs, and OpenTelemetry support.

## Linux packages

DEB, RPM, Arch (`.pkg.tar.zst`), and Alpine (`.apk`) packages are available for
amd64 and arm64. They install `/usr/bin/pkcs11-proxy` and the config at
`/etc/pkcs11-proxy/pkcs11-proxy.yaml`.

First installation enables the service for boot but does not start it. Configure
your TLS files and HSM middleware before starting it or rebooting. The service
runs as the non-login `pkcs11-proxy` user, not root.

```sh
sudo systemctl start pkcs11-proxy
journalctl -u pkcs11-proxy -f
```

Alpine uses OpenRC (`rc-service pkcs11-proxy start`) and a separate musl build.
Its middleware must also be musl-compatible. Standalone APKs are unsigned, so
verify their checksum before using `apk add --allow-untrusted`.

Upgrades preserve edited configuration and do not restart or re-enable the
service. Uninstall through your package manager. Audit data and keys under
`/var/lib/pkcs11-proxy` are retained.

Full instructions are in `packaging/README.md` in the source tree and
`/usr/share/doc/pkcs11-proxy/packaging.md` after installation.

## Standalone binaries

macOS and Windows downloads remain binary-only, with no installed config or
service. The standalone Linux binaries are also still available.

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

## Native PKCS#11 client libraries

`pkcs11-proxy-client_<platform>_<arch>.so`, `.dylib`, and `.dll` assets let
applications load the proxy as a PKCS#11 module. Both amd64 and arm64 are
available. Linux has separate glibc and `_linux_musl_` variants.

This is a small Rust client with TLS, YAML and environment configuration, and
common PKCS#11 operations. It is not the full Go client or a vendor middleware
bundle. See `pkcs11-proxy-client.README.md` for the supported subset and use the
matching server revision or newer. The client has no Go runtime.

Linux packages include the client at
`/usr/lib/pkcs11-proxy/libpkcs11_proxy_client.so`, with its separate config at
`/etc/pkcs11-proxy/client.yaml`. Installing it does not start an additional service.
macOS and Windows native libraries are standalone files with no installed config.

The shared libraries, example YAML, guide, and resolved Rust dependency lock are
covered by `checksums.txt` along with the existing server downloads.

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
