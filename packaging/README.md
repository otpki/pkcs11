# Linux packages

Release packages support amd64 and arm64. Download the package matching your
distribution from the GitHub release. Packages are standalone, not a repository.

| Distribution | Package | Service |
| --- | --- | --- |
| Debian, Ubuntu | `.deb` | systemd |
| Fedora, RHEL, Rocky, Alma, SUSE | `.rpm` | systemd |
| Arch, Manjaro | `.pkg.tar.zst` | systemd |
| Alpine | `.apk` | OpenRC |

DEB, RPM, and Arch packages require glibc 2.28 or newer. Alpine uses musl and
requires musl-compatible PKCS#11 middleware.

## Install

Replace `1.2.3` and `amd64` with the release version and architecture. Verify
the package checksum against `checksums.txt`.

```sh
sudo apt install ./pkcs11-proxy_1.2.3_linux_amd64.deb
sudo dnf install ./pkcs11-proxy_1.2.3_linux_amd64.rpm
sudo pacman -U ./pkcs11-proxy_1.2.3_linux_amd64.pkg.tar.zst
sudo apk add --allow-untrusted ./pkcs11-proxy_1.2.3_linux_amd64.apk
```

The packages install `pkcs11-proxy`, its config at
`/etc/pkcs11-proxy/pkcs11-proxy.yaml`, and a service unit. Alpine uses OpenRC;
the other packages use systemd when available. The packages are unsigned.

## Configure and start

Edit `/etc/pkcs11-proxy/pkcs11-proxy.yaml` and configure TLS certificates and
vendor middleware. The initial install enables startup at boot but does not
start the service. Give the `pkcs11-proxy` account access to required files and
devices. Do not put HSM PINs in the config.

```sh
# systemd
sudo systemctl start pkcs11-proxy
systemctl status pkcs11-proxy
journalctl -u pkcs11-proxy -f

# Alpine
sudo rc-service pkcs11-proxy start
sudo rc-service pkcs11-proxy status
sudo tail -f /var/log/pkcs11-proxy.log
```

## Upgrade and remove

Install a newer package with the same command. Upgrades do not restart the
service; restart it when ready. Package managers preserve modified config by
default.

Remove with `apt remove pkcs11-proxy`, `dnf remove pkcs11-proxy`,
`pacman -R pkcs11-proxy`, or `apk del pkcs11-proxy`. Package data, logs, and the
service account are retained.

## Native client

Linux packages also install the native PKCS#11 client library and its config.
See [the native client guide](../native/README.md) for setup and configuration.
