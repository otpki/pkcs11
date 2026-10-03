#!/bin/sh
# Shared by the package managers. This file is installed before postinstall runs
# and is still present during preremove. Never start or restart from this script.
set -eu

service=pkcs11-proxy
state=/var/lib/pkcs11-proxy
config=/etc/pkcs11-proxy/pkcs11-proxy.yaml

create_account() {
    # Use the distro's account tools. Alpine has BusyBox rather than shadow.
    if command -v getent >/dev/null 2>&1; then
        group_exists() { getent group "$service" >/dev/null 2>&1; }
    else
        group_exists() { grep -q "^$service:" /etc/group; }
    fi
    if ! group_exists; then
        if command -v groupadd >/dev/null 2>&1; then
            groupadd --system "$service"
        else
            addgroup -S "$service"
        fi
    fi
    if ! id -u "$service" >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            shell=/usr/sbin/nologin
            [ -x "$shell" ] || shell=/sbin/nologin
            [ -x "$shell" ] || shell=/bin/false
            useradd --system --gid "$service" --home-dir "$state" \
                --no-create-home --shell "$shell" "$service"
        else
            adduser -S -D -H -h "$state" -s /sbin/nologin -G "$service" "$service"
        fi
    fi
    # Do not recursively change ownership of existing audit data or middleware.
    if [ ! -e "$state" ]; then
        mkdir -p "$state"
        chown "$service:$service" "$state"
        chmod 0750 "$state"
    fi
    # Package formats differ in how they resolve named groups at extraction time.
    # Set the config group here, after the service account exists. Leave symlinks alone.
    if [ -f "$config" ] && [ ! -L "$config" ]; then
        chown "root:$service" "$config"
        chmod 0640 "$config"
    fi
}

reload_systemd() {
    # Containers and image builders may have systemctl without a running systemd.
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
}

case "${1:-}" in
    install|upgrade)
        create_account
        if command -v systemctl >/dev/null 2>&1 && [ -f /usr/lib/systemd/system/pkcs11-proxy.service ]; then
            reload_systemd
            if [ "$1" = install ]; then
                enabled=$(systemctl is-enabled "$service.service" 2>/dev/null || true)
                case "$enabled" in
                    masked|masked-runtime) ;;
                    *) systemctl --no-reload enable "$service.service" ;;
                esac
            fi
        elif command -v rc-update >/dev/null 2>&1 && [ -f /etc/init.d/pkcs11-proxy ]; then
            if [ "$1" = install ]; then
                rc-update add "$service" default
            fi
        fi
        ;;
    remove)
        if command -v systemctl >/dev/null 2>&1 && [ -f /usr/lib/systemd/system/pkcs11-proxy.service ]; then
            if [ -d /run/systemd/system ]; then
                systemctl stop "$service.service" || true
            fi
            systemctl --no-reload disable "$service.service" || true
        elif command -v rc-update >/dev/null 2>&1 && [ -f /etc/init.d/pkcs11-proxy ]; then
            if command -v rc-service >/dev/null 2>&1; then
                rc-service "$service" stop || true
            fi
            rc-update --all del "$service" || true
        fi
        # Keep the account, home, audit logs, and keys. Never delete HSM state here.
        ;;
    *)
        echo "usage: package-hooks install|upgrade|remove" >&2
        exit 2
        ;;
esac
