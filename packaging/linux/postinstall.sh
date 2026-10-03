#!/bin/sh
set -eu

# Debian passes "configure [old-version]". RPM passes an installed package count.
# Arch and Alpine use a different callback for upgrades.
action=install
case "${1:-}" in
    configure) [ -z "${2:-}" ] || action=upgrade ;;
    abort-*) exit 0 ;;
    ''|*[!0-9]*) ;;
    *) [ "$1" -le 1 ] || action=upgrade ;;
esac
/bin/sh /usr/lib/pkcs11-proxy/package-hooks "$action"
