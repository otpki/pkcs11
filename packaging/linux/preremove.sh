#!/bin/sh
set -eu
# Do not stop the old process while its package is being upgraded.
case "${1:-}" in
    upgrade|deconfigure|failed-upgrade|abort-*) exit 0 ;;
    ''|*[!0-9]*) ;;
    *) [ "$1" -eq 0 ] || exit 0 ;;
esac
/bin/sh /usr/lib/pkcs11-proxy/package-hooks remove
