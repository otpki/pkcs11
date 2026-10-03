#!/bin/sh
set -eu
# Used by Arch and Alpine. Do not re-enable a service the administrator disabled.
/bin/sh /usr/lib/pkcs11-proxy/package-hooks upgrade
