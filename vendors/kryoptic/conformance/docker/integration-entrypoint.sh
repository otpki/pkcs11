#!/bin/sh
set -eu

. /init-token.sh

# -run Integration matches every PKCS11_MODULE-gated test (TestIntegration,
# Test*Integration) in these packages and any added to them later.
cd /src
exec go test -count=1 -v -run Integration . ./proxy ./proxycmd
