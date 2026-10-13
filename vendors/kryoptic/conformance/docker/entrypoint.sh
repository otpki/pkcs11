#!/bin/sh
set -eu

. /init-token.sh
mkdir -p /reports

export CONFORMANCE_PROVIDER=kryoptic-pqc
exec /conformance/run-go-tests.sh "$@"
