#!/bin/sh
set -eu

. /init-token.sh
mkdir -p /reports

export CONFORMANCE_PROVIDER=softhsm2
exec /conformance/run-go-tests.sh "$@"
