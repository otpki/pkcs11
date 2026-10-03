#!/bin/sh
set -u

REPORT_DIR=${CONFORMANCE_REPORT_DIR:-/reports}
mkdir -p "$REPORT_DIR"

set +e
/conformance.test -test.v "$@" >"$REPORT_DIR/test.log" 2>&1
status=$?
set -e

cat "$REPORT_DIR/test.log"
printf '%s\n' "$status" >"$REPORT_DIR/exit-code"
printf 'CONFORMANCE_DONE provider=%s exit=%s\n' "${CONFORMANCE_PROVIDER:-unknown}" "$status"

if [ "${CONFORMANCE_HOLD:-1}" = "1" ]; then
  exec tail -f /dev/null
fi
exit "$status"
