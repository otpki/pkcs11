#!/bin/sh
set -eu

: "${PKCS11_TOKEN_LABEL:=otpki-conformance}"
: "${PKCS11_PIN:=123456}"
: "${PKCS11_SO_PIN:=12345678}"

mkdir -p /var/lib/softhsm/tokens /reports
export SOFTHSM2_CONF=/etc/softhsm2.conf

# Every container gets an empty token store, so initialization is deterministic.
/opt/softhsm/bin/softhsm2-util \
  --init-token \
  --free \
  --label "$PKCS11_TOKEN_LABEL" \
  --so-pin "$PKCS11_SO_PIN" \
  --pin "$PKCS11_PIN" >/tmp/softhsm-init.log
cat /tmp/softhsm-init.log

export PKCS11_MODULE=/opt/softhsm/lib/softhsm/libsofthsm2.so
export CONFORMANCE_PROVIDER=softhsm2
exec /conformance/run-go-tests.sh "$@"
