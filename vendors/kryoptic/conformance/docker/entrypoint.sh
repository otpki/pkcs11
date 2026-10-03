#!/bin/sh
set -eu

: "${PKCS11_TOKEN_LABEL:=otpki-conformance}"
: "${PKCS11_PIN:=123456}"
: "${PKCS11_SO_PIN:=12345678}"

mkdir -p /var/lib/kryoptic /reports
rm -f /var/lib/kryoptic/token.sql

export KRYOPTIC_CONF=/etc/kryoptic/token.conf
export PKCS11_MODULE=/opt/kryoptic/lib/libkryoptic_pkcs11.so

pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --slot 1 \
  --init-token \
  --label "$PKCS11_TOKEN_LABEL" \
  --so-pin "$PKCS11_SO_PIN"

pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --slot 1 \
  --login \
  --login-type so \
  --so-pin "$PKCS11_SO_PIN" \
  --init-pin \
  --pin "$PKCS11_PIN"

export CONFORMANCE_PROVIDER=kryoptic-pqc
exec /conformance/run-go-tests.sh "$@"
