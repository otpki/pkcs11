# SoftHSM token initialization shared by the conformance and integration
# entrypoints. Sourced, not executed, so exports reach the caller.
: "${PKCS11_TOKEN_LABEL:=otpki-conformance}"
: "${PKCS11_PIN:=123456}"
: "${PKCS11_SO_PIN:=12345678}"

mkdir -p /var/lib/softhsm/tokens
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
