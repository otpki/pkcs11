#!/bin/bash
# Boots the Utimaco simulator, provisions a token, then runs the conformance
# suite. The PKCS #11 client library reaches the simulator over loopback.
set -euo pipefail

SIM_DIR="${UTIMACO_SIM_DIR:-/opt/utimaco/simulator}"
SIM_HOST="${UTIMACO_SIM_HOST:-127.0.0.1}"
SIM_PORT="${SDK_PORT:-3001}"

SLOT="${UTIMACO_SLOT:-1}"
TOKEN_LABEL="${PKCS11_TOKEN_LABEL:-otpki-utimaco}"
SO_PIN="${PKCS11_SO_PIN:-87654321}"
USER_PIN="${PKCS11_PIN:-12345678}"
USER_INIT_PIN="${UTIMACO_USER_INIT_PIN:-init${USER_PIN}}"
ADMIN_KEY="${UTIMACO_ADMIN_KEY:-/opt/utimaco/admin/key/ADMIN_SIM.key}"
USR_NAME="${UTIMACO_USR_NAME:-USR_$(printf '%04d' "${SLOT}")}"
CXI_GROUP="${UTIMACO_CXI_GROUP:-SLOT_$(printf '%04d' "${SLOT}")}"

export CRYPTOSERVER="${CRYPTOSERVER:-${SIM_PORT}@${SIM_HOST}}"
export CS_PKCS11_R3_CFG="${CS_PKCS11_R3_CFG:-/opt/utimaco/etc/cs_pkcs11_R3.cfg}"
# bl_sim5 takes its listen port from SDK_PORT and resolves the persistent
# device files through SDK_PATH_DEVICES (default ../devices).
export SDK_PORT="${SIM_PORT}"
export SDK_PATH_DEVICES="${SIM_DIR}/devices"

log() { printf '[utimaco] %s\n' "$*"; }

# qemu-user-i386 cannot deliver guest realtime signals >= 61, which parks the
# simulator's scheduler before its accept loop starts. qemu_sigfix.so remaps
# them; preload is scoped to the i386 simulator only. cs_sim.sh is just
# "$DIR/bl_sim5 -h -o", so exec the binary directly to keep the preload off the
# 64-bit wrapper shell (avoids harmless ELF-class warnings in the log).
SIM_SHIM="${UTIMACO_SIM_SHIM:-/opt/utimaco/lib/qemu_sigfix.so}"
(cd "${SIM_DIR}/bin" && LD_PRELOAD="${SIM_SHIM}" exec ./bl_sim5 -h -o) &
SIM_PID=$!
trap 'kill -TERM "${SIM_PID}" 2>/dev/null || true; wait 2>/dev/null || true' EXIT TERM INT

until nc -z "${SIM_HOST}" "${SIM_PORT}" 2>/dev/null; do
  kill -0 "${SIM_PID}" 2>/dev/null || { log "simulator exited before listening"; exit 1; }
  sleep 0.2
done

until /opt/utimaco/admin/csadm GetState >/dev/null 2>&1; do
  kill -0 "${SIM_PID}" 2>/dev/null || { log "simulator exited before responding"; exit 1; }
  sleep 0.5
done
log "simulator up on ${SIM_HOST}:${SIM_PORT}"

/opt/utimaco/admin/csadm "Dev=${CRYPTOSERVER}" listfirmware 2>/dev/null || true

if /opt/utimaco/admin/p11tool2 \
    Slot="${SLOT}" Label="${TOKEN_LABEL}" \
    Login=ADMIN,"${ADMIN_KEY}" \
    InitToken="${SO_PIN}"; then
  log "initialized token on slot ${SLOT} (label=${TOKEN_LABEL})"

  # C_InitPin returns CKR_PIN_TOO_WEAK for every PIN on this firmware, so the
  # PKCS #11 user is provisioned through csadm with a throwaway PIN that is
  # immediately rotated to the real one.
  /opt/utimaco/admin/csadm LogonSign=ADMIN,"${ADMIN_KEY}" \
      AddUser="${USR_NAME},00000002{CXI_GROUP=${CXI_GROUP}},hmacpwd,${USER_INIT_PIN}"
  /opt/utimaco/admin/csadm LogonPass="${USR_NAME},${USER_INIT_PIN}" \
      ChangeUser="${USR_NAME},${USER_PIN}"
  export PKCS11_TOKEN_LABEL="${TOKEN_LABEL}"
  export PKCS11_PIN="${USER_PIN}"
elif [ -n "${UTIMACO_FALLBACK_PIN:-}" ]; then
  # Some QuantumProtect simulators ship a prepared PKCS #11 slot 0 whose
  # SO/USER PINs are fixed evaluation values (12345677 / 12345688).
  log "token init failed; falling back to pre-configured credentials"
  export PKCS11_PIN="${UTIMACO_FALLBACK_PIN}"
  export PKCS11_SLOT_ID="${UTIMACO_FALLBACK_SLOT:-0}"
  export PKCS11_TOKEN_LABEL="${UTIMACO_FALLBACK_LABEL:-}"
else
  log "token init failed and no fallback credentials are configured"
  exit 1
fi

export CONFORMANCE_PROVIDER="${UTIMACO_PROVIDER:-utimaco}"
exec /conformance/run-go-tests.sh "$@"
