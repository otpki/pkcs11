# The Utimaco simulator (bl_sim5) is a 32-bit i386 ELF and the PKCS #11 client
# library is x86_64, so this image is always built for linux/amd64. On arm64
# Docker Desktop the amd64 userland runs under Rosetta while qemu-i386 binfmt
# executes the simulator binary.

ARG GO_VERSION=1.26

# qemu-user-i386 cannot deliver guest realtime signals >= 61, which deadlocks
# the simulator's scheduler tick. qemu_sigfix.c remaps them onto unused lower
# signals; it must be built as a 32-bit object to match bl_sim5.
FROM debian:trixie-slim AS shim-build
RUN apt-get -o Acquire::Retries=5 update \
  && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
  gcc-multilib libc6-dev-i386 \
  && rm -rf /var/lib/apt/lists/*
COPY vendors/utimaco/conformance/docker/qemu_sigfix.c /src/qemu_sigfix.c
RUN mkdir -p /out && gcc -m32 -shared -fPIC -O2 -o /out/qemu_sigfix.so /src/qemu_sigfix.c -ldl

FROM golang:${GO_VERSION}-bookworm AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN set -eu; \
  for attempt in 1 2 3 4 5; do \
  go mod download && exit 0; \
  sleep $((attempt * 2)); \
  done; \
  exit 1
COPY . .
ARG PKCS11_BACKEND=cgo
RUN case "$PKCS11_BACKEND" in \
  cgo)    CGO_ENABLED=1 go test -c -trimpath -o /out/conformance.test ./vendors/utimaco/conformance ;; \
  purego) CGO_ENABLED=0 go test -c -trimpath -o /out/conformance.test ./vendors/utimaco/conformance ;; \
  *) echo >&2 "PKCS11_BACKEND must be cgo or purego, got $PKCS11_BACKEND"; exit 64 ;; \
  esac

FROM debian:trixie-slim
RUN dpkg --add-architecture i386 \
  && apt-get -o Acquire::Retries=5 update \
  && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
  libc6:i386 libgcc-s1:i386 libstdc++6 ca-certificates netcat-openbsd procps \
  && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/conformance.test /conformance.test
COPY --from=shim-build /out/qemu_sigfix.so /opt/utimaco/lib/qemu_sigfix.so
COPY licensed/utimaco/ /opt/utimaco/
COPY conformance/docker/common/run-go-tests.sh /conformance/run-go-tests.sh
COPY vendors/utimaco/conformance/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /conformance.test /conformance/run-go-tests.sh /entrypoint.sh \
  /opt/utimaco/simulator/bin/bl_sim5 \
  /opt/utimaco/simulator/bin/cs_sim.sh \
  /opt/utimaco/simulator/bin/cs_multi.sh \
  /opt/utimaco/admin/csadm \
  /opt/utimaco/admin/cxitool \
  /opt/utimaco/admin/gladm \
  /opt/utimaco/admin/p11tool2 \
  && mkdir -p /reports
RUN chmod 0755 /opt/utimaco/admin/qptool2 2>/dev/null || true
ENV CS_PKCS11_R3_CFG=/opt/utimaco/etc/cs_pkcs11_R3.cfg \
  CRYPTOSERVER=3001@127.0.0.1 \
  PKCS11_MODULE=/opt/utimaco/lib/libcs_pkcs11_R3.so \
  PKCS11_TOKEN_LABEL=otpki-utimaco \
  PKCS11_PIN=12345678 \
  PKCS11_SO_PIN=87654321 \
  PATH=/opt/utimaco/admin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT ["/entrypoint.sh"]
