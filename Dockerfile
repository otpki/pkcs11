# syntax=docker/dockerfile:1
#
# pkcs11-proxy broker image.
#
#   build:   golang:1.27-alpine + zig cc cross-compiling the cgo backend for a
#            pinned glibc floor (musl-only host, glibc output — zig carries its
#            own glibc sysroot). Both target architectures build natively on
#            BUILDPLATFORM, so multiarch needs no QEMU.
#   runtime: chainguard glibc-dynamic — a minimal glibc rootfs with no shell or
#            package manager; only ca-certs, a static busybox (wget/nc/sh) for
#            healthchecks, and the broker are added.
#
# The binary stays dynamically linked against glibc >= GLIBC_FLOOR because the
# broker dlopens vendor PKCS#11 middleware, which is glibc-linked native code.
#
#   docker build -t pkcs11-proxy .
#   docker buildx build --platform linux/amd64,linux/arm64 -t pkcs11-proxy .
#
#   docker run --rm -p 9443:9443 \
#     -v "$PWD/pkcs11-proxy.yaml:/etc/pkcs11-proxy/pkcs11-proxy.yaml:ro" \
#     -v /opt/hsm/vendor-pkcs11.so:/opt/hsm/vendor-pkcs11.so:ro \
#     -v pkcs11-audit:/var/lib/pkcs11-proxy \
#     pkcs11-proxy
#
# Hardware-free smoke test:
#   docker run --rm -p 9443:9443 \
#     pkcs11-proxy --test --insecure --listen 0.0.0.0:9443

ARG BASE_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest
ARG BUSYBOX_IMAGE=busybox:1.37-uclibc
ARG GLIBC_FLOOR=2.28

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
RUN apk add --no-cache zig binutils
ARG GLIBC_FLOOR
WORKDIR /src

# Dependency layer cached on go.mod/go.sum alone.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  set -eu; \
  for attempt in 1 2 3 4 5; do \
  go mod download && exit 0; \
  sleep $((attempt * 2)); \
  done; \
  exit 1

COPY . .
ARG TARGETOS TARGETARCH
# VERSION is stamped into the binary via -X main.version; the release pipeline
# passes the git tag, plain builds report "dev".
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  set -eux; \
  [ "${TARGETOS}" = "linux" ] || { echo "unsupported target OS: ${TARGETOS}" >&2; exit 1; }; \
  case "${TARGETARCH}" in \
  amd64) ZIG_ARCH="x86_64" ;; \
  arm64) ZIG_ARCH="aarch64" ;; \
  *) echo "unsupported target arch: ${TARGETARCH}" >&2; exit 64 ;; \
  esac; \
  ZIG_TARGET="${ZIG_ARCH}-linux-gnu.${GLIBC_FLOOR}"; \
  echo "building cgo glibc payload for linux/${TARGETARCH} via ${ZIG_TARGET}"; \
  CGO_ENABLED=1 GOOS=linux GOARCH="${TARGETARCH}" \
  CC="zig cc -target ${ZIG_TARGET}" \
  CXX="zig c++ -target ${ZIG_TARGET}" \
  go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.version=${VERSION} -linkmode=external" \
  -o /out/pkcs11-proxy ./cmd/pkcs11-proxy; \
  file /out/pkcs11-proxy 2>/dev/null || true; \
  if ! readelf -l /out/pkcs11-proxy | grep -q 'INTERP'; then \
  echo "ERROR: binary must be dynamically linked for dlopen" >&2; exit 1; \
  fi; \
  if ! readelf -d /out/pkcs11-proxy | grep -q '(NEEDED).*libc'; then \
  echo "ERROR: binary does not link libc" >&2; exit 1; \
  fi; \
  highest="$(readelf -V /out/pkcs11-proxy | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -uV | tail -1)"; \
  echo "highest glibc symbol: ${highest:-none} (floor ${GLIBC_FLOOR})"

# Static busybox per target platform — supplies wget/nc/sh on the shell-less
# chainguard rootfs without pulling in a package manager.
FROM ${BUSYBOX_IMAGE} AS busybox

FROM ${BASE_IMAGE}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/pkcs11-proxy /usr/local/bin/pkcs11-proxy
COPY --from=busybox /bin/busybox /usr/bin/wget
COPY --from=busybox /bin/busybox /usr/bin/nc
COPY --from=busybox /bin/busybox /usr/bin/sh

# Chainguard's nonroot uid; the image has no passwd tooling to create one.
USER 65532:65532
EXPOSE 9443
# TCP liveness on the broker port. For a richer check serve dev_ui and probe
# http://127.0.0.1:9463/dev/api/status.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["/usr/bin/nc", "-z", "127.0.0.1", "9443"]
ENTRYPOINT ["/usr/local/bin/pkcs11-proxy", "serve"]
CMD ["--config", "/etc/pkcs11-proxy/pkcs11-proxy.yaml"]
