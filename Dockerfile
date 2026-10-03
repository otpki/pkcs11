# syntax=docker/dockerfile:1


ARG BASE_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest
ARG BUSYBOX_IMAGE=busybox:1.37-uclibc
ARG GLIBC_FLOOR=2.28
ARG GIT_BRANCH=""
ARG GIT_HASH=""
ARG GIT_TAG=""

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
RUN apk add --no-cache zig binutils git ca-certificates
ARG GLIBC_FLOOR
WORKDIR /src

# Dependency layer cached on go.mod/go.sum alone.
COPY go.mod go.sum ./
RUN go mod download

# The source checkout is mounted, not COPYed into an image layer. This includes
# the optional private submodule when present.
ARG TARGETOS TARGETARCH
ARG GIT_BRANCH
ARG GIT_HASH
ARG GIT_TAG
RUN --mount=type=bind,target=/src,rw \
  --mount=type=tmpfs,target=/tmp \
  set -eu; \
  export GOCACHE=/tmp/go-build ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache; \
  CGO_ENABLED=0 go build -o /tmp/build build.go; \
  [ "${TARGETOS}" = "linux" ]; \
  case "${TARGETARCH}" in \
  amd64) ZIG_ARCH=x86_64 ;; \
  arm64) ZIG_ARCH=aarch64 ;; \
  *) echo "unsupported target arch: ${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  CGO_ENABLED=1 GOOS=linux GOARCH="${TARGETARCH}" \
  GIT_BRANCH="${GIT_BRANCH}" GIT_HASH="${GIT_HASH}" GIT_TAG="${GIT_TAG}" \
  CC="zig cc -target ${ZIG_ARCH}-linux-gnu.${GLIBC_FLOOR}" \
  CXX="zig c++ -target ${ZIG_ARCH}-linux-gnu.${GLIBC_FLOOR}" \
  /tmp/build > /tmp/build.log 2>&1 || { \
  echo "Build failed; run go run build.go locally for diagnostics." >&2; exit 1; \
  }; \
  mkdir -p /out; cp dist/pkcs11-proxy /out/pkcs11-proxy; \
  readelf -l /out/pkcs11-proxy | grep -q 'INTERP'; \
  readelf -d /out/pkcs11-proxy | grep -q '(NEEDED).*libc'; \
  highest="$(readelf -V /out/pkcs11-proxy | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -uV | tail -1)"; \
  echo "highest glibc symbol: ${highest:-none} (floor ${GLIBC_FLOOR})"; \
  [ -z "$highest" ] || [ "${highest#GLIBC_}" = "$(printf '%s\n%s\n' "${highest#GLIBC_}" "${GLIBC_FLOOR}" | sort -V | head -1)" ]

# Static busybox per target platform, supplies wget/nc/sh on the shell-less
# chainguard rootfs without pulling in a package manager.
FROM ${BUSYBOX_IMAGE} AS busybox

FROM ${BASE_IMAGE}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/pkcs11-proxy /usr/local/bin/pkcs11-proxy
COPY --from=busybox /bin/busybox /usr/bin/wget
COPY --from=busybox /bin/busybox /usr/bin/nc
COPY --from=busybox /bin/busybox /usr/bin/sh

# Chainguard's nonroot uid, the image has no passwd tooling to create one.
USER 65532:65532
EXPOSE 9443
# TCP liveness on the broker port. For a richer check serve dev_ui and probe
# http://127.0.0.1:9463/dev/api/status.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["/usr/bin/nc", "-z", "127.0.0.1", "9443"]
ENTRYPOINT ["/usr/local/bin/pkcs11-proxy", "serve"]
CMD ["--config", "/etc/pkcs11-proxy/pkcs11-proxy.yaml"]
