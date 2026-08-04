ARG GO_VERSION=1.26
ARG KRYOPTIC_VERSION=v1.5.2
ARG OPENSSL_VERSION=3.5.7

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
      cgo)    CGO_ENABLED=1 go test -c -trimpath -o /out/conformance.test ./vendors/kryoptic/conformance ;; \
      purego) CGO_ENABLED=0 go test -c -trimpath -o /out/conformance.test ./vendors/kryoptic/conformance ;; \
      *) echo >&2 "PKCS11_BACKEND must be cgo or purego, got $PKCS11_BACKEND"; exit 64 ;; \
    esac

FROM rust:1.88-bookworm AS kryoptic-build
ARG KRYOPTIC_VERSION
ARG OPENSSL_VERSION
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      build-essential ca-certificates clang git libclang-dev libsqlite3-dev \
      make perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    for attempt in 1 2 3 4 5; do \
      git clone --depth 1 --branch "openssl-${OPENSSL_VERSION}" \
        https://github.com/openssl/openssl.git /opt/openssl-src && exit 0; \
      rm -rf /opt/openssl-src; \
      sleep $((attempt * 2)); \
    done; \
    exit 1
RUN set -eu; \
    for attempt in 1 2 3 4 5; do \
      git clone --depth 1 --branch "${KRYOPTIC_VERSION}" \
        https://github.com/latchset/kryoptic.git /src/kryoptic && exit 0; \
      rm -rf /src/kryoptic; \
      sleep $((attempt * 2)); \
    done; \
    exit 1
WORKDIR /src/kryoptic
ENV KRYOPTIC_OPENSSL_SOURCES=/opt/openssl-src \
    CONFDIR=/etc/kryoptic \
    CARGO_NET_RETRY=5 \
    CARGO_HTTP_TIMEOUT=120
# Kryoptic releases are library source archives and do not currently ship a
# Cargo.lock. Resolve the tag's dependency graph once, then require that exact
# generated lockfile for the actual release build. The root workspace turns
# off default features on its ossl dependency, so select ossl/ossl-sys
# explicitly; that binding builds the pinned OpenSSL source tree and publishes
# DEP_OPENSSL4_VERSION_NUMBER to ossl/build.rs.
RUN cargo generate-lockfile \
    && cargo build --locked --release --no-default-features \
      --features standard,pqc,ossl/ossl-sys
RUN mkdir -p /out \
    && cp target/release/libkryoptic_pkcs11.so /out/libkryoptic_pkcs11.so

FROM debian:bookworm-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      ca-certificates libsqlite3-0 opensc \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/conformance.test /conformance.test
COPY --from=kryoptic-build /out/libkryoptic_pkcs11.so /opt/kryoptic/lib/libkryoptic_pkcs11.so
COPY conformance/docker/common/run-go-tests.sh /conformance/run-go-tests.sh
COPY vendors/kryoptic/conformance/docker/token.conf /etc/kryoptic/token.conf
COPY vendors/kryoptic/conformance/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /conformance.test /conformance/run-go-tests.sh /entrypoint.sh \
    && mkdir -p /reports /var/lib/kryoptic
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf \
    PKCS11_MODULE=/opt/kryoptic/lib/libkryoptic_pkcs11.so \
    PKCS11_TOKEN_LABEL=otpki-conformance \
    PKCS11_PIN=123456 \
    PKCS11_SO_PIN=12345678
ENTRYPOINT ["/entrypoint.sh"]
