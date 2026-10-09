ARG GO_VERSION=1.27
ARG SOFTHSM_REVISION=9ad87341c94ffdf1364ecf27b715475e0d80b0dd

FROM golang:${GO_VERSION}-trixie AS go-build
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
    cgo)    CGO_ENABLED=1 go test -c -trimpath -o /out/conformance.test ./vendors/softhsm/conformance ;; \
    purego) CGO_ENABLED=0 go test -c -trimpath -o /out/conformance.test ./vendors/softhsm/conformance ;; \
    *) echo >&2 "PKCS11_BACKEND must be cgo or purego, got $PKCS11_BACKEND"; exit 64 ;; \
    esac

FROM debian:trixie AS softhsm-build
ARG SOFTHSM_REVISION
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates curl libssl-dev \
    libtool libp11-kit-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fL --retry 5 --retry-delay 2 --retry-all-errors \
    -o /tmp/softhsm.tar.gz \
    "https://github.com/softhsm/SoftHSMv2/archive/${SOFTHSM_REVISION}.tar.gz" \
    && tar -xzf /tmp/softhsm.tar.gz --strip-components=1 \
    && rm -f /tmp/softhsm.tar.gz
RUN sh autogen.sh \
    && ./configure \
    --prefix=/opt/softhsm \
    --with-crypto-backend=openssl \
    --enable-ecc \
    --enable-eddsa \
    --enable-sha3 \
    --enable-mldsa \
    --enable-mlkem \
    --disable-gost \
    --disable-non-paged-memory \
    --disable-p11-kit \
    && make -j"$(nproc)" \
    && make install

# The integration target keeps the Go toolchain and module source from
# go-build so CI can run the PKCS11_MODULE-gated integration tests with a
# plain docker run. go-build and SoftHSM both target trixie, so the glibcs
# match.
FROM go-build AS integration
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=softhsm-build /opt/softhsm /opt/softhsm
COPY vendors/softhsm/conformance/docker/softhsm2.conf /etc/softhsm2.conf
COPY vendors/softhsm/conformance/docker/init-token.sh /init-token.sh
COPY vendors/softhsm/conformance/docker/integration-entrypoint.sh /entrypoint-integration.sh
RUN chmod 0755 /entrypoint-integration.sh \
    && mkdir -p /var/lib/softhsm/tokens
ENV SOFTHSM2_CONF=/etc/softhsm2.conf \
    PKCS11_MODULE=/opt/softhsm/lib/softhsm/libsofthsm2.so \
    PKCS11_TOKEN_LABEL=otpki-conformance \
    PKCS11_PIN=123456 \
    PKCS11_SO_PIN=12345678 \
    PKCS11_INTEGRATION_WRITE=1 \
    PKCS11_INTEGRATION_ALGORITHMS=rsa,ecdsa-p256,ed25519,aes-256,hmac-sha256
ENTRYPOINT ["/entrypoint-integration.sh"]

# The conformance stage stays last so it remains the default build target for
# testcontainers and bare docker build invocations.
FROM debian:trixie-slim AS conformance
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/conformance.test /conformance.test
COPY --from=softhsm-build /opt/softhsm /opt/softhsm
COPY conformance/docker/common/run-go-tests.sh /conformance/run-go-tests.sh
COPY vendors/softhsm/conformance/docker/softhsm2.conf /etc/softhsm2.conf
COPY vendors/softhsm/conformance/docker/init-token.sh /init-token.sh
COPY vendors/softhsm/conformance/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /conformance.test /conformance/run-go-tests.sh /entrypoint.sh \
    && mkdir -p /reports
ENV SOFTHSM2_CONF=/etc/softhsm2.conf \
    PKCS11_MODULE=/opt/softhsm/lib/softhsm/libsofthsm2.so \
    PKCS11_TOKEN_LABEL=otpki-conformance \
    PKCS11_PIN=123456 \
    PKCS11_SO_PIN=12345678
ENTRYPOINT ["/entrypoint.sh"]
