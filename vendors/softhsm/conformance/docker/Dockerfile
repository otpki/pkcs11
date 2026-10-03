ARG GO_VERSION=1.26
ARG SOFTHSM_REVISION=f12916ee8c6eb5c0025786479fcbf6b38480b134

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
         --enable-mldsa \
         --enable-mlkem \
         --disable-gost \
         --disable-non-paged-memory \
         --disable-p11-kit \
    && make -j"$(nproc)" \
    && make install

FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/conformance.test /conformance.test
COPY --from=softhsm-build /opt/softhsm /opt/softhsm
COPY conformance/docker/common/run-go-tests.sh /conformance/run-go-tests.sh
COPY vendors/softhsm/conformance/docker/softhsm2.conf /etc/softhsm2.conf
COPY vendors/softhsm/conformance/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /conformance.test /conformance/run-go-tests.sh /entrypoint.sh \
    && mkdir -p /reports
ENV SOFTHSM2_CONF=/etc/softhsm2.conf \
    PKCS11_MODULE=/opt/softhsm/lib/softhsm/libsofthsm2.so \
    PKCS11_TOKEN_LABEL=otpki-conformance \
    PKCS11_PIN=123456 \
    PKCS11_SO_PIN=12345678
ENTRYPOINT ["/entrypoint.sh"]
