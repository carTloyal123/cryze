# Dockerfile — Alpine ARM64 dev container for Wyze bridge
#
# Provides musl-based environment where Android .so files can be
# dlopen'd after patching with patchelf.
FROM alpine:3.20

RUN apk add --no-cache \
        bash \
        build-base \
        cmake \
        curl-dev \
        g++ \
        gcc \
        linux-headers \
        mbedtls-dev \
        musl-dev \
        ninja \
        nlohmann-json \
        openssl-dev \
        patchelf \
        util-linux-dev

WORKDIR /work
