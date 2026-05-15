# Dockerfile — Alpine ARM64 container for Wyze bridge + go2rtc
#
# Provides musl-based environment where Android .so files can be
# dlopen'd after patching with patchelf.  go2rtc serves the stream
# over RTSP/WebRTC/HLS with on-demand bridge lifecycle management.
FROM alpine:3.20

# Build dependencies
RUN apk add --no-cache \
        bash \
        build-base \
        cmake \
        curl \
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

# Install go2rtc (single static binary)
ARG GO2RTC_VERSION=1.9.9
RUN arch=$(uname -m) && \
    case "$arch" in \
        aarch64) go_arch="arm64" ;; \
        x86_64)  go_arch="amd64" ;; \
        armv7l)  go_arch="arm"   ;; \
        *)       go_arch="$arch" ;; \
    esac && \
    curl -fsSL "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_${go_arch}" \
         -o /usr/local/bin/go2rtc && \
    chmod +x /usr/local/bin/go2rtc

WORKDIR /work

# RTSP, WebRTC, Web UI
EXPOSE 8554 8555 1984

# Default: run entrypoint (setup + go2rtc).  Override with --entrypoint
# for dev use (e.g. --entrypoint sleep infinity).
CMD ["sh", "/work/scripts/entrypoint.sh"]
