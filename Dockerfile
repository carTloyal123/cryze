# Dockerfile — ARM64 bridge builder
#
# Builds the Wyze bridge binary from source in an Alpine ARM64 container.
# The entrypoint.py handles SDK lib patching at first run.
#
# Used by docker-compose.yml:
#   - bridge-builder service: builds binary, copies to shared volumes
#   - Standalone: runs entrypoint.py (relay + go2rtc)
FROM alpine:3.20

# Build + runtime dependencies
RUN apk add --no-cache \
        bash build-base cmake curl curl-dev g++ gcc \
        linux-headers mbedtls-dev musl-dev ninja \
        nlohmann-json openssl-dev patchelf python3 util-linux-dev

# go2rtc (single static binary)
ARG GO2RTC_VERSION=1.9.9
RUN arch=$(uname -m) && \
    case "$arch" in aarch64) go_arch="arm64" ;; *) go_arch="$arch" ;; esac && \
    curl -fsSL "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_${go_arch}" \
         -o /usr/local/bin/go2rtc && chmod +x /usr/local/bin/go2rtc

WORKDIR /work
EXPOSE 8554 8555 1984
STOPSIGNAL SIGINT

# Default: entrypoint handles lib setup, build, relay, go2rtc
# For bridge-builder service: override with copy command
CMD ["python3", "/work/scripts/entrypoint.py"]
