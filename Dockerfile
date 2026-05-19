FROM alpine:3.20

RUN apk add --no-cache \
        bash build-base cmake curl curl-dev g++ gcc \
        linux-headers mbedtls-dev musl-dev ninja \
        nlohmann-json openssl-dev patchelf python3 util-linux-dev \
        unzip

# go2rtc
ARG GO2RTC_VERSION=1.9.9
RUN arch=$(uname -m) && \
    case "$arch" in aarch64) go_arch="arm64" ;; *) go_arch="$arch" ;; esac && \
    curl -fsSL "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_${go_arch}" \
         -o /usr/local/bin/go2rtc && chmod +x /usr/local/bin/go2rtc

WORKDIR /work

COPY scripts/ scripts/
COPY src/ src/
COPY CMakeLists.txt .

# Download Wyze APK and extract SDK libraries
RUN python3 scripts/setup_apk.py

# Set up shim libraries (bionic compat, patchelf SDK .so files)
RUN python3 -c '\
import sys; sys.path.insert(0, "scripts"); \
from entrypoint import setup_libs; setup_libs()'

# Build bridge + daemon
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release . && ninja -C build

COPY go2rtc.yaml .

EXPOSE 8554 8555 1984
STOPSIGNAL SIGINT
CMD ["go2rtc", "-config", "/work/go2rtc.yaml"]
