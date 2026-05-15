#!/bin/sh
# entrypoint.sh — First-run setup then start go2rtc
#
# 1. Patch Android .so files (idempotent — skips if already done)
# 2. Build the bridge binary (skips if already built)
# 3. Start go2rtc (which launches the bridge on demand)
set -eu

# Step 1: Patch libs if not already done
if [ ! -f /work/libs/libiotp2pav.so ]; then
    echo "[entrypoint] Running first-time library setup..."
    sh /work/scripts/setup-libs.sh
else
    echo "[entrypoint] libs/ already set up, skipping."
fi

# Step 2: Build bridge if not already built
if [ ! -f /work/build/bridge ]; then
    echo "[entrypoint] Building bridge..."
    cmake -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release /work 2>&1 | tail -3
    ninja -C /work/build 2>&1
else
    echo "[entrypoint] bridge binary exists, skipping build."
fi

echo "[entrypoint] Starting go2rtc..."
echo "[entrypoint] RTSP:   rtsp://localhost:8554/doorbell"
echo "[entrypoint] WebRTC: http://localhost:1984"

# go2rtc needs LD_PRELOAD and LD_LIBRARY_PATH set for the bridge child processes
export LD_PRELOAD=/work/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a

exec go2rtc -config /work/go2rtc.yaml
