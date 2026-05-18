#!/bin/sh
# run_bridge.sh — Wrapper that sets up the ARM64 environment and runs the bridge.
#
# This script is copied into the bridge-bin Docker volume by the bridge-builder
# service. go2rtc's exec source calls this to launch the bridge on demand.
#
# The bridge binary is ARM64 (runs via QEMU on x86 hosts).
# SDK .so files are in /libs/ and /apk-libs/ volumes.

set -e

# ARM64 musl linker for QEMU on x86 hosts
if [ -f /libs/ld-musl-aarch64.so.1 ] && [ ! -f /lib/ld-musl-aarch64.so.1 ]; then
    ln -sf /libs/ld-musl-aarch64.so.1 /lib/ld-musl-aarch64.so.1 2>/dev/null || true
fi

export LD_PRELOAD=/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/libs:/apk-libs

# Defaults (overridden by .env)
P2P_URL="${P2P_URL:-|127.0.0.1}"
LAN_WAIT="${LAN_WAIT:-0}"
SUBSCRIBE_WAIT="${SUBSCRIBE_WAIT:-3}"
SKIP_WAKEUP="${SKIP_WAKEUP:-0}"

# Load .env (Wyze credentials + any overrides)
ENV_FILE="${ENV_FILE:-/config/.env}"
if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            \#*|"") continue ;;
        esac
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}" ; val="${val%\'}"
        export "$key=$val"
    done < "$ENV_FILE"
fi

# Apply defaults only if .env didn't set them
export P2P_URL="${P2P_URL:-|127.0.0.1}"
export LAN_WAIT="${LAN_WAIT:-0}"
export SUBSCRIBE_WAIT="${SUBSCRIBE_WAIT:-3}"
export SKIP_WAKEUP="${SKIP_WAKEUP:-0}"

# Run bridge — stdout outputs H.264 Annex B for go2rtc
exec /bridge/bridge --stdout "$@"
