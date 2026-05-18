#!/bin/sh
# run_bridge.sh — Wrapper that sets up the ARM64 environment and runs the bridge.
#
# This script is copied into the bridge-bin Docker volume by the bridge-builder
# service. go2rtc's exec source calls this to launch the bridge on demand.
#
# The bridge binary is ARM64 (runs via QEMU on x86 hosts).
# SDK .so files are in /libs/ and /apk-libs/ volumes.

set -e

# ARM64 SDK environment
export LD_PRELOAD=/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/libs:/apk-libs

# Bridge config — connect to local relay, fast timeouts
export P2P_URL="|127.0.0.1"
export LAN_WAIT=0
export SUBSCRIBE_WAIT=3

# Load Wyze credentials from .env
ENV_FILE="${ENV_FILE:-/config/.env}"
if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            \#*|"") continue ;;
        esac
        # Strip quotes
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}" ; val="${val%\'}"
        export "$key=$val"
    done < "$ENV_FILE"
fi

# Force local relay (override any .env setting)
export P2P_URL="|127.0.0.1"
export LAN_WAIT=0

# SKIP_WAKEUP: set to 0 to send cloud wakeup (needed for battery doorbells
# when the doorbell isn't already connected to the relay)
export SKIP_WAKEUP="${SKIP_WAKEUP:-0}"

# Run bridge — stdout outputs H.264 Annex B for go2rtc
exec /bridge/bridge --stdout "$@"
