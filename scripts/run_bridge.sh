#!/bin/sh
# run_bridge.sh — per-device bridge launcher
# Usage: run_bridge.sh --device AA:BB:CC:DD:EE:FF [extra bridge args]
#
# Parses --device from args, derives all per-device file paths (SESSION_KEY_PATH,
# CACHE_FILE), then exec's the bridge binary with --stdout.
#
# Every concurrent bridge process gets its own namespaced files — no collisions.
set -e

DEVICE_MAC=""
EXTRA_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --device)
            DEVICE_MAC="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

if [ -z "$DEVICE_MAC" ]; then
    echo "ERROR: run_bridge.sh requires --device <MAC>" >&2
    exit 1
fi

# Derive file paths from MAC (lowercase, no colons): "AA:BB:CC:DD:EE:FF" → "aabbccddeeff"
MAC_CLEAN=$(echo "$DEVICE_MAC" | tr '[:upper:]' '[:lower:]' | tr -d ':')

export LD_PRELOAD=/work/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/work/libs:/work/apk/xapk_contents/arm64_libs/lib/arm64-v8a

# Per-device file paths — bionic_interpose.c reads SESSION_KEY_PATH via getenv()
export SESSION_KEY_PATH="/cache/session_key_${MAC_CLEAN}.bin"
# wyze_auth.cpp cache_path() reads CACHE_FILE via getenv() — throws if not set
export CACHE_FILE="/cache/auth_${MAC_CLEAN}.json"

# Load .env for account credentials (WYZE_EMAIL, WYZE_PASSWORD, WYZE_KEY_ID, WYZE_API_KEY)
ENV_FILE="${ENV_FILE:-/work/.env}"
if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            \#*|"") continue ;;
        esac
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}" ; val="${val%\'}"
        # shellcheck disable=SC2163
        export "$key=$val"
    done < "$ENV_FILE"
fi

export P2P_URL="${P2P_URL:-|127.0.0.1}"
export LAN_WAIT="${LAN_WAIT:-0}"
export SUBSCRIBE_WAIT="${SUBSCRIBE_WAIT:-3}"
export SKIP_WAKEUP="${SKIP_WAKEUP:-0}"

if [ "${STREAM_OVERLAY:-0}" = "1" ] && [ -n "${RAW_PORT:-}" ]; then
    # Overlay mode: pipe bridge stdout to TCP relay for wyze-overlay container
    exec /work/build/bridge --stdout --device "$DEVICE_MAC" $EXTRA_ARGS \
        | python3 /work/scripts/tcp_relay.py --port "$RAW_PORT"
else
    # Default: bridge writes directly to go2rtc stdout (zero overhead)
    exec /work/build/bridge --stdout --device "$DEVICE_MAC" $EXTRA_ARGS
fi
