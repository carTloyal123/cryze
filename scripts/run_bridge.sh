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

# Cold-start retry: a camera that has gone dormant fails the first
# iv_start_av_link with err=20005 and the bridge exits non-zero having produced
# no frames. The HTTPS wakeup the bridge sends on each start brings the camera
# up after a couple of attempts. Retry on failure while holding stdout open so
# go2rtc keeps the producer pipe connected (no EOF) across attempts. The bridge
# exits 0 once frames have flowed (SIGINT/duration), which ends the loop.
MAX_TRIES="${BRIDGE_MAX_TRIES:-6}"
RETRY_DELAY="${BRIDGE_RETRY_DELAY:-2}"

stop=0
child=
# go2rtc stops the producer with SIGINT (killsignal=2). Forward it to the
# bridge child and stop retrying.
trap 'stop=1; [ -n "$child" ] && kill -INT "$child" 2>/dev/null' INT TERM

rc=1
i=0
while [ "$stop" -eq 0 ] && [ "$i" -lt "$MAX_TRIES" ]; do
    i=$((i + 1))
    /work/build/bridge --stdout --device "$DEVICE_MAC" $EXTRA_ARGS &
    child=$!
    # `|| rc=$?` captures the bridge's exit without set -e aborting the script.
    rc=0
    wait "$child" || rc=$?
    child=

    # rc 0  -> bridge streamed then exited (SIGINT/duration): done.
    # rc !=0 -> cold-start failure (dormant camera, err=20005): retry.
    [ "$rc" -eq 0 ] && break
    [ "$stop" -eq 1 ] && break
    echo "run_bridge: $DEVICE_MAC attempt $i failed (rc=$rc), retrying in ${RETRY_DELAY}s..." >&2
    sleep "$RETRY_DELAY"
done

exit "$rc"
