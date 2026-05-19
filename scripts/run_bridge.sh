#!/bin/sh
set -e

export LD_PRELOAD=/work/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/work/libs:/work/apk/xapk_contents/arm64_libs/lib/arm64-v8a

# Load .env
ENV_FILE="${ENV_FILE:-/work/.env}"
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

export P2P_URL="${P2P_URL:-|127.0.0.1}"
export LAN_WAIT="${LAN_WAIT:-0}"
export SUBSCRIBE_WAIT="${SUBSCRIBE_WAIT:-3}"
export SKIP_WAKEUP="${SKIP_WAKEUP:-0}"

exec /work/build/bridge --stdout "$@"
