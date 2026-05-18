#!/bin/sh
export LD_PRELOAD=/work/libs/bionic_interpose.so
export LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a

# Use real Mars for CALLING (Mac cannot DNAT)
export P2P_URL="|18.118.90.161"
export LAN_WAIT=0
export SUBSCRIBE_WAIT=5
export SKIP_WAKEUP=0
export DOORBELL_IP=192.168.1.81

# Load Wyze creds from .env
if [ -f /work/.env ]; then
    while IFS="=" read -r key val; do
        case "$key" in \#*|"") continue ;; esac
        val="${val#\"}" ; val="${val%\"}"
        export "$key=$val"
    done < /work/.env
fi

# Force Mars path
export P2P_URL="|18.118.90.161"
export LAN_WAIT=0

exec /work/build/bridge --stdout "$@"
