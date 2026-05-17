#!/usr/bin/env bash
# into.sh — Wyze doorbell bridge launcher
#
# Usage:
#   ./into.sh              Start go2rtc (Ctrl+C to stop cleanly)
#   ./into.sh stop         Stop and free all ports
#   ./into.sh logs         Tail live logs from running instance
#   ./into.sh restart      Stop and restart
#   ./into.sh shell        Interactive shell in container
#   ./into.sh test         Quick 15s smoke test (no go2rtc)
#   ./into.sh run [SECS]   Run bridge for N seconds (default 60)
#   ./into.sh build        Compile bridge only
#   ./into.sh clean        Stop + remove build artifacts and libs
#   ./into.sh rebuild      Full image rebuild from scratch

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="wyze-bridge:latest"
COMPOSE="docker compose --env-file /dev/null -f $HERE/docker-compose.yml"
DEV="wyze-bridge-dev"
ENV_VARS="LD_PRELOAD=/work/libs/bionic_interpose.so LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a"

# Load .env vars for dev container commands (test/run)
load_env_vars() {
    local env_file="$HERE/.env"
    if [[ -f "$env_file" ]]; then
        while IFS='=' read -r key val; do
            [[ -z "$key" || "$key" == \#* ]] && continue
            val="${val#\"}" ; val="${val%\"}"
            val="${val#\'}" ; val="${val%\'}"
            ENV_VARS="$ENV_VARS $key=$val"
        done < "$env_file"
    fi
}

ensure_image() {
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        echo "Building Docker image..."
        docker build --platform linux/arm64 -t "$IMAGE" "$HERE"
    fi
}

# Dev container: long-running, for shell/build/test/run commands
ensure_dev() {
    ensure_image
    if ! docker ps --format '{{.Names}}' | grep -qx "$DEV"; then
        docker rm -f "$DEV" 2>/dev/null || true
        docker run -d --name "$DEV" --platform linux/arm64 \
            --network host \
            -v "$HERE:/work" -v "$HERE/../apk:/apk:ro" \
            --cap-add NET_ADMIN --cap-add NET_RAW \
            -w /work "$IMAGE" sleep infinity
        # Run lib setup via entrypoint.py's setup function
        docker exec "$DEV" python3 -c "
import sys; sys.path.insert(0, '/work/scripts')
from entrypoint import setup_libs, build_bridge
setup_libs()
build_bridge()
"
    fi
}

dev_exec() {
    local tty_flag=""
    if [ -t 0 ]; then tty_flag="-it"; else tty_flag="-i"; fi
    docker exec $tty_flag "$DEV" "$@"
}

_ensure_relay() {
    # Start the relay if not already running in the dev container
    if ! docker exec "$DEV" pgrep -f "gutes_relay.py" >/dev/null 2>&1; then
        echo "Starting GUTES relay..."
        local relay_mode="proxy"
        local relay_keepalive=""
        local relay_upstream="3.13.212.24:28800"
        if [[ -f "$HERE/.env" ]]; then
            relay_mode=$(grep -m1 '^RELAY_MODE=' "$HERE/.env" 2>/dev/null | cut -d= -f2 || echo "proxy")
            [[ -z "$relay_mode" ]] && relay_mode="proxy"
            local ka=$(grep -m1 '^RELAY_KEEPALIVE=' "$HERE/.env" 2>/dev/null | cut -d= -f2)
            [[ "$ka" == "1" || "$ka" == "true" ]] && relay_keepalive="--keepalive"
        fi
        # Resolve Mars upstream
        local mars_ip=$(docker exec "$DEV" python3 -c "
import socket
try:
    r = socket.getaddrinfo('wyze-mars-asrv.wyzecam.com', None, socket.AF_INET)
    print(r[0][4][0])
except: print('3.13.212.24')
" 2>/dev/null)
        [[ -n "$mars_ip" ]] && relay_upstream="${mars_ip}:28800"
        docker exec -d "$DEV" python3 /work/scripts/gutes_relay.py \
            --mode "$relay_mode" --upstream "$relay_upstream" \
            --log-file /work/relay.log --local-ip 127.0.0.1 \
            --session-cache /work/cache/session_keys.json \
            $relay_keepalive
        sleep 0.5
        echo "  Relay started (mode=$relay_mode, upstream=$relay_upstream)"
    fi
}

_block_cloud_relay() {
    # Block outbound TCP and UDP to cloud relay servers (force LAN-only video).
    # The SDK uses both LAN UDP and cloud TCP/UDP relays simultaneously;
    # blocking non-LAN traffic eliminates the cloud relay path entirely.
    local CHAIN="WYZE_BLOCK_RELAY"
    # Flush and rebuild if already exists (Mars IPs may change)
    docker exec "$DEV" iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    docker exec "$DEV" iptables -F "$CHAIN" 2>/dev/null || true
    docker exec "$DEV" iptables -X "$CHAIN" 2>/dev/null || true

    echo "  Setting up LAN-only firewall rules..."
    docker exec "$DEV" iptables -N "$CHAIN"
    # Allow all LAN/localhost traffic (both TCP and UDP)
    docker exec "$DEV" iptables -A "$CHAIN" -d 192.168.0.0/16 -j RETURN
    docker exec "$DEV" iptables -A "$CHAIN" -d 10.0.0.0/8 -j RETURN
    docker exec "$DEV" iptables -A "$CHAIN" -d 172.16.0.0/12 -j RETURN
    docker exec "$DEV" iptables -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    # Allow UDP to Mars signaling ports only (28800 and 51701)
    docker exec "$DEV" iptables -A "$CHAIN" -p udp --dport 28800 -j RETURN
    docker exec "$DEV" iptables -A "$CHAIN" -p udp --dport 51701 -j RETURN
    # Allow HTTPS for wakeup API
    docker exec "$DEV" iptables -A "$CHAIN" -p tcp --dport 443 -j RETURN
    # Allow DNS
    docker exec "$DEV" iptables -A "$CHAIN" -p udp --dport 53 -j RETURN
    docker exec "$DEV" iptables -A "$CHAIN" -p tcp --dport 53 -j RETURN
    # Block everything else to external IPs (TCP relay servers only)
    # NOTE: Must allow UDP to external IPs for NAT hairpin (doorbell's WAN IP)
    docker exec "$DEV" iptables -A "$CHAIN" -p tcp -j REJECT
    # Insert into OUTPUT chain
    docker exec "$DEV" iptables -I OUTPUT 1 -j "$CHAIN"
    echo "  Cloud relay blocked — video will be LAN-only"
}

_run_bridge() {
    _ensure_relay
    # Block cloud relay TCP if LAN_ONLY is set or not explicitly disabled
    local lan_only="${LAN_ONLY:-}"
    if [[ -f "$HERE/.env" ]] && [[ -z "$lan_only" ]]; then
        lan_only=$(grep -m1 '^LAN_ONLY=' "$HERE/.env" 2>/dev/null | cut -d= -f2 || echo "")
    fi
    if [[ "$lan_only" == "1" || "$lan_only" == "true" ]]; then
        _block_cloud_relay
    fi
    local envfile
    envfile=$(mktemp)
    trap "rm -f '$envfile'" EXIT
    echo "LD_PRELOAD=/work/libs/bionic_interpose.so" >> "$envfile"
    echo "LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a" >> "$envfile"
    if [[ -f "$HERE/.env" ]]; then
        grep -v '^\s*#' "$HERE/.env" | grep -v '^\s*$' >> "$envfile"
    fi
    for v in P2P_PORT_TYPE LAN_WAKEUP_DELAY LAN_WAIT DOORBELL_IP DOORBELL_PORT P2P_URL CACHE_FILE; do
        [[ -n "${!v:-}" ]] && echo "$v=${!v}" >> "$envfile"
    done
    local DURATION="${2:-60}"
    echo "=== Running bridge (${DURATION}s) ==="
    local exec_args=()
    while IFS='=' read -r key val; do
        [[ -z "$key" ]] && continue
        exec_args+=("--env" "$key=$val")
    done < "$envfile"
    rm -f "$envfile"
    docker exec "${exec_args[@]}" "$DEV" ./build/bridge --duration "$DURATION" ${@:3}
}

case "${1:-up}" in

    up|start)
        docker rm -f "$DEV" 2>/dev/null || true
        echo "Starting Wyze doorbell bridge..."
        echo "  RTSP:   rtsp://localhost:8554/doorbell"
        echo "  WebRTC: http://localhost:1984"
        echo "  Ctrl+C to stop"
        echo ""
        $COMPOSE up --build
        ;;

    stop|down)
        $COMPOSE down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV" 2>/dev/null || true
        echo "Stopped."
        ;;

    logs)
        $COMPOSE logs -f --tail 100
        ;;

    restart)
        $COMPOSE down 2>/dev/null || true
        exec "$0" up
        ;;

    shell)
        ensure_dev
        dev_exec /bin/bash
        ;;

    build)
        ensure_dev
        dev_exec sh -c "cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug . 2>&1 | tail -3 && ninja -C build"
        ;;

    daemon)
        ensure_dev
        _run_bridge "$@"
        # Override: run the daemon binary instead of bridge
        ;;

    relay)
        ensure_dev
        load_env_vars
        echo "=== Starting GUTES relay ==="
        dev_exec env $ENV_VARS python3 scripts/gutes_relay.py ${@:2}
        ;;

    test)
        ensure_dev
        load_env_vars
        echo "=== Smoke test (15s) ==="
        dev_exec env $ENV_VARS ./build/bridge --duration 15 ${@:2}
        ;;

    run)
        ensure_dev
        _run_bridge "$@"
        ;;

    clean)
        $COMPOSE down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV" 2>/dev/null || true
        rm -rf "$HERE/libs" "$HERE/build"
        echo "Stopped. Removed libs/ and build/."
        ;;

    rebuild)
        $COMPOSE down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV" 2>/dev/null || true
        docker rmi "$IMAGE" 2>/dev/null || true
        rm -rf "$HERE/libs" "$HERE/build"
        docker build --platform linux/arm64 --no-cache -t "$IMAGE" "$HERE"
        echo "Done. Run './into.sh' to start."
        ;;

    *)
        echo "Usage: ./into.sh [COMMAND]"
        echo ""
        echo "  (default)     Start go2rtc with live logs (Ctrl+C to stop)"
        echo "  stop          Stop everything and free ports"
        echo "  logs          Tail logs from running instance"
        echo "  restart       Stop and restart"
        echo "  shell         Interactive shell in dev container"
        echo "  build         Compile bridge + daemon"
        echo "  test          Quick 15s smoke test"
        echo "  run [SECS]    Run bridge for N seconds (default 60)"
        echo "  relay [ARGS]  Start GUTES relay standalone"
        echo "  clean         Stop + remove build artifacts"
        echo "  rebuild       Full rebuild (image + libs + bridge)"
        exit 1
        ;;
esac
