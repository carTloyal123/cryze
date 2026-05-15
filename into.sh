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
            -v "$HERE:/work" -v "$HERE/../apk:/apk:ro" \
            -p 1984:1984 -p 8554:8554 -p 8555:8555/udp \
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

dev_exec() { docker exec -it "$DEV" "$@"; }

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

    test)
        ensure_dev
        load_env_vars
        echo "=== Smoke test (15s) ==="
        dev_exec env $ENV_VARS ./build/bridge --duration 15 ${@:2}
        ;;

    run)
        ensure_dev
        load_env_vars
        DURATION="${2:-60}"
        echo "=== Running bridge (${DURATION}s) ==="
        dev_exec env $ENV_VARS ./build/bridge --duration "$DURATION" ${@:3}
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
        echo "  build         Compile bridge only"
        echo "  test          Quick 15s smoke test"
        echo "  run [SECS]    Run bridge for N seconds (default 60)"
        echo "  clean         Stop + remove build artifacts"
        echo "  rebuild       Full rebuild (image + libs + bridge)"
        exit 1
        ;;
esac
