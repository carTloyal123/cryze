#!/usr/bin/env bash
# into.sh — Wyze doorbell bridge launcher
#
# Usage:
#   ./into.sh              # start go2rtc with live logs (Ctrl+C to stop)
#   ./into.sh stop         # stop and free all ports
#   ./into.sh logs         # tail live logs from running instance
#   ./into.sh test         # quick 15s smoke test (no go2rtc)
#   ./into.sh run [SECS]   # run bridge for N seconds (default 60)
#   ./into.sh shell        # interactive shell in the container
#   ./into.sh build        # compile bridge only
#   ./into.sh clean        # stop + remove build artifacts and libs
#   ./into.sh rebuild      # rebuild Docker image from scratch

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="wyze-bridge"
DEV_CONTAINER="wyze-bridge-dev"
IMAGE="wyze-bridge:latest"
ENV_VARS="LD_PRELOAD=/work/libs/bionic_interpose.so LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a"

# ── Helpers ────────────────────────────────────────────────────────

ensure_image() {
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        echo "Building Docker image..."
        docker build --platform linux/arm64 -t "$IMAGE" "$HERE"
    fi
}

# Start a long-running dev container (for shell/build/run/test commands)
ensure_dev_container() {
    ensure_image
    if ! docker ps --format '{{.Names}}' | grep -qx "$DEV_CONTAINER"; then
        docker rm -f "$DEV_CONTAINER" 2>/dev/null || true
        docker run -d --name "$DEV_CONTAINER" \
            --platform linux/arm64 \
            -v "$HERE:/work" \
            -v "$HERE/../apk:/apk:ro" \
            -p 1984:1984 -p 8554:8554 -p 8555:8555/udp \
            --cap-add NET_ADMIN --cap-add NET_RAW \
            -w /work \
            "$IMAGE" sleep infinity
        echo "Container $DEV_CONTAINER started."
        docker exec "$DEV_CONTAINER" sh /work/scripts/setup-libs.sh
    fi
}

dev_exec() { docker exec -it "$DEV_CONTAINER" "$@"; }

do_build() {
    dev_exec sh -c "cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug . 2>&1 | tail -3 && ninja -C build 2>&1"
}

# ── Commands ───────────────────────────────────────────────────────

case "${1:-up}" in

    # ── Production: docker compose manages everything ──────────────
    up|start|go2rtc)
        # Stop dev container if running (would hold same ports)
        docker rm -f "$DEV_CONTAINER" 2>/dev/null || true
        echo "Starting Wyze doorbell bridge..."
        echo "  RTSP:   rtsp://localhost:8554/doorbell"
        echo "  WebRTC: http://localhost:1984"
        echo "  Press Ctrl+C to stop"
        echo ""
        # docker compose up: builds if needed, shows live logs,
        # Ctrl+C sends SIGINT -> entrypoint.py -> graceful shutdown
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" up --build
        ;;

    stop|down)
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV_CONTAINER" 2>/dev/null || true
        echo "Stopped. All ports freed."
        ;;

    logs)
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" logs -f --tail 100
        ;;

    restart)
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" down 2>/dev/null || true
        exec "$0" up
        ;;

    # ── Dev: long-running container for interactive use ────────────
    shell)
        ensure_dev_container
        dev_exec /bin/bash
        ;;

    build)
        ensure_dev_container
        do_build
        ;;

    run)
        ensure_dev_container
        do_build
        DURATION="${2:-60}"
        echo ""
        echo "=== Running bridge (duration=${DURATION}s) ==="
        dev_exec env $ENV_VARS ./build/bridge --duration "$DURATION" ${@:3}
        ;;

    test)
        ensure_dev_container
        do_build
        echo ""
        echo "=== Smoke test (15s) ==="
        dev_exec env $ENV_VARS ./build/bridge --duration 15 ${@:2}
        ;;

    # ── Maintenance ────────────────────────────────────────────────
    clean)
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV_CONTAINER" 2>/dev/null || true
        rm -rf "$HERE/libs" "$HERE/build"
        echo "Stopped. Removed libs/ and build/."
        ;;

    rebuild)
        docker compose --env-file /dev/null -f "$HERE/docker-compose.yml" down --remove-orphans 2>/dev/null || true
        docker rm -f "$DEV_CONTAINER" 2>/dev/null || true
        docker rmi "$IMAGE" 2>/dev/null || true
        rm -rf "$HERE/libs" "$HERE/build"
        echo "Rebuilding Docker image..."
        docker build --platform linux/arm64 --no-cache -t "$IMAGE" "$HERE"
        echo "Done. Run './into.sh' to start."
        ;;

    *)
        cat <<'EOF'
Usage: ./into.sh [COMMAND]

Production:
  (default)     Start go2rtc with live logs (Ctrl+C to stop cleanly)
  stop          Stop everything and free ports
  logs          Tail live logs from running instance
  restart       Stop and restart

Development:
  shell         Interactive shell in dev container
  build         Compile bridge only
  run [SECS]    Run bridge for N seconds (default 60)
  test          Quick 15s smoke test

Maintenance:
  clean         Stop + remove build artifacts
  rebuild       Full rebuild (image + libs + bridge)
EOF
        exit 1
        ;;
esac
