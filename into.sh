#!/usr/bin/env bash
# into.sh — Drop into the bridge dev container or run bridge/go2rtc
#
# Usage:
#   ./into.sh          # interactive shell
#   ./into.sh build    # cmake + ninja build
#   ./into.sh run      # build + run bridge (60s, file output)
#   ./into.sh run 30   # build + run with 30s duration
#   ./into.sh test     # build + run with 15s timeout (quick smoke test)
#   ./into.sh go2rtc   # build + start go2rtc (on-demand RTSP)
#   ./into.sh stop     # stop container and free ports
#   ./into.sh clean    # stop + remove build artifacts and libs

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="wyze-bridge-dev"
IMAGE="wyze-bridge:latest"
ENV_VARS="LD_PRELOAD=/work/libs/bionic_interpose.so LD_LIBRARY_PATH=/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a"

# --- Cleanup helpers ---

# Kill go2rtc/bridge inside the container (graceful then force)
kill_container_procs() {
    if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" 2>/dev/null; then
        docker exec "$CONTAINER" sh -c '
            pkill -INT go2rtc 2>/dev/null
            pkill -INT bridge 2>/dev/null
            sleep 1
            pkill -9 go2rtc 2>/dev/null
            pkill -9 bridge 2>/dev/null
        ' 2>/dev/null || true
    fi
}

do_stop() {
    kill_container_procs
    docker rm -f "$CONTAINER" 2>/dev/null || true
    echo "Container stopped and ports freed."
}

# Trap Ctrl+C / SIGTERM — clean up container on exit for run/test/go2rtc
cleanup_on_exit() {
    echo ""
    echo "Caught signal, cleaning up..."
    kill_container_procs
    # Don't remove container on signal (user might want to inspect) —
    # just kill the processes so ports are freed.
    echo "Processes stopped. Container still running (use './into.sh stop' to remove)."
}

# --- Image + Container setup ---

# Ensure image exists
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Building Docker image..."
    docker build --platform linux/arm64 -t "$IMAGE" "$HERE"
fi

# Start container if not running
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    # Remove stale stopped container if it exists
    docker rm -f "$CONTAINER" 2>/dev/null || true
    docker run -d --name "$CONTAINER" \
        --platform linux/arm64 \
        -v "$HERE:/work" \
        -v "$HERE/../apk:/apk:ro" \
        --env-file "$HERE/.env" \
        -p 1984:1984 -p 8554:8554 -p 8555:8555/udp \
        --cap-add NET_ADMIN --cap-add NET_RAW \
        -w /work \
        "$IMAGE" sleep infinity
    echo "Container $CONTAINER started."
    # Setup: create musl-compatible lib shims and patch .so files
    docker exec "$CONTAINER" sh /work/scripts/setup-libs.sh
else
    # Container already running — kill any leftover go2rtc/bridge from
    # a previous session so ports are free for this run.
    kill_container_procs
fi

run_in() { docker exec -it "$CONTAINER" "$@"; }

do_build() {
    run_in sh -c "cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug . 2>&1 | tail -3 && ninja -C build 2>&1"
}

case "${1:-shell}" in
    shell)
        run_in /bin/bash
        ;;
    build)
        do_build
        ;;
    run)
        trap cleanup_on_exit INT TERM
        do_build
        DURATION="${2:-60}"
        echo ""
        echo "=== Running bridge (duration=${DURATION}s) ==="
        run_in env $ENV_VARS ./build/bridge --duration "$DURATION" ${@:3}
        ;;
    test)
        trap cleanup_on_exit INT TERM
        do_build
        echo ""
        echo "=== Smoke test (15s) ==="
        run_in env $ENV_VARS ./build/bridge --duration 15 ${@:2}
        ;;
    go2rtc)
        trap cleanup_on_exit INT TERM
        do_build
        echo ""
        echo "=== Starting go2rtc (on-demand RTSP) ==="
        echo "  RTSP:   rtsp://localhost:8554/doorbell"
        echo "  WebRTC: http://localhost:1984"
        echo "  Press Ctrl+C to stop"
        echo ""
        run_in env $ENV_VARS go2rtc -config /work/go2rtc.yaml
        ;;
    stop)
        do_stop
        ;;
    clean)
        do_stop
        rm -rf "$HERE/libs" "$HERE/build"
        echo "Removed libs/ and build/."
        ;;
    *)
        echo "Usage: $0 [shell|build|run [SECS]|test|go2rtc|stop|clean]"
        exit 1
        ;;
esac
