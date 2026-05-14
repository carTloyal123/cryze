#!/usr/bin/env bash
# into.sh — Drop into the bridge2 dev container or run bridge2
#
# Usage:
#   ./into.sh          # interactive shell
#   ./into.sh build    # cmake + ninja build
#   ./into.sh run      # build + run bridge2
#   ./into.sh run 30   # build + run with 30s duration
#   ./into.sh test     # build + run with 15s timeout (quick smoke test)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="wyze-bridge2-dev"
IMAGE="wyze-bridge-dev:latest"

# Ensure image exists
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Building Docker image..."
    docker build -t "$IMAGE" "$HERE/../bridge"
fi

# Start container if not running
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    # Stop stale container if exists
    docker rm -f "$CONTAINER" 2>/dev/null || true
    docker run -d --name "$CONTAINER" \
        --platform linux/arm64 \
        -v "$HERE:/work" \
        -v "$HERE/../bridge/libs:/work/libs:ro" \
        -v "$HERE/../apk:/apk:ro" \
        --env-file "$HERE/.env" \
        --network host \
        --cap-add NET_ADMIN --cap-add NET_RAW \
        -w /work \
        "$IMAGE" sleep infinity
    echo "Container $CONTAINER started."
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
        do_build
        DURATION="${2:-60}"
        echo ""
        echo "=== Running bridge2 (duration=${DURATION}s) ==="
        run_in ./build/bridge2 --duration "$DURATION" ${@:3}
        ;;
    test)
        do_build
        echo ""
        echo "=== Smoke test (15s) ==="
        run_in ./build/bridge2 --duration 15 ${@:2}
        ;;
    stop)
        docker rm -f "$CONTAINER" 2>/dev/null || true
        echo "Container stopped."
        ;;
    *)
        echo "Usage: $0 [shell|build|run [SECS]|test|stop]"
        exit 1
        ;;
esac
