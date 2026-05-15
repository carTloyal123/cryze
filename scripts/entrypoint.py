#!/usr/bin/env python3
"""entrypoint.py — Wyze doorbell bridge lifecycle manager.

Runs inside the Docker container as PID 1. Handles:
  1. First-run setup (lib patching, bridge compilation)
  2. Starting go2rtc (which manages bridge on-demand via exec source)
  3. Graceful shutdown on SIGINT/SIGTERM (Docker stop / Ctrl+C)
  4. Live log streaming from go2rtc + bridge to container stdout
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────

WORK       = "/work"
APK_LIB    = "/apk/xapk_contents/arm64_libs/lib/arm64-v8a"
LIBS_DIR   = f"{WORK}/libs"
BRIDGE_BIN = f"{WORK}/build/bridge"
GO2RTC_CFG = f"{WORK}/go2rtc.yaml"
SETUP_SH   = f"{WORK}/scripts/setup-libs.sh"

ENV_OVERLAY = {
    "LD_PRELOAD":      f"{LIBS_DIR}/bionic_interpose.so",
    "LD_LIBRARY_PATH": f"{LIBS_DIR}:{APK_LIB}",
}

go2rtc_proc = None  # type: subprocess.Popen | None
shutting_down = False


# ── Helpers ────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[entrypoint] {msg}", flush=True)


def load_env_file(path: str = f"{WORK}/.env") -> dict[str, str]:
    """Parse a .env file into a dict. Handles quotes and comments.
    
    Does NOT use shell expansion — dollar signs are literal, which is
    exactly what we need (docker compose corrupts $ in passwords).
    """
    env = {}
    p = Path(path)
    if not p.is_file():
        log(f"No .env file at {path}, skipping.")
        return env
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        # Strip surrounding quotes (single or double)
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        env[key] = val
    log(f"Loaded {len(env)} vars from {path}")
    return env


def run(cmd: str, label: str | None = None) -> None:
    """Run a shell command, streaming output. Raises on failure."""
    label = label or cmd.split()[0]
    log(f"Running: {cmd}")
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        log(f"FATAL: {label} failed (exit {rc})")
        sys.exit(rc)


def setup_libs() -> None:
    """Patch Android .so files if not already done."""
    if os.path.isfile(f"{LIBS_DIR}/libiotp2pav.so"):
        log("libs/ already set up, skipping.")
        return
    log("Running first-time library setup...")
    run(f"sh {SETUP_SH}", "setup-libs")


def build_bridge() -> None:
    """Compile the bridge binary if not already built."""
    if os.path.isfile(BRIDGE_BIN):
        log("bridge binary exists, skipping build.")
        return
    log("Building bridge...")
    run(f"cmake -B {WORK}/build -G Ninja -DCMAKE_BUILD_TYPE=Release {WORK}", "cmake")
    run(f"ninja -C {WORK}/build", "ninja")


# ── Signal handling ────────────────────────────────────────────────

def shutdown(signum: int, _frame) -> None:
    """Graceful shutdown: forward signal to go2rtc, wait, exit."""
    global shutting_down
    if shutting_down:
        return  # prevent re-entrancy
    shutting_down = True

    name = signal.Signals(signum).name
    log(f"Received {name}, shutting down...")

    if go2rtc_proc and go2rtc_proc.poll() is None:
        # Send SIGTERM to go2rtc (which sends SIGINT to bridge children)
        go2rtc_proc.terminate()
        try:
            go2rtc_proc.wait(timeout=8)
            log("go2rtc stopped gracefully.")
        except subprocess.TimeoutExpired:
            log("go2rtc didn't stop in 8s, killing...")
            go2rtc_proc.kill()
            go2rtc_proc.wait(timeout=3)

    log("Shutdown complete.")
    sys.exit(0)


# ── Main ───────────────────────────────────────────────────────────

def main() -> None:
    global go2rtc_proc

    # Register signal handlers FIRST
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log("Starting Wyze doorbell bridge...")

    # Phase 1: Setup
    setup_libs()
    build_bridge()

    # Phase 2: Start go2rtc
    dotenv = load_env_file()
    env = {**os.environ, **dotenv, **ENV_OVERLAY}

    log("Starting go2rtc...")
    log(f"  RTSP:   rtsp://localhost:8554/doorbell")
    log(f"  WebRTC: http://localhost:1984")
    log(f"  Web UI: http://localhost:1984")
    log("")

    go2rtc_proc = subprocess.Popen(
        ["go2rtc", "-config", GO2RTC_CFG],
        env=env,
        # stdout/stderr inherited — go2rtc logs (including bridge stderr)
        # flow directly to container stdout for `docker compose logs`
    )

    # Phase 3: Wait for go2rtc to exit (or signal)
    rc = go2rtc_proc.wait()

    if not shutting_down:
        log(f"go2rtc exited unexpectedly (code {rc})")
        sys.exit(rc)


if __name__ == "__main__":
    main()
