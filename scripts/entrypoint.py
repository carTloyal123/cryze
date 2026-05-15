#!/usr/bin/env python3
"""entrypoint.py — Wyze doorbell bridge lifecycle manager.

Runs inside the Docker container as PID 1. Handles:
  1. First-run setup (compile shims, patch Android .so files)
  2. Bridge compilation (cmake + ninja)
  3. Starting go2rtc (which manages bridge on-demand via exec source)
  4. Graceful shutdown on SIGINT/SIGTERM (Docker stop / Ctrl+C)
"""

import os
import shutil
import signal
import struct
import subprocess
import sys
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────

WORK       = Path("/work")
APK_LIBS   = Path("/apk/xapk_contents/arm64_libs/lib/arm64-v8a")
LIBS_DIR   = WORK / "libs"
BUILD_DIR  = WORK / "build"
BRIDGE_BIN = BUILD_DIR / "bridge"
GO2RTC_CFG = WORK / "go2rtc.yaml"
SRC_DIR    = WORK / "src"

# Bionic DT_NEEDED entries to strip from Android .so files
BIONIC_REMOVE = ["libc.so", "libm.so", "libdl.so", "liblog.so"]
# Rename libstdc++.so -> libstdc++.so.6 to match Alpine's naming
STDCPP_RENAME = ("libstdc++.so", "libstdc++.so.6")

# Android .so files to copy and patch from APK
SDK_LIBS = ["libiotp2pav.so", "libmbedtls.so"]

go2rtc_proc: subprocess.Popen | None = None
shutting_down = False


# ── Logging ────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[entrypoint] {msg}", flush=True)


# ── .env loader ────────────────────────────────────────────────────

def load_env_file(path: Path = WORK / ".env") -> dict[str, str]:
    """Parse a .env file into a dict without shell expansion.

    Dollar signs are kept literal — docker compose corrupts passwords
    containing $ when it does variable substitution, so we load .env
    ourselves at runtime instead.
    """
    env: dict[str, str] = {}
    if not path.is_file():
        log(f"No .env file at {path}, skipping.")
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        env[key] = val
    log(f"Loaded {len(env)} vars from {path}")
    return env


# ── Shell helper ───────────────────────────────────────────────────

def run(cmd: str | list[str], label: str | None = None) -> None:
    """Run a command, streaming output. Exit on failure."""
    if isinstance(cmd, str):
        display = cmd
        rc = subprocess.call(cmd, shell=True)
    else:
        display = " ".join(cmd)
        rc = subprocess.call(cmd)
    if rc != 0:
        log(f"FATAL: {label or display} failed (exit {rc})")
        sys.exit(rc)


# ── ELF patcher ───────────────────────────────────────────────────

def patch_init_fini_arraysz(path: Path) -> None:
    """Zero out DT_INIT_ARRAYSZ and DT_FINI_ARRAYSZ in an ELF64 binary.

    Android's bionic linker skips NULL entries in INIT_ARRAY/FINI_ARRAY,
    but musl calls them unconditionally -> SIGSEGV at pc=0. The Android
    .so files have NULL placeholder entries with no relocation to fill
    them, so we set the array sizes to 0 to tell musl to skip them.
    """
    DT_INIT_ARRAYSZ = 0x1B
    DT_FINI_ARRAYSZ = 0x1C

    data = bytearray(path.read_bytes())

    # Verify ELF64 little-endian
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        log(f"  {path.name}: not ELF64-LE, skipping init/fini patch")
        return

    # Parse ELF header
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    # Find PT_DYNAMIC (p_type == 2)
    dyn_offset = dyn_size = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type == 2:
            dyn_offset = struct.unpack_from("<Q", data, off + 8)[0]
            dyn_size = struct.unpack_from("<Q", data, off + 32)[0]
            break

    if not dyn_offset:
        log(f"  {path.name}: no PT_DYNAMIC found")
        return

    # Scan dynamic entries, zero INIT_ARRAYSZ and FINI_ARRAYSZ
    patched = 0
    pos = dyn_offset
    while pos < dyn_offset + dyn_size:
        tag = struct.unpack_from("<q", data, pos)[0]
        if tag == 0:  # DT_NULL
            break
        if tag in (DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ):
            name = "INIT_ARRAYSZ" if tag == DT_INIT_ARRAYSZ else "FINI_ARRAYSZ"
            struct.pack_into("<Q", data, pos + 8, 0)
            log(f"  {path.name}: zeroed {name}")
            patched += 1
        pos += 16

    if patched:
        path.write_bytes(data)
    else:
        log(f"  {path.name}: no INIT/FINI_ARRAYSZ found")


# ── Library setup ──────────────────────────────────────────────────

def setup_libs() -> None:
    """Compile shims and patch Android .so files for musl compatibility."""
    if (LIBS_DIR / "libiotp2pav.so").is_file():
        log("libs/ already set up, skipping.")
        return

    log("Setting up libraries...")

    # Clean slate
    if LIBS_DIR.exists():
        shutil.rmtree(LIBS_DIR)
    LIBS_DIR.mkdir()

    # -- Compile shim libraries --
    log("Compiling bionic_interpose.so...")
    run(f"gcc -shared -o {LIBS_DIR}/bionic_interpose.so {SRC_DIR}/bionic_interpose.c -fPIC -ldl -lpthread")

    log("Creating shim libraries...")

    # liblog.so — weak stubs (bridge exe provides strong ones via -rdynamic)
    liblog_src = """
#include <stdio.h>
#include <stdarg.h>
__attribute__((weak)) int __android_log_print(int p, const char* t, const char* f, ...) {
    (void)p; (void)t; (void)f; return 0;
}
__attribute__((weak)) int __android_log_write(int p, const char* t, const char* m) {
    (void)p; (void)t; (void)m; return 0;
}
__attribute__((weak)) int __android_log_vprint(int p, const char* t, const char* f, va_list a) {
    (void)p; (void)t; (void)f; (void)a; return 0;
}
"""
    tmp_log = Path("/tmp/shim_log.c")
    tmp_log.write_text(liblog_src)
    run(f"gcc -shared -o {LIBS_DIR}/liblog.so {tmp_log} -fPIC")

    # libc.so — symlink to musl
    (LIBS_DIR / "libc.so").symlink_to("/lib/ld-musl-aarch64.so.1")

    # libm.so, libdl.so — empty stubs (musl bundles these into libc)
    run(f"echo 'void __stub(void){{}}' | gcc -shared -o {LIBS_DIR}/libm.so -x c - -fPIC")
    run(f"echo 'void __stub(void){{}}' | gcc -shared -o {LIBS_DIR}/libdl.so -x c - -fPIC")

    # libstdc++.so — point to system
    (LIBS_DIR / "libstdc++.so").symlink_to("/usr/lib/libstdc++.so.6")

    # -- Copy and patch Android .so files --
    for lib in SDK_LIBS:
        src = APK_LIBS / lib
        dst = LIBS_DIR / lib
        log(f"Patching {lib}...")
        shutil.copy2(src, dst)

        # Strip bionic DT_NEEDED entries
        for needed in BIONIC_REMOVE:
            # --remove-needed is a no-op if the entry doesn't exist
            run(["patchelf", "--remove-needed", needed, str(dst)], f"patchelf {lib}")

        # Rename libstdc++.so -> libstdc++.so.6
        run(["patchelf", "--replace-needed", STDCPP_RENAME[0], STDCPP_RENAME[1], str(dst)],
            f"patchelf {lib}")

        # Zero INIT/FINI_ARRAYSZ to prevent musl SIGSEGV on NULL constructors
        patch_init_fini_arraysz(dst)

    # -- Verify --
    log("Verifying patched libraries:")
    for lib in SDK_LIBS:
        result = subprocess.run(
            ["patchelf", "--print-needed", str(LIBS_DIR / lib)],
            capture_output=True, text=True,
        )
        log(f"  {lib}: {', '.join(result.stdout.strip().splitlines()) or '(none)'}")

    log("Library setup complete.")


# ── Bridge build ───────────────────────────────────────────────────

def build_bridge() -> None:
    """Compile the bridge binary if not already built."""
    if BRIDGE_BIN.is_file():
        log("Bridge binary exists, skipping build.")
        return
    log("Building bridge...")
    run(f"cmake -B {BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=Release {WORK}", "cmake")
    run(f"ninja -C {BUILD_DIR}", "ninja")


# ── Signal handling ────────────────────────────────────────────────

def shutdown(signum: int, _frame) -> None:
    """Graceful shutdown: forward signal to go2rtc, wait, exit."""
    global shutting_down
    if shutting_down:
        return
    shutting_down = True

    name = signal.Signals(signum).name
    log(f"Received {name}, shutting down...")

    if go2rtc_proc and go2rtc_proc.poll() is None:
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

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log("Starting Wyze doorbell bridge...")

    # Phase 1: Setup and build
    setup_libs()
    build_bridge()

    # Phase 2: Start go2rtc with .env and LD_PRELOAD/LD_LIBRARY_PATH
    dotenv = load_env_file()
    env = {
        **os.environ,
        **dotenv,
        "LD_PRELOAD": str(LIBS_DIR / "bionic_interpose.so"),
        "LD_LIBRARY_PATH": f"{LIBS_DIR}:{APK_LIBS}",
    }

    log("Starting go2rtc...")
    log("  RTSP:   rtsp://localhost:8554/doorbell")
    log("  WebRTC: http://localhost:1984")

    go2rtc_proc = subprocess.Popen(
        ["go2rtc", "-config", str(GO2RTC_CFG)],
        env=env,
    )

    # Phase 3: Wait for go2rtc (or signal)
    rc = go2rtc_proc.wait()
    if not shutting_down:
        log(f"go2rtc exited unexpectedly (code {rc})")
        sys.exit(rc)


if __name__ == "__main__":
    main()
