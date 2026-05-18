#!/usr/bin/env python3
# Docker entrypoint: lib setup, bridge build, relay, go2rtc lifecycle.

import os
import shutil
import signal
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path('/work/src')))
sys.path.insert(0, str(Path('/work/src/network')))
from log_config import get_logger
from network_setup import (
    check_iptables,
    cleanup_all_iptables,
    detect_relay_ip,
    resolve_mars_ips,
    setup_iptables_dnat,
    setup_lan_only_firewall as _network_setup_lan_only_firewall,
)
log = get_logger('entrypoint')

WORK       = Path("/work")
APK_LIBS   = Path("/apk/xapk_contents/arm64_libs/lib/arm64-v8a")
LIBS_DIR   = WORK / "libs"
BUILD_DIR  = WORK / "build"
BRIDGE_BIN = BUILD_DIR / "bridge"
GO2RTC_CFG = WORK / "go2rtc.yaml"
SRC_DIR    = WORK / "src"

BIONIC_REMOVE = ["libc.so", "libm.so", "libdl.so", "liblog.so"]
STDCPP_RENAME = ("libstdc++.so", "libstdc++.so.6")

SDK_LIBS = ["libiotp2pav.so", "libmbedtls.so"]

go2rtc_proc: subprocess.Popen | None = None
relay_proc: subprocess.Popen | None = None
shutting_down = False


def load_env_file(path: Path = WORK / ".env") -> dict[str, str]:

    env: dict[str, str] = {}
    if not path.is_file():
        log.info("No .env file at %s, skipping.", path)
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
    log.info("Loaded %d vars from %s", len(env), path)
    return env


def run(cmd: str | list[str], label: str | None = None) -> None:
    """Run a command, streaming output. Exit on failure."""
    if isinstance(cmd, str):
        display = cmd
        rc = subprocess.call(cmd, shell=True)
    else:
        display = " ".join(cmd)
        rc = subprocess.call(cmd)
    if rc != 0:
        log.error("FATAL: %s failed (exit %d)", label or display, rc)
        sys.exit(rc)


def patch_init_fini_arraysz(path: Path) -> None:
    """Zero DT_INIT_ARRAYSZ/DT_FINI_ARRAYSZ to prevent musl SIGSEGV on NULL constructors."""
    DT_INIT_ARRAYSZ = 0x1B
    DT_FINI_ARRAYSZ = 0x1C

    data = bytearray(path.read_bytes())

    # Verify ELF64 little-endian
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        log.info("  %s: not ELF64-LE, skipping init/fini patch", path.name)
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
        log.info("  %s: no PT_DYNAMIC found", path.name)
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
            log.info("  %s: zeroed %s", path.name, name)
            patched += 1
        pos += 16

    if patched:
        path.write_bytes(data)
    else:
        log.info("  %s: no INIT/FINI_ARRAYSZ found", path.name)


def setup_libs() -> None:
    """Compile shims and patch Android .so files for musl compatibility."""
    if (LIBS_DIR / "libiotp2pav.so").is_file():
        log.info("libs/ already set up, skipping.")
        return

    log.info("Setting up libraries...")

    # Clean slate
    if LIBS_DIR.exists():
        shutil.rmtree(LIBS_DIR)
    LIBS_DIR.mkdir()

    log.info("Compiling bionic_interpose.so...")
    run(f"gcc -shared -o {LIBS_DIR}/bionic_interpose.so {SRC_DIR}/bridge/bionic_interpose.c -fPIC -ldl -lpthread")

    log.info("Creating shim libraries...")

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

    for lib in SDK_LIBS:
        src = APK_LIBS / lib
        dst = LIBS_DIR / lib
        log.info("Patching %s...", lib)
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

    log.info("Verifying patched libraries:")
    for lib in SDK_LIBS:
        result = subprocess.run(
            ["patchelf", "--print-needed", str(LIBS_DIR / lib)],
            capture_output=True, text=True,
        )
        log.info("  %s: %s", lib, ', '.join(result.stdout.strip().splitlines()) or '(none)')

    log.info("Library setup complete.")


def build_bridge() -> None:
    """Compile the bridge and daemon binaries if not already built."""
    if BRIDGE_BIN.is_file() and (BUILD_DIR / "bridge-daemon").is_file():
        log.info("Bridge binaries exist, skipping build.")
        return
    log.info("Building bridge + daemon...")
    run(f"cmake -B {BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=Release {WORK}", "cmake")
    run(f"ninja -C {BUILD_DIR}", "ninja")


def shutdown(signum: int, _frame) -> None:
    """Graceful shutdown: forward signal to go2rtc, wait, exit."""
    global shutting_down
    if shutting_down:
        return
    shutting_down = True

    name = signal.Signals(signum).name
    log.info("Received %s, shutting down...", name)

    if go2rtc_proc and go2rtc_proc.poll() is None:
        go2rtc_proc.terminate()
        try:
            go2rtc_proc.wait(timeout=8)
            log.info("go2rtc stopped gracefully.")
        except subprocess.TimeoutExpired:
            log.warning("go2rtc didn't stop in 8s, killing...")
            go2rtc_proc.kill()
            go2rtc_proc.wait(timeout=3)

    if relay_proc and relay_proc.poll() is None:
        relay_proc.terminate()
        try:
            relay_proc.wait(timeout=3)
            log.info("Relay stopped.")
        except subprocess.TimeoutExpired:
            relay_proc.kill()

    # Clean up iptables rules
    cleanup_iptables()

    log.info("Shutdown complete.")
    sys.exit(0)


def setup_doorbell_dnat() -> bool:
    """DNAT doorbell's Mars traffic to local relay. Delegates to network_setup."""
    dotenv = load_env_file()
    doorbell_ip = dotenv.get("DOORBELL_IP", os.environ.get("DOORBELL_IP", ""))
    if not doorbell_ip:
        log.info("DOORBELL_IP not set — skipping DNAT setup")
        return False

    lan_only = dotenv.get("LAN_ONLY", os.environ.get("LAN_ONLY", "0"))
    if lan_only not in ("1", "true", "yes"):
        log.info("LAN_ONLY not enabled — skipping DNAT setup")
        return False

    if not check_iptables():
        log.info("iptables not available — skipping DNAT setup")
        return False

    # Push .env values into environ so network_setup picks them up
    os.environ["DOORBELL_IP"] = doorbell_ip
    relay_ip_env = dotenv.get("RELAY_IP", os.environ.get("RELAY_IP", ""))
    if relay_ip_env:
        os.environ["RELAY_IP"] = relay_ip_env

    relay_ip = detect_relay_ip()
    if not relay_ip:
        log.warning("Cannot detect relay IP — skipping DNAT setup")
        return False
    log.info("Relay IP: %s", relay_ip)

    mars_ips = resolve_mars_ips()
    log.info("Setting up doorbell DNAT: %s → %s (%d Mars IPs)",
             doorbell_ip, relay_ip, len(mars_ips))

    count = setup_iptables_dnat(relay_ip, mars_ips, [doorbell_ip])
    if count > 0:
        log.info("  Applied %d DNAT rules (doorbell Mars traffic → local relay)", count)
        return True
    else:
        log.warning("  No DNAT rules applied (iptables may lack permissions)")
        return False


def setup_lan_only_firewall() -> bool:
    """Block outbound TCP to cloud relay servers. Delegates to network_setup."""
    dotenv = load_env_file()
    lan_only = dotenv.get("LAN_ONLY", os.environ.get("LAN_ONLY", "0"))
    if lan_only not in ("1", "true", "yes"):
        return False
    return _network_setup_lan_only_firewall()


def cleanup_iptables() -> None:
    """Remove all iptables rules added by the bridge. Delegates to network_setup."""
    cleanup_all_iptables()


def start_relay() -> subprocess.Popen | None:
    """Start GUTES relay as a background process."""
    dotenv = load_env_file()
    upstream = dotenv.get("RELAY_UPSTREAM", "3.13.212.24:28800")
    mode = dotenv.get("RELAY_MODE", "proxy")
    keepalive = dotenv.get("RELAY_KEEPALIVE", "0") in ("1", "true", "yes")
    log_file = str(WORK / "relay.log")

    # Resolve current Mars servers for upstream (only needed in proxy mode)
    if mode == "proxy":
        import socket as _sock
        try:
            results = _sock.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, _sock.AF_INET)
            ips = list(set(r[4][0] for r in results))
            if ips:
                upstream = f"{ips[0]}:28800"
                log.info("Resolved Mars relay: %s (from %d IPs)", upstream, len(ips))
        except Exception:
            log.warning("DNS resolution failed, using default upstream: %s", upstream)

    cmd = [
        sys.executable, str(WORK / "src" / "relay" / "gutes_relay.py"),
        "--mode", mode,
        "--upstream", upstream,
        "--log-file", log_file,
        "--local-ip", "127.0.0.1",
        "--session-cache", str(WORK / "cache" / "session_keys.json"),
    ]
    if keepalive:
        cmd.append("--keepalive")

    log.info("Starting GUTES relay (%s mode, upstream=%s, keepalive=%s)", mode, upstream, keepalive)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Give it a moment to bind ports
    import time
    time.sleep(0.3)
    if proc.poll() is not None:
        log.warning("Relay exited immediately (rc=%s)", proc.returncode)
        return None

    log.info("GUTES relay running (mode=%s, keepalive=%s)", mode, keepalive)
    return proc


def main() -> None:
    global go2rtc_proc

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("Starting Wyze doorbell bridge...")

    setup_libs()
    build_bridge()

    setup_doorbell_dnat()
    setup_lan_only_firewall()

    relay_proc = start_relay()

    dotenv = load_env_file()
    env = {
        **os.environ,
        **dotenv,
        "LD_PRELOAD": str(LIBS_DIR / "bionic_interpose.so"),
        "LD_LIBRARY_PATH": f"{LIBS_DIR}:{APK_LIBS}",
        # Point SDK at our local relay instead of Mars cloud
        "P2P_URL": dotenv.get("P2P_URL", "|127.0.0.1"),
    }

    log.info("Starting go2rtc...")
    log.info("  RTSP:   rtsp://localhost:8554/doorbell")
    log.info("  WebRTC: http://localhost:1984")

    go2rtc_proc = subprocess.Popen(
        ["go2rtc", "-config", str(GO2RTC_CFG)],
        env=env,
    )

    rc = go2rtc_proc.wait()
    if not shutting_down:
        log.error("go2rtc exited unexpectedly (code %d)", rc)
        # Also stop the relay
        if relay_proc and relay_proc.poll() is None:
            relay_proc.terminate()
        sys.exit(rc)


if __name__ == "__main__":
    main()
