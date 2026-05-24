#!/usr/bin/env python3
# Docker entrypoint: lib setup, bridge build, relay, go2rtc lifecycle.
# Multi-device: enumerates all GW_* cameras, discovers LAN IPs, registers
# per-device go2rtc streams automatically — no manual IP config required.

import concurrent.futures
import json
import os
import shutil
import signal
import socket as _socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path('/work/src')))
sys.path.insert(0, str(Path('/work/src/network')))
sys.path.insert(0, str(Path('/work/src/relay')))
from log_config import get_logger
from network_setup import (
    check_iptables,
    cleanup_all_iptables,
    detect_relay_ip,
    resolve_mars_ips,
    setup_iptables_dnat,
)
log = get_logger('entrypoint')

WORK       = Path("/work")
APK_LIBS   = WORK / "apk" / "xapk_contents" / "arm64_libs" / "lib" / "arm64-v8a"
LIBS_DIR   = WORK / "libs"
BUILD_DIR  = WORK / "build"
BRIDGE_BIN = BUILD_DIR / "bridge"
GO2RTC_CFG = WORK / "go2rtc.yaml"
SRC_DIR    = WORK / "src"
CACHE_DIR  = WORK / "cache"

BIONIC_REMOVE = ["libc.so", "libm.so", "libdl.so", "liblog.so"]
STDCPP_RENAME = ("libstdc++.so", "libstdc++.so.6")
SDK_LIBS = ["libiotp2pav.so", "libmbedtls.so"]

go2rtc_proc: subprocess.Popen | None = None
relay_proc:  subprocess.Popen | None = None
shutting_down = False


# ---------------------------------------------------------------------------
# Env / config helpers
# ---------------------------------------------------------------------------

def load_env_file(path: Path = WORK / ".env") -> dict:
    env: dict = {}
    if not path.is_file():
        log.info("No .env file at %s, skipping.", path)
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip(); val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        env[key] = val
    log.info("Loaded %d vars from %s", len(env), path)
    return env


def _parse_camera_macs(value: str):
    """Parse CAMERA_MACS. 'all' or '' → None (no filter). Else list of MACs."""
    if not value or value.strip().lower() in ("all", ""):
        return None
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def run(cmd, label=None):
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
    DT_INIT_ARRAYSZ = 0x1B
    DT_FINI_ARRAYSZ = 0x1C
    data = bytearray(path.read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        log.info("  %s: not ELF64-LE, skipping", path.name)
        return
    e_phoff    = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum    = struct.unpack_from("<H", data, 56)[0]
    dyn_offset = dyn_size = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, off)[0] == 2:
            dyn_offset = struct.unpack_from("<Q", data, off + 8)[0]
            dyn_size   = struct.unpack_from("<Q", data, off + 32)[0]
            break
    if not dyn_offset:
        return
    patched = 0
    pos = dyn_offset
    while pos < dyn_offset + dyn_size:
        tag = struct.unpack_from("<q", data, pos)[0]
        if tag == 0:
            break
        if tag in (DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ):
            struct.pack_into("<Q", data, pos + 8, 0)
            patched += 1
        pos += 16
    if patched:
        path.write_bytes(data)


def setup_libs() -> None:
    if (LIBS_DIR / "libiotp2pav.so").is_file():
        log.info("libs/ already set up, skipping.")
        return
    log.info("Setting up libraries...")
    if LIBS_DIR.exists():
        shutil.rmtree(LIBS_DIR)
    LIBS_DIR.mkdir()
    log.info("Compiling bionic_interpose.so...")
    run(f"gcc -shared -o {LIBS_DIR}/bionic_interpose.so {SRC_DIR}/bridge/bionic_interpose.c -fPIC -ldl -lpthread")
    log.info("Creating shim libraries...")
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
    (LIBS_DIR / "libc.so").symlink_to("/lib/ld-musl-aarch64.so.1")
    run(f"echo 'void __stub(void){{}}' | gcc -shared -o {LIBS_DIR}/libm.so -x c - -fPIC")
    run(f"echo 'void __stub(void){{}}' | gcc -shared -o {LIBS_DIR}/libdl.so -x c - -fPIC")
    (LIBS_DIR / "libstdc++.so").symlink_to("/usr/lib/libstdc++.so.6")
    for lib in SDK_LIBS:
        src = APK_LIBS / lib; dst = LIBS_DIR / lib
        log.info("Patching %s...", lib)
        shutil.copy2(src, dst)
        for needed in BIONIC_REMOVE:
            run(["patchelf", "--remove-needed", needed, str(dst)], f"patchelf {lib}")
        run(["patchelf", "--replace-needed", STDCPP_RENAME[0], STDCPP_RENAME[1], str(dst)],
            f"patchelf {lib}")
        patch_init_fini_arraysz(dst)
    log.info("Library setup complete.")


def build_bridge() -> None:
    if BRIDGE_BIN.is_file() and (BUILD_DIR / "bridge-daemon").is_file():
        log.info("Bridge binaries exist, skipping build.")
        return
    log.info("Building bridge + daemon...")
    run(f"cmake -B {BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=Release {WORK}", "cmake")
    run(f"ninja -C {BUILD_DIR}", "ninja")


# ---------------------------------------------------------------------------
# Device registry and LAN discovery
# ---------------------------------------------------------------------------

def build_device_registry(dotenv: dict):
    """Enumerate all cameras from Wyze API and discover their LAN IPs.

    Returns a populated DeviceRegistry with lan_ip set on any discovered device.
    """
    from device_registry import DeviceRegistry

    cache_path = CACHE_DIR / "device_registry.json"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    filter_macs = _parse_camera_macs(dotenv.get("CAMERA_MACS", "all"))

    log.info("Enumerating cameras from Wyze API...")
    try:
        registry = DeviceRegistry.from_wyze_api(
            email    = dotenv["WYZE_EMAIL"],
            password = dotenv["WYZE_PASSWORD"],
            key_id   = dotenv["WYZE_KEY_ID"],
            api_key  = dotenv["WYZE_API_KEY"],
            filter_macs=filter_macs,
        )
    except Exception as e:
        log.error("Failed to enumerate cameras: %s", e)
        sys.exit(1)

    log.info("Found %d camera(s): %s",
             len(registry.devices), [d.mac for d in registry.devices])

    # LAN discovery: concurrent broadcast + unicast probes
    _discover_lan_ips(registry)

    registry.save_cache(cache_path)
    return registry


def _discover_lan_ips(registry, timeout: float = 15.0) -> None:
    """Concurrently probe each device for its LAN IP via UDP broadcast + unicast."""
    probe = bytearray(28)
    probe[0] = 0x70; probe[1] = 0x02
    struct.pack_into('<H', probe, 2, 28)

    def probe_device(info) -> None:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.settimeout(2.0)
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                try:
                    sock.sendto(bytes(probe), ('255.255.255.255', 8899))
                    if info.cloud_ip:
                        sock.sendto(bytes(probe), (info.cloud_ip, 8899))
                except Exception:
                    pass
                try:
                    data, addr = sock.recvfrom(4096)
                    if len(data) >= 0x40 and data[0] == 0x70 and data[1] == 0x03:
                        frame_mac = ':'.join(f'{b:02x}' for b in data[0x3A:0x40]).upper()
                        if frame_mac == info.mac:
                            dst_id   = struct.unpack_from('<q', data, 0x1C)[0]
                            mtp_port = struct.unpack_from('<H', data, 0x2C)[0]
                            registry.update_discovery(info.mac, addr[0], mtp_port, dst_id)
                            log.info("  Discovered %s (%s) → %s mtp=%d",
                                     info.name, info.mac, addr[0], mtp_port)
                            return
                except _socket.timeout:
                    pass
        finally:
            sock.close()
        log.warning("  LAN discovery timeout for %s (%s cloud_ip=%s)",
                    info.name, info.mac, info.cloud_ip or '?')

    n = len(registry.devices)
    if n == 0:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(probe_device, registry.devices))


# ---------------------------------------------------------------------------
# Network setup
# ---------------------------------------------------------------------------

def setup_network(registry) -> bool:
    """Set up DNAT + ARP rules for all discovered device IPs."""
    doorbell_ips = [d.lan_ip for d in registry.devices if d.lan_ip]
    if not doorbell_ips:
        log.warning("No LAN IPs discovered — skipping DNAT setup")
        return False
    if not check_iptables():
        log.info("iptables not available — skipping DNAT setup")
        return False

    relay_ip = detect_relay_ip()
    if not relay_ip:
        log.warning("Cannot detect relay IP — skipping DNAT setup")
        return False

    mars_ips = resolve_mars_ips()
    log.info("Setting up DNAT for %d device(s): %s → relay %s (%d Mars IPs)",
             len(doorbell_ips), doorbell_ips, relay_ip, len(mars_ips))
    count = setup_iptables_dnat(relay_ip, mars_ips, doorbell_ips)
    log.info("Applied %d DNAT rules", count)
    return count > 0


# ---------------------------------------------------------------------------
# go2rtc stream registration
# ---------------------------------------------------------------------------

def write_go2rtc_streams(registry) -> None:
    """Write per-device streams directly into go2rtc.yaml before go2rtc starts.

    Each camera gets a stream named camera_{mac_clean} pointing at run_bridge.sh.
    go2rtc reads this file at startup — no REST API needed.
    """
    streams_block = ""
    for info in registry.devices:
        source = (f"exec:/work/scripts/run_bridge.sh --device {info.mac}"
                  f"#video=h264#killsignal=2#killtimeout=10")
        streams_block += f"  {info.stream_name}:\n    - {source}\n"

    config = f"""# go2rtc config — streams auto-generated by entrypoint.py at startup

streams:
{streams_block}
rtsp:
  listen: ":8554"
  default_query: "video"

webrtc:
  listen: ":8555"

api:
  listen: ":1984"

log:
  level: info
"""
    GO2RTC_CFG.write_text(config)
    log.info("Wrote %d stream(s) to %s", len(registry.devices), GO2RTC_CFG)
    for info in registry.devices:
        log.info("  %s → %s", info.stream_name, info.mac)


def register_go2rtc_streams(registry, api_url: str = "http://127.0.0.1:1984") -> None:
    """Kept for compatibility — stream registration now happens via go2rtc.yaml
    written before go2rtc starts. This function is a no-op."""
    pass


# ---------------------------------------------------------------------------
# Relay and shutdown
# ---------------------------------------------------------------------------

def start_relay(registry_path: str = "") -> subprocess.Popen | None:
    dotenv = load_env_file()
    mode   = dotenv.get("RELAY_MODE", "relay")
    log_file = str(WORK / "relay.log")

    upstream = "3.13.212.24:28800"
    if mode == "proxy":
        try:
            results = _socket.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, _socket.AF_INET)
            ips = list(set(r[4][0] for r in results))
            if ips:
                upstream = f"{ips[0]}:28800"
        except Exception:
            pass

    cmd = [
        sys.executable, str(WORK / "src" / "relay" / "gutes_relay.py"),
        "--mode", mode,
        "--log-file", log_file,
        "--local-ip", "127.0.0.1",
        "--session-cache", str(WORK / "cache" / "session_keys.json"),
        "--keepalive",
    ]
    if registry_path:
        cmd += ["--registry", registry_path]

    log.info("Starting GUTES relay (mode=%s, keepalive=yes)", mode)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.3)
    if proc.poll() is not None:
        log.warning("Relay exited immediately (rc=%s)", proc.returncode)
        return None
    log.info("GUTES relay running")
    return proc


def shutdown(signum: int, _frame) -> None:
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
        except subprocess.TimeoutExpired:
            go2rtc_proc.kill()
            go2rtc_proc.wait(timeout=3)
    if relay_proc and relay_proc.poll() is None:
        relay_proc.terminate()
        try:
            relay_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            relay_proc.kill()
    cleanup_all_iptables()
    log.info("Shutdown complete.")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global go2rtc_proc, relay_proc

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("Starting Wyze camera bridge (multi-device)...")

    setup_libs()
    build_bridge()

    dotenv = load_env_file()
    for k, v in dotenv.items():
        os.environ.setdefault(k, v)

    # 1. Enumerate cameras and discover LAN IPs
    registry      = build_device_registry(dotenv)
    registry_path = str(WORK / "cache" / "device_registry.json")

    # 2. Network rules for all discovered IPs
    setup_network(registry)

    # 3. Write per-device streams to go2rtc.yaml (must happen before go2rtc starts)
    write_go2rtc_streams(registry)

    # 4. Start relay — skip if RELAY_EXTERNAL=1 (relay runs in its own container)
    relay_external = os.environ.get("RELAY_EXTERNAL", "0") in ("1", "true", "yes")
    if relay_external:
        log.info("RELAY_EXTERNAL=1 — relay managed externally, skipping local start")
    else:
        relay_proc = start_relay(registry_path=registry_path)

    # 4. Start go2rtc
    env = {
        **os.environ,
        **dotenv,
        "LD_PRELOAD":      str(LIBS_DIR / "bionic_interpose.so"),
        "LD_LIBRARY_PATH": f"{LIBS_DIR}:{APK_LIBS}",
        "P2P_URL":         dotenv.get("P2P_URL", "|127.0.0.1"),
    }
    log.info("Starting go2rtc...")
    go2rtc_proc = subprocess.Popen(["go2rtc", "-config", str(GO2RTC_CFG)], env=env)

    # 5. Register per-device streams via go2rtc REST API
    register_go2rtc_streams(registry)

    # 6. Print stream URLs
    log.info("")
    log.info("=" * 60)
    log.info("  Streams registered (%d camera(s)):", len(registry.devices))
    for d in registry.devices:
        log.info("    %-20s (%s)", d.name, d.mac)
        log.info("      RTSP:   rtsp://localhost:8554/%s", d.stream_name)
        log.info("      WebRTC: http://localhost:1984/?src=%s", d.stream_name)
    log.info("=" * 60)
    log.info("")

    rc = go2rtc_proc.wait()
    if not shutting_down:
        log.error("go2rtc exited unexpectedly (code %d)", rc)
        if relay_proc and relay_proc.poll() is None:
            relay_proc.terminate()
        sys.exit(rc)


if __name__ == "__main__":
    main()
