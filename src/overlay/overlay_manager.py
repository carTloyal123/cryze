#!/usr/bin/env python3
"""overlay_manager.py — native amd64 ffmpeg overlay service.

For each camera in the registry:
  - Binds OVERLAY_PORT: go2rtc connects here (exec: nc 127.0.0.1 OVERLAY_PORT)
  - On viewer connect: starts ffmpeg reading raw H.264 from RAW_PORT (tcp_relay.py)
    with drawtext overlay from /cache/metrics_{mac}.txt, outputs to viewer
  - On disconnect: kills ffmpeg, waits for next viewer
"""
import json, logging, os, signal, socket, subprocess, sys, threading, time
from pathlib import Path

logging.basicConfig(level=os.environ.get("LOG_LEVEL","INFO").upper(),
    format="%(asctime)s [overlay] %(levelname)s %(message)s")
log = logging.getLogger("overlay")

CACHE_DIR = Path(os.environ.get("CACHE_DIR", "/cache"))
FONT      = "/usr/share/fonts/dejavu/DejaVuSans.ttf"


def load_registry():
    path = CACHE_DIR / "device_registry.json"
    for attempt in range(60):
        try:
            data = json.loads(path.read_text())
            devices = data.get("devices", [])
            if devices:
                return devices
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if attempt == 0:
            log.info("Waiting for device_registry.json...")
        time.sleep(1)
    log.error("device_registry.json not found after 60s"); sys.exit(1)


def build_ffmpeg_cmd(device):
    mc          = device["mac"].replace(":","").lower()
    raw_port    = device["raw_port"]
    metrics_txt = str(CACHE_DIR / f"metrics_{mc}.txt")
    drawtext = (
        f"drawtext=textfile={metrics_txt}:reload=1:"
        f"fontfile={FONT}:fontsize=20:fontcolor=white:"
        f"shadowcolor=black:shadowx=2:shadowy=2:x=10:y=10:fix_bounds=1"
    )
    return [
        "ffmpeg", "-loglevel", "warning",
        "-f", "h264", "-i", f"tcp://127.0.0.1:{raw_port}?timeout=30000000",
        "-vf", drawtext,
        "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
        "-x264-params", "keyint=30:min-keyint=30:scenecut=0",
        "-f", "h264", "pipe:1",
    ]


class OverlayPipeline:
    def __init__(self, device):
        self.device       = device
        self.name         = device.get("name", device["mac"])
        self.overlay_port = device["overlay_port"]
        self.raw_port     = device["raw_port"]
        self._t = threading.Thread(target=self._run, daemon=True,
                                   name=f"overlay-{device['mac'].replace(':','')[:8]}")

    def start(self): self._t.start()

    def _run(self):
        log.info("Pipeline ready: %s  raw=:%d  overlay=:%d",
                 self.name, self.raw_port, self.overlay_port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.overlay_port))
        srv.listen(1)

        while True:
            log.info("%s: waiting for viewer on :%d", self.name, self.overlay_port)
            try:
                client, addr = srv.accept()
            except OSError as e:
                log.error("%s: accept error: %s", self.name, e); break

            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            log.info("%s: viewer connected from %s", self.name, addr)

            cmd = build_ffmpeg_cmd(self.device)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                log.error("ffmpeg not found"); client.close(); continue

            def relay(proc=proc, client=client):
                try:
                    while True:
                        chunk = proc.stdout.read(65536)
                        if not chunk: break
                        client.sendall(chunk)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    client.close()
                    try: proc.send_signal(signal.SIGINT)
                    except ProcessLookupError: pass

            t = threading.Thread(target=relay, daemon=True); t.start(); t.join()
            proc.wait()
            log.info("%s: ffmpeg exited (rc=%d), ready for next viewer",
                     self.name, proc.returncode)


def main():
    log.info("wyze-overlay starting (cache=%s)", CACHE_DIR)
    devices = load_registry()
    log.info("Loaded %d device(s)", len(devices))
    for device in devices:
        device.setdefault("mac_clean", device["mac"].replace(":","").lower())
        if not device.get("raw_port") or not device.get("overlay_port"):
            log.warning("Device %s missing port assignments — skipping", device["mac"])
            continue
        p = OverlayPipeline(device)
        p.start()
        log.info("  Started pipeline: %s  raw=:%d  overlay=:%d",
                 device.get("name", device["mac"]),
                 device["raw_port"], device["overlay_port"])
    try:
        signal.pause()
    except KeyboardInterrupt:
        log.info("Shutting down")

if __name__ == "__main__":
    main()
