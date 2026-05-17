# Setup

## Docker Compose

```yaml
services:
  wyze-doorbell:
    build: ./bridge
    image: wyze-bridge:latest
    container_name: wyze-doorbell
    platform: linux/arm64
    working_dir: /work
    volumes:
      - ./bridge:/work
      - ./apk:/apk:ro
    ports:
      - "1984:1984"     # go2rtc Web UI
      - "8554:8554"     # RTSP
      - "8555:8555/udp" # WebRTC
    # On Linux, use network_mode: host instead of ports for full
    # UDP support (VLC, etc). Remove the ports section if you do.
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
    stop_grace_period: 15s
```

> Do not use `env_file:` in your compose config. The `.env` is loaded at runtime inside the container to preserve literal `$` characters in passwords.

## x86 Hosts

The Wyze SDK libraries are ARM64 binaries, but the bridge runs fine on x86_64 Linux via QEMU user-mode emulation. Docker handles this transparently — you just need binfmt_misc registered:

```bash
# One-time setup on x86 Linux (most Docker Desktop installs have this already)
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

The `platform: linux/arm64` in docker-compose.yml tells Docker to use QEMU automatically. First-run build takes longer under emulation (~2-3 min vs ~30s native) but subsequent starts are fast since everything is cached.

## VLC

VLC defaults to UDP for RTSP, which doesn't work through Docker's port mapping. Change VLC to use TCP:

1. **Preferences** > **Input / Codecs**
2. Set **RTP over RTSP (TCP)** or **Live555 stream transport** to **TCP**
3. Open `rtsp://localhost:8554/doorbell`

On a Linux host with `network_mode: host`, VLC works without any changes since UDP is not NATed.

Alternatively, use `ffplay` or the go2rtc Web UI — both work out of the box.
