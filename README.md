# Wyze Doorbell Bridge

RTSP/WebRTC bridge for Wyze Video Doorbells. Streams on-demand H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) — the doorbell only wakes when a viewer connects.

Works with Home Assistant, Frigate, Scrypted, VLC, or anything that speaks RTSP.

## Requirements

- Docker with ARM64 support (native ARM64 host, or Docker Desktop with Rosetta/QEMU)
- Wyze account with API keys
- Decompiled Wyze APK with `libiotp2pav.so` and `libmbedtls.so` (placed in `../apk/` relative to this directory)

## Quick Start

```bash
# 1. Clone and enter the project
git clone <repo-url>
cd bridge

# 2. Set up credentials
cp .env.example .env
# Edit .env with your Wyze email, password, and API keys

# 3. Start the bridge
./into.sh
```

First run takes ~60s (patches libraries, compiles bridge). Subsequent starts take ~3s.

Once running:

| Endpoint | URL |
|----------|-----|
| RTSP | `rtsp://localhost:8554/doorbell` |
| Web UI | http://localhost:1984 |
| WebRTC | http://localhost:1984 (click stream) |

## Docker Compose

Add this to your existing `docker-compose.yml`:

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
      - "8554:8554"     # RTSP
      - "8555:8555/udp" # WebRTC
      - "1984:1984"     # go2rtc Web UI
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
    stop_grace_period: 15s
```

> **Note:** Do not use `env_file:` in your compose config. The `.env` file is loaded at runtime inside the container to preserve literal `$` characters in passwords. Place your `.env` in the `bridge/` directory.

## Home Assistant

Add to `configuration.yaml`:

```yaml
camera:
  - platform: generic
    stream_source: rtsp://YOUR_HOST_IP:8554/doorbell
    name: Wyze Doorbell
```

## Frigate

Add to your Frigate config:

```yaml
cameras:
  wyze_doorbell:
    ffmpeg:
      inputs:
        - path: rtsp://wyze-doorbell:8554/doorbell
          roles: [detect, record]
    detect:
      width: 1920
      height: 1080
```

## Scrypted

Add as an RTSP Camera plugin source with URL: `rtsp://YOUR_HOST_IP:8554/doorbell`

## How It Works

```
Viewer connects ─> go2rtc ─> spawns bridge ─> Wyze auth + P2P ─> H.264 stream
Viewer disconnects ─> go2rtc ─> kills bridge ─> doorbell sleeps
```

The bridge is **on-demand**: go2rtc launches it when the first viewer connects and kills it (SIGINT) when the last viewer disconnects. First connection takes ~15s (authentication + doorbell wake + P2P handshake). The doorbell is not streaming when no one is watching.

## Development

```bash
./into.sh shell        # Interactive shell inside the container
./into.sh build        # Compile bridge only
./into.sh test         # 15s smoke test (no go2rtc)
./into.sh run 30       # Run bridge for 30 seconds
./into.sh clean        # Stop + remove libs/ and build/
./into.sh rebuild      # Full image rebuild from scratch
./into.sh stop         # Stop everything
./into.sh logs         # Tail logs from running instance
```

## Credentials

You need a Wyze API key pair. Get them at https://developer-api-console.wyze.com/

| Variable | Description |
|----------|-------------|
| `WYZE_EMAIL` | Wyze account email |
| `WYZE_PASSWORD` | Wyze account password |
| `WYZE_KEY_ID` | API key ID from developer console |
| `WYZE_API_KEY` | API key secret from developer console |

## Project Structure

```
bridge/
  src/                  # C++ bridge source
  scripts/
    entrypoint.py       # Container entrypoint: setup, build, go2rtc lifecycle
  go2rtc.yaml           # go2rtc stream config
  docker-compose.yml    # Service definition
  Dockerfile            # Alpine ARM64 image with build tools + go2rtc
  into.sh               # Host-side convenience wrapper
  CMakeLists.txt        # Build config
  .env                  # Your credentials (not committed)
  .env.example          # Credential template
```
