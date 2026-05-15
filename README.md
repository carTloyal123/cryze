# Wyze Doorbell Bridge

RTSP/WebRTC bridge for Wyze Video Doorbells. Streams on-demand H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) — the doorbell only wakes when a viewer connects.

## Requirements

- Docker with ARM64 support (native ARM64 host, or Docker Desktop with Rosetta/QEMU)
- Wyze account with API keys from https://developer-api-console.wyze.com/
- Decompiled Wyze APK with `libiotp2pav.so` and `libmbedtls.so` (placed in `../apk/` relative to this directory)

## Quick Start

```bash
# 1. Set up credentials
cp .env.example .env
# Edit .env with your Wyze email, password, and API keys

# 2. Start the bridge
./into.sh
```

First run takes ~60s (patches libraries, compiles bridge). Subsequent starts take ~3s.

## Stream Endpoints

| Endpoint | URL |
|----------|-----|
| Web UI (easiest) | http://localhost:1984 |
| RTSP | `rtsp://localhost:8554/doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://localhost:8554/doorbell` |

The stream is on-demand — the first connection takes ~15s while the doorbell wakes up.

## Docker Compose

To add to an existing `docker-compose.yml`:

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

> Do not use `env_file:` in your compose config. The `.env` is loaded at runtime inside the container to preserve literal `$` characters in passwords.

## How It Works

```
Viewer connects ─> go2rtc ─> spawns bridge ─> Wyze auth + P2P ─> H.264 stream
Viewer disconnects ─> go2rtc ─> kills bridge ─> doorbell sleeps
```

## Development

```bash
./into.sh              # Start go2rtc (Ctrl+C to stop)
./into.sh stop         # Stop and free ports
./into.sh logs         # Tail logs
./into.sh shell        # Interactive shell in container
./into.sh build        # Compile bridge only
./into.sh test         # 15s smoke test
./into.sh run 30       # Run bridge for 30 seconds
./into.sh clean        # Stop + remove build artifacts
./into.sh rebuild      # Full image rebuild
```

## Credentials

| Variable | Description |
|----------|-------------|
| `WYZE_EMAIL` | Wyze account email |
| `WYZE_PASSWORD` | Wyze account password |
| `WYZE_KEY_ID` | API key ID from developer console |
| `WYZE_API_KEY` | API key secret from developer console |
