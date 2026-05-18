# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Reverse-engineers the GUTES P2P protocol to stream H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) without cloud dependencies.

## Requirements

- Linux host with Docker (ARM64 native or x86_64 with QEMU)
- Wyze account + API keys from https://developer-api-console.wyze.com/

## Quick Start

```bash
# 1. Extract SDK libraries from Wyze APK
python3 scripts/setup_apk.py

# 2. Configure credentials
cp .env.example .env   # Edit with your Wyze email, password, API keys, DOORBELL_IP

# 3. Start
docker compose up -d

# 4. View stream
open http://localhost:1984/stream.html?src=doorbell
```

## Stream URLs

| Method | URL |
|--------|-----|
| Web UI | `http://HOST:1984/stream.html?src=doorbell` |
| RTSP | `rtsp://HOST:8554/doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://HOST:8554/doorbell` |

## Configuration

All settings via `.env` (see `.env.example`):

| Variable | Required | Description |
|----------|----------|-------------|
| `WYZE_EMAIL` | Yes | Wyze account email |
| `WYZE_PASSWORD` | Yes | Wyze account password |
| `WYZE_KEY_ID` | Yes | API key ID from developer console |
| `WYZE_API_KEY` | Yes | API key secret |
| `DOORBELL_IP` | Yes | Doorbell LAN IP (e.g. `192.168.1.81`) |
| `SKIP_WAKEUP` | No | `1` to skip cloud wakeup (doorbell already on relay keepalive) |
| `LAN_ONLY` | No | `1` to block cloud relay servers (force LAN video) |

## Development

```bash
scripts/into.sh              # Start go2rtc (dev mode)
scripts/into.sh build        # Compile bridge
scripts/into.sh run 30       # Run bridge for 30 seconds
scripts/into.sh shell        # Interactive shell in container
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for protocol details and system design.
