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

All settings via `.env` (see `.env.example`). Three deployment tiers:

| Tier | Internet Use | Extra Setup |
|------|-------------|-------------|
| **Tier 1: Hybrid** (default) | Mars CALLING signaling only (~6KB/session) | None |
| **Tier 2: Fully Offline** | First-run auth only | Router DNAT rule |
| **Tier 3: Auto-Offline** | First-run auth only | Linux host + NET_ADMIN |

See [docs/configuration.md](docs/configuration.md) for full variable reference and tier configs.

## Development

```bash
scripts/into.sh              # Start go2rtc (dev mode)
scripts/into.sh build        # Compile bridge
scripts/into.sh run 30       # Run bridge for 30 seconds
scripts/into.sh shell        # Interactive shell in container
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for protocol details and system design.
