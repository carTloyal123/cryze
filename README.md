# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Streams H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) with sub-5-second time-to-first-frame.

## Requirements

- Linux host with Docker (ARM64 native or x86_64 with QEMU)
- Wyze account with API keys from https://developer-api-console.wyze.com/

## Quick Start

```bash
# 1. Extract SDK libraries from Wyze APK
python3 scripts/setup_apk.py

# 2. Configure credentials
cp .env.example .env
# Edit .env with your Wyze email, password, API keys, and DOORBELL_IP

# 3. Start all services
docker compose up -d

# 4. View stream
# Open http://localhost:1984/stream.html?src=doorbell
```

## Viewing the Stream

| Method | URL |
|--------|-----|
| Web UI | `http://host:1984/stream.html?src=doorbell` |
| RTSP | `rtsp://host:8554/doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://host:8554/doorbell` |

## Services

| Service | What it does |
|---------|-------------|
| `network-setup` | iptables DNAT + ARP redirect (intercepts doorbell Mars traffic) |
| `relay` | GUTES protocol relay (handles all P2P signaling locally) |
| `go2rtc` | Stream server (RTSP / WebRTC / API) |
| `bridge-builder` | Compiles ARM64 bridge binary (one-shot, cached) |

## Development

```bash
./into.sh              # Start go2rtc (dev mode)
./into.sh build        # Compile bridge
./into.sh run 30       # Run bridge for 30 seconds
./into.sh shell        # Interactive shell in container
```

## Docs

- [docs/setup.md](docs/setup.md) — Docker Compose, x86 QEMU, VLC
- [docs/architecture.md](docs/architecture.md) — Protocol details, crypto
- [docs/offline.md](docs/offline.md) — Deployment tiers, traffic analysis
- [docs/configuration.md](docs/configuration.md) — Environment variables
