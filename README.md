# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Streams H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) with sub-4-second time-to-first-frame.

## Requirements

- Docker (ARM64 native or x86_64 with QEMU — see [docs/setup.md](docs/setup.md))
- Wyze account with API keys from https://developer-api-console.wyze.com/
- Decompiled Wyze APK with `libiotp2pav.so` and `libmbedtls.so` (placed in `../apk/`)

## Quick Start

```bash
# 1. Configure credentials
cp .env.example .env
# Edit .env with your Wyze email, password, and API keys

# 2. Start
docker compose up
```

First run takes ~60s (patches libraries, compiles bridge). Subsequent starts take ~3s.

## Viewing the Stream

| Method | URL |
|--------|-----|
| Web UI | http://localhost:1984 |
| RTSP | `rtsp://localhost:8554/doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://localhost:8554/doorbell` |

> VLC users: set **Preferences > Input/Codecs > RTP over RTSP** to **TCP**, or use ffplay/Web UI instead.

## Development

```bash
./into.sh              # Start go2rtc
./into.sh build        # Compile bridge
./into.sh run 30       # Run bridge for 30 seconds
./into.sh shell        # Interactive shell in container
./into.sh clean        # Stop + remove build artifacts
```

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/setup.md](docs/setup.md) | x86 hosts, Docker Compose, VLC setup |
| [docs/architecture.md](docs/architecture.md) | Protocol details, diagrams, crypto |
| [docs/offline.md](docs/offline.md) | Deployment tiers, fully offline setup, traffic analysis |
| [docs/configuration.md](docs/configuration.md) | All environment variables |
