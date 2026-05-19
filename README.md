# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Reverse-engineers the GUTES P2P protocol to stream H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) without cloud dependencies.

## Requirements

- Linux host with Docker (ARM64 native or x86_64 with QEMU binfmt)
- Wyze account + API keys from https://developer-api-console.wyze.com/

## Quick Start

```bash
git clone https://github.com/carTloyal123/cryze.git && cd cryze
cp .env.example .env   # Edit with your credentials + device IPs
docker compose up -d
```

The Docker image downloads the Wyze APK, extracts SDK libraries, and builds the bridge automatically. First build takes ~5 minutes.

## Stream URLs

| Method | URL |
|--------|-----|
| Web UI | `http://HOST:1984/stream.html?src=doorbell` |
| RTSP | `rtsp://HOST:8554/doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://HOST:8554/doorbell` |

## Configuration

All settings via `.env` — see [docs/configuration.md](docs/configuration.md) for the full variable reference.

## Architecture

See [docs/architecture.md](docs/architecture.md) for protocol details and system design.

## Development

```bash
scripts/into.sh              # Start go2rtc (dev mode)
scripts/into.sh build        # Compile bridge
scripts/into.sh run 30       # Run bridge for 30 seconds
scripts/into.sh shell        # Interactive shell in container
```
