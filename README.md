# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Reverse-engineers the GUTES P2P protocol to stream H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) without cloud dependencies.

## Requirements

- Linux host with Docker (ARM64 native or x86_64 with QEMU binfmt)
- Wyze account + API keys from [developer-api-console.wyze.com](https://developer-api-console.wyze.com/)
- Doorbell and chime LAN IPs (find in your router's client list)

## Quick Start

```bash
git clone https://github.com/carTloyal123/cryze.git
cd cryze
cp .env.example .env   # edit with your credentials + device IPs
docker compose up -d
```

First build downloads the Wyze APK (~400MB), extracts SDK libraries, compiles the C++ bridge, and bundles go2rtc. Takes ~3-5 minutes. Subsequent starts use cached images.

## Stream Access

| Method | URL |
|--------|-----|
| Web UI | `http://<host>:1984` |
| RTSP | `rtsp://<host>:8554/doorbell` |
| WebRTC | `http://<host>:1984/stream.html?src=doorbell` |
| ffplay | `ffplay -rtsp_transport tcp rtsp://<host>:8554/doorbell` |

## Services

| Container | Purpose |
|-----------|---------|
| `wyze-go2rtc` | Stream server — launches bridge on-demand, serves RTSP/WebRTC/HLS |
| `wyze-relay` | GUTES protocol relay — handles P2P signaling locally |
| `wyze-network` | Network intercept — ARP spoof, DNS intercept, iptables DNAT |

## Configuration

All settings via `.env`. See [docs/configuration.md](docs/configuration.md) for the full variable reference.

Key settings in `.env.example`:
- `WYZE_EMAIL`, `WYZE_PASSWORD`, `WYZE_KEY_ID`, `WYZE_API_KEY` — Wyze account credentials
- `DOORBELL_IP`, `CHIME_IP` — device LAN IPs
- `P2P_URL` — Mars server IP (`|18.118.90.161` for standard, `|127.0.0.1` for fully offline)

## Further Reading

- [docs/configuration.md](docs/configuration.md) — all environment variables
- [docs/architecture.md](docs/architecture.md) — GUTES protocol, frame formats, system design
- [docs/offline-deployment.md](docs/offline-deployment.md) — fully offline setup with router DNAT

## Development

```bash
scripts/into.sh              # Start go2rtc (dev mode)
scripts/into.sh build        # Compile bridge
scripts/into.sh run 30       # Run bridge for 30 seconds
scripts/into.sh shell        # Interactive shell in container
```
