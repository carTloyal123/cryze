# Wyze Doorbell Bridge

Offline RTSP/WebRTC bridge for the Wyze Video Doorbell Pro. Streams on-demand H.264 video via [go2rtc](https://github.com/AlexxIT/go2rtc) with sub-4-second time-to-first-frame — no Wyze cloud dependency for video.

## Architecture

```
                        LOCAL NETWORK
  ┌──────────┐     ┌───────────────────────┐     ┌──────────┐
  │  Viewer  │────>│  Bridge Container      │<───>│ Doorbell │
  │ (RTSP/   │     │  ┌─────────┐          │     │ (Wyze    │
  │  WebRTC) │     │  │ go2rtc  │          │     │  Pro)    │
  │          │     │  └────┬────┘          │     │          │
  │          │     │       │               │     │          │
  │          │     │  ┌────▼────┐          │     │          │
  │          │     │  │ Bridge  │          │     │          │
  │          │     │  │ (C/C++) │          │     │          │
  │          │     │  └────┬────┘          │     │          │
  │          │     │       │               │     │          │
  │          │     │  ┌────▼────┐          │     │          │
  │          │     │  │  GUTES  │◄─────────│─────│          │
  │          │     │  │  Relay  │  UDP     │     │          │
  │          │     │  │ (Python)│  video   │     │          │
  │          │     │  └─────────┘          │     │          │
  └──────────┘     └───────────────────────┘     └──────────┘
                           │
                    ┌──────▼──────┐
                    │ Mars Server │  (signaling ONLY, 5.7 KB)
                    │  (Wyze P2P) │  (eliminable — see Tier 2)
                    └─────────────┘
```

The bridge reverse-engineers Wyze's GUTES P2P protocol and operates in three deployment tiers:

| Tier | Mars Dependency | Time-to-First-Frame | Config Needed |
|------|----------------|---------------------|---------------|
| **1 (default)** | Signaling only (5.7 KB) | **3.4 seconds** | `.env` only |
| **2 (offline)** | Zero | **< 1 second** | `.env` + router DNAT |
| **3 (future)** | Zero | **< 1 second** | `.env` only (Linux host) |

## Requirements

- Docker (ARM64 native or x86_64 with QEMU emulation — see [x86 hosts](#x86-hosts))
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

The stream is on-demand — the first connection triggers the doorbell.

### VLC

VLC defaults to UDP for RTSP, which doesn't work through Docker's port mapping. Change VLC to use TCP:

1. **Preferences** > **Input / Codecs**
2. Set **RTP over RTSP (TCP)** or **Live555 stream transport** to **TCP**
3. Open `rtsp://localhost:8554/doorbell`

Alternatively, use `ffplay` or the go2rtc Web UI — both work out of the box.

> On a Linux host with `network_mode: host`, VLC works without any changes since UDP is not NATed.

## Deployment Tiers

### Tier 1: Local Relay + Mars Signaling (default)

Mars handles only the CALLING relay (~5.7 KB of UDP signaling). All video flows directly between bridge and doorbell on LAN. No cloud TCP relay servers are used.

```env
# .env — Tier 1 (default)
P2P_URL=|127.0.0.1
RELAY_MODE=relay
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=5
```

**Verified traffic breakdown** (20s session, 300 H.264 frames):

| Path | Data | % |
|------|------|---|
| LAN (doorbell direct) | 1,875 KB | 81.9% |
| Mars signaling (UDP) | 5.7 KB | 0.2% |
| External total | 5.7 KB | 0.2% |

### Tier 2: Fully Offline (router DNAT)

Zero external connections. Requires a DNAT rule on your router to redirect the doorbell's Mars-bound traffic to the bridge.

```env
# .env — Tier 2 (fully offline)
P2P_URL=|127.0.0.1
RELAY_MODE=relay
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=5
SKIP_WAKEUP=1
DOORBELL_IP=192.168.1.81
```

**Router DNAT rule** (redirect doorbell's Mars traffic to bridge):
```
Source:      <doorbell_ip>
Destination: Mars IPs (port 28800)
Redirect to: <bridge_host_ip>:28800
```

Mars IPs can be resolved from `wyze-mars-asrv.wyzecam.com`.

**Verified: zero external bytes** (2,428 packets analyzed, all localhost + LAN).

### Tier 3: Fully Offline, Zero Config (future — Linux host)

On a Linux host with `network_mode: host` and `NET_ADMIN`, the container can automatically add iptables DNAT rules to intercept the doorbell's Mars traffic. No router configuration needed.

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

## How It Works

### GUTES Protocol (reverse-engineered)

The Wyze P2P stack uses a proprietary protocol called GUTES, operating over UDP port 28800. The bridge's local relay emulates the Mars signaling server:

```
Session establishment (all local, ~118ms):
  LIST_REQ/RESP      Server discovery (relay responds immediately)
  DETECT_REQ/RESP    Server liveness check
  CERTIFY_REQ/RESP   Session key exchange (RC5 crypto, key verified)
  INIT_INFO/RESP     Device registration (SDK goes ONLINE)

Video path:
  CALLING_REQ/ACK    Call initiation (relay routes to doorbell)
  MTP_RES_RESP       Media transport allocation (LAN-only, no relays)
  MTP_DATA (0xCA)    H.264 video frames (direct LAN UDP)
```

### Key Cryptographic Details

- **Per-frame key**: derived from header bytes `[0],[1],[2],[3],[0x14],[0x15],[0x16]`
- **Session key**: 32 bytes, extracted from CERTIFY_REQ payload. Encrypted with RC5 (16-byte blocks, 6 rounds) using `mars_access_token[0x30:0x40]` as the certify key.
- **Session key verification**: `giot_hash_string` with initial value `0x4e67c6a7`, formula `h ^ (b + h*32 + (h>>2))`
- **ID encryption**: uses GWELL_KEY (not session key or certify key)
- **Response matching**: `stored_req_type == resp_type - 1`, `stored_sqnum == resp_chkval`
- **ACK matching**: `opt_ack=1` (bit 20), `frame[0x0C] == stored_sqnum`

## Development

```bash
./into.sh              # Start go2rtc (Ctrl+C to stop)
./into.sh stop         # Stop and free ports
./into.sh logs         # Tail logs
./into.sh shell        # Interactive shell in container
./into.sh build        # Compile bridge only
./into.sh test         # 15s smoke test
./into.sh run 30       # Run bridge for 30 seconds
./into.sh relay        # Start relay standalone
./into.sh daemon       # Start persistent bridge daemon
./into.sh clean        # Stop + remove build artifacts
./into.sh rebuild      # Full image rebuild
```

## Configuration

See `.env.example` for all available options. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WYZE_EMAIL` | (required) | Wyze account email |
| `WYZE_PASSWORD` | (required) | Wyze account password |
| `WYZE_KEY_ID` | (required) | API key ID from developer console |
| `WYZE_API_KEY` | (required) | API key secret from developer console |
| `P2P_URL` | `\|127.0.0.1` | P2P server (`\|<ip>` format). Use `127.0.0.1` for local relay |
| `RELAY_MODE` | `proxy` | `proxy` (uses Mars fallback) or `relay` (fully local) |
| `LAN_ONLY` | `0` | `1` to block cloud TCP relay servers via iptables |
| `SKIP_WAKEUP` | `0` | `1` to skip cloud wakeup API call |
| `DOORBELL_IP` | (auto) | Doorbell LAN IP for direct connection |
| `LAN_WAIT` | `90` | Seconds to wait for doorbell broadcast (0 to skip) |
| `SUBSCRIBE_WAIT` | `20` | Seconds to wait for subscribe (reduce for relay mode) |
