# Fully Offline Deployment

100% offline H.264 video streaming from a Wyze Video Doorbell Pro. Zero internet traffic during streaming — all GUTES P2P signaling handled by a local relay, video delivered directly over LAN UDP.

## Quick Start

### 1. Router Setup (one-time, 2 minutes)

Add static routes on your router so device traffic flows through the bridge host:

| Destination | Next Hop | Why |
|-------------|----------|-----|
| `<doorbell_ip>/32` | `<bridge_host_ip>` | Doorbell's Mars traffic gets intercepted |
| `<chime_ip>/32` | `<bridge_host_ip>` | Chime's Mars traffic gets intercepted |

On UniFi: Settings → Routing → Static Routes → Add.

### 2. Configure `.env`

```env
# Wyze credentials (login once, cached 7 days)
WYZE_EMAIL=you@example.com
WYZE_PASSWORD=your_password
WYZE_KEY_ID=your_api_key_id
WYZE_API_KEY=your_api_key

# Device IPs (find in your router's client list)
DOORBELL_IP=192.168.1.81
CHIME_IP=192.168.1.12

# Offline mode
P2P_URL=|127.0.0.1
RELAY_MODE=relay
RELAY_KEEPALIVE=1
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=3
SKIP_WAKEUP=1
```

### 3. Deploy

```bash
docker compose up -d
```

The `network-setup` service automatically:
- Enables IP forwarding on the host
- Disables ICMP redirects (prevents devices from bypassing intercept)
- ARP-spoofs devices to route through the bridge host
- Intercepts DNS to spoof Mars hostname → bridge IP
- Sets up iptables DNAT for Mars server IPs → local relay
- All with `--privileged` and `network_mode: host`

### 4. Stream

Access via go2rtc at `http://<bridge_host_ip>:1984`. Streams available as RTSP (`:8554`), WebRTC, or HLS.

## How It Works

```
Doorbell ─WiFi─▶ Router ─static route─▶ Bridge Host
                                           │
                               iptables DNAT + DNS spoof
                                           │
                                    ┌──────┴──────┐
                                    │  Local      │
                                    │  GUTES      │──▶ go2rtc (RTSP/WebRTC)
                                    │  Relay      │
                                    └─────────────┘
```

1. Doorbell wakes from sleep, resolves `wyze-mars-asrv.wyzecam.com` via DNS
2. DNS intercepted → returns bridge host IP instead of real Mars
3. Doorbell connects to our relay (thinking it's Mars)
4. Relay handles LIST/DETECT/CERTIFY/CALLING — all locally
5. Bridge SDK connects via relay, establishes AV link
6. Doorbell streams H.264 directly to bridge over LAN UDP

## What Requires Internet

| Operation | Internet? | Frequency |
|-----------|-----------|-----------|
| Wyze login + Mars token | Yes | Once per 7 days (cached) |
| DMS wakeup (deep sleep) | Optional | Only if doorbell WiFi is off |
| GUTES signaling | No | Always local |
| Video streaming | No | Always LAN |

After initial auth cache, the system runs offline indefinitely. The DMS wakeup (`SKIP_WAKEUP=0`) is only needed when the doorbell enters true deep sleep (WiFi off). With `RELAY_KEEPALIVE=1`, the relay maintains the doorbell's session to prevent sleep.

## Doorbell Sleep Behavior

The Wyze doorbell keeps WiFi active even when "asleep" — it just drops its GUTES session. When a new connection comes (via our relay), it responds in ~2 seconds. True deep sleep (WiFi off) only happens after extended idle or very low battery.

## Technical Details

### Session Key Capture
An LD_PRELOAD hook on `rc5_ctx_setkey` captures the 32-byte session key from the SDK's CERTIFY exchange. This enables the relay to session-encrypt CALLING and MTP frames.

### APP_ONLINE Bypass
The SDK's subscribe-gate flag (`unit+0x3bc`) is cleared after init, and the APP_ONLINE callback is invoked directly if INIT_INFO_RESP isn't accepted within 5 seconds.

### Network Intercept Stack
- **ARP spoof**: Tells devices the gateway MAC is the bridge host's MAC (500ms intervals + broadcast)
- **ICMP redirect suppression**: Disabled on ALL interfaces to prevent devices from learning the real gateway
- **DNS intercept**: Spoofs `wyze-mars-asrv.wyzecam.com` → bridge IP on port 5354
- **iptables DNAT**: Mars IPs × ports (28800, 51701, 8443, 8000) → local relay
