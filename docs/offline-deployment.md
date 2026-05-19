# Fully Offline Deployment

## Achievement

100% offline H.264 video streaming from a Wyze Video Doorbell Pro. Zero internet traffic during streaming — all GUTES P2P signaling handled by a local relay, video delivered directly over LAN UDP.

**Verified**: 101 H.264 frames, 467KB video, 21.5 seconds, zero external connections.

## How It Works

```
Doorbell ──UDP──▶ Bridge Host ──DNAT──▶ Local Relay ──GUTES──▶ Bridge SDK
   │                                        │                      │
   │              (ARP spoof +               │                      │
   │               static route)             │                      │
   ▼                                         ▼                      ▼
   WiFi stays on              Handles LIST/DETECT/         Streams H.264
   even when "asleep"         CERTIFY/CALLING/MTP          via go2rtc
                              for both bridge + doorbell    RTSP/WebRTC
```

The doorbell's Mars-bound GUTES traffic gets intercepted at three levels:
1. **ARP spoof**: Bridge host tells doorbell "I am the gateway"
2. **Router static route**: Router sends doorbell-destined traffic to bridge host
3. **Host iptables DNAT**: Mars IPs redirected to local relay (192.168.1.236)

## Network Requirements

### Router Configuration

Add static routes for both devices through the bridge host:

| Destination | Next Hop | Purpose |
|-------------|----------|---------|
| 192.168.1.81/32 (doorbell) | 192.168.1.236 (bridge) | Return traffic flows through bridge |
| 192.168.1.12/32 (chime) | 192.168.1.236 (bridge) | Chime traffic flows through bridge |

### Bridge Host

The `network-setup` Docker service automatically configures:
- ARP spoofing (tells devices the gateway MAC is the bridge host's MAC)
- DNS interception (spoofs `wyze-mars-asrv.wyzecam.com` to bridge IP)
- ICMP redirect suppression (prevents devices from learning the real gateway)
- iptables DNAT (Mars IPs redirected to local relay)

Additionally, host-level iptables DNAT rules are needed:

```bash
# Add DNAT on the host (not in a container) for Mars-bound traffic
for ip in 18.118.90.161 3.13.212.24 3.131.23.11 3.19.80.22 34.215.36.59 \
          35.81.136.54 35.85.21.174 52.201.137.206 54.208.16.245; do
  for port in 28800 51701 8443 8000; do
    iptables -t nat -A WYZE_HOST_DNAT -s 192.168.1.81 -d $ip -p udp --dport $port \
      -j DNAT --to-destination 192.168.1.236:$port
    iptables -t nat -A WYZE_HOST_DNAT -s 192.168.1.12 -d $ip -p udp --dport $port \
      -j DNAT --to-destination 192.168.1.236:$port
  done
done
```

### .env Configuration

```env
P2P_URL=|127.0.0.1
RELAY_MODE=relay
RELAY_KEEPALIVE=1
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=3
SKIP_WAKEUP=1
DOORBELL_IP=192.168.1.81
CHIME_IP=192.168.1.12
```

## Key Technical Discoveries

### Doorbell WiFi Behavior

The Wyze doorbell keeps WiFi active even in "sleep" mode. It drops its GUTES/Mars session but stays reachable on the LAN. This means:
- No BT wakeup needed in most cases
- The doorbell responds to UDP probes immediately
- A new GUTES session establishes in ~2-3 seconds

### Session Key Capture

The bridge's `libiotp2pav.so` SDK performs CERTIFY key exchange. An LD_PRELOAD hook on `rc5_ctx_setkey` captures the 32-byte session key when CERTIFY completes. This key is shared with the relay for session-encrypted CALLING/MTP_RES_RESP frames.

### APP_ONLINE Bypass

The SDK's `gat_rcv_init_info_msg_resp` checks `unit+0x3bc` before firing APP_ONLINE. This subscribe-gate flag is cleared by writing 0 directly to the SDK's memory after `iv_access_init`. A fallback direct callback invocation ensures APP_ONLINE fires even if the INIT_INFO_RESP format doesn't exactly match Mars's response.

## What Requires Internet

| Operation | Internet? | When |
|-----------|-----------|------|
| Initial Wyze login | Yes | Once, cached 7 days |
| Mars token registration | Yes | Once, cached 7 days |
| DMS wakeup (cold start) | Optional | Only if doorbell WiFi is off |
| GUTES signaling | No | Local relay |
| Video streaming | No | Direct LAN P2P |

After the initial auth (cached for 7 days), the system operates with zero internet for weeks. The DMS wakeup is only needed if the doorbell enters true deep sleep (very low battery), which rarely happens when RELAY_KEEPALIVE maintains the session.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker (ARM64 QEMU)                 │
│                                                  │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐     │
│  │ go2rtc   │  │  GUTES    │  │  Bridge  │     │
│  │ RTSP/    │◀═│  Relay    │  │  (C++)   │     │
│  │ WebRTC   │  │  :28800   │  │  SDK     │     │
│  │ :1984    │  └─────┬─────┘  └────┬─────┘     │
│  └──────────┘        │             │            │
└──────────────────────│─────────────│────────────┘
                       │             │
              Host iptables DNAT     │ H.264 stdout
                       │             │
         ┌─────────────┘             │
         │                           │
   ┌─────┴──────┐            ┌──────┴───────┐
   │  Doorbell   │───UDP P2P──│   Bridge     │
   │ 192.168.1.81│  (H.264)  │ 192.168.1.236│
   └─────────────┘            └──────────────┘
```
