# Architecture

## System Components

```
┌─────────────────────────────────────────────────┐
│              Docker (ARM64)                      │
│                                                  │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐     │
│  │ go2rtc   │  │  GUTES    │  │  Bridge  │     │
│  │ RTSP/    │◀═│  Relay    │  │  (C++)   │     │
│  │ WebRTC   │  │  :28800   │  │  SDK     │     │
│  │ :1984    │  └─────┬─────┘  └────┬─────┘     │
│  └──────────┘        │             │            │
│                  localhost          │            │
└──────────────────────│─────────────│────────────┘
                       │             │
                       │    Direct LAN UDP (H.264)
                       │             │
                       ▼             ▼
              ┌──────────────────────────────┐
              │     Wyze Doorbell (LAN)      │
              │     192.168.x.x              │
              └──────────────────────────────┘
```

**Services** (docker-compose.yml):

| Service | Role |
|---------|------|
| `network-setup` | iptables DNAT + ARP redirect (intercepts doorbell Mars traffic) |
| `relay` | GUTES protocol relay (all P2P signaling handled locally) |
| `go2rtc` | Stream server — launches bridge on-demand via exec |
| `bridge-builder` | One-shot ARM64 compilation (cached) |

## GUTES Protocol

The GUTES protocol (Gwell UDP Transport) handles P2P signaling over UDP.

### Frame Header (28 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 1 | protocol (`0x7F`=relay, `0x7E`=session, `0x70`=broadcast) |
| 0x01 | 1 | type (dispatch key) |
| 0x02 | 2 | frame length (LE) |
| 0x04 | 8 | term_id (RC5-encrypted device ID) |
| 0x0C | 4 | sqnum (LE) |
| 0x10 | 4 | chkval (LE) |
| 0x14 | 4 | opt_flags bitfield (LE) |

### Key Frame Types

| Type | Name | Purpose |
|------|------|---------|
| 0x01/0x02 | DETECT | Server discovery + RTT measurement |
| 0x0C/0x0D | CERTIFY | Session key exchange |
| 0x15/0x16 | LIST | Relay server list |
| 0xA4 | CALLING | Initiate P2P call (routed by relay) |
| 0xA3 | MTP_RES_RESP | NAT info for direct LAN connection |
| 0xCA | MTP_DATA | Video stream (direct LAN UDP) |

### Encryption

| Mode | Key Source | Usage |
|------|-----------|-------|
| Static | `www.gwell.cc` (RC5 8B/6R) | term_id in all frame headers |
| Per-frame | Derived from 7 header bytes | opt_encrypt=1 payloads |
| Session | 32B random from CERTIFY | opt_encrypt=2 payloads |

### Session Key Derivation

1. Per-frame decrypt CERTIFY_REQ payload (offset 0x18)
2. Extract encrypted_key from decrypted_payload[8:40]
3. RC5 decrypt with certify_key (16-byte blocks, 6 rounds)
4. certify_key = `mars_access_token[0x30:0x40]`

## Deployment Tiers

**Tier 1 — Hybrid**: Internet for CALLING relay only (5.7 KB signaling), all video on LAN.

**Tier 2 — Fully Offline**: Zero external connections. Requires router DNAT rule redirecting doorbell's Mars-bound UDP to the bridge host.

**Tier 3 — Auto-Offline** (Linux): Container automatically adds iptables DNAT rules (`NET_ADMIN` capability). No router config needed.

### Doorbell Connection

The doorbell gets Mars IPs from the BT wakeup payload (not DNS), so DNS overrides don't work. DNAT at the network level is required for full offline operation.

## Source Layout

```
src/
├── bridge/           C++ bridge (deliverable binary)
│   ├── main.cpp      One-shot: auth → init → subscribe → stream → exit
│   ├── daemon.cpp    Persistent: keeps SDK warm, stdin commands
│   ├── broadcast.*   Broadcast list polling + LAN injection
│   ├── signal.*      Crash handler + signal setup
│   ├── callbacks.*   SDK callback implementations
│   ├── sdk_loader.*  dlopen wrapper for libiotp2pav.so
│   ├── sdk_types.hpp ABI struct layouts (from Ghidra RE)
│   ├── wyze_auth.*   Cloud auth + credential caching
│   └── android_stubs.c  Bionic libc compatibility shim
├── relay/            Python GUTES relay (deliverable service)
│   ├── gutes_relay.py   Core relay server
│   ├── gutes_frame.py   Frame parser/builder
│   └── rc5.py           RC5 cipher + key derivation
└── network/          Python network setup (deliverable service)
    └── network_setup.py  iptables DNAT + ARP redirect
```
