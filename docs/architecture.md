# Wyze Video Doorbell Pro -- Architecture

## Components

| Component | IP | Role | Power | Connection to Mars |
|-----------|-----|------|-------|--------------------|
| **Doorbell** | 192.168.1.81 | Camera, H.264 encoder, battery-powered | Battery (sleeps) | GUTES UDP to Mars for signaling |
| **Chime** | 192.168.1.12 | Indoor chime, BT bridge to doorbell | Wall-powered (always on) | GUTES to Mars, BT to doorbell |
| **Mars Relay** | AWS IPs (rotate) | GUTES signaling rendezvous | Cloud | N/A |
| **DMS** | Wyze HTTPS API | Wakeup push, device registration | Cloud | N/A |
| **Our Bridge** | 192.168.5.x (Docker) | Replaces Wyze phone app, runs SDK | Docker container | Via our local relay |
| **Our Relay** | 127.0.0.1 (in container) | Local Mars proxy, instant DETECT | Same container | Proxies CERTIFY+CALLING to real Mars |
| **go2rtc** | Container :1984/:8554 | H.264 repackaging to RTSP/WebRTC | Same container | None |

---

## Diagram 1: Normal Wyze Flow (Stock, No Bridge/Proxy)

What happens when you open the Wyze app on your phone and tap "Live View" on the doorbell.

```
┌──────────┐    ┌──────────┐    ┌─────────────────┐    ┌──────────────┐
│  Wyze    │    │  Wyze    │    │   Wyze Cloud    │    │    Wyze      │
│  Phone   │    │  Chime   │    │                 │    │  Doorbell    │
│  App     │    │(plugged) │    │  DMS   Mars     │    │  (battery)   │
│          │    │          │    │  Push  Relay    │    │  (sleeping)  │
└────┬─────┘    └────┬─────┘    └───┬──────┬──────┘    └──────┬───────┘
     │               │             │      │                   │
     │  1. "Live View" tap         │      │                   │
     │──────────────────────────────▶      │                   │
     │  HTTPS: DMS wakeup push     │      │                   │
     │               │             │      │                   │
     │               │  2. Push notification (FCM/APNs)       │
     │               │             │──────│───────────────────▶│
     │               │             │      │         3. Doorbell wakes up
     │               │             │      │                   │  (boots ~60-70s)
     │               │             │      │                   │
     │               │  4. Also wakes via BT                  │
     │               │◀────────────│──────│───────────────────│
     │               │─────────────│──────│───────────────────▶│
     │               │  Chime pings doorbell over Bluetooth   │
     │               │             │      │                   │
     │  5. LIST_REQ (UDP)          │      │                   │
     │─────────────────────────────────────▶                   │
     │  6. LIST_RESP               │      │                   │
     │◀────────────────────────────────────│                   │
     │    (server list: 5 Mars relay IPs) │                   │
     │               │             │      │                   │
     │  7. DETECT_REQ to each Mars IP     │                   │
     │─────────────────────────────────────▶                   │
     │  8. DETECT_RESP (fastest wins)     │                   │
     │◀────────────────────────────────────│                   │
     │               │             │      │                   │
     │  9. CERTIFY_REQ (UDP, to fastest Mars)                 │
     │─────────────────────────────────────▶                   │
     │  10. CERTIFY_RESP (session key)    │                   │
     │◀────────────────────────────────────│                   │
     │               │             │      │                   │
     │  11. INIT_INFO_MSG          │      │                   │
     │─────────────────────────────────────▶                   │
     │               │             │      │                   │
     │               │             │      │  12. Doorbell also does
     │               │             │      │      LIST → DETECT → CERTIFY
     │               │             │      │◀──────────────────│
     │               │             │      │──────────────────▶│
     │               │             │      │   (same Mars relay)
     │               │             │      │                   │
     │  13. CALLING_REQ            │      │                   │
     │─────────────────────────────────────▶                   │
     │               │             │      │  14. CALLING routed
     │               │             │      │──────────────────▶│
     │               │             │      │                   │
     │               │             │      │  15. MTP_RES_RESP │
     │               │             │      │◀──────────────────│
     │  16. MTP_RES_RESP (NAT info)│      │                   │
     │◀────────────────────────────────────│                   │
     │               │             │      │                   │
     │  17. Direct P2P UDP (H.264 video stream)               │
     │◀═══════════════════════════════════════════════════════▶│
     │   (NAT-punched direct connection, bypasses Mars relay)  │
     │               │             │      │                   │
     │  Video playing│in ~5-8s     │      │                   │
     │  (if doorbell │was already  │      │                   │
     │   awake — otherwise +60-70s │for   │wake)              │
```

**Key points about the stock flow:**

- The **Mars Relay** (`wyze-mars-asrv.wyzecam.com`) is the rendezvous server -- it routes signaling only, not video.
- The **GUTES protocol** (Gwell UDP Transport) handles all signaling over UDP.
- **DMS** (Device Management Service) sends the wakeup push to the sleeping doorbell.
- The **chime** also wakes the doorbell via Bluetooth as a backup.
- Actual **video streams peer-to-peer** (NAT-punched UDP); the Mars relay is not in the data path.
- Total time: ~5-8s if doorbell is awake, **~65-75s if sleeping** (dominated by doorbell boot time).

---

## Diagram 2: Our Bridge/Proxy Flow (Local Relay)

The Wyze phone app is replaced by our C++ bridge running in Docker, which feeds H.264 into go2rtc for RTSP/WebRTC output.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Docker Container (ARM64)                         │
│                                                                     │
│  ┌──────────┐   ┌──────────────┐   ┌────────────┐                 │
│  │ go2rtc   │   │ GUTES Relay  │   │  Bridge    │                 │
│  │          │   │ (Python)     │   │  (C++)     │                 │
│  │ RTSP/    │◀══│              │   │            │                 │
│  │ WebRTC   │H264 stdout pipe  │   │ libiotp2pav│                 │
│  │ :1984    │   │ :28800       │   │ .so (SDK)  │                 │
│  │ :8554    │   │ :8443        │   │            │                 │
│  │ :8555    │   │ :8000        │   │  P2P_URL=  │                 │
│  │          │   │ :51701       │   │ |127.0.0.1 │                 │
│  └──────────┘   └──────┬───────┘   └─────┬──────┘                 │
│                        │                  │                         │
└────────────────────────│──────────────────│─────────────────────────┘
                         │                  │
          localhost UDP   │                  │  localhost UDP
    ┌─────────────────────┘                  │
    │                                        │
    │  Signaling flow (inside container):    │
    │                                        │
    │    Bridge SDK ──LIST_REQ──▶ Relay      │
    │    Bridge SDK ◀─LIST_RESP── Relay      │  (local, instant)
    │      (relay returns 127.0.0.1:28800)   │
    │                                        │
    │    Bridge SDK ──DETECT_REQ─▶ Relay     │
    │    Bridge SDK ◀─DETECT_RESP─ Relay     │  (local, <1ms)
    │      (relay uses its own server_tid)   │
    │                                        │
    │    Bridge SDK ──CERTIFY_REQ─▶ Relay ───│──▶ Mars Cloud (real)
    │    Bridge SDK ◀─CERTIFY_RESP─ Relay ◀──│─── Mars Cloud
    │      (relay proxies to real Mars)      │
    │                                        │
    │    Bridge SDK ──CALLING_REQ──▶ Relay ──│──▶ Mars Cloud
    │      Mars routes CALLING to doorbell   │
    │    Bridge SDK ◀─MTP_RES_RESP─ Relay ◀──│─── Mars Cloud
    │                                        │
    └────────────────────────────────────────┘

                         │
                         │ UDP (CERTIFY, CALLING, signaling)
                         ▼
              ┌─────────────────┐
              │   Wyze Cloud    │
              │                 │
              │  DMS   Mars     │
              │  Push  Relay    │
              └───┬──────┬──────┘
                  │      │
                  │      │ CALLING routed
                  │      │
    ┌─────────┐   │      │          ┌──────────────┐
    │  Wyze   │   │      │          │    Wyze      │
    │  Chime  │   │      └─────────▶│  Doorbell    │
    │  .12    │   │                 │  .81         │
    │(plugged)│   │  Wakeup push   │  (battery)   │
    │         │◀──┘  + BT wakeup   │              │
    │         │─────────────────┬──▶│              │
    └─────────┘     Bluetooth   │   └──────┬───────┘
                                │          │
                                │          │
                                │   After NAT exchange:
                                │          │
              ┌─────────────────│──────────┘
              │                 │
              ▼                 │
    ┌─────────────────────────────────────────────────────────────────┐
    │  Docker Container                                               │
    │                                                                 │
    │   Bridge SDK ◀════ Direct LAN P2P UDP (H.264) ════▶ Doorbell   │
    │     192.168.5.x:random  ◀──────────▶  192.168.1.81:P2P_port   │
    │                                                                 │
    │   Bridge writes H.264 ──▶ stdout ──▶ go2rtc ──▶ RTSP/WebRTC   │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
```

---

## Timeline Comparison

```
STOCK WYZE APP (doorbell sleeping):
├─ 0.0s  DMS wakeup push sent
├─ 0.1s  Mars signaling (LIST→DETECT→CERTIFY→CALLING) ~200ms
│         ... waiting for doorbell to boot ...
├─ 65s   Doorbell online, completes CERTIFY + CALLING
├─ 66s   NAT exchange, P2P established
├─ 67s   First H.264 frame
└─ 68s   Video visible in app
          TOTAL: ~68s

OUR BRIDGE + LOCAL RELAY (doorbell sleeping):
├─ 0.0s  DMS wakeup push + relay starts
├─ 0.0s  LIST_REQ → Relay (local, instant)
├─ 0.0s  DETECT_REQ → Relay (local, <1ms)
├─ 0.1s  CERTIFY → Mars (proxied, ~30ms)
├─ 0.2s  SDK online, waiting for doorbell...
│         ... doorbell boots ~60-70s ...
├─ 65s   CALLING → Mars → Doorbell
├─ 66s   P2P established (LAN direct)
├─ 67s   First H.264 frame → go2rtc → RTSP
└─ 67s   Video visible
          TOTAL: ~67s (same, bottleneck is doorbell boot)

OUR BRIDGE + LOCAL RELAY (doorbell KEPT AWAKE via chime):
├─ 0.0s  LIST_REQ → Relay (local, instant)
├─ 0.0s  DETECT_REQ → Relay (local, <1ms)
├─ 0.1s  CERTIFY → Mars (proxied, ~30ms RTT)
├─ 0.3s  CALLING → Mars → Doorbell (already online)
├─ 0.5s  NAT exchange / LAN P2P direct
├─ 1.0s  First H.264 keyframe
├─ 1.5s  go2rtc serves RTSP/WebRTC
└─ 2.0s  Video visible
          TOTAL: ~2s  (meets < 10s target)

FUTURE: FULLY LOCAL RELAY (no Mars at all):
├─ 0.0s  LIST_REQ → Relay (local)
├─ 0.0s  DETECT → Relay (local, <1ms)
├─ 0.0s  CERTIFY → Relay (local, cached keys)
├─ 0.1s  CALLING → Relay → Doorbell (LAN direct)
├─ 0.3s  P2P established (pure LAN)
├─ 0.5s  First H.264 keyframe
└─ 1.0s  Video visible
          TOTAL: ~1s  (fully offline)
```

---

## GUTES Protocol Summary

The GUTES protocol (Gwell UDP Transport for Embedded Systems) is the P2P signaling layer used by Wyze (via the IoTVideo/Gwell SDK). All signaling runs over UDP on a single source port.

### Frame Header (28 bytes, 0x1C)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 1 | protocol | 0x7F=relay, 0x7E=session, 0x70=broadcast |
| 0x01 | 1 | type | Frame type / dispatch key |
| 0x02 | 2 | frm_len | Total frame length including header (LE) |
| 0x04 | 8 | term_id | 64-bit device ID, RC5-encrypted |
| 0x0C | 4 | sqnum | Sequence number (LE) |
| 0x10 | 4 | chkval | Checksum (LE) |
| 0x14 | 4 | opt_flags | Bitfield (LE) |
| 0x18 | 2 | flags2 | Additional flags (LE) |
| 0x1A | 2 | ack_result | ACK result code (LE) |

### opt_flags Bitfield

| Bits | Field | Values |
|------|-------|--------|
| 0 | compressed | 0=no, 1=yes |
| 1-15 | nonce | Random per-frame |
| 16-17 | opt_encrypt | 0=none, 1=per-frame key, 2=session key |
| 18-19 | qos | 0=fire-forget, 1=need-ack, 2=?, 3=ack+callback |
| 20 | is_ack | 1=this is an ACK |
| 21 | is_response | 1=this is a response |
| 22 | signature | 1=HMAC-MD5 appended (16 bytes) |
| 24 | ntp_appended | 1=NTP timestamp appended |
| 25 | relay_flag | 1=through relay server |

### Frame Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 0x01 | DETECT_REQ | C->S | Server discovery probe (68B, per-frame enc) |
| 0x02 | DETECT_RESP | S->C | Server identity + RTT measurement (56B) |
| 0x0C | CERTIFY_REQ | C->S | Authentication handshake (164B, signed) |
| 0x0D | CERTIFY_RESP | S->C | Session key exchange (72B) |
| 0x15 | LIST_REQ | C->S | Request relay server list (40B) |
| 0x16 | LIST_RESP | S->C | Relay server list (176B, per-frame enc) |
| 0x17 | KEEPALIVE | C->S | Connection keep-alive (44B) |
| 0xA0 | SUBSCRIBE | C->S | Subscribe to device events |
| 0xA2 | MTP_RES_RESP | S->C | P2P connection response with NAT info |
| 0xA4 | CALLING_REQ | C->S->C | Initiate P2P call (routed by relay) |
| 0xA6 | INIT_INFO_MSG | C->S | Post-certify capabilities registration |
| 0xA7 | GDM_PUSH | S->C | Device management push |
| 0xAA | CALLING_ERR | S->C | Call error / GDM data |
| 0xB0 | SESSION_CTL | C->S | Session control |
| 0xB4 | ONLINE_MSG | S->C | Device online notification |
| 0xBD | PASSTHROUGH | C->S->C | Generic data relay |

### RC5 Encryption Key Hierarchy

| Context | Block Size | Key Source | When Used |
|---------|-----------|------------|-----------|
| ctx[0x26] | 8 bytes | Static: `www.gwell.cc` | term_id encryption in all frame headers |
| ctx[0x27] | 8 bytes | Per-frame: 7 bytes from header | opt_encrypt=1 payload encryption |
| ctx[0x28] | 8 bytes | 32-byte random (post-certify) | opt_encrypt=2 session payload encryption |
| ctx[0x29] | 16 bytes | Device secret (from access_token) | CERTIFY key material encryption |

### Session Flow (from pcap capture)

```
Time     Frame             Size  Direction  Notes
0.000s   LIST_REQ           40B  C→S        Sent to 3 Mars list servers (:51701)
0.034s   LIST_RESP         176B  S→C        Returns 5 relay server IPs
0.034s   DETECT_REQ         68B  C→S        Sent to all 5 servers simultaneously
0.063s   DETECT_RESP        56B  S→C        First response (29ms RTT)
0.065s   DETECT_RESP        56B  S→C        Second response (31ms RTT)
0.067s   DETECT_REQ         68B  C→S        Round 2 of detect probes
0.085s   CERTIFY_REQ       164B  C→S        To fastest server (per-frame enc + HMAC)
0.116s   CERTIFY_ACK        48B  S→C        Server acknowledges
0.116s   CERTIFY_RESP       72B  S→C        Session key exchange (per-frame enc)
0.116s   CERTIFY_RESP_ACK   32B  C→S        Client acknowledges
0.134s   INIT_INFO_MSG      62B  C→S        Register capabilities (session enc)
0.166s   INIT_INFO_ACK      32B  S→C        Server acknowledges
0.303s   GDM_PUSH          121B  S→C        Device management data
0.315s   CALLING_ERR       789B  S→C        GDM/device state data
0.335s   SUBSCRIBE          48B  C→S        Subscribe to device events
0.436s   SESSION_CTL       108B  C→S        Session control
0.476s   SESSION_CTL_RESP   56B  S→C        Session response
4.984s   KEEPALIVE          44B  C→S        Keep connection alive
```

### LAN Broadcast Protocol (port 8899/8900)

Separate from the Mars relay path, the SDK also discovers devices on the LAN:

- **Bridge** broadcasts DETECT_RESP (type 0x02, proto 0x70) on port 8899 every ~1.2s
- **Doorbell** responds with type 0x03 frames (102B) on port 8900 containing its P2P identity
- This enables direct LAN P2P without going through Mars at all
- The broadcast list entry contains: dst_id, LAN IP, P2P port, device string

---

## File Map

```
bridge/
├── src/
│   ├── main.cpp            C++ bridge: SDK init → subscribe → AV link → H.264
│   ├── callbacks.cpp       SDK callback handlers (video frame → stdout)
│   ├── sdk_types.hpp       Reverse-engineered SDK struct layouts
│   ├── sdk_loader.cpp      dlopen/dlsym loader for libiotp2pav.so
│   ├── wyze_auth.cpp       Wyze cloud auth (login → device list → Mars tokens)
│   ├── android_stubs.c     Stub implementations for Android APIs
│   └── bionic_interpose.c  LD_PRELOAD shim: bionic→musl translation
├── scripts/
│   ├── entrypoint.py       Docker PID 1: setup → relay → go2rtc lifecycle
│   ├── gutes_relay.py      GUTES relay server (proxy + standalone modes)
│   ├── gutes_capture.py    Full session capture to pcap + JSON trace
│   ├── gutes_frame.py      GUTES frame parser
│   ├── gutes_proxy.py      TCP MitM proxy (early prototype)
│   ├── rc5.py              RC5 cipher + SDK key derivation
│   ├── mars_probe.py       Diagnostic tool: probe real Mars servers
│   └── parse_gutes_pcap.py Pcap parser for GUTES frames
├── go2rtc.yaml             go2rtc config (exec source → RTSP/WebRTC)
├── docker-compose.yml      Single-container deployment
├── Dockerfile              Alpine ARM64 + go2rtc + build tools
├── into.sh                 Dev launcher (shell/build/test/run)
└── docs/
    └── ARCHITECTURE.md     This file
```
