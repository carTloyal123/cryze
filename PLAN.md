# Wyze Video Doorbell Pro — Offline Bridge

## Goal: Sub-5 Second Time-to-First-Frame ✅ ACHIEVED

**Measured: 3.4 seconds** (warm doorbell, Mars-mediated CALLING via TCP relay)

---

## Verified Timing Breakdown (2026-05-16)

| Phase | Time | Cumulative |
|-------|------|------------|
| Auth (cached) | ~50ms | 50ms |
| SDK init + CERTIFY + ONLINE | 700ms | 750ms |
| Subscribe (error → immediate break) | 90ms | 840ms |
| AV link CALLING sent | 0ms | 840ms |
| CALLING ACK from Mars | 60ms | 900ms |
| TCP relay connects (MTP) | ~2.2s | 3.1s |
| AV link success | 200ms | 3.3s |
| **First H.264 frame** | **~100ms** | **3.4s** |

300 frames in 20s (15fps continuous), 1.9MB H.264, 1920x1080

---

## Architecture

```
Viewer → go2rtc → bridge → SDK → Mars (signaling) → TCP relay → doorbell
                              ↑
                    P2P_URL=|mars-ip (LIST/CERTIFY/CALLING)
```

Key insight: The doorbell **never** responds to LAN broadcast (even when awake).
All connections go through Mars-mediated TCP relay. Setting `LAN_WAIT=0` skips
the useless broadcast poll entirely.

---

## ✅ Completed Steps

### 1. GUTES Relay (local signaling)
- LIST_RESP: correct payload format, unencrypted, BE port encoding
- DETECT_RESP: per-frame key extraction for response matching
- CERTIFY_RESP: local key exchange, session_id tracking
- INIT_INFO_RESP: sqnum prediction, device list, relay_flag bypass
- SUBSCRIBE_RESP: early error break (no wasted timeout)

### 2. Bridge Optimizations
- Subscribe early-break on error (saves 2-3s)
- LAN_WAIT=0 (doorbell never broadcasts, skip useless poll)
- Fallback LAN-INJECT for SDK's find_dst_id_inlan check
- Cached auth (no HTTP roundtrip on warm start)

### 3. End-to-End Verified
- Wakeup via `run_action_batch` → doorbell wakes in ~90s
- Once awake: SDK → Mars → CALLING → TCP relay → video in 3.4s
- 15fps H.264 stream, stable for 20+ seconds tested

---

## Remaining Work (Future)

### For Full Offline Mode
1. **Proxy CALLING/MTP through local relay** — currently requires Mars for
   TCP relay allocation. Need to implement local MTP relay or learn the
   doorbell's direct P2P port.

2. **Doorbell keepalive** — send periodic pings to keep doorbell awake
   (currently goes to sleep after ~5min idle). Requires knowing the
   doorbell's GUTES session port (only available when it's connected to Mars).

3. **Local DNS override** — point `wyze-mars-asrv.wyzecam.com` to local relay
   so doorbell connects to us instead of Mars. Then we can proxy CALLING locally.

### For Production Deployment
1. **Docker compose integration** — `docker compose up` from zero to RTSP
2. **go2rtc pipe transport** — `--stdout` mode feeds H.264 directly to go2rtc
3. **Persistent daemon** — keeps SDK warm for instant reconnect (<2s)
4. **Health monitoring** — auto-restart on doorbell disconnect

---

## Quick Start

```bash
# 1. Configure .env (see .env.example)
#    Required: WYZE_EMAIL, WYZE_PASSWORD, WYZE_KEY_ID, WYZE_API_KEY
#    Required: P2P_URL=|<mars-ip>  (use: dig +short wyze-mars-asrv.wyzecam.com)
#    Set: LAN_WAIT=0  SUBSCRIBE_WAIT=5  DOORBELL_IP=192.168.1.81

# 2. Build and run
./into.sh build
./into.sh run 30     # 30 second capture → logs/frames.h264

# 3. Play the captured stream
ffplay logs/frames.h264
```

---

## Network Requirements

- Bridge host needs **UDP access to Mars** (wyze-mars-asrv.wyzecam.com:28800/51701)
- Bridge host needs **TCP access to relay servers** (various AWS IPs, ports 8000-50000)
- **No DNAT needed** — bridge uses `P2P_URL` to specify Mars directly
- **No router config needed** — works on any standard network
- Doorbell must be able to reach Mars for cloud wakeup to work
