# Wyze Video Doorbell Pro — Offline Bridge

## Goal: Sub-5 Second Time-to-First-Frame ACHIEVED

**Measured: 3.4 seconds** (warm doorbell, Mars-mediated CALLING via TCP relay)

---

## Verified Timing Breakdown (2026-05-16)

| Phase | Time | Cumulative |
|-------|------|------------|
| Auth (cached) | ~50ms | 50ms |
| SDK init + CERTIFY + ONLINE | 700ms | 750ms |
| Subscribe (error -> immediate break) | 90ms | 840ms |
| AV link CALLING sent | 0ms | 840ms |
| CALLING ACK from Mars | 60ms | 900ms |
| TCP relay connects (MTP) | ~2.2s | 3.1s |
| AV link success | 200ms | 3.3s |
| **First H.264 frame** | **~100ms** | **3.4s** |

300 frames in 20s (15fps continuous), 1.9MB H.264, 1920x1080

---

## Deployment Tiers

### Tier 1: Semi-Offline (Working NOW, 3.4s)
```
Bridge SDK -> Local Relay (LIST/DETECT/CERTIFY/INIT_INFO) -> ONLINE in 450ms
Bridge SDK -> Real Mars (CALLING only) -> doorbell wakes -> video in 3.4s
Video: doorbell -> direct UDP on LAN -> bridge (no Mars in data path)
```
- **Requires**: Internet for CALLING relay only (tiny bandwidth)
- **No router config needed**: works on any network
- **Config**: P2P_URL=|<mars-ip>, LAN_WAIT=0, SUBSCRIBE_WAIT=5

### Tier 2: Fully Offline (Requires Router DNAT)
```
Bridge SDK -> Local Relay (all signaling) -> ONLINE in 450ms
Doorbell -> DNAT intercepts Mars traffic -> Local Relay -> stays connected
Bridge CALLING -> Local Relay -> routes to doorbell -> video flows
```
- **Requires**: Router DNAT rule (source=doorbell_ip, dest=mars_ips -> relay_ip)
- **No internet needed** after initial auth token cache
- **One-time router config**: single NAT rule per doorbell

### Tier 3: Fully Offline + Zero Config (Future)
```
Bridge container runs on a Linux host with host networking
Container uses iptables DNAT to intercept doorbell's Mars traffic
Everything automated via DOORBELL_IP env var
```
- **Requires**: Linux host (not macOS/VM) with host networking + NET_ADMIN
- **No router config**: container manages iptables automatically
- **Config**: just DOORBELL_IP in .env

---

## Completed (Verified)

### GUTES Protocol RE
- Session key extraction from CERTIFY_REQ (mars_access_token[0x30:0x40] -> RC5-16B decrypt)
- Session key verification via giot_hash_string (init=0x4e67c6a7)
- ID encryption uses GWELL_KEY (not session/certify key) - verified via pcap
- Per-frame encryption starts at offset 0x18 (not 0x1C)
- Response matching: stored_req_type == resp_type-1, stored_sqnum == resp_chkval
- ACK matching (mode=1): opt_ack=1 (bit 20), raw sqnum at 0x0C
- bit25 in opt_flags bypasses session_id routing check

### Local Relay (gutes_relay.py)
- LIST_RESP: correct payload format, unencrypted, BE port encoding
- DETECT_RESP: per-frame key extraction for response matching  
- CERTIFY_RESP: real session key extraction + caching
- INIT_INFO_RESP: sqnum prediction (CERTIFY+1), device list, relay_flag bypass
- SUBSCRIBE_RESP + SESSION_CTL_RESP: success responses
- CALLING_ACK: session-encrypted, GWELL_KEY for ID, opt_with_netaddr=1
- KEEPALIVE ACK: responds to doorbell keepalive requests
- TCP signaling server on port 28800
- MTP TCP relay on port 23000
- Role identification via DOORBELL_IP/CHIME_IP env vars

### Bridge Optimizations
- Subscribe early-break on error (saves 2-3s)
- LAN_WAIT=0 (doorbell never broadcasts)
- Cached auth tokens

### Key Discoveries (2026-05-17)
- Doorbell uses NO DNS - gets Mars IP from BT wakeup payload
- Doorbell only sends traffic to bridge IP (direct LAN UDP for video)
- Chime uses push notifications (FCM), not Mars GUTES, for wakeup delivery
- Container iptables DNAT doesn't work on macOS/Colima (traffic doesn't traverse VM)
- Router-level DNAT is required for intercepting doorbell's Mars connection

---

## Remaining Work

### For Tier 2 (Router DNAT)
1. Test with router DNAT: `src=192.168.1.81 dst=<mars_ips> -> DNAT to relay_ip`
2. Verify doorbell connects to relay via DNAT
3. Test full video flow: relay routes CALLING between bridge and doorbell
4. Implement MTP data bridging if direct LAN connection doesn't work

### For Tier 3 (Zero Config)  
1. Move to Linux host (not macOS VM) where iptables sees LAN traffic
2. Automate iptables rules in container startup
3. Add DNS interception for doorbell (redirect DNS queries to local resolver)
4. Package as single docker-compose with health monitoring

---

## Quick Start

```bash
# 1. Configure .env (see .env.example)
#    Required: WYZE_EMAIL, WYZE_PASSWORD, WYZE_KEY_ID, WYZE_API_KEY
#    Required: P2P_URL=|<mars-ip>  (use: dig +short wyze-mars-asrv.wyzecam.com)
#    Set: LAN_WAIT=0  SUBSCRIBE_WAIT=5  DOORBELL_IP=192.168.1.81

# 2. Build and run
./into.sh build
./into.sh run 30     # 30 second capture -> logs/frames.h264

# 3. Play the captured stream
ffplay logs/frames.h264
```
