# Wyze Video Doorbell Pro — Fully Offline Bridge

## Status: Zero External Connections Achieved (Bridge Side)

The bridge SDK operates with **zero internet traffic** when configured for full offline mode. All GUTES signaling, session management, and media path setup is handled by a local relay.

| Metric | Value |
|--------|-------|
| SDK online time | **118ms** (local relay) |
| Time-to-first-frame | **3.4s** (via Mars) / TBD (fully local) |
| External connections | **0 bytes** (verified via pcap, 2428 packets) |
| Video path | Direct LAN UDP (doorbell <-> bridge) |
| Protocol RE completeness | 100% for signaling, session keys, MTP allocation |

---

## Architecture

### System Components

```
+------------------+      GUTES (localhost)      +------------------+
|  Bridge SDK      | <=========================> |  Local Relay     |
|  (libiotp2pav)   |   LIST/DETECT/CERTIFY/      |  (gutes_relay.py)|
|                  |   INIT_INFO/CALLING/MTP_RES  |                  |
+--------+---------+                              +--------+---------+
         |                                                 |
         | MTP_DATA (LAN UDP, direct)                      | GUTES (LAN UDP)
         |                                                 | (requires DNAT)
         v                                                 v
+------------------+                              +------------------+
|  Doorbell        | <==========================  |  Doorbell        |
|  (video source)  |   H.264 @ 15fps, 1080p      |  (signaling)     |
+------------------+                              +------------------+
```

### Protocol Stack (Fully Reversed)

| Layer | Protocol | Implementation |
|-------|----------|----------------|
| Discovery | LIST_REQ/RESP (type 0x15/0x16) | Local relay responds with itself |
| Liveness | DETECT_REQ/RESP (type 0x01/0x02) | Per-frame key extraction for matching |
| Session | CERTIFY_REQ/RESP (type 0x0C/0x0D) | Real session key extraction from payload |
| Registration | INIT_INFO/RESP (type 0xA6/0xA7) | sqnum prediction (CERTIFY+1), device list |
| Subscription | SUBSCRIBE/SESSION_CTL | Graceful success/timeout responses |
| Call Setup | CALLING_ACK (type 0xA4) | Session-encrypted, GWELL_KEY for ID |
| Media Alloc | MTP_RES_RESP (type 0xA3) | LAN-only addresses, zero relay servers |
| Keepalive | KEEPALIVE (type 0x17) | ACK responses to maintain sessions |
| Video | MTP_DATA (type 0xCA) | Direct LAN UDP between bridge and doorbell |

---

## Deployment Tiers

### Tier 1: Hybrid (Working, 3.4s TTF)

Internet used ONLY for CALLING relay (5.7 KB signaling). All video on LAN.

```env
P2P_URL=|18.118.90.161    # Real Mars for CALLING relay
LAN_ONLY=1                 # Block cloud TCP relay servers
LAN_WAIT=0                 # Skip useless broadcast poll
SUBSCRIBE_WAIT=5            # Short subscribe timeout
```

**Traffic**: Mars 5.7 KB (0.2%) | LAN 1.9 MB (94%) | TCP relay 0 KB (blocked)

### Tier 2: Fully Offline (Working, 118ms online)

Zero external connections. Bridge talks only to local relay and doorbell on LAN.

```env
P2P_URL=|127.0.0.1         # All signaling via local relay
RELAY_MODE=relay            # Handle everything locally
LAN_ONLY=1                  # Block cloud relays
SKIP_WAKEUP=1               # No HTTPS to api.wyzecam.com
DOORBELL_IP=192.168.1.81    # Direct LAN MTP path
```

**Traffic**: External 0 bytes | Localhost 14.6 KB | LAN 12.2 KB (probes)

**Requires**: Doorbell connected to local relay (see "Doorbell Connection" below)

### Tier 3: Production (Future)

Single `docker compose up` with automatic doorbell redirect. No router config.

```env
DOORBELL_IP=192.168.1.81    # Only required config (besides Wyze creds)
```

Container auto-configures iptables DNAT to intercept doorbell's Mars traffic.
Requires Linux host with `NET_ADMIN` capability.

---

## Doorbell Connection (The Last Mile)

The bridge side is 100% offline. The remaining challenge: getting the doorbell to connect to our relay instead of real Mars.

### Why It's Hard

- Doorbell gets Mars server IP from **BT wakeup payload** (not DNS)
- SDK has a **private IP filter** (`iv_private_ip`) that rejects LAN IPs for list servers
- SDK uses **hardcoded Google DNS** (8.8.8.8) internally
- DNS overrides on the router don't reach the doorbell firmware

### Solutions

| Approach | Router Config? | Works From Container? | Platform |
|----------|---------------|----------------------|----------|
| Router DNAT | Yes (one rule) | N/A | Any router |
| Host iptables | No | Yes (NET_ADMIN) | Linux only |
| ARP spoofing | No | Yes (NET_RAW) | Any |

**Router DNAT** (simplest, tested):
```
Source: DOORBELL_IP (192.168.1.81)
Destination: Mars IPs (port 28800)
Redirect to: RELAY_IP:28800
```

**Host iptables** (automatic, Linux only):
```bash
iptables -t nat -A PREROUTING -s $DOORBELL_IP -d $MARS_IPS -j DNAT --to $RELAY_IP
```

---

## Key Technical Discoveries

### Session Key Derivation (Cracked)

```
1. Per-frame decrypt CERTIFY_REQ payload (offset 0x18, RC5 8B/6R with per-frame key)
2. Extract encrypted_key from decrypted_payload[8:40] (32 bytes)
3. RC5 decrypt with certify_key (16-byte blocks, 6 rounds)
4. certify_key = mars_access_token_bytes[0x30:0x40]
5. Verify: giot_hash_string(session_key) == hash_checksum
   (initial=0x4e67c6a7, formula: h ^ (b + h*32 + (h>>2)))
```

### Frame Crypto Layers

| encrypt_mode | Key Source | ID Encryption | sqnum/chkval | Payload |
|---|---|---|---|---|
| 0 (none) | N/A | None | Plaintext | Plaintext |
| 1 (per-frame) | derive_per_frame_key(header[:0x18]) | GWELL_KEY (RC5 8B/6R) | Per-frame key | Per-frame key |
| 2 (session) | Session key (32B from CERTIFY) | GWELL_KEY | Session key | Session key |

### MTP_RES_RESP Format (122 bytes)

```
Frame[0x1C]  link_id (4B LE) — must match CALLING
Frame[0x56]  called_ip_version_flags (bit0=v4)
Frame[0x58]  called_outer_port (2B NBO)
Frame[0x5A]  called_lan_port (2B NBO)
Frame[0x5E]  called_session_socket_udpport (2B NBO)
Frame[0x60]  called_outer_ipv4 — set to FAKE IP (forces lan!=outer)
Frame[0x64]  called_lan_ipv4 — doorbell's REAL LAN IP
Frame[0x78]  v4_cnt = 0 (NO relay servers)
Frame[0x79]  v6_cnt = 0
```

Setting `called_lan_ipv4 != called_outer_ipv4` triggers LAN channel creation
(mode=3, highest priority in `iv_get_connect_mode_link_chn`).

### SDK Internals

- **Private IP filter**: `iv_private_ip()` rejects 10.x, 192.168.x, 172.16-31.x for list servers. 127.x.x.x is NOT filtered (our relay uses localhost).
- **Response matching**: `stored_req_type == resp_type - 1` AND `stored_sqnum == resp_chkval`
- **ACK matching** (mode=1): `opt_ack=1` (bit 20), raw sqnum at frame[0x0C]
- **bit25** in opt_flags: bypasses session_id routing check entirely
- **LAN priority**: type=2 (LAN) breaks immediately in scoring loop, always preferred over relay

---

## Quick Start

```bash
# 1. Configure
cp .env.example .env
# Edit .env with Wyze credentials + DOORBELL_IP

# 2. Build
./into.sh build

# 3. Test (Tier 1 — hybrid, needs internet for CALLING)
P2P_URL='|18.118.90.161' LAN_WAIT=0 ./into.sh run 30

# 4. Test (Tier 2 — fully offline, needs doorbell on relay)
P2P_URL='|127.0.0.1' SKIP_WAKEUP=1 ./into.sh run 30

# 5. Play
ffplay logs/frames.h264
```
