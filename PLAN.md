# Next Steps

## ✅ 1. Relay fix (DONE)
Relay sends its own server term_id in DETECT_RESP (not echo of client's). Validated against real Mars servers via mars_probe.py.

## ✅ 2. Session key caching (DONE)
Relay captures session keys from proxied CERTIFY_RESP. Keys stored in `cache/session_keys.json` for offline operation.

## ✅ 3. Local CERTIFY (DONE)
In `--relay` mode, CERTIFY is handled locally:
- Parses client's 32-byte key contribution from CERTIFY_REQ
- Generates server key, derives session_key = client_key XOR server_key
- Builds proper CERTIFY_RESP with per-frame encrypted payload

## ✅ 4. Local CALLING routing (DONE)
In `--relay` mode, CALLING frames are routed between bridge and doorbell:
- Decrypts CALLING payload with session key to find destination term_id
- Routes directly to connected target via UDP or TCP
- Falls back to heuristic routing (bridge↔doorbell) if decryption fails

## ✅ 5. Doorbell keepalive (DONE)
`--keepalive` flag sends KEEPALIVE (type 0x17) every 25s to prevent doorbell sleep:
- Tracks doorbell addr from CERTIFY/DETECT
- Monitors ACK responses; warns after 3 consecutive misses
- Enabled via `RELAY_KEEPALIVE=1` in .env

## ✅ 6. Persistent bridge daemon (DONE)
`bridge-daemon` binary keeps SDK initialized and subscribed. On viewer connect:
- Skips 5s init + 2s subscribe (already done)
- Only calls iv_start_av_link (fast path)
- Commands via stdin: start/stop/quit/status

## ✅ 7. Docker cleanup (DONE)
- Healthcheck for go2rtc API
- .env.example with all config knobs documented
- Single `docker compose up` from zero to RTSP stream

---

## Testing Checklist

### Proxy mode (current default — internet required):
```bash
# 1. Build and start
./into.sh rebuild   # or just: docker compose up --build

# 2. Verify relay log shows CERTIFY flowing through:
tail -f relay.log   # Look for CERTIFY_REQ → FWD → CERTIFY_RESP → RELAY

# 3. Connect viewer:
ffplay rtsp://localhost:8554/doorbell
```

### Relay mode (fully offline after first auth):
```bash
# 1. Run once in proxy mode to cache Mars token + session keys
#    (cache/auth.json + cache/session_keys.json)

# 2. Switch to relay mode:
#    In .env: RELAY_MODE=relay  RELAY_KEEPALIVE=1

# 3. Disconnect internet and test:
docker compose up
ffplay rtsp://localhost:8554/doorbell
# Expected: <5s time-to-first-frame (doorbell kept awake by keepalive)
```

### Persistent daemon mode (fastest reconnect):
```bash
# Start daemon (keeps SDK warm):
./into.sh shell
./build/bridge-daemon --device YOUR_MAC

# In another terminal, send commands:
echo "start" > /proc/PID/fd/0   # or pipe stdin
# H.264 flows on stdout immediately
echo "stop" > /proc/PID/fd/0    # stops stream, keeps SDK alive
echo "start" > /proc/PID/fd/0   # instant restart (<2s)
```

---

## ⚠️ Critical: DNAT Configuration

**Current blocker**: Router-level DNAT redirects ALL Mars traffic (TCP+UDP to
`wyze-mars-asrv.wyzecam.com` IPs) to the local bridge host. This also breaks:
- **Doorbell → Mars session**: doorbell can't maintain its cloud connection
- **Chime → Mars session**: chime can't receive push notifications
- **Cloud wakeup**: DMS `run_action_batch` queues but never reaches doorbell

**Required fix (on OPNsense router):**
1. **Remove** the broad Mars DNAT rule (or restrict source to bridge host IP only)
2. The bridge does NOT need DNAT — it uses `P2P_URL=|127.0.0.1` to talk to the local relay directly
3. The doorbell and chime MUST be able to reach real Mars for wakeup to work
4. Alternatively: add source exception for doorbell (192.168.1.81) and chime (192.168.1.12)

Once DNAT is fixed:
- Cloud wakeup (`run_action_batch`) → Mars → doorbell (via chime BT or direct session)
- Doorbell wakes, connects to real Mars, responds to LAN broadcast
- SDK finds doorbell in broadcast list with correct P2P port
- LAN CALLING succeeds with `opt_lan_call=1` → MTP establishes → video flows

---

## Architecture (Final)

```
Viewer → go2rtc → bridge/daemon → SDK → [local relay] → doorbell
                                              ↑
                                    keepalive (25s) ─── doorbell stays awake
```

| Path | Time-to-First-Frame | Internet Required |
|------|---------------------|-------------------|
| Cold start (proxy) | ~90s | Yes (Mars + DMS wakeup) |
| Warm start (keepalive) | ~9s | No (cached creds) |
| Daemon + keepalive | ~2-3s | No |
