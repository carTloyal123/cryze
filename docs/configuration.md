# Configuration

All configuration is via environment variables in `.env`. See `.env.example` for a template.

## Required

| Variable | Description |
|----------|-------------|
| `WYZE_EMAIL` | Wyze account email |
| `WYZE_PASSWORD` | Wyze account password |
| `WYZE_KEY_ID` | API key ID from https://developer-api-console.wyze.com/ |
| `WYZE_API_KEY` | API key secret from developer console |

## Relay

| Variable | Default | Description |
|----------|---------|-------------|
| `P2P_URL` | `\|127.0.0.1` | P2P server address. `\|<ip>` format. Use `127.0.0.1` for local relay, or a real Mars IP (e.g., `\|18.118.90.161`) for direct cloud |
| `RELAY_MODE` | `proxy` | `proxy` = forward unknown frames to Mars. `relay` = handle everything locally |
| `RELAY_KEEPALIVE` | `0` | `1` = send KEEPALIVE to connected doorbell every 25s |
| `RELAY_UPSTREAM` | (auto) | Mars upstream for proxy mode. Auto-resolved from `wyze-mars-asrv.wyzecam.com` |
| `MTP_PORT` | `23000` | TCP port for local MTP relay bridging |
| `LOCAL_IP` | (auto) | LAN IP used in CALLING ACK netaddr field |

## Network

| Variable | Default | Description |
|----------|---------|-------------|
| `LAN_ONLY` | `0` | `1` = block outbound TCP to non-LAN IPs via iptables (eliminates cloud TCP relay servers) |
| `LAN_WAIT` | `90` | Seconds to wait for doorbell LAN broadcast response. Set to `0` to skip (recommended — doorbell never responds to broadcast) |
| `SUBSCRIBE_WAIT` | `20` | Seconds to wait for subscribe completion. In relay mode subscribe always fails gracefully — use `3`-`5` for faster startup |
| `SKIP_WAKEUP` | `0` | `1` = skip the HTTPS `run_action_batch` wakeup API call. Use when doorbell stays connected via relay keepalive |
| `P2P_PORT_TYPE` | `0` | Broadcast port type: `0` = IPv6+IPv4, `1` = IPv4 only, `2` = IPv4 alt |

## Device

| Variable | Default | Description |
|----------|---------|-------------|
| `DOORBELL_IP` | (none) | Doorbell LAN IP. Used for CALLING ACK (tells SDK where to send video) and MTP_RES_RESP (LAN channel target) |
| `DOORBELL_PORT` | `8899` | Doorbell P2P discovery port |
| `CHIME_IP` | (none) | Chime LAN IP (for future local wakeup support) |
| `DEVICE_MAC` | (auto) | Specific device MAC to stream. Leave blank to auto-detect the first `GW_` model (doorbell) |

## Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_FILE` | `cache/auth.json` | Auth token cache file. Mars token has 7-day TTL |

## Recommended Configurations

### Default (Tier 1 — minimal cloud)

```env
WYZE_EMAIL=you@example.com
WYZE_PASSWORD=your-password
WYZE_KEY_ID=your-key-id
WYZE_API_KEY=your-api-key
P2P_URL=|127.0.0.1
RELAY_MODE=relay
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=5
```

### Fully Offline (Tier 2 — requires router DNAT)

```env
WYZE_EMAIL=you@example.com
WYZE_PASSWORD=your-password
WYZE_KEY_ID=your-key-id
WYZE_API_KEY=your-api-key
P2P_URL=|127.0.0.1
RELAY_MODE=relay
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=5
SKIP_WAKEUP=1
DOORBELL_IP=192.168.1.81
```
