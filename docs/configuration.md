# Configuration Reference

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `WYZE_EMAIL` | Wyze account email |
| `WYZE_PASSWORD` | Wyze account password |
| `WYZE_KEY_ID` | API key ID from https://developer-api-console.wyze.com/ |
| `WYZE_API_KEY` | API key secret |
| `DOORBELL_IP` | Doorbell LAN IP (e.g. `192.168.1.81`) |

### Bridge

| Variable | Default | Description |
|----------|---------|-------------|
| `P2P_URL` | `\|18.118.90.161` | P2P server. `\|<ip>` format. Mars IP for standard operation |
| `SKIP_WAKEUP` | `0` | `1` = skip HTTPS wakeup (doorbell must already be awake) |
| `LAN_ONLY` | `1` | Block cloud TCP relay servers via iptables |
| `LAN_WAIT` | `15` | Seconds to wait for doorbell broadcast. `0` = skip, use injection |
| `SUBSCRIBE_WAIT` | `3` | Seconds to wait for subscribe response |

### Relay

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_MODE` | `relay` | `relay` = handle signaling locally. `proxy` = forward to Mars |
| `RELAY_KEEPALIVE` | `1` | Send keepalive to doorbell every 25s (keeps it awake) |

### Network

| Variable | Default | Description |
|----------|---------|-------------|
| `CHIME_IP` | | Chime LAN IP |
| `GATEWAY_IP` | `192.168.1.1` | Router IP (for ARP redirect) |
| `NET_INTERFACE` | auto | Network interface |
| `RELAY_IP` | auto | Host LAN IP (auto-detected) |
| `DOORBELL_PORT` | `51850` | Doorbell P2P port |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FILE` | per-service | `logs/bridge.log`, `logs/relay.log`, `logs/network.log` |

### Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_FILE` | `cache/auth.json` | Auth token cache (7-day TTL) |
