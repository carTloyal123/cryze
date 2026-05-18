# Configuration Reference

## Deployment Modes

The bridge operates in three tiers with progressively less cloud dependency.

### Mode Matrix

| Setting | Tier 1: Hybrid | Tier 2: Fully Offline | Tier 3: Auto-Offline |
|---------|---------------|----------------------|---------------------|
| `P2P_URL` | `\|18.118.90.161` | `\|127.0.0.1` | `\|127.0.0.1` |
| `RELAY_MODE` | `relay` | `relay` | `relay` |
| `SKIP_WAKEUP` | `0` | `1` | `1` |
| `LAN_ONLY` | `1` | `1` | `1` |
| `LAN_WAIT` | `15` | `0` | `0` |
| `SUBSCRIBE_WAIT` | `3` | `3` | `3` |
| `DOORBELL_IP` | required | required | required |
| `RELAY_KEEPALIVE` | `1` | `1` | `1` |
| Router DNAT | no | **yes** | no |
| Linux host + NET_ADMIN | no | no | **yes** |

### What each tier uses the internet for

| | Wyze Login (HTTPS) | Mars Wakeup (HTTPS) | Mars CALLING (UDP) | Cloud Video Relay | LAN Video |
|-|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | on first run | every stream | yes (~6KB) | blocked | yes |
| **Tier 2** | on first run | no | no | no | yes |
| **Tier 3** | on first run | no | no | no | yes |

After first run, login credentials are cached for 7 days (`cache/auth.json`).

### Tier 1: Hybrid (simplest, current default)

Internet used for CALLING signaling only (~6KB UDP). All video on LAN.
The SDK connects to a real Mars server for the CALLING relay which tells
the doorbell to start streaming to the bridge's LAN IP.

```env
P2P_URL=|18.118.90.161
RELAY_MODE=relay
RELAY_KEEPALIVE=1
LAN_ONLY=1
LAN_WAIT=15
SUBSCRIBE_WAIT=3
SKIP_WAKEUP=0
DOORBELL_IP=192.168.1.81
```

### Tier 2: Fully Offline (requires router DNAT)

Zero external connections after initial auth. The local relay handles all
signaling. Requires a DNAT rule on your router to redirect the doorbell's
Mars-bound UDP traffic to the bridge host.

```env
P2P_URL=|127.0.0.1
RELAY_MODE=relay
RELAY_KEEPALIVE=1
LAN_ONLY=1
LAN_WAIT=0
SUBSCRIBE_WAIT=3
SKIP_WAKEUP=1
DOORBELL_IP=192.168.1.81
```

Router DNAT rule:
```
Source: <doorbell_ip>  Dest: Mars IPs (port 28800 UDP)  → Redirect to: <bridge_host_ip>:28800
```

### Tier 3: Auto-Offline (Linux only)

Same as Tier 2 but the container automatically creates iptables DNAT rules.
No router configuration needed. Requires Linux host with `NET_ADMIN`.

Same `.env` as Tier 2. The `network-setup` service handles the DNAT automatically.

## All Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `WYZE_EMAIL` | Wyze account email |
| `WYZE_PASSWORD` | Wyze account password |
| `WYZE_KEY_ID` | API key ID from https://developer-api-console.wyze.com/ |
| `WYZE_API_KEY` | API key secret |
| `DOORBELL_IP` | Doorbell LAN IP (e.g. `192.168.1.81`) |

### Bridge Behavior

| Variable | Default | Description |
|----------|---------|-------------|
| `P2P_URL` | `\|127.0.0.1` | P2P server. `\|<ip>` format. `127.0.0.1` = local relay, Mars IP = hybrid |
| `SKIP_WAKEUP` | `0` | `1` = skip HTTPS wakeup API call (use when doorbell stays on via keepalive) |
| `LAN_ONLY` | `0` | `1` = block cloud TCP relay servers via iptables |
| `LAN_WAIT` | `90` | Seconds to wait for doorbell broadcast response. `0` = skip (use injection) |
| `SUBSCRIBE_WAIT` | `20` | Seconds to wait for subscribe. `3` recommended (relay mode always times out) |

### Relay

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_MODE` | `relay` | `relay` = handle all signaling locally. `proxy` = forward to Mars |
| `RELAY_KEEPALIVE` | `0` | `1` = send keepalive to doorbell every 25s (keeps it awake) |

### Network

| Variable | Default | Description |
|----------|---------|-------------|
| `DOORBELL_PORT` | `8899` | Doorbell P2P port (rarely needs changing) |
| `CHIME_IP` | | Chime LAN IP (for future local wakeup) |
| `GATEWAY_IP` | `192.168.1.1` | Router IP (for ARP redirect) |
| `NET_INTERFACE` | auto | Network interface for ARP redirect |
| `RELAY_IP` | auto | Host LAN IP (auto-detected from DOORBELL_IP subnet) |
| `P2P_PORT_TYPE` | `0` | SDK broadcast mode: `0`=IPv6+IPv4, `1`=IPv4 only |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FILE` | per-service | Set by docker-compose. `logs/bridge.log`, `logs/relay.log`, `logs/network.log` |

### Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_FILE` | `cache/auth.json` | Auth token cache (Mars token has 7-day TTL) |
