"""CALLING/wakeup routing — handles CALLING_REQ routing and doorbell wakeup."""

import socket as _socket
import struct
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from log_config import get_logger
log = get_logger('relay.calling')

from rc5 import RC5
from constants import HEADER_SIZE
from models import ClientSession, PendingWakeup


def handle_calling(relay, data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
    """Handle CALLING_REQ with full routing logic.

    In the real Mars relay, CALLING is routed by destination term_id
    (encrypted in the frame payload with opt_encrypt=2 session key).

    Relay mode routing:
    1. Resolve sender's device MAC from ClientSession.device_mac
    2. Route CALLING to the doorbell for that MAC if online
    3. Generate MTP_RES_RESP directing bridge to our local TCP relay

    Args:
        relay: GutesRelay instance
        data:  Raw CALLING_REQ frame bytes
        addr:  Sender (ip, port) tuple
        sender_term_id: Decoded term_id of sender

    Returns: MTP_RES_RESP bytes to send back to caller, or None.
    """
    state = relay.state

    if relay.mode == "relay":
        sender_client = state.clients.get(sender_term_id)
        sender_mac    = sender_client.device_mac if sender_client else ""

        # Try to decrypt payload to find explicit destination term_id
        dest_term_id = _extract_calling_dest(relay, data, sender_term_id)

        # Determine routing target based on sender role + MAC
        target_term_id = dest_term_id
        if not target_term_id and sender_client:
            if sender_client.role == "bridge" and sender_mac:
                target_term_id = state.doorbell_term_ids.get(sender_mac, 0)
            elif sender_client.role == "doorbell" and sender_mac:
                target_term_id = state.bridge_term_ids.get(sender_mac, 0)

        if target_term_id:
            target = state.clients.get(target_term_id)
            if target and (time.time() - target.last_seen) < 30:
                _route_calling_to(relay, data, target, sender_term_id)
            else:
                # Doorbell offline — trigger chime wakeup + queue
                log.info("  [CALLING] Doorbell offline, triggering chime wakeup (mac=%s)", sender_mac)
                _trigger_chime_wakeup(relay, sender_mac)
                chime_tid = state.chime_term_ids.get(sender_mac, 0)
                if chime_tid:
                    chime = state.clients.get(chime_tid)
                    if chime and (time.time() - chime.last_seen) < 120:
                        _route_calling_to(relay, data, chime, sender_term_id)
                state.pending_callings.setdefault(sender_mac, []).append(
                    PendingWakeup(calling_data=data, bridge_term_id=sender_term_id,
                                  timestamp=time.time(), timeout=90.0))
        else:
            # Can't determine destination — trigger wakeup as fallback
            log.info("  [CALLING] Unknown dest, triggering chime wakeup (mac=%s)", sender_mac)
            _trigger_chime_wakeup(relay, sender_mac)
            chime_tid = state.chime_term_ids.get(sender_mac, 0)
            if chime_tid:
                chime = state.clients.get(chime_tid)
                if chime and (time.time() - chime.last_seen) < 120:
                    _route_calling_to(relay, data, chime, sender_term_id)
            state.pending_callings.setdefault(sender_mac, []).append(
                PendingWakeup(calling_data=data, bridge_term_id=sender_term_id,
                              timestamp=time.time(), timeout=90.0))

        # Build CALLING_ACK + MTP_RES_RESP — direct SDK to local TCP relay
        calling_ack = relay._build_calling_ack(data, addr, sender_term_id)
        mtp_resp    = relay._build_mtp_res_resp(data, addr, sender_term_id)
        if calling_ack and mtp_resp:
            log.info("  [MTP] Sending CALLING_ACK + MTP_RES_RESP to bridge %s:%d",
                     addr[0], addr[1])
            relay._extra_responses.append((calling_ack, addr))
            return mtp_resp
        elif mtp_resp:
            log.info("  [MTP] Sending MTP_RES_RESP to bridge %s:%d", addr[0], addr[1])
            return mtp_resp
        return None

    else:
        log.info("  [PROXY] CALLING forwarded to Mars for routing")
        return None


def _extract_calling_dest(relay, data: bytes, sender_term_id: int) -> int:
    """Try to extract destination term_id from CALLING payload.

    The CALLING_REQ payload is session-encrypted (opt_encrypt=2).
    If we have the sender's session key, we can decrypt to find
    the destination term_id (first 8 bytes of decrypted payload).
    """
    state = relay.state
    opt_flags = struct.unpack_from('<I', data, 0x14)[0]
    encrypt_mode = (opt_flags >> 16) & 3
    payload = data[0x18:]

    if encrypt_mode != 2 or len(payload) < 8:
        return 0

    session_key = relay.get_session_key(sender_term_id)
    if not session_key:
        # Try addr-based lookup; prefer the key for the sender's device MAC
        sender_client = state.clients.get(sender_term_id)
        sender_mac    = sender_client.device_mac if sender_client else ""
        if sender_mac:
            for a, sk in state.addr_session_keys.items():
                client_tid = state.addr_to_term.get(a)
                if client_tid:
                    c = state.clients.get(client_tid)
                    if c and c.device_mac == sender_mac:
                        session_key = sk
                        break
        if not session_key:
            # Last resort: first available key
            for sk in state.addr_session_keys.values():
                session_key = sk
                break

    if not session_key:
        log.info("  [CALLING] No session key for sender %d, cannot extract dest", sender_term_id)
        return 0

    try:
        rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
        dec_len = (len(payload) // 8) * 8
        if dec_len < 8:
            return 0
        decrypted = rc5.decrypt(bytes(payload[:dec_len]))
        dest_id = struct.unpack_from('<q', decrypted, 0)[0]
        log.info("  [CALLING] Decrypted dest_term_id=%d", dest_id)
        return dest_id
    except Exception as e:
        log.info("  [CALLING] Decrypt failed: %s", e)
        return 0


def _route_calling_to(relay, data: bytes, target: ClientSession, sender_term_id: int):
    """Route a CALLING frame directly to a connected target."""
    if target.tcp_writer:
        try:
            target.tcp_writer.write(data)
            log.info("  [CALLING] Routed to %s:%d (TCP) term_id=%d",
                     target.addr[0], target.addr[1], target.term_id)
            target.frames_out += 1
        except Exception as e:
            log.info("  [CALLING] TCP route failed: %s", e)
    elif target.our_port in relay.relay_socks:
        try:
            relay.relay_socks[target.our_port].sendto(data, target.addr)
            log.info("  [CALLING] Routed to %s:%d:%d (UDP) term_id=%d",
                     target.addr[0], target.addr[1], target.our_port, target.term_id)
            target.frames_out += 1
        except OSError as e:
            log.info("  [CALLING] UDP route failed: %s", e)
    else:
        log.info("  [CALLING] No route to target term_id=%d", target.term_id)


def _trigger_chime_wakeup(relay, device_mac: str = ""):
    """Send a CALLING frame to the chime to trigger BT doorbell wakeup.

    Builds a plaintext CALLING_REQ (0xA4) with bit25 bypass that the chime's
    SDK can process. The chime receives CALLING and triggers BT wakeup of
    the doorbell, same as when Mars forwards CALLING.

    Args:
        relay:       GutesRelay instance
        device_mac:  MAC of the camera/doorbell to wake (used to find chime + doorbell IP)
    """
    state   = relay.state
    chime_tid = state.chime_term_ids.get(device_mac, 0)
    if not chime_tid:
        log.info("  [WAKEUP] No chime connected for mac=%s", device_mac)
        return

    chime = state.clients.get(chime_tid)
    if not chime or (time.time() - chime.last_seen) > 120:
        log.info("  [WAKEUP] Chime session stale for mac=%s", device_mac)
        return

    sock = relay.relay_socks.get(chime.our_port)
    if not sock:
        log.info("  [WAKEUP] No socket for chime port %d", chime.our_port)
        return

    # Resolve doorbell IP via registry
    registry   = state.registry
    doorbell_ip = ""
    if registry and device_mac:
        info = registry.get_by_mac(device_mac)
        if info and info.lan_ip:
            doorbell_ip = info.lan_ip
    bridge_ip = relay.local_ip

    import random as _rand
    link_id = _rand.randint(1, 0x7FFFFFFF)

    payload = bytearray(32)
    # dest_term_id: broadcast (chime processes)
    struct.pack_into('<Q', payload, 0, 0)
    struct.pack_into('<I', payload, 8, link_id)
    # caller IP (relay's IP)
    try:
        ip_bytes = _socket.inet_aton(bridge_ip)
    except OSError:
        ip_bytes = b'\x00\x00\x00\x00'
    payload[0x0C:0x10] = ip_bytes
    struct.pack_into('>H', payload, 0x10, 28800)  # caller port
    payload[0x12] = 1  # call_type = live

    pad = (8 - len(payload) % 8) % 8
    payload += b'\x00' * pad

    frame_size = HEADER_SIZE + len(payload)
    calling = bytearray(frame_size)
    calling[0] = 0x7F  # relay proto
    calling[1] = 0xA4  # CALLING_REQ
    struct.pack_into('<H', calling, 2, frame_size)
    struct.pack_into('<q', calling, 4, relay.server_term_id)
    sqnum = relay.server_sqnum
    relay.server_sqnum = (relay.server_sqnum + 1) & 0xFFFFFFFF
    struct.pack_into('<I', calling, 0x0C, sqnum)
    struct.pack_into('<I', calling, 0x14, (1 << 25))  # opt_flags: bit25 bypass
    calling[HEADER_SIZE:HEADER_SIZE + len(payload)] = payload

    try:
        sock.sendto(bytes(calling), chime.addr)
        log.info("  [WAKEUP] Sent CALLING to chime %s:%d (link_id=%d, %dB, doorbell=%s)",
                 chime.addr[0], chime.addr[1], link_id, frame_size, doorbell_ip)
    except OSError as e:
        log.info("  [WAKEUP] CALLING send failed: %s", e)


def deliver_pending_callings(relay, doorbell_term_id: int, device_mac: str):
    """Deliver queued CALLING frames to the newly-connected doorbell.

    Called when a doorbell for device_mac connects and completes CERTIFY.

    Args:
        relay:            GutesRelay instance
        doorbell_term_id: term_id of the newly connected doorbell
        device_mac:       MAC of the camera/doorbell
    """
    state = relay.state
    now   = time.time()
    queue = state.pending_callings.get(device_mac, [])
    if not queue:
        return

    delivered = 0
    expired   = 0
    remaining = []

    for pending in queue:
        age = now - pending.timestamp
        if age > pending.timeout:
            expired += 1
            continue

        doorbell = state.clients.get(doorbell_term_id)
        if doorbell:
            log.info("  [WAKEUP] Delivering queued CALLING to doorbell mac=%s (queued %.1fs ago)",
                     device_mac, age)
            if doorbell.tcp_writer:
                try:
                    doorbell.tcp_writer.write(pending.calling_data)
                    delivered += 1
                    continue
                except Exception:
                    pass
            elif doorbell.our_port in relay.relay_socks:
                try:
                    relay.relay_socks[doorbell.our_port].sendto(
                        pending.calling_data, doorbell.addr)
                    delivered += 1
                    continue
                except Exception:
                    pass
        remaining.append(pending)

    state.pending_callings[device_mac] = remaining
    if delivered or expired:
        log.info("  [WAKEUP] Delivered %d CALLINGs, expired %d (mac=%s)",
                 delivered, expired, device_mac)


def identify_device_role(relay, term_id: int, addr: tuple) -> str:
    """Identify device role using the DeviceRegistry.

    - doorbell: addr IP matches any registry DeviceInfo.lan_ip
    - bridge:   addr IP is relay's own IP or loopback
    - unknown:  everything else
    """
    registry = relay.state.registry
    ip = addr[0]

    if registry and registry.is_doorbell_ip(ip):
        return "doorbell"
    if ip in (relay.local_ip, "127.0.0.1"):
        return "bridge"
    return "unknown"


def on_client_certified(relay, term_id: int):
    """Called when a client completes CERTIFY. Identify role and handle wakeups."""
    state  = relay.state
    client = state.clients.get(term_id)
    if not client:
        return

    role = identify_device_role(relay, term_id, client.addr)

    # For bridges: use CERTIFY payload for precise device-MAC identification
    if role in ("bridge", "unknown"):
        certify_data = relay._last_certify_frames.get(term_id)
        if certify_data and state.registry:
            mac = state.registry.identify_bridge_mac(certify_data)
            if mac:
                client.device_mac = mac
                role = "bridge"
                log.info("  [CERTIFY-ID] Bridge identified: term_id=%d mac=%s", term_id, mac)

    client.role = role
    mac = client.device_mac

    if role == "chime":
        # Chimes: associate with a doorbell by IP adjacency or fallback to IP key
        # Use registry to find which doorbell this chime belongs to
        registry = state.registry
        if registry and mac:
            state.chime_term_ids[mac] = term_id
        else:
            # Store under addr-derived key as best-effort
            state.chime_term_ids[client.addr[0]] = term_id
        log.info("  [ROLE] CHIME: term_id=%d addr=%s:%d mac=%s",
                 term_id, client.addr[0], client.addr[1], mac or '?')

    elif role == "doorbell":
        # Resolve MAC from registry by LAN IP if not already set
        if not mac and state.registry:
            info = state.registry.get_by_lan_ip(client.addr[0])
            if info:
                mac = info.mac
                client.device_mac = mac
        if mac:
            state.doorbell_term_ids[mac] = term_id
            state.doorbell_addrs[mac]    = client.addr
            state.keepalive_misses[mac]  = 0
            log.info("  [ROLE] DOORBELL: term_id=%d addr=%s:%d mac=%s",
                     term_id, client.addr[0], client.addr[1], mac)
            if state.keepalive_enabled:
                log.info("  [KEEPALIVE] Doorbell connected — keepalive active for %s", mac)
            # Deliver any pending CALLINGs for this device
            if state.pending_callings.get(mac):
                deliver_pending_callings(relay, term_id, mac)
        else:
            log.info("  [ROLE] DOORBELL (mac unknown): term_id=%d addr=%s:%d",
                     term_id, client.addr[0], client.addr[1])

    elif role == "bridge":
        if mac:
            state.bridge_term_ids[mac] = term_id
            log.info("  [ROLE] BRIDGE: term_id=%d mac=%s", term_id, mac)
        else:
            log.info("  [ROLE] BRIDGE (mac unknown): term_id=%d addr=%s:%d",
                     term_id, client.addr[0], client.addr[1])

    else:
        log.info("  [ROLE] UNKNOWN: term_id=%d addr=%s:%d",
                 term_id, client.addr[0], client.addr[1])
