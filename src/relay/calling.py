"""CALLING/wakeup routing — handles CALLING_REQ routing and doorbell wakeup."""

import os
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
    1. Try to decrypt payload to find destination term_id
    2. Route CALLING to doorbell if online
    3. Generate MTP_RES_RESP directing bridge to our local TCP relay
    
    Proxy mode: Mars handles routing, we just log and forward.
    
    Args:
        relay: GutesRelay instance
        data: Raw CALLING_REQ frame bytes
        addr: Sender (ip, port) tuple
        sender_term_id: Decoded term_id of sender
    
    Returns: MTP_RES_RESP bytes to send back to caller, or None.
    """
    state = relay.state
    
    if relay.mode == "relay":
        # Try to determine destination from payload
        dest_term_id = _extract_calling_dest(relay, data, sender_term_id)
        
        # Determine target: explicit destination or heuristic
        target_term_id = dest_term_id
        if not target_term_id:
            # Heuristic: if sender is bridge, target is doorbell (and vice versa)
            if sender_term_id == state.bridge_term_id:
                target_term_id = state.doorbell_term_id
            elif sender_term_id == state.doorbell_term_id:
                target_term_id = state.bridge_term_id
        
        if target_term_id:
            target = state.clients.get(target_term_id)
            if target and (time.time() - target.last_seen) < 30:
                # Target is online — route CALLING directly to it
                _route_calling_to(relay, data, target, sender_term_id)
        else:
            # Target not connected — queue CALLING and trigger wakeup
            log.info(f"  [CALLING] Target offline (dest={target_term_id}) — queuing + wakeup")
            state.pending_callings.append(PendingWakeup(
                calling_data=data,
                bridge_term_id=sender_term_id,
                timestamp=time.time(),
                timeout=30.0
            ))
            _trigger_chime_wakeup(relay)
        
        # Generate MTP_RES_RESP to direct the bridge to our local TCP relay
        # This tells the SDK: "connect to our relay for media transport"
        # But first, send a CALLING ACK with the doorbell's address
        # (the SDK expects this before MTP_RES_RESP)
        calling_ack = relay._build_calling_ack(data, addr, sender_term_id)
        mtp_resp = relay._build_mtp_res_resp(data, addr, sender_term_id)
        if calling_ack and mtp_resp:
            log.info(f"  [MTP] Sending CALLING_ACK + MTP_RES_RESP to bridge {addr[0]}:{addr[1]}")
            # Return both concatenated — the recv loop will need to handle this
            # Actually we can't return two frames. Send the ACK via the socket
            # and return the MTP_RES_RESP
            relay._extra_responses.append((calling_ack, addr))
            return mtp_resp
        elif mtp_resp:
            log.info(f"  [MTP] Sending MTP_RES_RESP to bridge {addr[0]}:{addr[1]}")
            return mtp_resp
        return None
    # In proxy mode: Mars handles routing, but log for awareness
    else:
        log.info(f"  [PROXY] CALLING forwarded to Mars for routing")
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
    payload = data[0x18:]  # Encryption starts at 0x18
    
    if encrypt_mode != 2 or len(payload) < 8:
        return 0
    
    session_key = relay.get_session_key(sender_term_id)
    if not session_key:
        # Try addr-based lookup (CALLING comes from same addr as CERTIFY)
        # We need to find which addr has this sender_term_id
        for a, sk in state.addr_session_keys.items():
            session_key = sk
            break  # Use first available session key (bridge usually only has one)
    if not session_key:
        log.info(f"  [CALLING] No session key for sender {sender_term_id}, cannot extract dest")
        return 0
    
    try:
        rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
        dec_len = (len(payload) // 8) * 8
        if dec_len < 8:
            return 0
        decrypted = rc5.decrypt(bytes(payload[:dec_len]))
        # First 8 bytes of CALLING payload = destination term_id (int64 LE)
        dest_id = struct.unpack_from('<q', decrypted, 0)[0]
        log.info(f"  [CALLING] Decrypted dest_term_id={dest_id}")
        return dest_id
    except Exception as e:
        log.info(f"  [CALLING] Decrypt failed: {e}")
        return 0


def _route_calling_to(relay, data: bytes, target: ClientSession, sender_term_id: int):
    """Route a CALLING frame directly to a connected target."""
    if target.tcp_writer:
        try:
            target.tcp_writer.write(data)
            log.info(f"  [CALLING] Routed to {target.addr[0]}:{target.addr[1]} (TCP) "
                    f"term_id={target.term_id}")
            target.frames_out += 1
        except Exception as e:
            log.info(f"  [CALLING] TCP route failed: {e}")
    elif target.our_port in relay.relay_socks:
        try:
            relay.relay_socks[target.our_port].sendto(data, target.addr)
            log.info(f"  [CALLING] Routed to {target.addr[0]}:{target.addr[1]}:{target.our_port} (UDP) "
                    f"term_id={target.term_id}")
            target.frames_out += 1
        except OSError as e:
            log.info(f"  [CALLING] UDP route failed: {e}")
    else:
        log.info(f"  [CALLING] No route to target term_id={target.term_id}")


def _trigger_chime_wakeup(relay):
    """Send a wakeup command to the chime via GUTES.
    
    The chime is always connected (it's plugged in). We need to send it
    a GDM PASSTHROUGH frame that instructs it to wake the doorbell via BT.
    
    From the RE: the wakeup is triggered by a PASSTHROUGH frame (type 0xBD)
    containing a GDM action_key='wakeup' with action_params={'wakeup-live-view': 1}.
    
    The exact frame format will be determined once we capture the chime's
    traffic through our relay. For now, this is a placeholder.
    """
    state = relay.state
    if not state.chime_term_id:
        log.info(f"  [WAKEUP] No chime connected — cannot trigger local wakeup")
        log.info(f"  [WAKEUP] Falling back to cloud wakeup (DMS HTTP)")
        return
    
    chime = state.clients.get(state.chime_term_id)
    if not chime or (time.time() - chime.last_seen) > 60:
        log.info(f"  [WAKEUP] Chime session stale — cannot trigger local wakeup")
        return
    
    # TODO: Build and send the actual wakeup PASSTHROUGH frame to chime
    # This will be filled in once we capture the chime's GDM traffic
    # and understand what frame triggers the BT wakeup
    log.info(f"  [WAKEUP] Would send wakeup to chime term_id={state.chime_term_id}")
    log.info(f"  [WAKEUP] (pending: capture chime traffic to learn wakeup frame format)")


def deliver_pending_callings(relay, doorbell_term_id: int):
    """Deliver queued CALLING frames to the newly-connected doorbell.
    
    Called when the doorbell connects and completes CERTIFY.
    """
    state = relay.state
    now = time.time()
    delivered = 0
    expired = 0
    
    remaining = []
    for pending in state.pending_callings:
        age = now - pending.timestamp
        if age > pending.timeout:
            expired += 1
            continue
        
        # Deliver this CALLING to the doorbell
        doorbell = state.clients.get(doorbell_term_id)
        if doorbell:
            log.info(f"  [WAKEUP] Delivering queued CALLING to doorbell "
                    f"(queued {age:.1f}s ago)")
            # In relay mode: send directly to doorbell's address
            if doorbell.tcp_writer:
                # TCP delivery
                try:
                    doorbell.tcp_writer.write(pending.calling_data)
                    delivered += 1
                except:
                    remaining.append(pending)
            elif doorbell.our_port in relay.relay_socks:
                # UDP delivery
                try:
                    relay.relay_socks[doorbell.our_port].sendto(
                        pending.calling_data, doorbell.addr)
                    delivered += 1
                except:
                    remaining.append(pending)
        else:
            remaining.append(pending)
    
    state.pending_callings = remaining
    if delivered or expired:
        log.info(f"  [WAKEUP] Delivered {delivered} CALLINGs, expired {expired}")


def identify_device_role(relay, term_id: int, addr: tuple) -> str:
    """Identify device role based on IP matching.

    Uses environment variables for configurable IPs:
    - DOORBELL_IP: IP of the doorbell
    - CHIME_IP: IP of the chime (optional)
    - Bridge: localhost or our own IP
    """
    ip = addr[0]
    doorbell_ip = os.environ.get('DOORBELL_IP', '192.168.1.81')
    chime_ip = os.environ.get('CHIME_IP', '192.168.1.12')

    if ip == doorbell_ip:
        return "doorbell"
    elif ip == chime_ip:
        return "chime"
    elif ip in (relay.local_ip, "127.0.0.1", "192.168.5.1"):
        return "bridge"
    
    # Heuristic: if from the same subnet but not doorbell/chime, likely bridge
    return "unknown"


def on_client_certified(relay, term_id: int):
    """Called when a client completes CERTIFY. Identify role and handle wakeups."""
    state = relay.state
    client = state.clients.get(term_id)
    if not client:
        return
    
    # Identify role
    role = identify_device_role(relay, term_id, client.addr)
    client.role = role
    
    if role == "chime":
        state.chime_term_id = term_id
        log.info(f"  [ROLE] Identified CHIME: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
    elif role == "doorbell":
        state.doorbell_term_id = term_id
        state.doorbell_addr = client.addr
        state.keepalive_misses = 0
        log.info(f"  [ROLE] Identified DOORBELL: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
        if state.keepalive_enabled:
            log.info(f"  [KEEPALIVE] Doorbell connected — keepalive will begin to {client.addr[0]}:{client.addr[1]}")
        # Deliver any pending CALLINGs
        if state.pending_callings:
            deliver_pending_callings(relay, term_id)
    elif role == "bridge":
        state.bridge_term_id = term_id
        log.info(f"  [ROLE] Identified BRIDGE: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
    else:
        log.info(f"  [ROLE] Unknown device: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
