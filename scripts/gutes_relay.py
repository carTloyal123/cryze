#!/usr/bin/env python3
"""GUTES Local Relay Server / UDP MitM Proxy.

Modes:
  --proxy    Forward all traffic to real Mars relay (capture + learn)
  --relay    Standalone local relay (no internet needed)

Architecture:
  - Listens on multiple ports (28800, 8443, 8000, 443, 51701)
  - Routes frames between clients using term_id (decrypted with static RC5 key)
  - In proxy mode: intercepts DETECT locally, forwards everything else to Mars
  - In relay mode: handles all signaling locally (CERTIFY, CALLING routing, GDM)

Usage:
  # Proxy mode (capture chime + bridge traffic, learn the protocol):
  python3 gutes_relay.py --proxy --upstream 3.13.212.24:28800

  # Standalone relay mode (fully offline):
  python3 gutes_relay.py --relay

  # Then point DNS: wyze-mars-asrv.wyzecam.com → this machine's IP
"""

import argparse
import asyncio
import hashlib
import os
import socket
import struct
import sys
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_decrypt, id_encrypt

# --- Frame type constants (verified from pcap) ---
TYPE_DETECT_REQ = 0x01
TYPE_DETECT_RESP = 0x02
TYPE_CERTIFY_REQ = 0x0C
TYPE_CERTIFY_RESP = 0x0D
TYPE_LIST_REQ = 0x15
TYPE_LIST_RESP = 0x16
TYPE_KEEPALIVE = 0x17
TYPE_SUBSCRIBE = 0xA0
TYPE_SUBSCRIBE_RESP = 0xA1
TYPE_MTP_RES_RESPONSE = 0xA2
TYPE_CALLING_REQ = 0xA4
TYPE_INIT_INFO_MSG = 0xA6
TYPE_GDM_PUSH = 0xA7
TYPE_CALLING_ERR = 0xAA
TYPE_SESSION_CTL = 0xB0
TYPE_SESSION_CTL_RESP = 0xB1
TYPE_ONLINE_MSG = 0xB4
TYPE_PASSTHROUGH = 0xBD

FRAME_TYPES = {
    0x01: "DETECT_REQ", 0x02: "DETECT_RESP",
    0x0C: "CERTIFY", 0x0D: "CERTIFY_RESP",
    0x15: "LIST_REQ", 0x16: "LIST_RESP",
    0x17: "KEEPALIVE",
    0xA0: "SUBSCRIBE", 0xA1: "SUBSCRIBE_RESP",
    0xA2: "MTP_RES_RESP", 0xA4: "CALLING_REQ",
    0xA6: "INIT_INFO", 0xA7: "GDM_PUSH",
    0xAA: "CALLING_ERR/GDM", 0xB0: "SESSION_CTL",
    0xB1: "SESSION_CTL_RESP", 0xB4: "ONLINE_MSG",
    0xBD: "PASSTHROUGH",
}

HEADER_SIZE = 0x1C


@dataclass
class ClientSession:
    """Tracks a connected client (bridge, chime, or doorbell)."""
    term_id: int = 0
    addr: tuple = ('', 0)
    session_id: int = 0
    last_seen: float = 0.0
    frames_in: int = 0
    frames_out: int = 0
    role: str = "unknown"  # "bridge", "chime", "doorbell"
    certified: bool = False
    # Track which port the client uses to talk to us
    our_port: int = 0
    # TCP connection (if connected via TCP)
    tcp_writer: Optional[object] = None  # asyncio.StreamWriter
    # Known device IDs associated with this client (from INIT_INFO_MSG)
    device_ids: list = field(default_factory=list)


@dataclass
class PendingWakeup:
    """A CALLING that's waiting for the doorbell to connect."""
    calling_data: bytes = b''
    bridge_term_id: int = 0
    timestamp: float = 0.0
    timeout: float = 30.0  # Max wait time (seconds)


@dataclass
class RelayState:
    """Global relay state."""
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> session
    addr_to_term: dict[tuple, int] = field(default_factory=dict)  # (ip, port) -> term_id
    next_session_id: int = 7640526817926134784  # Match real Mars session IDs
    
    # Wakeup infrastructure
    pending_callings: list = field(default_factory=list)  # PendingWakeup queue
    
    # Known device mapping (from captured GDM/INIT_INFO)
    # These are the 64-bit device IDs from the Wyze ecosystem
    known_devices: dict[int, str] = field(default_factory=dict)  # numeric_did -> role
    
    # Chime → doorbell association
    chime_term_id: int = 0  # Term ID of the connected chime
    doorbell_term_id: int = 0  # Term ID of the doorbell (when connected)
    bridge_term_id: int = 0  # Term ID of our bridge


class GutesRelay:
    """UDP-based GUTES relay server with full proxy + standalone capability."""

    def __init__(self, listen_ports: list[int] = None, list_port: int = 51701,
                 mode: str = "proxy", upstream: str = "3.13.212.24:28800",
                 log_file: Optional[str] = None, local_ip: str = ""):
        self.listen_ports = listen_ports or [28800, 8443, 8000]
        self.list_port = list_port
        self.mode = mode
        self.upstream_host = upstream.split(':')[0]
        self.upstream_port = int(upstream.split(':')[1])
        self.state = RelayState()
        self.t0 = time.time()
        self.log_fp = open(log_file, 'a') if log_file else None
        self.local_ip = local_ip or self._detect_local_ip()
        
        # Socket references
        self.relay_socks: dict[int, socket.socket] = {}  # port -> socket
        self.list_sock: Optional[socket.socket] = None
        self.upstream_socks: dict[int, socket.socket] = {}  # client_term_id -> upstream socket
        
        # For proxy mode: map upstream responses to clients
        self.upstream_to_client: dict[int, tuple] = {}  # upstream_sock_fd -> (client_addr, relay_port)

    def _detect_local_ip(self) -> str:
        """Detect our LAN IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.168.1.1", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def log(self, msg: str):
        elapsed = time.time() - self.t0
        line = f"[{elapsed:8.3f}] {msg}"
        print(line, flush=True)
        if self.log_fp:
            self.log_fp.write(line + "\n")
            self.log_fp.flush()

    def decode_term_id(self, frame_data: bytes) -> int:
        """Decode term_id from frame header using static RC5 key."""
        if len(frame_data) < HEADER_SIZE:
            return 0
        encrypted_id = frame_data[4:12]
        sqnum_bytes = frame_data[0x0C:0x10]
        chkval_bytes = frame_data[0x10:0x14]
        try:
            id_bytes = id_decrypt(encrypted_id, chkval_bytes, sqnum_bytes)
            return struct.unpack_from('<q', id_bytes)[0]
        except:
            return 0

    def get_frame_info(self, data: bytes) -> tuple[int, int, int, int]:
        """Extract (protocol, type, frm_len, opt_flags) from frame."""
        if len(data) < HEADER_SIZE:
            return (0, 0, 0, 0)
        protocol = data[0]
        ftype = data[1]
        frm_len = struct.unpack_from('<H', data, 2)[0]
        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        return (protocol, ftype, frm_len, opt_flags)

    def is_ack(self, opt_flags: int) -> bool:
        return bool((opt_flags >> 20) & 1)

    def is_response(self, opt_flags: int) -> bool:
        return bool((opt_flags >> 21) & 1)

    def build_detect_resp(self, req_data: bytes) -> bytes:
        """Build DETECT_RESP matching the real Mars relay format.
        
        Real DETECT_RESP (56 bytes):
          Header (0x1C):
            [0]: 0x7F, [1]: 0x02, [2:4]: 0x0038 (56)
            [4:12]: term_id (copied from req)
            [0x0C:0x10]: sqnum (copied from req)
            [0x10:0x14]: chkval (copied from req)
            [0x14:0x18]: opt_flags = 0x0000a6d0 (specific to detect_resp)
            [0x18:0x1A]: flags2 = 0x0001
            [0x1A:0x1C]: ack_result = 0
          Payload (28 bytes):
            +0x00: NTP time (4B LE)
            +0x04: 0x00000000
            +0x08: MTU info (0x5a, 0x00, 0x58, 0x00) — 90 and 88
            +0x0c: NTP time (repeat)
            +0x10: 0x00000000
            +0x14: server uptime/random (4B)
            +0x18: server load/flags (4B, e.g., 0x84010000 = 388)
        """
        resp = bytearray(0x38)  # 56 bytes
        resp[0] = 0x7F
        resp[1] = TYPE_DETECT_RESP
        struct.pack_into('<H', resp, 2, 0x38)
        
        # Copy term_id, sqnum, chkval from request
        resp[4:12] = req_data[4:12]
        resp[0x0C:0x10] = req_data[0x0C:0x10]
        resp[0x10:0x14] = req_data[0x10:0x14]
        
        # opt_flags: match real Mars relay response exactly
        struct.pack_into('<I', resp, 0x14, 0x0000a6d0)
        
        # flags2 = 0x0001
        struct.pack_into('<H', resp, 0x18, 0x0001)
        # ack_result = 0
        struct.pack_into('<H', resp, 0x1A, 0x0000)
        
        # Payload (28 bytes)
        now = int(time.time())
        # NTP time at +0x00
        struct.pack_into('<I', resp, 0x1C, now)
        # +0x04: zero
        struct.pack_into('<I', resp, 0x20, 0)
        # +0x08: MTU values (90, 88 from real capture)
        resp[0x24] = 0x5A  # 90
        resp[0x25] = 0x00
        resp[0x26] = 0x58  # 88  
        resp[0x27] = 0x00
        # +0x0C: NTP time repeat
        struct.pack_into('<I', resp, 0x28, now)
        # +0x10: zero
        struct.pack_into('<I', resp, 0x2C, 0)
        # +0x14: uptime/random
        struct.pack_into('<I', resp, 0x30, int(time.time()) & 0x7FFFFFFF)
        # +0x18: server load (low = better)
        struct.pack_into('<I', resp, 0x34, 1)  # minimal load
        
        return bytes(resp)

    def build_list_resp(self, req_data: bytes, reply_ip: str = None) -> bytes:
        """Build LIST_RESP with our relay as the only server.
        
        Format (from captured 176-byte response, frm_len=0xB0):
        - Header (0x1C bytes)
        - Payload: server list entries (per-frame encrypted)
        
        Each server entry (from RE of iv_get_srv_list_from_Rmtlist_Resp):
        - 4 bytes: IPv4 address (network byte order)  
        - 2 bytes: port (LE)
        - 2 bytes: server_id (LE)
        - 2 bytes: flags
        
        Since the payload is per-frame encrypted and we know the key derivation,
        we can build a valid encrypted response.
        """
        # Build a minimal response with one server entry
        # We need to match the real response structure so the SDK parses it
        
        # Header
        resp = bytearray(0xB0)  # 176 bytes like real response
        resp[0] = 0x7F
        resp[1] = TYPE_LIST_RESP
        struct.pack_into('<H', resp, 2, 0xB0)
        
        # Copy term_id, sqnum from request (SDK verifies these match)
        resp[4:12] = req_data[4:12]
        
        # Increment sqnum for response
        sqnum = struct.unpack_from('<I', req_data, 0x0C)[0]
        struct.pack_into('<I', resp, 0x0C, sqnum)
        
        # Compute chkval (simple checksum of payload — varies by implementation)
        struct.pack_into('<I', resp, 0x10, 0)  # placeholder
        
        # opt_flags: encrypt=1 (per-frame), is_response=1
        opt_flags = (1 << 16) | (1 << 21)  # encrypt=1, is_response
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # Build plaintext payload with our server entry
        # The real payload has: num_servers(2B) + entries[]
        # Each entry: ip(4B, network order) + port(2B LE) + srv_id(2B LE) + flags(2B)
        payload = bytearray(0xB0 - HEADER_SIZE)
        
        # Number of servers = 1
        struct.pack_into('<H', payload, 0, 1)
        
        # Our server entry at offset 2
        ip_bytes = socket.inet_aton(reply_ip or self.local_ip)
        payload[2:6] = ip_bytes
        struct.pack_into('<H', payload, 6, self.listen_ports[0])  # port
        struct.pack_into('<H', payload, 8, 1)  # srv_id
        struct.pack_into('<H', payload, 10, 0)  # flags
        
        # Encrypt payload with per-frame key
        pfk = derive_per_frame_key(bytes(resp[:0x18]))
        rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
        
        # Ensure payload is a multiple of 8 bytes for RC5
        pad_len = (len(payload) + 7) & ~7
        payload_padded = bytes(payload) + b'\x00' * (pad_len - len(payload))
        encrypted = rc5.encrypt(payload_padded)
        
        resp[HEADER_SIZE:HEADER_SIZE + len(encrypted)] = encrypted
        
        return bytes(resp)

    def get_upstream_sock(self, term_id: int) -> socket.socket:
        """Get or create a dedicated upstream socket for a client."""
        if term_id not in self.upstream_socks:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.05)  # Blocking with short timeout for run_in_executor
            self.upstream_socks[term_id] = sock
        return self.upstream_socks[term_id]

    def handle_packet(self, data: bytes, addr: tuple, our_port: int) -> Optional[bytes]:
        """Process incoming packet. Returns local response or None (forward/route)."""
        if len(data) < 4:
            return None
        
        protocol, ftype, frm_len, opt_flags = self.get_frame_info(data)
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
        ack = self.is_ack(opt_flags)
        
        # Register/update client
        if term_id != 0:
            if term_id not in self.state.clients:
                self.state.clients[term_id] = ClientSession(
                    term_id=term_id, addr=addr, our_port=our_port)
                self.log(f"NEW CLIENT: term_id={term_id} from {addr[0]}:{addr[1]}")
            client = self.state.clients[term_id]
            client.addr = addr
            client.our_port = our_port
            client.last_seen = time.time()
            client.frames_in += 1
            self.state.addr_to_term[addr] = term_id

        # --- DETECT: always respond locally (we want to win the race) ---
        if ftype == TYPE_DETECT_REQ:
            self.log(f"← DETECT_REQ from {addr[0]}:{addr[1]} term_id={term_id}")
            resp = self.build_detect_resp(data)
            self.log(f"→ DETECT_RESP to {addr[0]}:{addr[1]} (instant)")
            return resp

        # --- LIST_REQ: forward to real Mars and relay the response ---
        # The LIST_RESP format is complex (per-frame encrypted server entries).
        # In proxy mode: forward to Mars, relay response back, SDK then sends DETECT to those IPs.
        # Our iptables DNAT (or DNS override) ensures DETECT comes back to us anyway.
        # In relay mode: respond locally with our address.
        elif ftype == TYPE_LIST_REQ:
            self.log(f"← LIST_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if self.mode == "proxy":
                return None  # Forward to upstream — response routed via _upstream_recv_loop
            else:
                reply_ip = "127.0.0.1" if addr[0].startswith("127.") else self.local_ip
                resp = self.build_list_resp(data, reply_ip)
                self.log(f"→ LIST_RESP to {addr[0]}:{addr[1]} (servers: {reply_ip}, {len(resp)}B)")
                return resp

        # --- CERTIFY ---
        elif ftype == TYPE_CERTIFY_REQ:
            if ack:
                self.log(f"← CERTIFY_ACK from {addr[0]}:{addr[1]} term_id={term_id}")
            else:
                self.log(f"← CERTIFY_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if self.mode == "relay":
                return self._handle_certify_local(data, addr, term_id)
            return None  # proxy: forward

        elif ftype == TYPE_CERTIFY_RESP:
            self.log(f"← CERTIFY_RESP for term_id={term_id} ({frm_len}B)")
            if term_id in self.state.clients:
                self.state.clients[term_id].certified = True
                self._on_client_certified(term_id)
            return None  # proxy: forward to client

        # --- INIT_INFO ---
        elif ftype == TYPE_INIT_INFO_MSG:
            self.log(f"← INIT_INFO{'_ACK' if ack else ''} from {addr[0]}:{addr[1]} term_id={term_id}")
            if not ack and term_id in self.state.clients:
                self.state.clients[term_id].certified = True
                self._on_client_certified(term_id)
            return None  # proxy: forward

        # --- CALLING: log and handle wakeup routing ---
        elif ftype == TYPE_CALLING_REQ:
            self.log(f"← CALLING_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            self._handle_calling(data, addr, term_id)
            return None

        # --- SUBSCRIBE ---
        elif ftype == TYPE_SUBSCRIBE:
            self.log(f"← SUBSCRIBE from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            return None

        # --- All other frames ---
        else:
            if not ack:  # Don't spam ACK logs
                self.log(f"← {type_name} from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            return None

    def _handle_certify_local(self, data: bytes, addr: tuple, term_id: int) -> Optional[bytes]:
        """Handle CERTIFY in standalone relay mode.
        
        For v1: generate a fake certify response.
        The SDK needs: ACK + CERTIFY_RESP with session_id.
        """
        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        if self.is_ack(opt_flags):
            return None  # ACK from client, no response needed
        
        # Build ACK first
        ack = bytearray(0x30)  # 48 bytes like real ACK
        ack[0] = 0x7F
        ack[1] = TYPE_CERTIFY_REQ  # Same type, ACK bit set
        struct.pack_into('<H', ack, 2, 0x30)
        ack[4:12] = data[4:12]  # term_id
        ack[0x0C:0x10] = data[0x0C:0x10]  # sqnum
        ack[0x10:0x14] = data[0x10:0x14]  # chkval
        ack_flags = opt_flags | (1 << 20) | (1 << 21)  # ACK + response bits
        struct.pack_into('<I', ack, 0x14, ack_flags)
        # NTP timestamp
        now = int(time.time())
        struct.pack_into('<I', ack, 0x1C, now)
        
        # TODO: Build proper CERTIFY_RESP with session key exchange
        # For now, just send the ACK — the full certify needs more RE work
        self.log(f"  [RELAY] CERTIFY handling incomplete — need device secret for proper response")
        return bytes(ack)

    # ===== WAKEUP ROUTING INFRASTRUCTURE =====

    def _handle_calling(self, data: bytes, addr: tuple, sender_term_id: int):
        """Handle CALLING_REQ with wakeup routing logic.
        
        In the real Mars relay, CALLING is routed by destination term_id
        (encrypted in the frame payload). Since the payload is session-encrypted
        (opt_encrypt=2), we can't decode the destination in proxy mode.
        
        For wakeup routing, the flow is:
        1. Bridge sends CALLING → relay forwards to Mars (proxy mode)
        2. Mars routes to doorbell; if doorbell is offline, Mars notifies via GDM
        3. In standalone mode: we queue the CALLING and trigger local wakeup
        
        When the doorbell connects to our relay, we deliver pending CALLINGs.
        """
        if self.mode == "relay":
            # In relay mode: check if doorbell is connected, if not, trigger wakeup
            if self.state.doorbell_term_id:
                doorbell = self.state.clients.get(self.state.doorbell_term_id)
                if doorbell and (time.time() - doorbell.last_seen) < 30:
                    self.log(f"  [WAKEUP] Doorbell is connected, routing CALLING directly")
                    return
            
            # Doorbell not connected — queue CALLING and send wakeup to chime
            self.log(f"  [WAKEUP] Doorbell offline — queuing CALLING, triggering wakeup")
            self.state.pending_callings.append(PendingWakeup(
                calling_data=data,
                bridge_term_id=sender_term_id,
                timestamp=time.time(),
                timeout=30.0
            ))
            self._trigger_chime_wakeup()
        # In proxy mode: Mars handles routing, but log for awareness
        else:
            self.log(f"  [PROXY] CALLING forwarded to Mars for routing")

    def _trigger_chime_wakeup(self):
        """Send a wakeup command to the chime via GUTES.
        
        The chime is always connected (it's plugged in). We need to send it
        a GDM PASSTHROUGH frame that instructs it to wake the doorbell via BT.
        
        From the RE: the wakeup is triggered by a PASSTHROUGH frame (type 0xBD)
        containing a GDM action_key='wakeup' with action_params={'wakeup-live-view': 1}.
        
        The exact frame format will be determined once we capture the chime's
        traffic through our relay. For now, this is a placeholder.
        """
        if not self.state.chime_term_id:
            self.log(f"  [WAKEUP] No chime connected — cannot trigger local wakeup")
            self.log(f"  [WAKEUP] Falling back to cloud wakeup (DMS HTTP)")
            return
        
        chime = self.state.clients.get(self.state.chime_term_id)
        if not chime or (time.time() - chime.last_seen) > 60:
            self.log(f"  [WAKEUP] Chime session stale — cannot trigger local wakeup")
            return
        
        # TODO: Build and send the actual wakeup PASSTHROUGH frame to chime
        # This will be filled in once we capture the chime's GDM traffic
        # and understand what frame triggers the BT wakeup
        self.log(f"  [WAKEUP] Would send wakeup to chime term_id={self.state.chime_term_id}")
        self.log(f"  [WAKEUP] (pending: capture chime traffic to learn wakeup frame format)")

    def _deliver_pending_callings(self, doorbell_term_id: int):
        """Deliver queued CALLING frames to the newly-connected doorbell.
        
        Called when the doorbell connects and completes CERTIFY.
        """
        now = time.time()
        delivered = 0
        expired = 0
        
        remaining = []
        for pending in self.state.pending_callings:
            age = now - pending.timestamp
            if age > pending.timeout:
                expired += 1
                continue
            
            # Deliver this CALLING to the doorbell
            doorbell = self.state.clients.get(doorbell_term_id)
            if doorbell:
                self.log(f"  [WAKEUP] Delivering queued CALLING to doorbell "
                        f"(queued {age:.1f}s ago)")
                # In relay mode: send directly to doorbell's address
                if doorbell.tcp_writer:
                    # TCP delivery
                    try:
                        doorbell.tcp_writer.write(pending.calling_data)
                        delivered += 1
                    except:
                        remaining.append(pending)
                elif doorbell.our_port in self.relay_socks:
                    # UDP delivery
                    try:
                        self.relay_socks[doorbell.our_port].sendto(
                            pending.calling_data, doorbell.addr)
                        delivered += 1
                    except:
                        remaining.append(pending)
            else:
                remaining.append(pending)
        
        self.state.pending_callings = remaining
        if delivered or expired:
            self.log(f"  [WAKEUP] Delivered {delivered} CALLINGs, expired {expired}")

    def identify_device_role(self, term_id: int, addr: tuple) -> str:
        """Attempt to identify device role based on IP and behavior.
        
        Known IPs from our network:
        - 192.168.1.12  = Chime (always on, plugged in)
        - 192.168.1.81  = Doorbell (connects when woken)
        - 192.168.1.245 = Bridge on macOS/Colima
        - 192.168.1.236 = Bridge on ccc.local
        """
        ip = addr[0]
        
        # Direct IP matching (works for known devices)
        if ip == "192.168.1.12":
            return "chime"
        elif ip == "192.168.1.81":
            return "doorbell"
        elif ip in ("192.168.1.245", "192.168.1.236", "127.0.0.1", "192.168.5.1"):
            return "bridge"
        
        # Heuristic: the first certified client from a non-bridge IP
        # that sends INIT_INFO with 2 devices is likely the bridge
        return "unknown"

    def _on_client_certified(self, term_id: int):
        """Called when a client completes CERTIFY. Identify role and handle wakeups."""
        client = self.state.clients.get(term_id)
        if not client:
            return
        
        # Identify role
        role = self.identify_device_role(term_id, client.addr)
        client.role = role
        
        if role == "chime":
            self.state.chime_term_id = term_id
            self.log(f"  [ROLE] Identified CHIME: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
        elif role == "doorbell":
            self.state.doorbell_term_id = term_id
            self.log(f"  [ROLE] Identified DOORBELL: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
            # Deliver any pending CALLINGs
            if self.state.pending_callings:
                self._deliver_pending_callings(term_id)
        elif role == "bridge":
            self.state.bridge_term_id = term_id
            self.log(f"  [ROLE] Identified BRIDGE: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
        else:
            self.log(f"  [ROLE] Unknown device: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")

    async def run(self):
        """Main entry point."""
        self.log(f"GUTES Relay v2 starting")
        self.log(f"  Mode: {self.mode.upper()}")
        self.log(f"  Local IP: {self.local_ip}")
        self.log(f"  Relay ports: {self.listen_ports}")
        self.log(f"  List port: {self.list_port}")
        if self.mode == "proxy":
            self.log(f"  Upstream: {self.upstream_host}:{self.upstream_port}")
        self.log("")

        loop = asyncio.get_event_loop()

        # Bind all relay ports
        for port in self.listen_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('0.0.0.0', port))
                sock.settimeout(1.0)  # Blocking with timeout for run_in_executor
                self.relay_socks[port] = sock
                self.log(f"  Listening on UDP :{port}")
            except OSError as e:
                self.log(f"  WARN: Cannot bind :{port} ({e})")

        # Bind list port
        self.list_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.list_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.list_sock.bind(('0.0.0.0', self.list_port))
            self.list_sock.settimeout(1.0)
            self.log(f"  Listening on UDP :{self.list_port} (list)")
        except OSError as e:
            self.log(f"  WARN: Cannot bind list port :{self.list_port} ({e})")
            self.list_sock = None

        self.log("")
        self.log("Ready — waiting for connections...")
        self.log("=" * 60)

        # Create tasks for all sockets
        tasks = []
        for port, sock in self.relay_socks.items():
            tasks.append(asyncio.create_task(self._recv_loop(sock, port, "relay")))
        if self.list_sock:
            tasks.append(asyncio.create_task(self._recv_loop(self.list_sock, self.list_port, "list")))
        
        # Upstream receiver (proxy mode only)
        if self.mode == "proxy":
            tasks.append(asyncio.create_task(self._upstream_recv_loop()))
        
        # TCP proxy listeners (same ports as UDP)
        if self.mode == "proxy":
            for port in self.listen_ports:
                tasks.append(asyncio.create_task(self._tcp_listen(port)))
        
        # Periodic status log
        tasks.append(asyncio.create_task(self._status_loop()))

        await asyncio.gather(*tasks)

    async def _recv_loop(self, sock: socket.socket, port: int, role: str):
        """Receive loop for a single socket."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
            except socket.timeout:
                await asyncio.sleep(0)
                continue
            except OSError as e:
                await asyncio.sleep(0.01)
                continue

            # Process the packet
            resp = self.handle_packet(data, addr, port)
            
            if resp is not None:
                # Local response
                try:
                    sock.sendto(resp, addr)
                except OSError as e:
                    self.log(f"  ERROR sending to {addr}: {e}")
            else:
                # Forward/route
                if self.mode == "proxy":
                    await self._forward_to_upstream(data, addr, port, sock)
                else:
                    await self._route_to_peer(data, addr, port, sock)

    async def _forward_to_upstream(self, data: bytes, client_addr: tuple, 
                                    client_port: int, client_sock: socket.socket):
        """Forward a packet to the real Mars relay (proxy mode)."""
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        
        # Get/create upstream socket for this client
        upstream_sock = self.get_upstream_sock(term_id)
        
        # Track the mapping so we can route responses back
        fd = upstream_sock.fileno()
        self.upstream_to_client[fd] = (client_addr, client_port, client_sock, term_id)
        
        # Determine upstream port based on what port the client connected to
        # LIST_REQ goes to port 51701, everything else to the relay port
        if client_port == self.list_port:
            dest = (self.upstream_host, 51701)
        else:
            dest = (self.upstream_host, self.upstream_port)
        
        try:
            upstream_sock.sendto(data, dest)
            ftype = data[1] if len(data) > 1 else 0
            type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
            self.log(f"  → FWD {type_name} to upstream {dest[0]}:{dest[1]}")
        except OSError as e:
            self.log(f"  ERROR forwarding to upstream: {e}")

    def _rewrite_list_resp(self, data: bytes) -> bytes:
        """Rewrite LIST_RESP to replace all server IPs with our local IP.
        
        The payload is per-frame encrypted. We decrypt, replace IPs, re-encrypt.
        Server entry format (from RE): IP(4B NBO) + port(2B LE) + srv_id(2B LE) + ...
        """
        if len(data) < HEADER_SIZE + 8:
            return data
        
        try:
            # Decrypt payload
            pfk = derive_per_frame_key(data[:0x18])
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            payload = bytearray(data[HEADER_SIZE:])
            dec_len = (len(payload) // 8) * 8
            if dec_len == 0:
                return data
            decrypted = bytearray(rc5.decrypt(bytes(payload[:dec_len])))
            
            # The real LIST_RESP has server entries starting at some offset
            # From our pcap analysis, the format seems to be:
            # offset 0: header/count bytes
            # Then entries with IPv4 at various offsets
            # Let's find all IPv4 addresses (non-private, non-zero) and replace them
            local_ip_bytes = socket.inet_aton(self.local_ip)
            replaced = 0
            
            # Scan for valid public IPv4 addresses (4-byte aligned)
            for offset in range(0, dec_len - 3, 2):
                ip_candidate = decrypted[offset:offset+4]
                # Check if it looks like a public IP (not 0.0.0.0, not 192.168.x.x, not 10.x.x.x)
                if (ip_candidate[0] not in (0, 10, 127, 192, 172, 255) and
                    ip_candidate != b'\x00\x00\x00\x00'):
                    # Check if next 2 bytes could be a reasonable port (1-65535)
                    if offset + 5 < dec_len:
                        port_val = struct.unpack_from('<H', decrypted, offset + 4)[0]
                        if port_val in (28800, 8443, 8000, 443, 51701):
                            old_ip = socket.inet_ntoa(bytes(ip_candidate))
                            decrypted[offset:offset+4] = local_ip_bytes
                            # Also replace port with our relay port
                            struct.pack_into('<H', decrypted, offset + 4, self.listen_ports[0])
                            replaced += 1
                            self.log(f"  [REWRITE] {old_ip}:{port_val} → {self.local_ip}:{self.listen_ports[0]}")
            
            if replaced > 0:
                # Re-encrypt and rebuild frame
                encrypted = rc5.encrypt(bytes(decrypted[:dec_len]))
                new_data = bytearray(data)
                new_data[HEADER_SIZE:HEADER_SIZE + dec_len] = encrypted
                self.log(f"  [REWRITE] Replaced {replaced} server IPs in LIST_RESP")
                return bytes(new_data)
            
        except Exception as e:
            self.log(f"  [REWRITE] Failed to rewrite LIST_RESP: {e}")
        
        return data

    async def _upstream_recv_loop(self):
        """Receive responses from upstream and route back to clients."""
        loop = asyncio.get_event_loop()
        while True:
            # Poll all upstream sockets
            for term_id, sock in list(self.upstream_socks.items()):
                try:
                    data, upstream_addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
                except (socket.timeout, BlockingIOError, OSError):
                    continue
                
                # Decode response
                ftype = data[1] if len(data) > 1 else 0
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                resp_term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                
                self.log(f"  ← UPS {type_name} from {upstream_addr[0]}:{upstream_addr[1]} "
                        f"({len(data)}B) term_id={resp_term_id}")
                
                # Rewrite LIST_RESP to replace server IPs with our local IP
                if ftype == TYPE_LIST_RESP:
                    data = self._rewrite_list_resp(data)
                
                # Route back to the client that sent the request
                fd = sock.fileno()
                if fd in self.upstream_to_client:
                    client_addr, client_port, client_sock, _ = self.upstream_to_client[fd]
                    try:
                        client_sock.sendto(data, client_addr)
                        self.log(f"  → RELAY to {client_addr[0]}:{client_addr[1]}")
                    except OSError as e:
                        self.log(f"  ERROR relaying to client: {e}")
                elif resp_term_id in self.state.clients:
                    # Fall back to routing by term_id
                    client = self.state.clients[resp_term_id]
                    if client.our_port in self.relay_socks:
                        client_sock = self.relay_socks[client.our_port]
                        try:
                            client_sock.sendto(data, client.addr)
                            self.log(f"  → RELAY to {client.addr[0]}:{client.addr[1]} (by term_id)")
                        except OSError as e:
                            self.log(f"  ERROR relaying: {e}")
            
            await asyncio.sleep(0.001)

    async def _route_to_peer(self, data: bytes, sender_addr: tuple,
                             sender_port: int, sender_sock: socket.socket):
        """Route frame to the appropriate peer (relay mode)."""
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        ftype = data[1] if len(data) > 1 else 0
        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
        
        # Find ALL other connected clients to forward to
        routed = False
        for tid, client in self.state.clients.items():
            if tid != term_id and client.addr != sender_addr:
                if client.our_port in self.relay_socks:
                    try:
                        self.relay_socks[client.our_port].sendto(data, client.addr)
                        self.log(f"  → ROUTE {type_name} to {client.addr[0]}:{client.addr[1]} "
                                f"(term_id={tid})")
                        client.frames_out += 1
                        routed = True
                    except OSError as e:
                        self.log(f"  ERROR routing to {client.addr}: {e}")
        
        if not routed and ftype not in (TYPE_KEEPALIVE,):
            self.log(f"  ! NO PEER to route {type_name} (term_id={term_id}, "
                    f"clients={list(self.state.clients.keys())})")

    async def _tcp_listen(self, port: int):
        """Listen for TCP connections and proxy them to upstream Mars relay."""
        server = await asyncio.start_server(
            lambda r, w: self._tcp_handle_client(r, w, port),
            '0.0.0.0', port, reuse_address=True)
        self.log(f"  Listening on TCP :{port}")
        async with server:
            await server.serve_forever()

    async def _tcp_handle_client(self, client_reader: asyncio.StreamReader,
                                  client_writer: asyncio.StreamWriter, local_port: int):
        """Handle a single TCP client by proxying to upstream Mars relay."""
        client_addr = client_writer.get_extra_info('peername')
        self.log(f"← TCP connection from {client_addr[0]}:{client_addr[1]} on port {local_port}")
        
        # Connect to upstream
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port)
            self.log(f"  → TCP connected to upstream {self.upstream_host}:{self.upstream_port}")
        except Exception as e:
            self.log(f"  ERROR: Cannot connect to upstream: {e}")
            client_writer.close()
            return
        
        # Bidirectional proxy with frame logging
        async def client_to_upstream():
            try:
                while True:
                    data = await client_reader.read(8192)
                    if not data:
                        break
                    # Log frame type
                    if len(data) >= 2 and data[0] == 0x7F:
                        ftype = data[1]
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                        self.log(f"  TCP C→S {type_name} ({len(data)}B) term_id={term_id}")
                        # Track client
                        if term_id != 0:
                            if term_id not in self.state.clients:
                                self.state.clients[term_id] = ClientSession(
                                    term_id=term_id, addr=client_addr, our_port=local_port)
                                self.log(f"  TCP NEW CLIENT: term_id={term_id} from {client_addr[0]}:{client_addr[1]}")
                            self.state.clients[term_id].last_seen = time.time()
                            self.state.clients[term_id].frames_in += 1
                            self.state.clients[term_id].tcp_writer = client_writer
                            # Identify role and handle CERTIFY/INIT_INFO
                            if ftype == TYPE_CERTIFY_REQ and not self.is_ack(struct.unpack_from('<I', data, 0x14)[0]):
                                pass  # Wait for CERTIFY_RESP from server
                            elif ftype == TYPE_INIT_INFO_MSG:
                                self.state.clients[term_id].certified = True
                                self._on_client_certified(term_id)
                            elif ftype == TYPE_CALLING_REQ:
                                self._handle_calling(data, client_addr, term_id)
                    upstream_writer.write(data)
                    await upstream_writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                upstream_writer.close()
        
        async def upstream_to_client():
            try:
                while True:
                    data = await upstream_reader.read(8192)
                    if not data:
                        break
                    # Log frame type and handle CERTIFY_RESP
                    if len(data) >= 2 and data[0] == 0x7F:
                        ftype = data[1]
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                        self.log(f"  TCP S→C {type_name} ({len(data)}B) term_id={term_id}")
                        # When we see CERTIFY_RESP, the client is now certified
                        if ftype == TYPE_CERTIFY_RESP and term_id != 0:
                            if term_id in self.state.clients:
                                self.state.clients[term_id].certified = True
                                self._on_client_certified(term_id)
                    client_writer.write(data)
                    await client_writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                client_writer.close()
        
        await asyncio.gather(client_to_upstream(), upstream_to_client())
        self.log(f"  TCP connection from {client_addr[0]}:{client_addr[1]} closed")

    async def _status_loop(self):
        """Periodically log relay status."""
        while True:
            await asyncio.sleep(30)
            if self.state.clients:
                self.log(f"--- STATUS: {len(self.state.clients)} clients ---")
                for tid, client in self.state.clients.items():
                    age = time.time() - client.last_seen
                    self.log(f"  term_id={tid} addr={client.addr[0]}:{client.addr[1]} "
                            f"role={client.role} cert={client.certified} "
                            f"in={client.frames_in} out={client.frames_out} "
                            f"last_seen={age:.0f}s ago")


def main():
    parser = argparse.ArgumentParser(description="GUTES Local Relay / UDP Proxy")
    parser.add_argument('--mode', choices=['proxy', 'relay'], default='proxy',
                       help='Operating mode (default: proxy)')
    parser.add_argument('--proxy', action='store_const', const='proxy', dest='mode')
    parser.add_argument('--relay', action='store_const', const='relay', dest='mode')
    parser.add_argument('--ports', default='28800,8443,8000',
                       help='Comma-separated relay ports (default: 28800,8443,8000)')
    parser.add_argument('--list-port', type=int, default=51701,
                       help='List server port (default: 51701)')
    parser.add_argument('--upstream', default='3.13.212.24:28800',
                       help='Upstream relay for proxy mode')
    parser.add_argument('--log-file', default=None,
                       help='Append log to file')
    parser.add_argument('--local-ip', default='',
                       help='Override local IP for LIST_RESP')
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(',')]

    relay = GutesRelay(
        listen_ports=ports,
        list_port=args.list_port,
        mode=args.mode,
        upstream=args.upstream,
        log_file=args.log_file,
        local_ip=args.local_ip,
    )

    try:
        asyncio.run(relay.run())
    except KeyboardInterrupt:
        print("\nRelay stopped.")
        # Print final summary
        if relay.state.clients:
            print(f"\nSession summary ({len(relay.state.clients)} clients):")
            for tid, c in relay.state.clients.items():
                print(f"  {tid}: {c.addr} role={c.role} in={c.frames_in} out={c.frames_out}")


if __name__ == "__main__":
    main()
