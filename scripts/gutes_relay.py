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


@dataclass
class RelayState:
    """Global relay state."""
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> session
    addr_to_term: dict[tuple, int] = field(default_factory=dict)  # (ip, port) -> term_id
    next_session_id: int = 7640526817926134784  # Match real Mars session IDs


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
        """Build DETECT_RESP — instant response makes us win the race."""
        resp = bytearray(0x38)  # 56 bytes like real responses
        resp[0] = 0x7F
        resp[1] = TYPE_DETECT_RESP
        struct.pack_into('<H', resp, 2, 0x38)
        
        # Copy term_id (encrypted), sqnum, chkval from request
        resp[4:12] = req_data[4:12]
        resp[0x0C:0x10] = req_data[0x0C:0x10]
        resp[0x10:0x14] = req_data[0x10:0x14]
        
        # Set opt_flags with is_response bit
        req_flags = struct.unpack_from('<I', req_data, 0x14)[0]
        resp_flags = req_flags | (1 << 21)  # is_response
        struct.pack_into('<I', resp, 0x14, resp_flags)
        
        # Copy flags2
        resp[0x18:0x1A] = req_data[0x18:0x1A]
        # ack_result = 0 (success)
        struct.pack_into('<H', resp, 0x1A, 0)
        
        # Payload: server time (NTP-like) at offset 0x1C
        now = int(time.time())
        struct.pack_into('<I', resp, 0x1C, now)
        
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
            sock.setblocking(False)
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

        # --- LIST_REQ: always respond locally with our own address ---
        # This ensures ALL subsequent traffic (DETECT, CERTIFY, session) goes through us
        elif ftype == TYPE_LIST_REQ:
            self.log(f"← LIST_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            # Use the IP the client used to reach us (127.0.0.1 for local, LAN IP for remote)
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
            return None  # proxy: forward to client

        # --- INIT_INFO ---
        elif ftype == TYPE_INIT_INFO_MSG:
            self.log(f"← INIT_INFO{'_ACK' if ack else ''} from {addr[0]}:{addr[1]} term_id={term_id}")
            if not ack and term_id in self.state.clients:
                self.state.clients[term_id].certified = True
            return None  # proxy: forward

        # --- CALLING: log and forward/route ---
        elif ftype == TYPE_CALLING_REQ:
            self.log(f"← CALLING_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
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

    async def _upstream_recv_loop(self):
        """Receive responses from upstream and route back to clients."""
        loop = asyncio.get_event_loop()
        while True:
            # Poll all upstream sockets
            for term_id, sock in list(self.upstream_socks.items()):
                try:
                    data, upstream_addr = await asyncio.wait_for(
                        loop.run_in_executor(None, sock.recvfrom, 4096), timeout=0.05)
                except (asyncio.TimeoutError, BlockingIOError, OSError):
                    continue
                
                # Decode response
                ftype = data[1] if len(data) > 1 else 0
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                resp_term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                
                self.log(f"  ← UPS {type_name} from {upstream_addr[0]}:{upstream_addr[1]} "
                        f"({len(data)}B) term_id={resp_term_id}")
                
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
