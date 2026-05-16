#!/usr/bin/env python3
"""GUTES Local Relay Server / UDP MitM Proxy.

Modes:
  --proxy    Forward all traffic to real Mars relay (capture + learn)
  --relay    Standalone local relay (no internet needed)

The server handles:
1. LIST_REQ (port 51701) — return self as the only relay server
2. DETECT_REQ — respond instantly (0ms RTT wins the race)
3. CERTIFY_REQ — validate and establish session (or forward in proxy mode)
4. All session frames — route by term_id between bridge and doorbell

Usage:
  # Proxy mode (captures traffic, forwards to real relay):
  python3 gutes_relay.py --proxy --upstream 3.13.212.24:28800

  # Standalone relay mode (fully offline):
  python3 gutes_relay.py --relay

  # Then point DNS: wyze-mars-asrv.wyzecam.com → this machine's IP
"""

import argparse
import asyncio
import socket
import struct
import sys
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from gutes_frame import parse_frame, HEADER_SIZE, FRAME_TYPES
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


@dataclass
class ClientSession:
    """Tracks a connected client (bridge or doorbell)."""
    term_id: int = 0
    addr: tuple = ('', 0)  # (ip, port)
    session_id: int = 0
    session_key: bytes = b''  # 32-byte key after certify
    last_seen: float = 0.0
    frames_sent: int = 0
    frames_recv: int = 0
    role: str = "unknown"  # "bridge" or "doorbell"
    certify_random: bytes = b''  # Client's 32-byte random from certify


@dataclass 
class RelayState:
    """Global relay state."""
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> session
    addr_to_term: dict[tuple, int] = field(default_factory=dict)  # (ip,port) -> term_id
    next_session_id: int = 1000000
    

class GutesRelay:
    """UDP-based GUTES relay server."""

    def __init__(self, listen_port: int = 28800, list_port: int = 51701,
                 mode: str = "proxy", upstream: str = "3.13.212.24:28800",
                 log_file: Optional[str] = None):
        self.listen_port = listen_port
        self.list_port = list_port
        self.mode = mode  # "proxy" or "relay"
        self.upstream_host, self.upstream_port = upstream.split(':')[0], int(upstream.split(':')[1])
        self.state = RelayState()
        self.t0 = time.time()
        self.log_fp = open(log_file, 'w') if log_file else None
        
        # For proxy mode: upstream socket and pending responses
        self.upstream_sock: Optional[socket.socket] = None
        self.pending_responses: dict[int, tuple] = {}  # sqnum -> client_addr

    def log(self, msg: str):
        elapsed = time.time() - self.t0
        line = f"[{elapsed:8.3f}] {msg}"
        print(line, flush=True)
        if self.log_fp:
            self.log_fp.write(line + "\n")
            self.log_fp.flush()

    def decode_term_id(self, frame_data: bytes) -> int:
        """Decode the term_id from a frame header using static RC5 key."""
        if len(frame_data) < HEADER_SIZE:
            return 0
        encrypted_id = frame_data[4:12]
        sqnum_bytes = frame_data[0x0C:0x10]
        chkval_bytes = frame_data[0x10:0x14]
        try:
            id_bytes = id_decrypt(encrypted_id, chkval_bytes, sqnum_bytes)
            return struct.unpack_from('<q', id_bytes)[0]
        except:
            return struct.unpack_from('<q', encrypted_id)[0]

    def build_detect_resp(self, req_data: bytes, server_addr: tuple) -> bytes:
        """Build a DETECT_RESP frame in response to a DETECT_REQ.
        
        The detect response mirrors the request's sqnum/chkval and adds
        server info. Format derived from captured responses (56 bytes).
        """
        # Response format (56 bytes = 0x38):
        # Header: protocol=0x7F, type=0x02, len=0x38
        # Copy term_id, sqnum, chkval from request
        # opt_flags: same encrypt mode but with is_response bit set
        resp = bytearray(0x38)
        
        # Copy header structure from request
        resp[0] = 0x7F  # protocol
        resp[1] = TYPE_DETECT_RESP  # type
        struct.pack_into('<H', resp, 2, 0x38)  # frm_len
        
        # Copy encrypted term_id from request (we don't re-encrypt)
        resp[4:12] = req_data[4:12]
        
        # Copy sqnum and chkval
        resp[0x0C:0x10] = req_data[0x0C:0x10]
        resp[0x10:0x14] = req_data[0x10:0x14]
        
        # opt_flags: mark as response, keep encrypt mode
        req_flags = struct.unpack_from('<I', req_data, 0x14)[0]
        resp_flags = req_flags | (1 << 21)  # set is_response bit
        struct.pack_into('<I', resp, 0x14, resp_flags)
        
        # flags2 and ack_result
        resp[0x18:0x1A] = req_data[0x18:0x1A]
        struct.pack_into('<H', resp, 0x1A, 0)  # ack_result = 0 (success)
        
        # Payload: server identification (from captured response pattern)
        # The real server puts some opaque data here. For our relay,
        # we just need to respond quickly — the SDK checks timing, not content.
        # Fill with a minimal valid pattern.
        
        return bytes(resp)

    def build_list_resp(self, req_data: bytes, relay_ip: str, relay_port: int) -> bytes:
        """Build a LIST_RESP frame returning our relay as the only server.
        
        The list response (176 bytes) contains encrypted server entries.
        For simplicity in relay mode, we build a minimal response that
        the SDK can parse. The real response is per-frame encrypted.
        """
        # For now, in proxy mode, we forward to the real server.
        # In relay mode, we'd need to craft this properly.
        # This is a placeholder — the full implementation requires
        # understanding the LIST_RESP payload format.
        return None  # Forward to upstream in proxy mode

    def handle_packet(self, data: bytes, addr: tuple, sock: socket.socket) -> Optional[bytes]:
        """Process an incoming GUTES UDP packet.
        
        Returns response bytes to send back, or None if forwarding.
        """
        if len(data) < 4:
            return None
        
        protocol = data[0]
        frame_type = data[1]
        frm_len = struct.unpack_from('<H', data, 2)[0]
        
        # Decode term_id for routing
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        
        # Track client
        if term_id != 0 and addr not in [('', 0)]:
            if term_id not in self.state.clients:
                self.state.clients[term_id] = ClientSession(term_id=term_id, addr=addr)
                self.log(f"NEW CLIENT: term_id={term_id} addr={addr}")
            client = self.state.clients[term_id]
            client.addr = addr
            client.last_seen = time.time()
            client.frames_recv += 1
            self.state.addr_to_term[addr] = term_id
        
        # Frame type name for logging
        type_name = FRAME_TYPES.get(frame_type, f"0x{frame_type:02X}")
        
        # --- Handle specific frame types ---
        
        if frame_type == TYPE_DETECT_REQ:
            # Always respond to detect probes locally (instant response = we win)
            self.log(f"← DETECT_REQ from {addr} (term_id={term_id}, {frm_len}B)")
            resp = self.build_detect_resp(data, addr)
            self.log(f"→ DETECT_RESP to {addr} ({len(resp)}B) [LOCAL]")
            return resp
        
        elif frame_type == TYPE_LIST_REQ:
            self.log(f"← LIST_REQ from {addr} (term_id={term_id}, {frm_len}B)")
            if self.mode == "proxy":
                # Forward to real server
                return None  # Will be forwarded by caller
            else:
                # Relay mode: build our own response
                resp = self.build_list_resp(data, "0.0.0.0", self.listen_port)
                if resp:
                    return resp
                return None
        
        elif frame_type == TYPE_CERTIFY_REQ:
            opt_flags = struct.unpack_from('<I', data, 0x14)[0]
            is_ack = bool((opt_flags >> 20) & 1)
            if is_ack:
                self.log(f"← CERTIFY_ACK from {addr} (term_id={term_id})")
            else:
                self.log(f"← CERTIFY_REQ from {addr} (term_id={term_id}, {frm_len}B, flags=0x{opt_flags:08x})")
            if self.mode == "proxy":
                return None  # Forward
            else:
                # Relay mode: TODO handle certify locally
                self.log(f"  [RELAY] certify handling not yet implemented")
                return None
        
        elif frame_type == TYPE_CERTIFY_RESP:
            self.log(f"{'←' if 'S' in '' else '→'} CERTIFY_RESP {addr} (term_id={term_id}, {frm_len}B)")
            return None  # Forward
        
        elif frame_type == TYPE_INIT_INFO_MSG:
            opt_flags = struct.unpack_from('<I', data, 0x14)[0]
            is_ack = bool((opt_flags >> 20) & 1)
            self.log(f"← INIT_INFO{'_ACK' if is_ack else ''} from {addr} (term_id={term_id})")
            return None  # Forward
        
        elif frame_type in (TYPE_CALLING_REQ, TYPE_MTP_RES_RESPONSE, TYPE_SUBSCRIBE,
                           TYPE_SUBSCRIBE_RESP, TYPE_GDM_PUSH, TYPE_CALLING_ERR,
                           TYPE_SESSION_CTL, TYPE_SESSION_CTL_RESP, TYPE_ONLINE_MSG,
                           TYPE_PASSTHROUGH):
            opt_flags = struct.unpack_from('<I', data, 0x14)[0]
            is_ack = bool((opt_flags >> 20) & 1)
            self.log(f"← {type_name}{'(ACK)' if is_ack else ''} from {addr} ({frm_len}B)")
            
            if self.mode == "relay":
                # Route to peer
                # For now, we need to figure out the dst_id from the payload
                # In relay mode, we'd route based on the dst_id in CALLING frames
                pass
            return None  # Forward in proxy mode
        
        else:
            self.log(f"← UNKNOWN type=0x{frame_type:02X} from {addr} ({frm_len}B)")
            return None

    async def run_proxy_mode(self):
        """Run as a UDP MitM proxy — forward to real relay, log everything."""
        self.log(f"Starting GUTES UDP Proxy")
        self.log(f"  Listen: 0.0.0.0:{self.listen_port} (relay) + 0.0.0.0:{self.list_port} (list)")
        self.log(f"  Upstream: {self.upstream_host}:{self.upstream_port}")
        self.log(f"  Mode: PROXY (forward + log)")
        self.log("")

        # Create sockets
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        relay_sock.bind(('0.0.0.0', self.listen_port))
        relay_sock.setblocking(False)

        list_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        list_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        list_sock.bind(('0.0.0.0', self.list_port))
        list_sock.setblocking(False)

        # Upstream socket for forwarding
        self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream_sock.setblocking(False)

        loop = asyncio.get_event_loop()
        
        # Track which upstream port maps to which client
        # The SDK uses a single source port for all relay traffic
        client_by_upstream_sqnum: dict = {}  # For response routing

        async def handle_relay_recv():
            """Handle packets on the relay port."""
            while True:
                try:
                    data, addr = await loop.run_in_executor(None, 
                        lambda: relay_sock.recvfrom(4096))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.001)
                    continue
                
                # Check if this is from upstream (response) or client (request)
                if addr[0] == self.upstream_host and addr[1] == self.upstream_port:
                    # Response from upstream — route to client
                    # We need to identify which client this is for
                    # In practice, we use the term_id or the last client address
                    frame = parse_frame(data)
                    if frame:
                        type_name = FRAME_TYPES.get(frame.frame_type, f"0x{frame.frame_type:02X}")
                        self.log(f"  S→C {type_name} ({frame.frm_len}B) term_id={frame.term_id}")
                    
                    # Forward to the last known client
                    # This is a simplification — real routing uses term_id
                    for tid, client in self.state.clients.items():
                        if client.addr[0] != self.upstream_host:
                            relay_sock.sendto(data, client.addr)
                            break
                else:
                    # Request from client
                    resp = self.handle_packet(data, addr, relay_sock)
                    if resp:
                        # Local response (e.g., DETECT_RESP)
                        relay_sock.sendto(resp, addr)
                    else:
                        # Forward to upstream
                        self.upstream_sock.sendto(data, 
                            (self.upstream_host, self.upstream_port))

        async def handle_list_recv():
            """Handle packets on the list port (51701)."""
            while True:
                try:
                    data, addr = await loop.run_in_executor(None,
                        lambda: list_sock.recvfrom(4096))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.001)
                    continue
                
                resp = self.handle_packet(data, addr, list_sock)
                if resp:
                    list_sock.sendto(resp, addr)
                else:
                    # Forward LIST_REQ to upstream's list port (51701)
                    self.log(f"  → forwarding LIST_REQ to {self.upstream_host}:51701")
                    self.upstream_sock.sendto(data, (self.upstream_host, 51701))

        async def handle_upstream_recv():
            """Handle responses from upstream."""
            while True:
                try:
                    data, addr = await loop.run_in_executor(None,
                        lambda: self.upstream_sock.recvfrom(4096))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.001)
                    continue
                
                frame = parse_frame(data)
                type_name = ""
                if frame:
                    type_name = FRAME_TYPES.get(frame.frame_type, f"0x{frame.frame_type:02X}")
                    self.log(f"  S→C {type_name} from {addr} ({len(data)}B)")
                
                # Route response back to the appropriate client
                # Simple heuristic: send to the most recently seen client
                for tid, client in self.state.clients.items():
                    if client.addr[0] not in (self.upstream_host, ''):
                        if addr[1] == 51701:
                            list_sock.sendto(data, client.addr)
                        else:
                            relay_sock.sendto(data, client.addr)
                        break

        self.log("Proxy ready — waiting for connections...")
        
        # Run all handlers concurrently
        await asyncio.gather(
            handle_relay_recv(),
            handle_list_recv(), 
            handle_upstream_recv(),
        )

    async def run_relay_mode(self):
        """Run as a standalone local relay (no internet needed)."""
        self.log(f"Starting GUTES Local Relay")
        self.log(f"  Listen: 0.0.0.0:{self.listen_port} (relay) + 0.0.0.0:{self.list_port} (list)")
        self.log(f"  Mode: STANDALONE RELAY (no internet)")
        self.log("")

        # Create sockets
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        relay_sock.bind(('0.0.0.0', self.listen_port))
        relay_sock.setblocking(False)

        list_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        list_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        list_sock.bind(('0.0.0.0', self.list_port))
        list_sock.setblocking(False)

        loop = asyncio.get_event_loop()

        async def handle_relay():
            while True:
                try:
                    data, addr = await loop.run_in_executor(None,
                        lambda: relay_sock.recvfrom(4096))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.001)
                    continue
                
                resp = self.handle_packet(data, addr, relay_sock)
                if resp:
                    relay_sock.sendto(resp, addr)
                else:
                    # In relay mode, route to peer
                    term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                    # Find the OTHER client to forward to
                    for tid, client in self.state.clients.items():
                        if tid != term_id and client.addr != addr:
                            relay_sock.sendto(data, client.addr)
                            client.frames_sent += 1
                            break

        async def handle_list():
            while True:
                try:
                    data, addr = await loop.run_in_executor(None,
                        lambda: list_sock.recvfrom(4096))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.001)
                    continue
                
                resp = self.handle_packet(data, addr, list_sock)
                if resp:
                    list_sock.sendto(resp, addr)

        self.log("Relay ready — waiting for connections...")
        await asyncio.gather(handle_relay(), handle_list())

    async def run(self):
        if self.mode == "proxy":
            await self.run_proxy_mode()
        else:
            await self.run_relay_mode()


def main():
    parser = argparse.ArgumentParser(description="GUTES Local Relay / UDP Proxy")
    parser.add_argument('--mode', choices=['proxy', 'relay'], default='proxy',
                       help='Operating mode (default: proxy)')
    parser.add_argument('--proxy', action='store_const', const='proxy', dest='mode',
                       help='Run in proxy mode (forward to real relay)')
    parser.add_argument('--relay', action='store_const', const='relay', dest='mode',
                       help='Run in standalone relay mode')
    parser.add_argument('--port', type=int, default=28800,
                       help='Relay listen port (default: 28800)')
    parser.add_argument('--list-port', type=int, default=51701,
                       help='List server port (default: 51701)')
    parser.add_argument('--upstream', default='3.13.212.24:28800',
                       help='Upstream relay for proxy mode (default: 3.13.212.24:28800)')
    parser.add_argument('--log-file', default=None,
                       help='Write log to file')
    args = parser.parse_args()

    relay = GutesRelay(
        listen_port=args.port,
        list_port=args.list_port,
        mode=args.mode,
        upstream=args.upstream,
        log_file=args.log_file)

    try:
        asyncio.run(relay.run())
    except KeyboardInterrupt:
        print("\nRelay stopped.")


if __name__ == "__main__":
    main()
