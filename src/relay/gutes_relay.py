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
TYPE_MTP_RES_RESP_A3 = 0xA3  # MTP resource response (relay server list)
TYPE_SESSION_CTL = 0xB0
TYPE_SESSION_CTL_RESP = 0xB1
TYPE_ONLINE_MSG = 0xB4
TYPE_WAKEUP = 0xBB  # WakeUp frame — sent by Mars to wake sleeping devices
TYPE_PASSTHROUGH = 0xBD
TYPE_MTP_DATA = 0xCA  # MTP media data over TCP relay

FRAME_TYPES = {
    0x01: "DETECT_REQ", 0x02: "DETECT_RESP",
    0x0C: "CERTIFY", 0x0D: "CERTIFY_RESP",
    0x15: "LIST_REQ", 0x16: "LIST_RESP",
    0x17: "KEEPALIVE",
    0xA0: "SUBSCRIBE", 0xA1: "SUBSCRIBE_RESP",
    0xA2: "MTP_RES_RESP", 0xA3: "MTP_RES_RESP_A3",
    0xA4: "CALLING_REQ",
    0xBB: "WAKEUP",
    0xA6: "INIT_INFO", 0xA7: "GDM_PUSH",
    0xAA: "CALLING_ERR/GDM", 0xB0: "SESSION_CTL",
    0xB1: "SESSION_CTL_RESP", 0xB4: "ONLINE_MSG",
    0xBD: "PASSTHROUGH", 0xCA: "MTP_DATA",
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
class MtpConnection:
    """Tracks one side of an MTP TCP relay connection."""
    reader: object = None  # asyncio.StreamReader
    writer: object = None  # asyncio.StreamWriter
    addr: tuple = ('', 0)
    term_id: int = 0
    role: str = "unknown"  # "bridge" or "doorbell"
    link_id: int = 0
    bytes_relayed: int = 0


@dataclass
class MtpRelayPair:
    """A paired MTP relay session (bridge <-> doorbell)."""
    link_id: int = 0
    bridge: Optional[MtpConnection] = None
    doorbell: Optional[MtpConnection] = None
    created: float = 0.0
    active: bool = False


@dataclass
class RelayState:
    """Global relay state."""
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> session
    addr_to_term: dict[tuple, int] = field(default_factory=dict)  # (ip, port) -> term_id
    next_session_id: int = 7640526817926134784  # Match real Mars session IDs
    
    # Session key cache: term_id -> 32-byte session key (client_key XOR server_key)
    session_keys: dict[int, bytes] = field(default_factory=dict)
    # Also index session keys by source address for session-encrypted frame lookup
    addr_session_keys: dict[tuple, bytes] = field(default_factory=dict)
    # Session ID returned in CERTIFY_RESP (addr → 8-byte session_id)
    # INIT_INFO_RESP must use this as its term_id field for routing validation
    addr_session_id: dict[tuple, bytes] = field(default_factory=dict)
    # Track per-client sqnum for prediction (CERTIFY sqnum → INIT_INFO sqnum = +1)
    addr_last_sqnum: dict[tuple, int] = field(default_factory=dict)
    
    # Wakeup infrastructure
    pending_callings: list = field(default_factory=list)  # PendingWakeup queue
    
    # Known device mapping (from captured GDM/INIT_INFO)
    # These are the 64-bit device IDs from the Wyze ecosystem
    known_devices: dict[int, str] = field(default_factory=dict)  # numeric_did -> role
    
    # Chime → doorbell association
    chime_term_id: int = 0  # Term ID of the connected chime
    doorbell_term_id: int = 0  # Term ID of the doorbell (when connected)
    bridge_term_id: int = 0  # Term ID of our bridge
    
    # Keepalive state
    doorbell_addr: tuple = ('', 0)  # Last known (ip, port) of doorbell
    doorbell_last_ack: float = 0.0  # Timestamp of last received keepalive ACK
    keepalive_misses: int = 0  # Consecutive unacknowledged keepalives
    keepalive_enabled: bool = False  # Whether the keepalive loop is active
    
    # Doorbell broadcast discovery
    doorbell_mtp_port: int = 0  # Discovered from LAN broadcast response (type=0x03)
    doorbell_dst_id: int = 0  # Device ID from broadcast response
    
    # MTP relay state
    mtp_link_counter: int = 1  # Incrementing link_id for MTP sessions
    mtp_pairs: dict[int, 'MtpRelayPair'] = field(default_factory=dict)  # link_id -> pair
    mtp_pending_bridges: list = field(default_factory=list)  # MtpConnections waiting for doorbell
    mtp_pending_doorbells: list = field(default_factory=list)  # MtpConnections waiting for bridge


class GutesRelay:
    """UDP-based GUTES relay server with full proxy + standalone capability."""

    def __init__(self, listen_ports: list[int] = None, list_port: int = 51701,
                 mode: str = "proxy", upstream: str = "3.13.212.24:28800",
                 log_file: Optional[str] = None, local_ip: str = "",
                 keepalive: bool = False,
                 session_cache: str = "cache/session_keys.json",
                 mtp_port: int = 23000):
        self.listen_ports = listen_ports or [28800, 8443, 8000]
        self.list_port = list_port
        self.mtp_port = mtp_port
        self.mode = mode
        self._extra_responses = []  # [(bytes, addr)] queue for multi-response sends
        self.upstream_host = upstream.split(':')[0]
        self.upstream_port = int(upstream.split(':')[1])
        self.state = RelayState(keepalive_enabled=keepalive)
        self.t0 = time.time()
        self.log_fp = open(log_file, 'a') if log_file else None
        self.local_ip = local_ip or self._detect_local_ip()
        self.session_cache_path = Path(session_cache)
        
        # Server identity — the relay needs its own stable term_id.
        # Real Mars servers use unique 64-bit IDs; DETECT_RESP carries the
        # SERVER's term_id (NOT an echo of the client's).  We generate a
        # deterministic ID from our IP so it's stable across restarts.
        ip_hash = hashlib.md5(self.local_ip.encode()).digest()
        self.server_term_id: int = struct.unpack_from('<q', ip_hash)[0]
        self.server_sqnum: int = int(time.time()) & 0xFFFFFFFF  # incrementing counter
        
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

    def _next_sqnum(self) -> int:
        """Return and increment server sequence number."""
        sq = self.server_sqnum
        self.server_sqnum = (self.server_sqnum + 1) & 0xFFFFFFFF
        return sq

    def _make_server_chkval(self, sqnum: int) -> int:
        """Generate a chkval for our server frames (simple hash of sqnum)."""
        h = hashlib.md5(struct.pack('<I', sqnum)).digest()
        return struct.unpack_from('<I', h)[0]

    def _encrypt_server_id(self, sqnum: int, chkval: int) -> bytes:
        """Encrypt our server term_id for a frame header."""
        return id_encrypt(
            struct.pack('<q', self.server_term_id),
            struct.pack('<I', chkval),
            struct.pack('<I', sqnum),
        )

    def build_detect_resp(self, req_data: bytes) -> bytes:
        """Build DETECT_RESP that the SDK will accept.

        Key insight: The SDK dispatches responses via iv_gutes_on_rcvfrm_resp
        which matches pending requests by: pending_req.sqnum == response.chkval_field.
        
        So we need:
          - opt_resp=1 (bit 21 of opt_flags) to route through response matching
          - chkval field = the original DETECT_REQ's sqnum (extracted by decrypting)
        
        With opt_resp=1, the SDK skips chkval verification entirely and just
        uses the chkval field for request-response matching.
        """
        import random as _rand

        # Extract the request's sqnum by decrypting bytes 0x0C-0x13
        # The DETECT_REQ has opt_encrypt=1, so sqnum is encrypted with per-frame key
        req_sqnum = self._extract_req_sqnum(req_data)

        resp = bytearray(0x38)  # 56 bytes
        resp[0] = 0x7F
        resp[1] = TYPE_DETECT_RESP
        struct.pack_into('<H', resp, 2, 0x38)

        # Server's term_id (plaintext — no encryption since opt_encrypt=0)
        sqnum = self._next_sqnum()
        term_id_bytes = struct.pack('<q', self.server_term_id)
        resp[4:12] = term_id_bytes
        struct.pack_into('<I', resp, 0x0C, sqnum)
        # chkval = the REQUEST's sqnum (for response matching)
        struct.pack_into('<I', resp, 0x10, req_sqnum)

        # opt_flags: opt_resp=1 (bit 21), no encryption, random nonce
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (1 << 21)  # opt_resp=1
        struct.pack_into('<I', resp, 0x14, opt_flags)

        # flags2 = 0x0001, ack_result = 0x0000
        struct.pack_into('<H', resp, 0x18, 0x0001)
        struct.pack_into('<H', resp, 0x1A, 0x0000)

        # Payload (28 bytes) — match real Mars layout from pcap
        now = int(time.time())
        uptime_ms = int((time.time() - self.t0) * 1000) & 0xFFFFFFFF
        struct.pack_into('<I', resp, 0x1C, uptime_ms)
        struct.pack_into('<I', resp, 0x20, 0)
        resp[0x24] = 0x58  # MTU: 88
        resp[0x25] = 0x00
        resp[0x26] = 0x56  # MTU: 86
        resp[0x27] = 0x00
        struct.pack_into('<I', resp, 0x28, uptime_ms)
        struct.pack_into('<I', resp, 0x2C, 0)
        struct.pack_into('<I', resp, 0x30, now)
        struct.pack_into('<I', resp, 0x34, 1)  # server load

        return bytes(resp)

    def _decrypt_session_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt the 32-byte session key from CERTIFY_REQ.
        
        The SDK encrypts the session key with RC5(16-byte blocks, 6 rounds)
        using certify_key = mars_access_token_bytes[0x30:0x40] (16 bytes).
        Two 16-byte blocks are encrypted separately.
        """
        # Get mars_access_token from env or cache
        access_token = os.environ.get('MARS_ACCESS_TOKEN', '')
        if not access_token:
            # Try loading from cache
            try:
                import json
                cache_path = os.environ.get('SESSION_CACHE', '/work/cache/session_keys.json')
                auth_path = os.path.join(os.path.dirname(cache_path), 'auth.json')
                with open(auth_path) as f:
                    auth = json.load(f)
                access_token = auth.get('mars_access_token', '')
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass
        
        if not access_token:
            self.log("  [RELAY] No mars_access_token available for session key decryption")
            return None
        
        # mars_access_token: first 128 hex chars = 64 bytes
        try:
            token_bytes = bytes.fromhex(access_token[:128])
        except ValueError:
            self.log(f"  [RELAY] mars_access_token not valid hex")
            return None
        
        if len(token_bytes) < 0x40:
            self.log(f"  [RELAY] mars_access_token too short ({len(token_bytes)}B, need 64B)")
            return None
        
        # Certify key is bytes [0x30:0x40] (16 bytes)
        certify_key = token_bytes[0x30:0x40]
        self.log(f"  [RELAY] Certify key: {certify_key.hex()}")
        
        # RC5 decrypt: 16-byte blocks, 6 rounds
        rc5 = RC5(block_bytes=16, rounds=6)
        rc5.setkey(certify_key)
        
        # Decrypt two 16-byte blocks
        block1 = rc5.decrypt_block(bytes(encrypted_key[0:16]))
        block2 = rc5.decrypt_block(bytes(encrypted_key[16:32]))
        
        return block1 + block2
    
    def _giot_hash_string(self, data: bytes) -> int:
        """Compute the hash checksum used to verify the session key.
        
        From decompiled: giot_hash_string(param_1, param_2)
        Initial value = 0x4e67c6a7
        hash = hash ^ (byte + hash * 0x20 + (hash >> 2))
        """
        h = 0x4e67c6a7
        for b in data:
            h = (h ^ (b + (h * 0x20) + (h >> 2))) & 0xFFFFFFFF
        return h

    def _extract_req_sqnum(self, req_data: bytes, addr: tuple = None) -> int:
        """Extract the plaintext sqnum from an encrypted request frame.
        
        For opt_encrypt=1: bytes 0x0C-0x13 encrypted with per-frame key.
        For opt_encrypt=2: bytes 0x0C-0x13 encrypted with session RC5 key.
        """
        if len(req_data) < HEADER_SIZE:
            return 0
        
        opt_flags = struct.unpack_from('<I', req_data, 0x14)[0]
        opt_encrypt = (opt_flags >> 16) & 3
        
        if opt_encrypt == 0:
            # Not encrypted — read sqnum directly
            return struct.unpack_from('<I', req_data, 0x0C)[0]
        
        if opt_encrypt == 2 and addr:
            # Session-encrypted — use session key
            session_key = self.state.addr_session_keys.get(addr)
            if not session_key:
                # Try matching by IP only (SDK may use different ports per socket)
                for a, sk in self.state.addr_session_keys.items():
                    if a[0] == addr[0]:
                        session_key = sk
                        break
            if session_key:
                self.log(f"  [DEBUG] _extract_req_sqnum: using session_key={session_key[:8].hex()}... for addr={addr}")
                rc5 = RC5(block_bytes=8, rounds=6)
                rc5.setkey(session_key)  # Full 32-byte session key
                decrypted_block = rc5.decrypt_block(bytes(req_data[0x0C:0x14]))
                sqnum = struct.unpack_from('<I', decrypted_block, 0)[0]
                self.log(f"  [DEBUG] _extract_req_sqnum: decrypted sqnum={sqnum} from enc_bytes={req_data[0x0C:0x14].hex()}")
                return sqnum
            else:
                self.log(f"  [DEBUG] _extract_req_sqnum: NO session key for addr={addr}, keys={list(self.state.addr_session_keys.keys())}")
        
        # Fallback: per-frame key (for opt_encrypt=1, or if no session key)
        pfk = derive_per_frame_key(req_data)
        rc5 = RC5(block_bytes=8, rounds=6)
        rc5.setkey(pfk)
        
        # Decrypt the 8 bytes at offset 0x0C (sqnum + chkval)
        decrypted_block = rc5.decrypt_block(bytes(req_data[0x0C:0x14]))
        
        return struct.unpack_from('<I', decrypted_block, 0)[0]

    def _build_ack(self, req_data: bytes, frame_type: int, addr: tuple = None) -> bytes:
        """Build a generic ACK frame for a reliable request.
        
        Detects whether the request uses session encryption (proto=0x7E, opt_encrypt=2)
        and builds the ACK accordingly.
        
        ACK format: header-only (0x1C bytes), same frame type.
        For session-encrypted: proto=0x7E, opt_encrypt=2, session-encrypted sqnum/chkval
        For unencrypted: proto=0x7F, opt_encrypt=0
        """
        import random as _rand
        
        req_sqnum = self._extract_req_sqnum(req_data)
        req_proto = req_data[0] if len(req_data) > 0 else 0x7F
        req_opt = struct.unpack_from('<I', req_data, 0x14)[0] if len(req_data) >= 0x18 else 0
        req_encrypt = (req_opt >> 16) & 3
        
        # ACK frame: header (0x1C) + 4-byte payload (acked sqnum)
        ack_len = HEADER_SIZE + 4
        ack = bytearray(ack_len)
        ack[0] = req_proto  # Match the request's protocol byte
        ack[1] = frame_type
        struct.pack_into('<H', ack, 2, ack_len)
        
        # Server term_id
        term_id_bytes = struct.pack('<q', self.server_term_id)
        ack[4:12] = term_id_bytes
        
        sqnum = self._next_sqnum()
        struct.pack_into('<I', ack, 0x0C, sqnum)
        struct.pack_into('<I', ack, 0x10, req_sqnum)  # chkval = request sqnum (for matching)
        
        # opt_flags: match encryption mode, set ack=1 (bit 20), resp=1 (bit 21)
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (req_encrypt << 16) | (1 << 20) | (1 << 21)
        struct.pack_into('<I', ack, 0x14, opt_flags)
        
        # flags2 + ack_result (ack_result = confirmed sqnum for reliable delivery)
        struct.pack_into('<H', ack, 0x18, 0x0000)
        struct.pack_into('<H', ack, 0x1A, req_sqnum & 0xFFFF)  # Lower 16 bits of acked sqnum
        
        # Payload: full 32-bit acked sqnum
        struct.pack_into('<I', ack, HEADER_SIZE, req_sqnum)
        
        # If session encrypted, encrypt sqnum+chkval and ID with session key
        if req_encrypt == 2:
            # Look up session key by address (most reliable for session-encrypted frames)
            session_key = self.state.addr_session_keys.get(addr) if addr else None
            if not session_key:
                # Fallback: try decoded term_id
                req_term_id = self.decode_term_id(req_data)
                session_key = self.get_session_key(req_term_id)
            if session_key:
                # Per-frame key derivation is the same for all encrypt modes
                pfk = derive_per_frame_key(bytes(ack[:0x18]))
                rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
                
                # Encrypt sqnum + chkval with per-frame key
                enc_sqn = rc5.encrypt_block(bytes(ack[0x0C:0x14]))
                ack[0x0C:0x14] = enc_sqn
                
                # For opt_encrypt=2, ID is encrypted with SESSION KEY (not GWELL_KEY!)
                rc5_id = RC5(block_bytes=8, rounds=6).setkey(session_key[:8])
                enc_id = bytearray(rc5_id.encrypt_block(bytes(term_id_bytes)))
                # XOR with encrypted sqnum/chkval
                for i in range(4):
                    enc_id[i] ^= ack[0x0C + i]
                    enc_id[4+i] ^= ack[0x10 + i]
                ack[4:12] = enc_id
                
                # Encrypt payload with session key (opt_encrypt=2)
                if len(ack) > HEADER_SIZE:
                    # Pad payload to 8 bytes if needed for RC5 block
                    payload_start = HEADER_SIZE
                    payload_len = len(ack) - HEADER_SIZE
                    if payload_len >= 8:
                        rc5_sess = RC5(block_bytes=8, rounds=6).setkey(session_key[:8])
                        enc_payload = rc5_sess.encrypt_block(bytes(ack[payload_start:payload_start+8]))
                        ack[payload_start:payload_start+8] = enc_payload
                    elif payload_len == 4:
                        # Pad to 8 bytes, encrypt, truncate back
                        padded = bytes(ack[payload_start:payload_start+4]) + b'\x00\x00\x00\x00'
                        rc5_sess = RC5(block_bytes=8, rounds=6).setkey(session_key[:8])
                        enc_payload = rc5_sess.encrypt_block(padded)
                        # Actually, just expand the frame to 8 bytes payload
                        ack = ack[:payload_start] + bytearray(enc_payload)
                        struct.pack_into('<H', ack, 2, len(ack))  # Update frm_len
        
        return bytes(ack)

    def _build_init_info_resp(self, req_data: bytes, addr: tuple, req_sqnum: int) -> bytes:
        """Build INIT_INFO_RESP with session encryption (opt_encrypt=2).
        
        The chime firmware requires session-encrypted responses — opt_encrypt=0
        with bit25 bypass only works for the bridge SDK, not for device-side SDKs.
        
        Uses the same session encryption pattern as _build_calling_ack:
        1. Build plaintext frame with payload
        2. Compute chkval
        3. Encrypt payload (0x18+) with session key
        4. Encrypt sqnum+chkval (0x0C-0x13) with session key
        5. Encrypt ID (0x04-0x0B) with GWELL_KEY + XOR with encrypted sqnum/chkval
        """
        import random as _rand
        
        # Get session key for this client
        session_key = self.state.addr_session_keys.get(addr)
        if not session_key:
            for a, sk in self.state.addr_session_keys.items():
                if a[0] == addr[0]:
                    session_key = sk
                    break
        
        # Build payload: flags2(2B) + ack_result(2B) + online_cnt(2B) + offline_cnt(2B) + device_entry(28B)
        device_id = getattr(self, 'device_numeric_id', 429728659090583)
        
        dev_entry = bytearray(28)
        struct.pack_into('<Q', dev_entry, 0, device_id)
        dev_entry[24] = 1  # status = online
        dev_entry[25] = 1  # auth = authorized
        
        flags2 = 0x0001  # bit 0 = has device list
        payload = struct.pack('<HHHH', flags2, 0, 1, 0)  # flags2, ack_result=0, online=1, offline=0
        payload += bytes(dev_entry)
        
        # Pad payload to 8-byte boundary for RC5 encryption
        pad_len = (8 - len(payload) % 8) % 8
        payload += b'\x00' * pad_len
        
        CRYPTO_HDR = 0x18
        frame_size = CRYPTO_HDR + len(payload)
        resp = bytearray(frame_size)
        resp[0] = 0x7E  # session proto
        resp[1] = TYPE_INIT_INFO_MSG + 1  # 0xA7 response
        struct.pack_into('<H', resp, 2, frame_size)
        
        # term_id — use session_id from CERTIFY
        session_id_bytes = self.state.addr_session_id.get(addr)
        if not session_id_bytes:
            for a, sid in self.state.addr_session_id.items():
                if a[0] == addr[0]:
                    session_id_bytes = sid
                    break
        if session_id_bytes and len(session_id_bytes) >= 8:
            resp[4:12] = session_id_bytes[:8]
        else:
            struct.pack_into('<q', resp, 4, self.server_term_id)
        
        # sqnum = our own, chkval = request's plaintext sqnum (for response matching)
        sqnum = self._next_sqnum()
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, req_sqnum & 0xFFFFFFFF)
        
        # opt_flags: encrypt=2 (session), opt_resp=1 (bit 21), relay_flag=1 (bit 25)
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (2 << 16) | (1 << 21) | (1 << 25)
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # Payload (plaintext)
        resp[CRYPTO_HDR:CRYPTO_HDR + len(payload)] = payload
        
        if session_key and self._verify_session_key_valid(session_key, req_data):
            # Session key verified — use session encryption
            chkval = self._compute_chkval(resp)
            struct.pack_into('<I', resp, 0x10, chkval)
            # But chkval field is ALSO used for response matching — SDK reads it AFTER decrypt
            # The SDK decrypts sqnum+chkval at 0x0C-0x13, then checks decrypted chkval == stored_req_sqnum
            # So we put req_sqnum in chkval position, compute chkval, but then replace with req_sqnum
            # Actually: the chkval check is skipped for opt_resp=1 frames! So we just need chkval for
            # the pre-decrypt validation path. Let me set chkval = req_sqnum for response matching.
            struct.pack_into('<I', resp, 0x10, req_sqnum & 0xFFFFFFFF)
            
            # Session encrypt
            rc5_session = RC5(block_bytes=8, rounds=6)
            rc5_session.setkey(session_key)
            
            # 1. Encrypt payload (0x18+)
            enc_payload = rc5_session.encrypt(bytes(resp[0x18:]))
            resp[0x18:0x18 + len(enc_payload)] = enc_payload
            
            # 2. Encrypt sqnum+chkval (0x0C-0x13)
            enc_sqchk = rc5_session.encrypt_block(bytes(resp[0x0C:0x14]))
            resp[0x0C:0x14] = enc_sqchk
            
            # 3. Encrypt ID: RC5_enc with GWELL_KEY, then XOR with encrypted sqnum/chkval
            rc5_id = RC5(block_bytes=8, rounds=6)
            rc5_id.setkey(GWELL_KEY)
            enc_id = bytearray(rc5_id.encrypt_block(bytes(resp[4:12])))
            for i in range(4):
                enc_id[i] ^= resp[0x0C + i]
                enc_id[4 + i] ^= resp[0x10 + i]
            resp[4:12] = enc_id
            
            self.log(f"  [DEBUG] INIT_INFO_RESP session-encrypted with key={session_key[:8].hex()}...")
        else:
            # No session key — use opt_encrypt=0 fallback (works for bridge SDK)
            opt_flags = (1 << 21) | (1 << 25)  # opt_resp=1, bit25
            struct.pack_into('<I', resp, 0x14, opt_flags)
            self.log(f"  [DEBUG] INIT_INFO_RESP plaintext (no session key)")
        
        self.log(f"  [DEBUG] RESP hex: {resp[:24].hex()}")
        return bytes(resp)

    def _verify_session_key_valid(self, session_key: bytes, req_data: bytes) -> bool:
        """Check if our stored session key can actually decrypt this frame.
        
        If we derived the session key with the WRONG certify key (e.g., bridge's
        key for a chime's CERTIFY), the decrypted session key is garbage and
        session encryption will fail. We detect this by checking if the 32-byte
        key has a repeating pattern (characteristic of wrong-key decryption).
        """
        # Check for repeating 8-byte pattern (sign of wrong certify key)
        if len(session_key) >= 16:
            if session_key[:8] == session_key[8:16]:
                return False
        return True

    def _build_subscribe_resp(self, addr: tuple, predicted_sqnum: int) -> bytes:
        """Build SUBSCRIBE_RESP (type=0xA1) with opt_encrypt=0, opt_resp=1, bit25=1.
        
        The SDK's gat_rcv_subscribe_dev_resp reads:
        - ack_result (frame offset 0x1A): 0 = success
        - error_code (frame offset 0x34): 0 = no error
        """
        # Payload: flags2(2B) + ack_result(2B) + padding to cover error_code at offset 0x34
        # error_code is at frame offset 0x34 - 0x18 = 0x1C from payload start
        # Payload: [0x18]=flags2=0, [0x1A]=ack_result=0, [0x1C..0x35]=zeros (including error at 0x34)
        payload_size = 0x34 - 0x18 + 2  # up to and including error_code field = 30 bytes
        payload = bytearray(payload_size)  # all zeros = success
        
        CRYPTO_HDR = 0x18
        frame_size = CRYPTO_HDR + payload_size
        resp = bytearray(frame_size)
        resp[0] = 0x7E  # Session protocol
        resp[1] = TYPE_SUBSCRIBE_RESP  # 0xA1
        struct.pack_into('<H', resp, 2, frame_size)
        
        # term_id = session_id from CERTIFY
        session_id_bytes = self.state.addr_session_id.get(addr)
        if session_id_bytes:
            resp[4:12] = session_id_bytes
        else:
            struct.pack_into('<q', resp, 4, self.server_term_id)
        
        # sqnum and chkval = predicted request sqnum
        sqnum = self._next_sqnum()
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, predicted_sqnum & 0xFFFFFFFF)
        
        # opt_flags: opt_encrypt=0, opt_resp=1 (bit 21), relay_flag=1 (bit 25)
        opt_flags = (1 << 21) | (1 << 25)
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # Payload (all zeros = success)
        resp[CRYPTO_HDR:] = payload
        
        self.log(f"  → SUBSCRIBE_RESP to {addr[0]}:{addr[1]} ({frame_size}B) chkval={predicted_sqnum}")
        return bytes(resp)

    def _build_session_ctl_resp(self, data: bytes, addr: tuple, predicted_sqnum: int) -> Optional[bytes]:
        """Build SESSION_CTL_RESP (type=0xB1) — success response.
        
        Same structure as SUBSCRIBE_RESP but with type 0xB1.
        """
        payload_size = 0x34 - 0x18 + 2  # 30 bytes
        payload = bytearray(payload_size)  # all zeros = success
        
        CRYPTO_HDR = 0x18
        frame_size = CRYPTO_HDR + payload_size
        resp = bytearray(frame_size)
        resp[0] = 0x7E  # Session protocol
        resp[1] = TYPE_SESSION_CTL_RESP  # 0xB1
        struct.pack_into('<H', resp, 2, frame_size)
        
        # term_id = session_id from CERTIFY
        session_id_bytes = self.state.addr_session_id.get(addr)
        if session_id_bytes:
            resp[4:12] = session_id_bytes
        else:
            struct.pack_into('<q', resp, 4, self.server_term_id)
        
        sqnum = self._next_sqnum()
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, predicted_sqnum & 0xFFFFFFFF)
        
        # opt_flags: opt_encrypt=0, opt_resp=1 (bit 21), relay_flag=1 (bit 25)
        opt_flags = (1 << 21) | (1 << 25)
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # Payload (all zeros = success)
        resp[CRYPTO_HDR:] = payload
        
        return bytes(resp)

    def _build_calling_ack(self, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
        """Build session-encrypted CALLING ACK with doorbell's network address.
        
        CRITICAL DISCOVERY: iv_gutes_frm_decrypt IS called before iv_gutes_on_rcvfrm_ack!
        All incoming frames (except DETECT_RESP) are decrypted at line 18053 in iv_gutes_on_rcvpkt.
        
        For opt_encrypt=0 with opt_ack=1 (opt_resp=0): SDK validates chkval → FAILS (our chkval=0).
        Real Mars uses opt_encrypt=2 (session) for the ACK. After SDK decrypts, it reads plaintext sqnum.
        
        ACK matching (after decryption): stored_req_sqnum == decrypted_ack_frame[0x0C]
        Callback iv_on_ackfrm_Calling reads decrypted payload at frame offsets 0x18, 0x20, 0x24.
        """
        # Get session key
        session_key = self.state.addr_session_keys.get(addr)
        if not session_key:
            for a, sk in self.state.addr_session_keys.items():
                if a[0] == addr[0]:
                    session_key = sk
                    break
        if not session_key:
            self.log(f"  [MTP] No session key for CALLING_ACK")
            return None
        
        # Get certify key for ID encryption
        import json
        try:
            with open(os.path.join(os.path.dirname(__file__), '..', 'cache', 'auth.json')) as f:
                auth_data = json.load(f)
            certify_key = bytes.fromhex(auth_data['mars_access_token'][:128])[0x30:0x40]
        except Exception:
            certify_key = session_key[:16]
        
        doorbell_ip_str = os.environ.get('DOORBELL_IP', '192.168.1.81')
        doorbell_port = 8899
        
        # Extract request's plaintext sqnum
        req_sqnum = self._extract_req_sqnum(calling_data, addr)
        self.log(f"  [MTP] CALLING req_sqnum={req_sqnum} (for ACK matching)")
        
        # Build ACK frame — must be multiple of 8 bytes for encryption
        # Header (24) + payload must be padded to 8-byte boundary
        # Payload: 2B flags + 2B ack_result + 4B padding + 4B IP + 2B port = 14 bytes → pad to 16
        payload_size = 16  # padded to 8-byte multiple
        frame_size = 0x18 + payload_size  # 24 + 16 = 40 bytes
        resp = bytearray(frame_size)
        resp[0] = 0x7E  # session proto
        resp[1] = 0xA4  # Same type as request
        struct.pack_into('<H', resp, 2, frame_size)
        
        # term_id (plaintext, will be encrypted with certify key)
        session_id_bytes = self.state.addr_session_id.get(addr)
        if not session_id_bytes:
            for a, sid in self.state.addr_session_id.items():
                if a[0] == addr[0]:
                    session_id_bytes = sid
                    break
        if session_id_bytes and len(session_id_bytes) >= 8:
            resp[4:12] = session_id_bytes[:8]
        else:
            struct.pack_into('<q', resp, 4, self.server_term_id)
        
        # sqnum = request's plaintext sqnum (will match after SDK decrypts)
        struct.pack_into('<I', resp, 0x0C, req_sqnum)
        # chkval will be computed below
        
        # opt_flags: encrypt=2 (session), opt_ack=1 (bit 20), relay_flag=1 (bit 25)
        import random as _rand
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (2 << 16) | (1 << 20) | (1 << 25)
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # Payload at 0x18 (plaintext before encryption):
        struct.pack_into('<H', resp, 0x18, 1)  # opt_with_netaddr = 1
        struct.pack_into('<H', resp, 0x1A, 0)  # ack_result = 0 (success)
        # bytes 0x1C-0x1F: padding (0)
        # bytes 0x20-0x23: doorbell IPv4
        ip_bytes = socket.inet_aton(doorbell_ip_str)
        resp[0x20:0x24] = ip_bytes
        # bytes 0x24-0x25: doorbell port (network byte order)
        struct.pack_into('>H', resp, 0x24, doorbell_port)
        
        # Compute chkval (XOR of all dwords, excluding chkval itself)
        chkval = self._compute_chkval(resp)
        struct.pack_into('<I', resp, 0x10, chkval)
        
        # --- Session encrypt ---
        # SDK decrypts: 0x0C-0x13 (sqnum+chkval) and 0x18+ (payload), all with session key
        # encrypt_data_len = frm_len - 0x18
        rc5_session = RC5(block_bytes=8, rounds=6)
        rc5_session.setkey(session_key)
        
        # 1. Encrypt payload (0x18 to end) — SDK decrypts from 0x18
        payload_data = bytes(resp[0x18:])
        if len(payload_data) >= 8:
            enc_payload = rc5_session.encrypt(payload_data[:len(payload_data) - len(payload_data) % 8])
            resp[0x18:0x18 + len(enc_payload)] = enc_payload
        
        # 2. Encrypt sqnum+chkval (0x0C-0x13)
        enc_sqchk = rc5_session.encrypt_block(bytes(resp[0x0C:0x14]))
        resp[0x0C:0x14] = enc_sqchk
        
        # 3. Encrypt ID (0x04-0x0B): RC5_enc with GWELL_KEY, then XOR with encrypted sqnum/chkval
        rc5_id = RC5(block_bytes=8, rounds=6)
        rc5_id.setkey(GWELL_KEY)
        enc_id = bytearray(rc5_id.encrypt_block(bytes(resp[4:12])))
        for i in range(4):
            enc_id[i] ^= resp[0x0C + i]      # XOR with encrypted sqnum
            enc_id[4 + i] ^= resp[0x10 + i]  # XOR with encrypted chkval
        resp[4:12] = enc_id
        
        self.log(f"  [MTP] Built CALLING_ACK (session-enc): doorbell={doorbell_ip_str}:{doorbell_port} "
                 f"req_sqnum={req_sqnum} frame_size={frame_size}")
        return bytes(resp)

    def _build_mtp_res_resp(self, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
        """Build MTP_RES_RESP (type 0xA3) for LAN-only video path.
        
        Frame layout (from decompiled gat_on_rcvpkt_MTP_RES_RESPONSE):
        The SDK reads from the frame context buffer (frame at offset 0x1B0).
        Field offsets below are relative to frame start.
        
        For the CALLING side (state==1, our bridge SDK):
          frame[0x1C:0x20]  link_id (4B LE) — must match CALLING
          frame[0x56]       called_ip_version_flags (bit0=v4, bit1=v6)
          frame[0x58:0x5A]  called_outer_port (2B NBO)
          frame[0x5A:0x5C]  called_lan_port (2B NBO)
          frame[0x5C:0x5E]  called_ipv6_port (2B NBO)
          frame[0x5E:0x60]  called_session_socket_udpport (2B NBO)
          frame[0x60:0x64]  called_outer_ipv4 (4B) — set to FAKE IP
          frame[0x64:0x68]  called_lan_ipv4 (4B) — doorbell's LAN IP
          frame[0x68:0x78]  called_ipv6 (16B) — zeros
          frame[0x78]       v4_cnt (1B) — 0 = no relay servers!
          frame[0x79]       v6_cnt (1B) — 0
        
        LAN channel creation condition (line 27374):
          if (lan_ipv4 != 0 && lan_ipv4 != outer_ipv4):
              add_lan_or_nat(type=2, lan_sockaddr)
        
        LAN mode (type=2) has HIGHEST priority in iv_get_connect_mode_link_chn.
        Setting v4_cnt=0 means NO relay servers — forces LAN or NAT only.
        """
        import random as _rand
        
        # Extract link_id from CALLING_REQ (at frame offset 0x1C)
        # CALLING payload is session-encrypted — link_id is in the encrypted payload
        # After decryption, link_id is at payload[4] = frame[0x1C]
        # But we can also extract it from _extract_calling_link_id
        link_id = self._extract_calling_link_id(calling_data, addr)
        if link_id is None:
            self.log(f"  [MTP] Cannot extract link_id from CALLING, using counter")
            link_id = self.state.mtp_link_counter
            self.state.mtp_link_counter += 1
        
        doorbell_ip = os.environ.get('DOORBELL_IP', '192.168.1.81')
        doorbell_port = self.state.doorbell_mtp_port or int(os.environ.get('DOORBELL_PORT', '8899'))
        if self.state.doorbell_mtp_port:
            self.log(f"  [MTP] Using broadcast-discovered port {doorbell_port}")
        else:
            self.log(f"  [MTP] No broadcast port discovered, using fallback {doorbell_port}")
        
        # Build the frame — needs to be at least 0x7A bytes (122)
        CRYPTO_HDR = 0x18
        frame_size = 0x7A  # 122 bytes: header + payload up to relay counts
        resp = bytearray(frame_size)
        
        # --- Header ---
        resp[0] = 0x7E  # Session protocol
        resp[1] = 0xA3  # MTP_RES_RESP
        struct.pack_into('<H', resp, 2, frame_size)
        
        # term_id = session_id from CERTIFY
        session_id_bytes = self.state.addr_session_id.get(addr)
        if session_id_bytes:
            resp[4:12] = session_id_bytes
        else:
            struct.pack_into('<q', resp, 4, self.server_term_id)
        
        # sqnum and chkval
        sqnum = self._next_sqnum()
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, 0)  # chkval — set after computation
        
        # opt_flags: opt_encrypt=0, opt_resp=0, relay_flag=1 (bit25)
        opt_flags = (1 << 25)
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # --- Payload (starts at 0x18) ---
        # flags2 at 0x18: bit0=1 (has_netaddr), bit1=1 (has_ipv6)
        struct.pack_into('<H', resp, 0x18, 0x0003)
        # ack_result at 0x1A
        struct.pack_into('<H', resp, 0x1A, 0)
        
        # link_id at 0x1C (matches CALLING)
        struct.pack_into('<I', resp, 0x1C, link_id)
        
        # --- Calling peer block (frame[0x32]-[0x44]) --- 
        # This is OUR info (the bridge's address) for the doorbell to send to
        # ip_version_flags at 0x32: bit0=1 (has ipv4)
        resp[0x32] = 0x01
        # calling_outer_port at 0x34 (NBO) — bridge's port
        struct.pack_into('>H', resp, 0x34, 0)  # SDK fills this
        # calling_lan_port at 0x36 (NBO)
        struct.pack_into('>H', resp, 0x36, 0)
        # calling_session_socket_udpport at 0x3A (NBO)
        struct.pack_into('>H', resp, 0x3A, 0)
        # calling_outer_ipv4 at 0x3C — set to bridge's LAN IP
        bridge_ip_bytes = socket.inet_aton(self.local_ip)
        resp[0x3C:0x40] = bridge_ip_bytes
        # calling_lan_ipv4 at 0x40
        resp[0x40:0x44] = bridge_ip_bytes
        
        # --- Called peer block (frame[0x56]-[0x78]) ---
        # This is the DOORBELL's info for the bridge to connect to
        # ip_version_flags at 0x56: bit0=1 (has ipv4)
        resp[0x56] = 0x01
        
        doorbell_ip_bytes = socket.inet_aton(doorbell_ip)
        # Set outer_ipv4 to a FAKE external IP (ensures lan != outer check passes)
        fake_outer = socket.inet_aton('1.2.3.4')
        
        # called_outer_port at 0x58 (NBO)
        struct.pack_into('>H', resp, 0x58, doorbell_port)
        # called_lan_port at 0x5A (NBO) — doorbell's LAN port
        struct.pack_into('>H', resp, 0x5A, doorbell_port)
        # called_ipv6_port at 0x5C (NBO)
        struct.pack_into('>H', resp, 0x5C, 0)
        # called_session_socket_udpport at 0x5E (NBO) — for hole punch
        struct.pack_into('>H', resp, 0x5E, doorbell_port)
        
        # called_outer_ipv4 at 0x60 — FAKE IP (forces LAN path creation)
        resp[0x60:0x64] = fake_outer
        # called_lan_ipv4 at 0x64 — doorbell's REAL LAN IP  
        resp[0x64:0x68] = doorbell_ip_bytes
        # called_ipv6 at 0x68 (16 bytes zeros)
        
        # --- Relay list ---
        # v4_cnt at 0x78 = 0 (NO relay servers!)
        resp[0x78] = 0
        # v6_cnt at 0x79 = 0
        resp[0x79] = 0
        
        # --- Compute chkval ---
        chkval = self._compute_chkval(resp)
        struct.pack_into('<I', resp, 0x10, chkval)
        
        self.log(f"  [MTP] Built MTP_RES_RESP: link_id={link_id} "
                f"doorbell_lan={doorbell_ip}:{doorbell_port} "
                f"v4_cnt=0 v6_cnt=0 (LAN-only, no relay servers) "
                f"({frame_size}B)")
        
        return bytes(resp)

    def _compute_chkval(self, frame: bytearray) -> int:
        """Compute the GUTES frame checksum matching iv_gute_frm_init_chkval.
        
        From decompiled code (libiotp2pav.c:17589):
          chkval = (opt_flags & 0xffffff) ^ dword[0] ^ dword[1] ^ dword[2] ^ dword[3]
          for each payload dword starting at offset 0x18:
              chkval ^= dword
          
        Frame is treated as uint32 LE array:
          [0]=bytes 0-3, [1]=4-7, [2]=8-11, [3]=12-15(sqnum),
          [4]=16-19(chkval), [5]=20-23(opt_flags), [6+]=24+(payload)
        """
        d = [struct.unpack_from('<I', frame, i*4)[0] for i in range(len(frame)//4)]
        # opt_flags & 0x00ffffff ^ first 4 dwords (header bytes 0x00-0x0F)
        chk = (d[5] & 0x00FFFFFF) ^ d[0] ^ d[1] ^ d[2] ^ d[3]
        # XOR all dwords from offset 0x18 onward (index 6+)
        for i in range(6, len(d)):
            chk ^= d[i]
        return chk & 0xFFFFFFFF

    def _extract_calling_link_id(self, data: bytes, addr: tuple) -> Optional[int]:
        """Extract link_id from CALLING_REQ frame.
        
        The CALLING_REQ has link_id at frame[0x1C] (payload[0x04]).
        For session-encrypted frames, we decrypt the payload first.
        """
        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        encrypt_mode = (opt_flags >> 16) & 3
        
        if len(data) < 0x20:
            return None
        
        if encrypt_mode == 2:
            # Session-encrypted: decrypt payload to get link_id
            session_key = self.state.addr_session_keys.get(addr)
            if not session_key:
                # Try IP-based lookup
                for a, sk in self.state.addr_session_keys.items():
                    if a[0] == addr[0]:
                        session_key = sk
                        break
            if session_key:
                rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
                # Decrypt from 0x18 (first 8 bytes of payload contain link_id at offset 4)
                enc = bytes(data[0x18:0x20])
                dec = rc5.decrypt_block(enc)
                link_id = struct.unpack_from('<I', dec, 4)[0]
                self.log(f"  [MTP] Extracted link_id={link_id} from CALLING (session-dec)")
                return link_id
        elif encrypt_mode == 1:
            # Per-frame encrypted
            pfk = derive_per_frame_key(data[:0x18])
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            enc = bytes(data[0x18:0x20])
            dec = rc5.decrypt_block(enc)
            link_id = struct.unpack_from('<I', dec, 4)[0]
            self.log(f"  [MTP] Extracted link_id={link_id} from CALLING (pfk-dec)")
            return link_id
        else:
            # Plaintext
            link_id = struct.unpack_from('<I', data, 0x1C)[0]
            self.log(f"  [MTP] Extracted link_id={link_id} from CALLING (plaintext)")
            return link_id
        
        return None

    def build_list_resp(self, list_req_data: bytes, reply_ip: str = None) -> bytes:
        """Build LIST_RESP with our relay as the only server.

        Payload format (from decompiled gat_on_rcvpkt_LIST_RESP):
          Frame offset 0x1C+0: uint16 timer_interval (minutes, valid range: 60-180)
          Frame offset 0x1C+2: uint8  server_count
          Frame offset 0x1C+3: padding byte
          Frame offset 0x1C+4: server entries, each 36 bytes (0x24)
        
        Each 36-byte server entry:
          +0:  uint32  IPv4 address (network byte order from inet_aton)
          +4:  uint8[16] IPv6 address (zeros for v4-only)
          +20: uint8   flags
          +21: uint8   padding
          +22: uint16  unknown (0)
          +24: uint16  port1 (LE)
          +26: uint16  port2 (LE)
          +28: uint16  port3 (LE)
          +30: uint16  port4 (LE)
          +32: 4 bytes padding
        
        We send opt_encrypt=0, opt_resp=0, and compute the correct chkval.
        
        The SDK's dispatch: for opt_resp=0, the frame goes through a type-based
        callback dispatch (param_1[0x2b]) which routes to gat_on_rcvpkt_LIST_RESP.
        For opt_resp=1, it goes to iv_gutes_on_rcvfrm_resp which uses request-matching
        that never matches LIST (since LIST_REQ uses reliable=0).
        
        Chkval formula (from iv_gute_frm_init_chkval):
          chk = (opt_flags & 0x00FFFFFF) ^ dword[0] ^ dword[1] ^ dword[2] ^ dword[3]
          for each dword at offset 0x18+: chk ^= dword[i]
        Where dword[n] = frame as uint32 LE array. dword[4] (chkval itself) is excluded.
        """
        import random as _rand

        num_servers = 1  # just one server entry pointing to us
        payload_size = 4 + num_servers * 36  # timer(2) + count(1) + pad(1) + entries
        frame_size = HEADER_SIZE + payload_size
        
        resp = bytearray(frame_size)
        resp[0] = 0x7F
        resp[1] = TYPE_LIST_RESP
        struct.pack_into('<H', resp, 2, frame_size)

        # Server term_id (plaintext — no encryption when opt_encrypt=0)
        sqnum = self._next_sqnum()
        term_id_bytes = struct.pack('<q', self.server_term_id)
        resp[4:12] = term_id_bytes
        struct.pack_into('<I', resp, 0x0C, sqnum)
        # chkval will be set after computation
        
        # opt_flags: encrypt=0, resp=0, ack=0, reliable=0, random nonce
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1)  # no encrypt, no resp, no ack
        struct.pack_into('<I', resp, 0x14, opt_flags)
        
        # flags2 and ack_result (frame bytes 0x18-0x1B)
        struct.pack_into('<H', resp, 0x18, 0x0000)
        struct.pack_into('<H', resp, 0x1A, 0x0000)
        
        # --- Payload (starts at HEADER_SIZE = 0x1C) ---
        ip_bytes = socket.inet_aton(reply_ip or self.local_ip)
        main_port = self.listen_ports[0]  # 28800
        
        # Timer interval: uint16 LE at payload offset 0 (60 minutes = 0x3C)
        struct.pack_into('<H', resp, HEADER_SIZE, 60)
        # Server count: uint8 at payload offset 2
        resp[HEADER_SIZE + 2] = num_servers
        # Padding byte at offset 3 (already 0)
        
        # Server entry at payload offset 4 (frame offset 0x20)
        entry_off = HEADER_SIZE + 4
        resp[entry_off:entry_off+4] = ip_bytes          # IPv4 (4 bytes)
        # IPv6 stays zero (bytes 4-19)
        # flags byte at +20 stays 0
        # padding at +21 stays 0
        # unknown uint16 at +22 stays 0
        struct.pack_into('>H', resp, entry_off + 24, main_port)  # port1 (BE/network order)
        struct.pack_into('>H', resp, entry_off + 26, main_port)  # port2 (BE/network order)
        struct.pack_into('>H', resp, entry_off + 28, main_port)  # port3 (BE/network order)
        struct.pack_into('>H', resp, entry_off + 30, main_port)  # port4 (BE/network order)
        # 4 bytes padding at +32 stays 0
        
        # Compute chkval: XOR of opt_flags(lower 24 bits), dwords [0..3], payload dwords
        # dword[4] (chkval itself at 0x10) is excluded
        # dword[5] (opt_flags at 0x14) is used separately as & 0xffffff
        chk = opt_flags & 0x00FFFFFF
        chk ^= struct.unpack_from('<I', resp, 0)[0]   # dword[0]: proto+type+frm_len
        chk ^= struct.unpack_from('<I', resp, 4)[0]   # dword[1]: term_id[0:4]
        chk ^= struct.unpack_from('<I', resp, 8)[0]   # dword[2]: term_id[4:8]
        chk ^= struct.unpack_from('<I', resp, 0xC)[0]  # dword[3]: sqnum
        # XOR payload dwords starting at offset 0x18
        for off in range(0x18, frame_size - 3, 4):
            chk ^= struct.unpack_from('<I', resp, off)[0]
        chk &= 0xFFFFFFFF
        struct.pack_into('<I', resp, 0x10, chk)
        
        return bytes(resp)
    def get_upstream_sock(self, term_id: int) -> socket.socket:
        """Get or create a dedicated upstream socket for a client."""
        if term_id not in self.upstream_socks:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.05)  # Blocking with short timeout for run_in_executor
            self.upstream_socks[term_id] = sock
        return self.upstream_socks[term_id]

    def hexdump(self, data: bytes, max_bytes: int = 128) -> str:
        """Return a compact hex dump string for logging."""
        truncated = len(data) > max_bytes
        d = data[:max_bytes]
        hex_str = ' '.join(f'{b:02x}' for b in d)
        if truncated:
            hex_str += f' ... (+{len(data) - max_bytes}B)'
        return hex_str

    def handle_packet(self, data: bytes, addr: tuple, our_port: int) -> Optional[bytes]:
        """Process incoming packet. Returns local response or None (forward/route)."""
        if len(data) < 4:
            self.log(f"← RUNT ({len(data)}B) from {addr[0]}:{addr[1]} port={our_port} | {self.hexdump(data)}")
            return None
        
        protocol, ftype, frm_len, opt_flags = self.get_frame_info(data)
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
        ack = self.is_ack(opt_flags)
        is_resp = self.is_response(opt_flags)
        encrypt_mode = (opt_flags >> 16) & 0xF
        
        # Register/update client
        if term_id != 0:
            is_new = term_id not in self.state.clients
            if is_new:
                self.state.clients[term_id] = ClientSession(
                    term_id=term_id, addr=addr, our_port=our_port)
                self.log(f"NEW CLIENT: term_id={term_id} from {addr[0]}:{addr[1]} port={our_port}")
                self.log(f"  HDR: proto=0x{protocol:02x} type=0x{ftype:02x}({type_name}) len={frm_len} "
                        f"opt=0x{opt_flags:08x} enc={encrypt_mode} ack={ack} resp={is_resp}")
                self.log(f"  HEX: {self.hexdump(data, 256)}")
            client = self.state.clients[term_id]
            client.addr = addr
            client.our_port = our_port
            client.last_seen = time.time()
            client.frames_in += 1
            self.state.addr_to_term[addr] = term_id

        # --- DETECT: always respond locally (we want to win the race) ---
        if ftype == TYPE_DETECT_REQ:
            self.log(f"← DETECT_REQ from {addr[0]}:{addr[1]}:{our_port} "
                    f"client_tid={term_id} ({frm_len}B)")
            resp = self.build_detect_resp(data)
            self.log(f"→ DETECT_RESP to {addr[0]}:{addr[1]} "
                    f"server_tid={self.server_term_id} ({len(resp)}B)")
            return resp

        # --- LIST_REQ: respond locally with our relay as the only server ---
        # We ALWAYS respond locally because:
        # 1. Container networking blocks outbound UDP to Mars:51701
        # 2. We want the SDK to DETECT against our local relay
        elif ftype == TYPE_LIST_REQ:
            self.log(f"← LIST_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            reply_ip = "127.0.0.1" if addr[0].startswith("127.") else self.local_ip
            resp = self.build_list_resp(data, reply_ip)
            self.log(f"→ LIST_RESP to {addr[0]}:{addr[1]} (local, servers: {reply_ip}, {len(resp)}B)")
            return resp

        # --- CERTIFY ---
        elif ftype == TYPE_CERTIFY_REQ:
            if ack:
                self.log(f"← CERTIFY_ACK from {addr[0]}:{addr[1]} term_id={term_id}")
            else:
                self.log(f"← CERTIFY_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
                # CERTIFY uses opt_encrypt=1 (per-frame key) — extract plaintext sqnum
                # so we can predict INIT_INFO sqnum = certify_sqnum + 1
                certify_sqnum = self._extract_req_sqnum(data)
                self.state.addr_last_sqnum[addr] = certify_sqnum
                self.log(f"  [DEBUG] CERTIFY plaintext sqnum={certify_sqnum}")
            if self.mode == "relay":
                return self._handle_certify_local(data, addr, term_id)
            return None  # proxy: forward

        elif ftype == TYPE_CERTIFY_RESP:
            self.log(f"← CERTIFY_RESP for term_id={term_id} ({frm_len}B)")
            if term_id in self.state.clients:
                self.state.clients[term_id].certified = True
                self._on_client_certified(term_id)
            # In proxy mode, capture session key material before forwarding
            if self.mode == "proxy":
                self._capture_session_key_from_resp(data, term_id)
            return None  # proxy: forward to client

        # --- INIT_INFO ---
        elif ftype == TYPE_INIT_INFO_MSG:
            self.log(f"← INIT_INFO{'_ACK' if ack else ''} from {addr[0]}:{addr[1]} term_id={term_id}")
            if term_id in self.state.clients:
                self.state.clients[term_id].certified = True
                self._on_client_certified(term_id)
            # Send INIT_INFO_RESP (response, not just ACK)
            if not ack and not is_resp:
                # Try to extract the real sqnum from session-encrypted frame
                req_sqnum = self._extract_req_sqnum(data, addr)
                if req_sqnum is not None:
                    self.log(f"  [DEBUG] Extracted real sqnum={req_sqnum} from INIT_INFO")
                else:
                    # Fallback: predict sqnum
                    req_sqnum = self.state.addr_last_sqnum.get(addr, 0) + 1
                    self.log(f"  [DEBUG] Using predicted sqnum={req_sqnum} for INIT_INFO_RESP")
                resp = self._build_init_info_resp(data, addr, req_sqnum)
                self.log(f"  → INIT_INFO_RESP to {addr[0]}:{addr[1]} ({len(resp)}B) chkval={req_sqnum}")
                self.log(f"  [DEBUG] RESP hex: {resp[:24].hex()}")
                # Track for next prediction
                self.state.addr_last_sqnum[addr] = req_sqnum
                return resp
            return None

        # --- CALLING: log and handle wakeup routing ---
        elif ftype == TYPE_CALLING_REQ:
            self.log(f"← CALLING_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            self.log(f"  HEX: {self.hexdump(data, 256)}")
            mtp_resp = self._handle_calling(data, addr, term_id)
            if mtp_resp:
                return mtp_resp
            return None

        # --- SUBSCRIBE ---
        elif ftype == TYPE_SUBSCRIBE:
            self.log(f"← SUBSCRIBE from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if not ack and not is_resp:
                # Respond with SUBSCRIBE_RESP (opt_encrypt=0, opt_resp=1, bit25=1)
                # The subscribe sqnum = CERTIFY_sqnum + 3 (CERTIFY=N, INIT_INFO=N+1, ???=N+2, SUB=N+3)
                # We stored the INIT_INFO predicted sqnum (N+1), so subscribe = N+3 = stored + 2
                base_sqnum = self.state.addr_last_sqnum.get(addr, 0)
                predicted_sqnum = base_sqnum + 2  # INIT_INFO was +1, subscribe is +3 from CERTIFY
                self.log(f"  [DEBUG] SUBSCRIBE predicted_sqnum={predicted_sqnum} (base={base_sqnum})")
                resp = self._build_subscribe_resp(addr, predicted_sqnum)
                self.state.addr_last_sqnum[addr] = predicted_sqnum
                return resp
            return None

        # --- KEEPALIVE handling ---
        elif ftype == TYPE_KEEPALIVE:
            doorbell_ip = os.environ.get('DOORBELL_IP', '192.168.1.81')
            if ack:
                # ACK from a device (response to our keepalive)
                if term_id != 0 and term_id in self.state.clients:
                    client = self.state.clients[term_id]
                    if client.role == "doorbell" or addr[0] == doorbell_ip:
                        self.state.doorbell_last_ack = time.time()
                        self.state.keepalive_misses = 0
                        self.log(f"← KEEPALIVE_ACK from doorbell {addr[0]}:{addr[1]} "
                                f"term_id={term_id} — misses reset")
                        return None
                self.log(f"← KEEPALIVE_ACK from {addr[0]}:{addr[1]} term_id={term_id}")
                return None
            else:
                # KEEPALIVE request FROM device (device is sending keepalive TO us)
                # We must respond with a KEEPALIVE_ACK to keep the session alive
                self.log(f"← KEEPALIVE from {addr[0]}:{addr[1]} term_id={term_id}")
                # Update last_seen and track doorbell
                if addr[0] == doorbell_ip:
                    self.state.doorbell_last_ack = time.time()
                    self.state.keepalive_misses = 0
                    if not self.state.doorbell_term_id and term_id:
                        self.state.doorbell_term_id = term_id
                        self.log(f"  [ROLE] Doorbell identified via KEEPALIVE: term_id={term_id}")
                # Build a KEEPALIVE ACK response
                ack_resp = self._build_keepalive_ack(data, addr)
                if ack_resp:
                    return ack_resp
                return None

        # --- SESSION_CTL (0xB0) — subscribe/registration from devices ---
        elif ftype == TYPE_SESSION_CTL:
            self.log(f"← SESSION_CTL from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if not ack and not is_resp:
                # Respond with SESSION_CTL_RESP (type 0xB1) — success
                # Use same approach as SUBSCRIBE_RESP
                base_sqnum = self.state.addr_last_sqnum.get(addr, 0)
                predicted_sqnum = base_sqnum + 2
                resp = self._build_session_ctl_resp(data, addr, predicted_sqnum)
                if resp:
                    self.state.addr_last_sqnum[addr] = predicted_sqnum
                    self.log(f"  → SESSION_CTL_RESP to {addr[0]}:{addr[1]} ({len(resp)}B)")
                    return resp
            return None

        # --- All other frames ---
        else:
            self.log(f"← {type_name}{'_ACK' if ack else ''} from {addr[0]}:{addr[1]}:{our_port} "
                    f"term_id={term_id} ({frm_len}B) opt=0x{opt_flags:08x} enc={encrypt_mode}")
            if ftype not in (TYPE_KEEPALIVE,) or ack:  # Hex dump non-keepalive or keepalive ACKs
                self.log(f"  HEX: {self.hexdump(data, 256)}")
            return None

    def _handle_certify_local(self, data: bytes, addr: tuple, term_id: int) -> Optional[bytes]:
        """Handle CERTIFY in standalone relay mode.
        
        Performs the session key exchange:
        1. Parse client's 32-byte key contribution from CERTIFY_REQ payload
        2. Generate server's 32-byte random key
        3. Derive session key = client_key XOR server_key (Gwell SDK standard)
        4. Build CERTIFY_RESP (type 0x0D) with server key in payload
        5. Cache the derived session key
        
        CERTIFY_REQ payload (after per-frame decryption): session_id(8B) + client_key(32B)
        CERTIFY_RESP format: header(0x1C) + session_id(8B) + server_key(32B) + padding = ~80B
        """
        import random as _rand

        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        if self.is_ack(opt_flags):
            return None  # ACK from client, no response needed
        
        # --- Extract client key from CERTIFY_REQ payload ---
        encrypt_mode = (opt_flags >> 16) & 3  # 2 bits: 0=none, 1=per-frame, 2=session
        # Per-frame encryption starts at offset 0x18 (not HEADER_SIZE=0x1C!)
        # Frame layout: [0x00-0x17]=header, [0x18+]=encrypted payload
        payload = data[0x18:]
        self.log(f"  [DEBUG] Raw payload (first 48B): {payload[:48].hex()} encrypt_mode={encrypt_mode}")
        
        if encrypt_mode == 1:
            # Per-frame key decryption (opt_encrypt=1)
            pfk = derive_per_frame_key(data[:0x18])
            self.log(f"  [DEBUG] Per-frame key: {pfk.hex()}")
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            dec_len = (len(payload) // 8) * 8
            if dec_len > 0:
                payload = rc5.decrypt(bytes(payload[:dec_len]))
            self.log(f"  [DEBUG] Decrypted payload (first 48B): {payload[:48].hex()}")
        
        # Payload format after per-frame decrypt:
        #   payload[0:4] = flags2/ack_result
        #   payload[4:8] = hash checksum of session key (giot_hash_string)
        #   payload[8:40] = ENCRYPTED 32-byte session key (encrypted with certify RC5 key)
        if len(payload) < 40:
            self.log(f"  [RELAY] CERTIFY_REQ payload too short ({len(payload)}B), cannot extract client key")
            return None
        
        hash_checksum = struct.unpack_from('<I', payload, 4)[0]
        encrypted_session_key = payload[8:40]
        self.log(f"  [DEBUG] hash_checksum=0x{hash_checksum:08x} enc_key={encrypted_session_key.hex()}")
        
        # --- Decrypt the session key using the certify key ---
        # Certify key = access_token_bytes[0x30:0x40] (16 bytes)
        # RC5 with 16-byte blocks, 6 rounds
        session_key = self._decrypt_session_key(encrypted_session_key)
        if session_key:
            # Verify with hash
            computed_hash = self._giot_hash_string(session_key)
            if computed_hash == hash_checksum:
                self.log(f"  [RELAY] Session key VERIFIED! hash={hash_checksum:#x}")
            else:
                self.log(f"  [RELAY] Session key hash mismatch: computed={computed_hash:#x} expected={hash_checksum:#x}")
                # Still use it — hash mismatch might be due to additional transforms
        else:
            # Fallback: generate our own (won't match SDK's internal key)
            session_key = os.urandom(32)
            self.log(f"  [RELAY] Could not decrypt session key, using random (WILL NOT WORK for session frames)")
        
        # Use first 8 bytes of payload as client_session_id for response
        client_session_id = payload[0:8]
        self.log(f"  [RELAY] CERTIFY session_key={session_key[:8].hex()}... session_id={client_session_id.hex()}")
        
        # --- Session key is already decrypted from the CERTIFY_REQ above ---
        # No need to XOR with server_key — the SDK uses its own internal session key
        # which is the same 32 bytes it generated and encrypted in the CERTIFY_REQ.
        server_key = os.urandom(32)  # still needed for CERTIFY_RESP payload
        
        # Cache the REAL session key (by term_id AND by address)
        self.state.session_keys[term_id] = session_key
        self.state.addr_session_keys[addr] = session_key
        self._persist_session_key(term_id, session_key)
        self.log(f"  [RELAY] Cached REAL session_key={session_key[:8].hex()}... for term_id={term_id}")
        
        # Track doorbell's source port as its MTP port
        # The doorbell's GUTES source port IS the port it listens on for MTP
        role = self.identify_device_role(term_id, addr)
        if role == "doorbell" and addr[1] > 0:
            self.state.doorbell_mtp_port = addr[1]
            self.log(f"  [RELAY] Doorbell MTP port captured: {addr[1]} (from CERTIFY source port)")
        
        # Mark client as certified
        if term_id in self.state.clients:
            self.state.clients[term_id].certified = True
            self._on_client_certified(term_id)
        
        # --- Build CERTIFY_RESP (type 0x0D) ---
        # Use opt_encrypt=0, opt_resp=1 — simplest approach:
        # SDK skips decryption and chkval verification, just does response matching
        # on the plaintext chkval field = req_sqnum
        resp_len = 0x50  # 80 bytes
        resp = bytearray(resp_len)
        resp[0] = 0x7F
        resp[1] = TYPE_CERTIFY_RESP
        struct.pack_into('<H', resp, 2, resp_len)
        
        # Server term_id (plaintext — no encryption since opt_encrypt=0)
        sqnum = self._next_sqnum()
        # CRITICAL: chkval must = the REQUEST's sqnum for response matching
        req_sqnum = self._extract_req_sqnum(data)
        term_id_bytes = struct.pack('<q', self.server_term_id)
        resp[4:12] = term_id_bytes
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, req_sqnum)
        
        # opt_flags: encrypt=0, response=1, random nonce
        nonce = _rand.randint(0, 0x7FFF)
        resp_opt_flags = (nonce << 1) | (1 << 21)  # opt_resp=1, no encrypt
        struct.pack_into('<I', resp, 0x14, resp_opt_flags)
        
        # flags2 = 0x0001, ack_result = 0x0000
        struct.pack_into('<H', resp, 0x18, 0x0001)
        struct.pack_into('<H', resp, 0x1A, 0x0000)
        
        # Plaintext payload: session_id(8B) + server_key(32B) + padding(12B)
        resp[HEADER_SIZE:HEADER_SIZE+8] = client_session_id
        resp[HEADER_SIZE+8:HEADER_SIZE+40] = server_key
        # Remaining bytes stay zero
        
        # Store the session_id so INIT_INFO_RESP can use it as term_id
        self.state.addr_session_id[addr] = client_session_id
        
        self.log(f"  [RELAY] -> CERTIFY_RESP to {addr[0]}:{addr[1]} ({resp_len}B)")
        return bytes(resp)

    # ===== WAKEUP ROUTING INFRASTRUCTURE =====

    def _handle_calling(self, data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
        """Handle CALLING_REQ with full routing logic.
        
        In the real Mars relay, CALLING is routed by destination term_id
        (encrypted in the frame payload with opt_encrypt=2 session key).
        
        Relay mode routing:
        1. Try to decrypt payload to find destination term_id
        2. Route CALLING to doorbell if online
        3. Generate MTP_RES_RESP directing bridge to our local TCP relay
        
        Proxy mode: Mars handles routing, we just log and forward.
        
        Returns: MTP_RES_RESP bytes to send back to caller, or None.
        """
        if self.mode == "relay":
            # Try to determine destination from payload
            dest_term_id = self._extract_calling_dest(data, sender_term_id)
            
            # Determine target: explicit destination or heuristic
            target_term_id = dest_term_id
            if not target_term_id:
                # Heuristic: if sender is bridge, target is doorbell (and vice versa)
                if sender_term_id == self.state.bridge_term_id:
                    target_term_id = self.state.doorbell_term_id
                elif sender_term_id == self.state.doorbell_term_id:
                    target_term_id = self.state.bridge_term_id
            
            if target_term_id:
                target = self.state.clients.get(target_term_id)
                if target and (time.time() - target.last_seen) < 30:
                    # Target is online — route CALLING directly to it
                    self._route_calling_to(data, target, sender_term_id)
            else:
                # Target not connected — queue CALLING and trigger wakeup
                self.log(f"  [CALLING] Target offline (dest={target_term_id}) — queuing + wakeup")
                self.state.pending_callings.append(PendingWakeup(
                    calling_data=data,
                    bridge_term_id=sender_term_id,
                    timestamp=time.time(),
                    timeout=30.0
                ))
                self._trigger_chime_wakeup()
            
            # Generate MTP_RES_RESP to direct the bridge to our local TCP relay
            # This tells the SDK: "connect to our relay for media transport"
            # But first, send a CALLING ACK with the doorbell's address
            # (the SDK expects this before MTP_RES_RESP)
            calling_ack = self._build_calling_ack(data, addr, sender_term_id)
            mtp_resp = self._build_mtp_res_resp(data, addr, sender_term_id)
            if calling_ack and mtp_resp:
                self.log(f"  [MTP] Sending CALLING_ACK + MTP_RES_RESP to bridge {addr[0]}:{addr[1]}")
                # Return both concatenated — the recv loop will need to handle this
                # Actually we can't return two frames. Let me send the ACK via the socket
                # and return the MTP_RES_RESP
                self._extra_responses.append((calling_ack, addr))
                return mtp_resp
            elif mtp_resp:
                self.log(f"  [MTP] Sending MTP_RES_RESP to bridge {addr[0]}:{addr[1]}")
                return mtp_resp
            return None
        # In proxy mode: Mars handles routing, but log for awareness
        else:
            self.log(f"  [PROXY] CALLING forwarded to Mars for routing")
            return None

    def _extract_calling_dest(self, data: bytes, sender_term_id: int) -> int:
        """Try to extract destination term_id from CALLING payload.
        
        The CALLING_REQ payload is session-encrypted (opt_encrypt=2).
        If we have the sender's session key, we can decrypt to find
        the destination term_id (first 8 bytes of decrypted payload).
        """
        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        encrypt_mode = (opt_flags >> 16) & 3
        payload = data[0x18:]  # Encryption starts at 0x18
        
        if encrypt_mode != 2 or len(payload) < 8:
            return 0
        
        session_key = self.get_session_key(sender_term_id)
        if not session_key:
            # Try addr-based lookup (CALLING comes from same addr as CERTIFY)
            # We need to find which addr has this sender_term_id
            for a, sk in self.state.addr_session_keys.items():
                session_key = sk
                break  # Use first available session key (bridge usually only has one)
        if not session_key:
            self.log(f"  [CALLING] No session key for sender {sender_term_id}, cannot extract dest")
            return 0
        
        try:
            rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
            dec_len = (len(payload) // 8) * 8
            if dec_len < 8:
                return 0
            decrypted = rc5.decrypt(bytes(payload[:dec_len]))
            # First 8 bytes of CALLING payload = destination term_id (int64 LE)
            dest_id = struct.unpack_from('<q', decrypted, 0)[0]
            self.log(f"  [CALLING] Decrypted dest_term_id={dest_id}")
            return dest_id
        except Exception as e:
            self.log(f"  [CALLING] Decrypt failed: {e}")
            return 0

    def _route_calling_to(self, data: bytes, target: 'ClientSession', sender_term_id: int):
        """Route a CALLING frame directly to a connected target."""
        if target.tcp_writer:
            try:
                target.tcp_writer.write(data)
                self.log(f"  [CALLING] Routed to {target.addr[0]}:{target.addr[1]} (TCP) "
                        f"term_id={target.term_id}")
                target.frames_out += 1
            except Exception as e:
                self.log(f"  [CALLING] TCP route failed: {e}")
        elif target.our_port in self.relay_socks:
            try:
                self.relay_socks[target.our_port].sendto(data, target.addr)
                self.log(f"  [CALLING] Routed to {target.addr[0]}:{target.addr[1]}:{target.our_port} (UDP) "
                        f"term_id={target.term_id}")
                target.frames_out += 1
            except OSError as e:
                self.log(f"  [CALLING] UDP route failed: {e}")
        else:
            self.log(f"  [CALLING] No route to target term_id={target.term_id}")

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
        elif ip in (self.local_ip, "127.0.0.1", "192.168.5.1"):
            return "bridge"
        
        # Heuristic: if from the same subnet but not doorbell/chime, likely bridge
        return "unknown"
    def _persist_session_key(self, term_id: int, session_key: bytes):
        """Persist session key to JSON cache file."""
        try:
            self.session_cache_path.parent.mkdir(parents=True, exist_ok=True)
            # Load existing cache
            cache = {}
            if self.session_cache_path.exists():
                try:
                    cache = json.loads(self.session_cache_path.read_text())
                except (json.JSONDecodeError, OSError):
                    pass
            # Store key as hex string, keyed by term_id string
            cache[str(term_id)] = session_key.hex()
            self.session_cache_path.write_text(json.dumps(cache, indent=2))
        except OSError as e:
            self.log(f"  WARN: Failed to persist session key: {e}")

    def _capture_session_key_from_resp(self, data: bytes, term_id: int):
        """Extract and cache session key from a proxied CERTIFY_RESP.
        
        The CERTIFY_RESP payload (per-frame encrypted) contains:
          session_id(8B) + server_key(32B) + padding
        
        We need both client_key (from the original CERTIFY_REQ) and server_key
        to derive session_key = client_key XOR server_key.
        
        Since the payload is per-frame encrypted (opt_encrypt=1), we can decrypt
        it with the per-frame key derived from the response header.
        """
        if len(data) < HEADER_SIZE + 40:
            return
        
        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        encrypt_mode = (opt_flags >> 16) & 0xF
        payload = data[HEADER_SIZE:]
        
        if encrypt_mode == 1:
            # Decrypt with per-frame key
            pfk = derive_per_frame_key(data[:0x18])
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            dec_len = (len(payload) // 8) * 8
            if dec_len >= 40:
                payload = rc5.decrypt(bytes(payload[:dec_len]))
            else:
                return
        
        if len(payload) < 40:
            return
        
        # Extract server key from payload bytes 8:40
        server_key = payload[8:40]
        
        # We store the raw server_key; full session key derivation requires
        # client_key which we may not have captured. Store what we can.
        # If we have the full 32 bytes and they're not all zeros, cache it.
        if server_key != b'\x00' * 32:
            self.state.session_keys[term_id] = server_key
            self._persist_session_key(term_id, server_key)
            self.log(f"  [CACHE] Captured session key material from CERTIFY_RESP for term_id={term_id}")
            self.log(f"  [CACHE] server_key={server_key[:8].hex()}...")

    def get_session_key(self, term_id: int) -> Optional[bytes]:
        """Look up session key for a term_id.
        
        Checks in-memory cache first, then falls back to persistent JSON file.
        Returns the 32-byte session key or None if not found.
        """
        # Check in-memory cache
        if term_id in self.state.session_keys:
            return self.state.session_keys[term_id]
        
        # Fall back to persistent cache
        try:
            if self.session_cache_path.exists():
                cache = json.loads(self.session_cache_path.read_text())
                key_hex = cache.get(str(term_id))
                if key_hex:
                    key_bytes = bytes.fromhex(key_hex)
                    # Populate in-memory cache
                    self.state.session_keys[term_id] = key_bytes
                    return key_bytes
        except (json.JSONDecodeError, OSError, ValueError):
            pass
        
        return None

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
            self.state.doorbell_addr = client.addr
            self.state.keepalive_misses = 0
            self.log(f"  [ROLE] Identified DOORBELL: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
            if self.state.keepalive_enabled:
                self.log(f"  [KEEPALIVE] Doorbell connected — keepalive will begin to {client.addr[0]}:{client.addr[1]}")
            # Deliver any pending CALLINGs
            if self.state.pending_callings:
                self._deliver_pending_callings(term_id)
        elif role == "bridge":
            self.state.bridge_term_id = term_id
            self.log(f"  [ROLE] Identified BRIDGE: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")
        else:
            self.log(f"  [ROLE] Unknown device: term_id={term_id} addr={client.addr[0]}:{client.addr[1]}")

    def build_keepalive(self, target_addr: tuple) -> bytes:
        """Construct a KEEPALIVE frame (type 0x17) to send to the doorbell.

        Frame format (from pcap): header-only, no payload.
          [0]:    0x7F (protocol)
          [1]:    0x17 (TYPE_KEEPALIVE)
          [2:4]:  0x001C (frm_len = 28, header only)
          [4:12]: RC5-encrypted server term_id
          [0x0C:0x10]: sqnum (LE)
          [0x10:0x14]: chkval (LE)
          [0x14:0x18]: opt_flags with qos=1 (need-ack), bits[17:16]=0 (no encrypt)
          [0x18:0x1A]: flags2 = 0x0000
          [0x1A:0x1C]: ack_result = 0x0000
        """
        import random as _rand

        frame = bytearray(HEADER_SIZE)  # 0x1C = 28 bytes, header only
        frame[0] = 0x7F
        frame[1] = TYPE_KEEPALIVE
        struct.pack_into('<H', frame, 2, HEADER_SIZE)  # frm_len = 0x1C

        # Server identity
        sqnum = self._next_sqnum()
        chkval = self._make_server_chkval(sqnum)
        encrypted_id = self._encrypt_server_id(sqnum, chkval)
        frame[4:12] = encrypted_id
        struct.pack_into('<I', frame, 0x0C, sqnum)
        struct.pack_into('<I', frame, 0x10, chkval)

        # opt_flags: qos=1 (need-ack) is bit 18, random nonce in bits 1-15
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (1 << 18)  # qos=1
        struct.pack_into('<I', frame, 0x14, opt_flags)

        # flags2 and ack_result = 0
        struct.pack_into('<H', frame, 0x18, 0x0000)
        struct.pack_into('<H', frame, 0x1A, 0x0000)

        return bytes(frame)

    def _build_keepalive_ack(self, request_data: bytes, addr: tuple) -> Optional[bytes]:
        """Build a KEEPALIVE ACK in response to a device's KEEPALIVE.
        
        The ACK echoes the request's sqnum in the response's sqnum field,
        and sets opt_ack=1 (bit 20).
        """
        if len(request_data) < HEADER_SIZE:
            return None
        
        ack = bytearray(HEADER_SIZE)
        ack[0] = request_data[0]  # Same proto (0x7E or 0x7F)
        ack[1] = TYPE_KEEPALIVE
        struct.pack_into('<H', ack, 2, HEADER_SIZE)
        
        # Use our server term_id
        import random as _rand
        sqnum = struct.unpack_from('<I', request_data, 0x0C)[0]  # Echo request sqnum
        chkval = 0
        encrypted_id = self._encrypt_server_id(sqnum, chkval)
        ack[4:12] = encrypted_id
        struct.pack_into('<I', ack, 0x0C, sqnum)
        struct.pack_into('<I', ack, 0x10, chkval)
        
        # opt_flags: opt_ack=1 (bit 20), random nonce
        nonce = _rand.randint(0, 0x7FFF)
        opt_flags = (nonce << 1) | (1 << 20)  # opt_ack=1
        struct.pack_into('<I', ack, 0x14, opt_flags)
        
        # flags2 and ack_result = 0
        struct.pack_into('<H', ack, 0x18, 0x0000)
        struct.pack_into('<H', ack, 0x1A, 0x0000)
        
        return bytes(ack)

    async def _keepalive_loop(self):
        """Periodically send KEEPALIVE frames to the doorbell to prevent sleep.

        Runs every 25s (doorbell sleep timeout is ~30-45s). If 3 consecutive
        keepalives go unacknowledged, mark the doorbell as dormant.
        """
        INTERVAL = 25  # seconds
        MAX_MISSES = 3

        self.log(f"[KEEPALIVE] Loop started (interval={INTERVAL}s, max_misses={MAX_MISSES})")

        while True:
            await asyncio.sleep(INTERVAL)

            if not self.state.keepalive_enabled:
                continue

            # Need a known doorbell address to send to
            if self.state.doorbell_addr == ('', 0):
                continue

            target_addr = self.state.doorbell_addr

            # Build and send KEEPALIVE frame
            frame = self.build_keepalive(target_addr)

            # Find an appropriate socket to send from (prefer the port the doorbell uses)
            doorbell_client = self.state.clients.get(self.state.doorbell_term_id)
            send_port = doorbell_client.our_port if doorbell_client else self.listen_ports[0]
            sock = self.relay_socks.get(send_port) or next(iter(self.relay_socks.values()), None)

            if sock is None:
                self.log(f"[KEEPALIVE] No socket available to send keepalive")
                continue

            try:
                sock.sendto(frame, target_addr)
                self.state.keepalive_misses += 1
                self.log(f"→ KEEPALIVE to {target_addr[0]}:{target_addr[1]} "
                        f"(miss_count={self.state.keepalive_misses})")
            except OSError as e:
                self.log(f"[KEEPALIVE] Send error: {e}")
                self.state.keepalive_misses += 1

            # Check for dormant doorbell
            if self.state.keepalive_misses >= MAX_MISSES:
                self.log(f"[KEEPALIVE] WARNING: {MAX_MISSES} consecutive keepalives "
                        f"unacknowledged — doorbell is dormant")
                # Reset to avoid spamming warnings every cycle
                self.state.keepalive_misses = MAX_MISSES

    async def run(self):
        """Main entry point."""
        self.log(f"GUTES Relay v3 starting")
        self.log(f"  Mode: {self.mode.upper()}")
        self.log(f"  Local IP: {self.local_ip}")
        self.log(f"  Server term_id: {self.server_term_id}")
        self.log(f"  Relay ports: {self.listen_ports}")
        self.log(f"  List port: {self.list_port}")
        self.log(f"  MTP relay port: {self.mtp_port}")
        self.log(f"  Keepalive: {'ENABLED' if self.state.keepalive_enabled else 'disabled'}")
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

        # Keepalive loop (when enabled)
        if self.state.keepalive_enabled:
            tasks.append(asyncio.create_task(self._keepalive_loop()))

        # TCP signaling listener on port 28800 (relay mode - SDK falls back to TCP)
        if self.mode == "relay":
            for port in self.listen_ports:
                tasks.append(asyncio.create_task(self._tcp_signaling_listen(port)))

        # MTP TCP relay listener (relay mode)
        if self.mode == "relay":
            tasks.append(asyncio.create_task(self._mtp_tcp_listen()))

        # Broadcast listener on port 8900 — captures doorbell LAN announcements
        if self.mode == "relay":
            tasks.append(asyncio.create_task(self._broadcast_listen()))

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
                # Send any extra responses first (e.g., CALLING_ACK before MTP_RES_RESP)
                while self._extra_responses:
                    extra_data, extra_addr = self._extra_responses.pop(0)
                    try:
                        sock.sendto(extra_data, extra_addr)
                    except OSError as e:
                        self.log(f"  ERROR sending extra to {extra_addr}: {e}")
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
                
                opt = struct.unpack_from('<I', data, 0x14)[0] if len(data) >= 0x18 else 0
                self.log(f"  ← UPS {type_name} from {upstream_addr[0]}:{upstream_addr[1]} "
                        f"({len(data)}B) term_id={resp_term_id} opt=0x{opt:08x}")
                self.log(f"    UPS HEX: {self.hexdump(data, 256)}")
                
                # Rewrite LIST_RESP to replace server IPs with our local IP
                if ftype == TYPE_LIST_RESP:
                    self.log(f"    [LIST_RESP] Passing through unmodified ({len(data)}B)")
                    # TODO: rewrite IPs once format is confirmed working
                    # data = self._rewrite_list_resp(data)
                
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
        """Route frame to the appropriate peer (relay mode).
        
        Only routes to clients on DIFFERENT IPs to prevent echo-back to the same device.
        The SDK creates multiple ports from the same IP — routing back to those is harmful.
        """
        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        ftype = data[1] if len(data) > 1 else 0
        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
        
        # Only route to clients on a DIFFERENT IP (prevent echo to self)
        sender_ip = sender_addr[0]
        routed = False
        for tid, client in self.state.clients.items():
            if client.addr[0] != sender_ip:
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

    async def _tcp_signaling_listen(self, port: int):
        """TCP signaling server for relay mode.
        
        The SDK falls back to TCP when UDP CALLING times out.
        We handle GUTES frames over TCP the same way as UDP.
        """
        server = await asyncio.start_server(
            lambda r, w: self._tcp_signaling_handle(r, w, port),
            '0.0.0.0', port, reuse_address=True)
        self.log(f"  Listening on TCP :{port} (signaling)")
        async with server:
            await server.serve_forever()

    async def _tcp_signaling_handle(self, reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter, local_port: int):
        """Handle TCP signaling connection — same protocol as UDP but framed over TCP.
        
        GUTES over TCP: each frame is len-prefixed by the frm_len field at bytes [2:4].
        """
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else '127.0.0.1'
        peer_port = peer[1] if peer else 0
        tcp_addr = (peer_ip, peer_port)
        self.log(f"← TCP signaling connection from {peer_ip}:{peer_port} on port {local_port}")
        
        try:
            while True:
                # Read frame header (first 4 bytes: proto, type, len_lo, len_hi)
                hdr = await reader.readexactly(4)
                proto = hdr[0]
                ftype = hdr[1]
                frm_len = struct.unpack_from('<H', hdr, 2)[0]
                
                if frm_len < 4 or frm_len > 4096:
                    self.log(f"  TCP-SIG: Invalid frame len={frm_len}, closing")
                    break
                
                # Read the rest of the frame
                rest = await reader.readexactly(frm_len - 4)
                frame_data = hdr + rest
                
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                self.log(f"  TCP-SIG ← {type_name} ({frm_len}B) from {peer_ip}:{peer_port}")
                
                # Process through same handler as UDP
                resp = self.handle_packet(frame_data, tcp_addr, local_port)
                
                if resp:
                    writer.write(resp)
                    await writer.drain()
                    resp_type = resp[1] if len(resp) >= 2 else 0
                    resp_name = FRAME_TYPES.get(resp_type, f"0x{resp_type:02X}")
                    self.log(f"  TCP-SIG → {resp_name} ({len(resp)}B)")
                
                # Send any extra responses queued by handle_packet
                if hasattr(self, '_extra_responses') and self._extra_responses:
                    for extra_resp, _ in self._extra_responses:
                        writer.write(extra_resp)
                        await writer.drain()
                        if len(extra_resp) >= 2:
                            er_type = extra_resp[1]
                            er_name = FRAME_TYPES.get(er_type, f"0x{er_type:02X}")
                            self.log(f"  TCP-SIG → {er_name} ({len(extra_resp)}B) [extra]")
                    self._extra_responses.clear()
                    
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
            self.log(f"  TCP-SIG connection from {peer_ip}:{peer_port} closed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

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

    # ===== MTP TCP RELAY SERVER =====

    async def _mtp_tcp_listen(self):
        """Listen for MTP TCP connections from bridge and doorbell.
        
        After we send MTP_RES_RESP, the SDK connects to our mtp_port via TCP.
        The bridge connects first (it initiated the CALLING).
        The doorbell may connect later (after receiving the routed CALLING).
        
        We pair connections and forward MTP_DATA (0xCA) between them.
        """
        server = await asyncio.start_server(
            self._mtp_tcp_handle_client,
            '0.0.0.0', self.mtp_port, reuse_address=True)
        self.log(f"  [MTP] Listening on TCP :{self.mtp_port} (MTP relay)")
        async with server:
            await server.serve_forever()

    async def _mtp_tcp_handle_client(self, reader: asyncio.StreamReader,
                                      writer: asyncio.StreamWriter):
        """Handle an incoming MTP TCP connection.
        
        Connection identification strategy:
        - Read the first frame to determine the sender's identity
        - If from bridge IP → bridge side
        - If from doorbell IP → doorbell side
        - Pair bridge+doorbell and start bidirectional forwarding
        """
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else 'unknown'
        peer_port = peer[1] if peer else 0
        self.log(f"  [MTP] TCP connection from {peer_ip}:{peer_port}")
        
        # Create MTP connection object
        conn = MtpConnection(
            reader=reader,
            writer=writer,
            addr=(peer_ip, peer_port),
        )
        
        # Identify the role based on IP
        role = self._identify_mtp_role(peer_ip)
        conn.role = role
        self.log(f"  [MTP] Identified as: {role} (from {peer_ip}:{peer_port})")
        
        if role == "bridge":
            # Bridge connecting — try to pair with a waiting doorbell
            paired = self._mtp_try_pair_bridge(conn)
            if paired:
                await self._mtp_relay_loop(paired)
            else:
                # No doorbell yet — wait for one
                self.state.mtp_pending_bridges.append(conn)
                self.log(f"  [MTP] Bridge queued, waiting for doorbell connection...")
                # Wait up to 30s for doorbell to connect
                paired = await self._mtp_wait_for_pair(conn, "bridge")
                if paired:
                    await self._mtp_relay_loop(paired)
                else:
                    self.log(f"  [MTP] Bridge connection timed out waiting for doorbell")
                    writer.close()
        elif role == "doorbell":
            # Doorbell connecting — try to pair with a waiting bridge
            paired = self._mtp_try_pair_doorbell(conn)
            if paired:
                await self._mtp_relay_loop(paired)
            else:
                # No bridge yet — wait for one
                self.state.mtp_pending_doorbells.append(conn)
                self.log(f"  [MTP] Doorbell queued, waiting for bridge connection...")
                paired = await self._mtp_wait_for_pair(conn, "doorbell")
                if paired:
                    await self._mtp_relay_loop(paired)
                else:
                    self.log(f"  [MTP] Doorbell connection timed out waiting for bridge")
                    writer.close()
        else:
            # Unknown — read first frame to try to identify
            self.log(f"  [MTP] Unknown role for {peer_ip}:{peer_port}, "
                    f"reading first frame to identify...")
            try:
                first_data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
                if first_data:
                    conn.role = self._identify_mtp_role_from_frame(first_data, peer_ip)
                    self.log(f"  [MTP] Re-identified as: {conn.role} from first frame")
                    # Try pairing again
                    if conn.role == "bridge":
                        self.state.mtp_pending_bridges.append(conn)
                    else:
                        self.state.mtp_pending_doorbells.append(conn)
                    paired = await self._mtp_wait_for_pair(conn, conn.role)
                    if paired:
                        # Send the buffered first_data to the peer
                        if conn.role == "bridge" and paired.doorbell:
                            paired.doorbell.writer.write(first_data)
                        elif conn.role == "doorbell" and paired.bridge:
                            paired.bridge.writer.write(first_data)
                        await self._mtp_relay_loop(paired)
                    else:
                        writer.close()
                else:
                    writer.close()
            except (asyncio.TimeoutError, ConnectionError):
                self.log(f"  [MTP] Connection from {peer_ip}:{peer_port} failed/timed out")
                writer.close()

    def _identify_mtp_role(self, ip: str) -> str:
        """Identify whether an MTP TCP connection is from bridge or doorbell."""
        # Check against known client IPs
        for tid, client in self.state.clients.items():
            if client.addr[0] == ip:
                if client.role in ("bridge", "doorbell"):
                    return client.role
        
        # Direct IP heuristics
        if ip in ("192.168.1.245", "192.168.1.236", "127.0.0.1", "192.168.5.1"):
            return "bridge"
        elif ip == "192.168.1.81":
            return "doorbell"
        
        # If bridge is local (same machine), the IP might match local_ip
        if ip == self.local_ip or ip == "127.0.0.1":
            return "bridge"
        
        return "unknown"

    def _identify_mtp_role_from_frame(self, data: bytes, ip: str) -> str:
        """Try to identify role from the first MTP frame data."""
        if len(data) >= HEADER_SIZE:
            term_id = self.decode_term_id(data)
            if term_id == self.state.bridge_term_id:
                return "bridge"
            elif term_id == self.state.doorbell_term_id:
                return "doorbell"
        # Fallback: first connector is likely bridge (it initiated CALLING)
        return "bridge"

    def _mtp_try_pair_bridge(self, bridge_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Try to pair a bridge connection with a waiting doorbell."""
        if self.state.mtp_pending_doorbells:
            doorbell_conn = self.state.mtp_pending_doorbells.pop(0)
            pair = MtpRelayPair(
                link_id=self.state.mtp_link_counter,
                bridge=bridge_conn,
                doorbell=doorbell_conn,
                created=time.time(),
                active=True,
            )
            self.log(f"  [MTP] PAIRED: bridge {bridge_conn.addr} <-> doorbell {doorbell_conn.addr}")
            return pair
        return None

    def _mtp_try_pair_doorbell(self, doorbell_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Try to pair a doorbell connection with a waiting bridge."""
        if self.state.mtp_pending_bridges:
            bridge_conn = self.state.mtp_pending_bridges.pop(0)
            pair = MtpRelayPair(
                link_id=self.state.mtp_link_counter,
                bridge=bridge_conn,
                doorbell=doorbell_conn,
                created=time.time(),
                active=True,
            )
            self.log(f"  [MTP] PAIRED: bridge {bridge_conn.addr} <-> doorbell {doorbell_conn.addr}")
            return pair
        return None

    async def _mtp_wait_for_pair(self, conn: MtpConnection, role: str,
                                  timeout: float = 30.0) -> Optional[MtpRelayPair]:
        """Wait for the other side to connect and pair with us."""
        start = time.time()
        while (time.time() - start) < timeout:
            await asyncio.sleep(0.1)
            # Check if we've been paired (removed from pending list means paired)
            if role == "bridge" and conn not in self.state.mtp_pending_bridges:
                # We were paired by a doorbell connecting
                # Find the pair that has us
                for pair in self.state.mtp_pairs.values():
                    if pair.bridge is conn:
                        return pair
                # Also check — the doorbell handler may have created a pair directly
                # Check if there's a new pair with this bridge
                break
            elif role == "doorbell" and conn not in self.state.mtp_pending_doorbells:
                for pair in self.state.mtp_pairs.values():
                    if pair.doorbell is conn:
                        return pair
                break
            
            # Actively try to pair
            if role == "bridge" and self.state.mtp_pending_doorbells:
                doorbell_conn = self.state.mtp_pending_doorbells.pop(0)
                # Remove ourselves from pending
                if conn in self.state.mtp_pending_bridges:
                    self.state.mtp_pending_bridges.remove(conn)
                pair = MtpRelayPair(
                    link_id=self.state.mtp_link_counter,
                    bridge=conn,
                    doorbell=doorbell_conn,
                    created=time.time(),
                    active=True,
                )
                self.state.mtp_pairs[pair.link_id] = pair
                self.log(f"  [MTP] PAIRED (delayed): bridge {conn.addr} <-> doorbell {doorbell_conn.addr}")
                return pair
            elif role == "doorbell" and self.state.mtp_pending_bridges:
                bridge_conn = self.state.mtp_pending_bridges.pop(0)
                if conn in self.state.mtp_pending_doorbells:
                    self.state.mtp_pending_doorbells.remove(conn)
                pair = MtpRelayPair(
                    link_id=self.state.mtp_link_counter,
                    bridge=bridge_conn,
                    doorbell=conn,
                    created=time.time(),
                    active=True,
                )
                self.state.mtp_pairs[pair.link_id] = pair
                self.log(f"  [MTP] PAIRED (delayed): bridge {bridge_conn.addr} <-> doorbell {conn.addr}")
                return pair
        
        # Cleanup: remove from pending if still there
        if role == "bridge" and conn in self.state.mtp_pending_bridges:
            self.state.mtp_pending_bridges.remove(conn)
        elif role == "doorbell" and conn in self.state.mtp_pending_doorbells:
            self.state.mtp_pending_doorbells.remove(conn)
        return None

    async def _mtp_relay_loop(self, pair: MtpRelayPair):
        """Bidirectional relay between paired bridge and doorbell TCP connections.
        
        Forwards all data (including MTP_DATA frames, type 0xCA) between the two.
        """
        if not pair.bridge or not pair.doorbell:
            self.log(f"  [MTP] Cannot relay — incomplete pair (link_id={pair.link_id})")
            return
        
        pair.active = True
        bridge_r = pair.bridge.reader
        bridge_w = pair.bridge.writer
        doorbell_r = pair.doorbell.reader
        doorbell_w = pair.doorbell.writer
        
        self.log(f"  [MTP] RELAY ACTIVE: bridge {pair.bridge.addr} <-> doorbell {pair.doorbell.addr}")
        
        bytes_b2d = 0  # bridge -> doorbell
        bytes_d2b = 0  # doorbell -> bridge
        
        async def bridge_to_doorbell():
            nonlocal bytes_b2d
            try:
                while True:
                    data = await bridge_r.read(65536)
                    if not data:
                        break
                    doorbell_w.write(data)
                    await doorbell_w.drain()
                    bytes_b2d += len(data)
                    # Log first frame or periodically
                    if bytes_b2d == len(data) or bytes_b2d % (1024 * 1024) < len(data):
                        ftype = data[1] if len(data) >= 2 else 0
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        self.log(f"  [MTP] B→D: {type_name} ({len(data)}B) "
                                f"total={bytes_b2d}B")
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
        
        async def doorbell_to_bridge():
            nonlocal bytes_d2b
            try:
                while True:
                    data = await doorbell_r.read(65536)
                    if not data:
                        break
                    bridge_w.write(data)
                    await bridge_w.drain()
                    bytes_d2b += len(data)
                    if bytes_d2b == len(data) or bytes_d2b % (1024 * 1024) < len(data):
                        ftype = data[1] if len(data) >= 2 else 0
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        self.log(f"  [MTP] D→B: {type_name} ({len(data)}B) "
                                f"total={bytes_d2b}B")
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
        
        try:
            await asyncio.gather(bridge_to_doorbell(), doorbell_to_bridge())
        finally:
            pair.active = False
            self.log(f"  [MTP] RELAY CLOSED: link_id={pair.link_id} "
                    f"B→D={bytes_b2d}B D→B={bytes_d2b}B")
            # Cleanup
            try:
                bridge_w.close()
            except:
                pass
            try:
                doorbell_w.close()
            except:
                pass

    async def _broadcast_listen(self):
        """Listen on UDP port 8900 for doorbell LAN broadcast responses AND
        actively send broadcast probes to discover the doorbell.
        
        The doorbell sends type=0x03 broadcast frames on port 8900 when awake.
        These contain:
          - dst_id at offset 0x1C (8 bytes LE) — the doorbell's device ID
          - MTP port at offset 0x2C (2 bytes LE) — the port for video MTP sessions
          - MAC address at offset 0x3A (6 bytes)
        
        Active probing: sends broadcast probe to doorbell every 5 seconds.
        This runs BEFORE the bridge SDK starts, so we get the response
        before the SDK binds port 8900 and steals it.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        try:
            sock.bind(('0.0.0.0', 8900))
            self.log(f"  Broadcast listener on UDP :8900 (doorbell discovery)")
        except OSError as e:
            self.log(f"  WARN: Cannot bind broadcast port 8900 ({e})")
            return
        
        loop = asyncio.get_event_loop()
        doorbell_ip = os.environ.get('DOORBELL_IP', '')
        probe_interval = 5  # seconds between active probes
        last_probe = 0
        
        # Build a broadcast probe (type=0x02 = probe request, proto=0x70)
        probe = bytearray(28)
        probe[0] = 0x70  # broadcast proto
        probe[1] = 0x02  # probe request type
        struct.pack_into('<H', probe, 2, 28)  # frame length
        
        while True:
            try:
                now = asyncio.get_event_loop().time()
                
                # Send active probes to doorbell IP and broadcast
                if now - last_probe > probe_interval and self.state.doorbell_mtp_port == 0:
                    last_probe = now
                    try:
                        if doorbell_ip:
                            sock.sendto(bytes(probe), (doorbell_ip, 8899))
                        sock.sendto(bytes(probe), ('255.255.255.255', 8899))
                    except Exception:
                        pass  # Best effort
                
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
            except socket.timeout:
                await asyncio.sleep(0)
                continue
            except Exception:
                await asyncio.sleep(1)
                continue
            
            src_ip = addr[0]
            
            # Only process broadcast responses (proto=0x70, type=0x03)
            if len(data) < 0x2E or data[0] != 0x70 or data[1] != 0x03:
                if len(data) > 1 and data[0] == 0x70:
                    self.log(f"[BROADCAST:8900] frame: proto=0x{data[0]:02x} type=0x{data[1]:02x} "
                            f"({len(data)}B) from {src_ip}")
                continue
            
            # Extract device ID from offset 0x1C (8 bytes LE)
            dst_id = struct.unpack_from('<q', data, 0x1C)[0]
            
            # Extract MTP port from offset 0x2C (2 bytes LE)
            mtp_port = struct.unpack_from('<H', data, 0x2C)[0]
            
            # Extract MAC from offset 0x3A (6 bytes)
            mac = ':'.join(f'{b:02x}' for b in data[0x3A:0x40])
            
            # Update state
            if mtp_port > 0 and mtp_port != self.state.doorbell_mtp_port:
                self.log(f"[BROADCAST] Doorbell discovered: {src_ip} "
                        f"dst_id={dst_id} mtp_port={mtp_port} mac={mac}")
                self.state.doorbell_mtp_port = mtp_port
                self.state.doorbell_dst_id = dst_id
                
                # Also update DOORBELL_IP if not set
                if not doorbell_ip:
                    os.environ['DOORBELL_IP'] = src_ip
                    self.log(f"[BROADCAST] Auto-set DOORBELL_IP={src_ip}")

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
    parser.add_argument('--keepalive', action='store_true', default=False,
                       help='Enable periodic KEEPALIVE to doorbell to prevent sleep')
    parser.add_argument('--session-cache', default='cache/session_keys.json',
                       help='Path to persistent session key cache (default: cache/session_keys.json)')
    parser.add_argument('--mtp-port', type=int, default=23000,
                       help='TCP port for MTP relay server (default: 23000)')
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(',')]

    relay = GutesRelay(
        listen_ports=ports,
        list_port=args.list_port,
        mode=args.mode,
        upstream=args.upstream,
        log_file=args.log_file,
        local_ip=args.local_ip,
        keepalive=args.keepalive,
        session_cache=args.session_cache,
        mtp_port=args.mtp_port,
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
