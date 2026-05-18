#!/usr/bin/env python3
"""GUTES protocol relay for local Wyze doorbell P2P signaling."""

import argparse
import asyncio
import hashlib
import os
import socket
import struct
import sys
import time
import json
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_config import get_logger
log = get_logger('relay')
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_decrypt, id_encrypt
from constants import *
from models import *
from session_crypto import (
    decrypt_session_key, giot_hash_string, extract_request_sequence_number,
    verify_session_key, extract_calling_link_id, persist_session_key,
    capture_session_key_from_response, get_session_key,
)
from frame_builder import (
    next_sqnum as _fb_next_sqnum,
    make_server_chkval as _fb_make_server_chkval,
    encrypt_server_id as _fb_encrypt_server_id,
    compute_chkval as _fb_compute_chkval,
    build_detect_resp as _fb_build_detect_resp,
    build_ack as _fb_build_ack,
    build_init_info_resp as _fb_build_init_info_resp,
    build_subscribe_resp as _fb_build_subscribe_resp,
    build_session_ctl_resp as _fb_build_session_ctl_resp,
    build_calling_ack as _fb_build_calling_ack,
    build_mtp_res_resp as _fb_build_mtp_res_resp,
    build_list_resp as _fb_build_list_resp,
    build_keepalive as _fb_build_keepalive,
    build_keepalive_ack as _fb_build_keepalive_ack,
)
from mtp_relay import MtpRelay
from broadcast import broadcast_listen
from calling import (
    handle_calling as _calling_handle,
    identify_device_role as _calling_identify_role,
    on_client_certified as _calling_on_certified,
)


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

        # Extra responses to send before the main response (e.g., ACK before RESP)
        self._extra_responses: list[tuple[bytes, tuple]] = []

        # MTP relay subsystem
        self._mtp_relay = MtpRelay(self)

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
        log.info(msg)

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
        """Delegate to frame_builder.next_sqnum."""
        return _fb_next_sqnum(self)

    def _make_server_chkval(self, sqnum: int) -> int:
        """Delegate to frame_builder.make_server_chkval."""
        return _fb_make_server_chkval(sqnum)

    def _encrypt_server_id(self, sqnum: int, chkval: int) -> bytes:
        """Delegate to frame_builder.encrypt_server_id."""
        return _fb_encrypt_server_id(self.server_term_id, sqnum, chkval)

    def build_detect_resp(self, req_data: bytes) -> bytes:
        """Delegate to frame_builder.build_detect_resp."""
        return _fb_build_detect_resp(self, req_data)

    def _decrypt_session_key(self, encrypted_key: bytes) -> bytes:
        """Delegate to session_crypto.decrypt_session_key."""
        return decrypt_session_key(encrypted_key)
    
    def _giot_hash_string(self, data: bytes) -> int:
        """Delegate to session_crypto.giot_hash_string."""
        return giot_hash_string(data)

    def _extract_req_sqnum(self, req_data: bytes, addr: tuple = None) -> int:
        """Delegate to session_crypto.extract_request_sequence_number."""
        return extract_request_sequence_number(req_data, addr, self.state)

    def _build_ack(self, req_data: bytes, frame_type: int, addr: tuple = None) -> bytes:
        """Delegate to frame_builder.build_ack."""
        return _fb_build_ack(self, req_data, frame_type, addr)

    def _build_init_info_resp(self, req_data: bytes, addr: tuple, req_sqnum: int) -> bytes:
        """Delegate to frame_builder.build_init_info_resp."""
        return _fb_build_init_info_resp(self, req_data, addr, req_sqnum)

    def _verify_session_key_valid(self, session_key: bytes, req_data: bytes) -> bool:
        """Delegate to session_crypto.verify_session_key."""
        return verify_session_key(session_key, req_data)

    def _build_subscribe_resp(self, addr: tuple, predicted_sqnum: int) -> bytes:
        """Delegate to frame_builder.build_subscribe_resp."""
        return _fb_build_subscribe_resp(self, addr, predicted_sqnum)

    def _build_session_ctl_resp(self, data: bytes, addr: tuple, predicted_sqnum: int) -> Optional[bytes]:
        """Delegate to frame_builder.build_session_ctl_resp."""
        return _fb_build_session_ctl_resp(self, data, addr, predicted_sqnum)

    def _build_calling_ack(self, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
        """Delegate to frame_builder.build_calling_ack."""
        return _fb_build_calling_ack(self, calling_data, addr, sender_term_id)

    def _build_mtp_res_resp(self, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
        """Delegate to frame_builder.build_mtp_res_resp."""
        return _fb_build_mtp_res_resp(self, calling_data, addr, sender_term_id)

    def _compute_chkval(self, frame: bytearray) -> int:
        """Delegate to frame_builder.compute_chkval."""
        return _fb_compute_chkval(frame)

    def _extract_calling_link_id(self, data: bytes, addr: tuple) -> Optional[int]:
        """Delegate to session_crypto.extract_calling_link_id."""
        return extract_calling_link_id(data, addr, self.state)

    def build_list_resp(self, list_req_data: bytes, reply_ip: str = None) -> bytes:
        """Delegate to frame_builder.build_list_resp."""
        return _fb_build_list_resp(self, list_req_data, reply_ip)

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
                _calling_on_certified(self, term_id)
            # In proxy mode, capture session key material before forwarding
            if self.mode == "proxy":
                self._capture_session_key_from_resp(data, term_id)
            return None  # proxy: forward to client

        # --- INIT_INFO ---
        elif ftype == TYPE_INIT_INFO_MSG:
            self.log(f"← INIT_INFO{'_ACK' if ack else ''} from {addr[0]}:{addr[1]} term_id={term_id}")
            if term_id in self.state.clients:
                self.state.clients[term_id].certified = True
                _calling_on_certified(self, term_id)
            if not ack and not is_resp:
                has_session_key = addr in self.state.addr_session_keys
                if has_session_key:
                    req_sqnum = self._extract_req_sqnum(data, addr)
                    self.log(f"  [DEBUG] Extracted real sqnum={req_sqnum} from INIT_INFO")
                    resp = self._build_init_info_resp(data, addr, req_sqnum)
                    self.log(f"  → INIT_INFO_RESP to {addr[0]}:{addr[1]} ({len(resp)}B) chkval={req_sqnum}")
                    self.state.addr_last_sqnum[addr] = req_sqnum
                    return resp
                else:
                    # No session key — proxy INIT_INFO to Mars too
                    mars_resp = self._proxy_frame_to_mars(data, "INIT_INFO")
                    if mars_resp:
                        self.log(f"  [MARS-PROXY] → INIT_INFO_RESP from Mars ({len(mars_resp)}B)")
                        return mars_resp
                    # Fallback to predicted sqnum
                    base = self.state.addr_last_sqnum.get(addr, 0)
                    req_sqnum = (base + 1) & 0xFFFFFFFF
                    self.log(f"  [DEBUG] Predicted sqnum={req_sqnum} (no session key)")
                    resp = self._build_init_info_resp(data, addr, req_sqnum)
                    self.state.addr_last_sqnum[addr] = req_sqnum
                    return resp
            return None

        # --- CALLING: log and handle wakeup routing ---
        elif ftype == TYPE_CALLING_REQ:
            self.log(f"← CALLING_REQ from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            self.log(f"  HEX: {self.hexdump(data, 256)}")
            mtp_resp = _calling_handle(self, data, addr, term_id)
            if mtp_resp:
                return mtp_resp
            return None

        # --- SUBSCRIBE ---
        elif ftype == TYPE_SUBSCRIBE:
            self.log(f"← SUBSCRIBE from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if not ack and not is_resp:
                base_sqnum = self.state.addr_last_sqnum.get(addr, 0)
                predicted_sqnum = base_sqnum + 2
                self.log(f"  [DEBUG] SUBSCRIBE predicted_sqnum={predicted_sqnum} (base={base_sqnum})")
                resp = self._build_subscribe_resp(addr, predicted_sqnum)
                self.state.addr_last_sqnum[addr] = predicted_sqnum
                return resp
            return None

        # --- KEEPALIVE handling ---
        elif ftype == TYPE_KEEPALIVE:
            doorbell_ip = os.environ.get('DOORBELL_IP', '192.168.1.81')
            if ack:
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
                self.log(f"← KEEPALIVE from {addr[0]}:{addr[1]} term_id={term_id}")
                if addr[0] == doorbell_ip:
                    self.state.doorbell_last_ack = time.time()
                    self.state.keepalive_misses = 0
                    if not self.state.doorbell_term_id and term_id:
                        self.state.doorbell_term_id = term_id
                        self.log(f"  [ROLE] Doorbell identified via KEEPALIVE: term_id={term_id}")
                ack_resp = self._build_keepalive_ack(data, addr)
                if ack_resp:
                    return ack_resp
                return None

        # --- SESSION_CTL (0xB0) ---
        elif ftype == TYPE_SESSION_CTL:
            self.log(f"← SESSION_CTL from {addr[0]}:{addr[1]} term_id={term_id} ({frm_len}B)")
            if not ack and not is_resp:
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
            if ftype not in (TYPE_KEEPALIVE,) or ack:
                self.log(f"  HEX: {self.hexdump(data, 256)}")
            return None

    def _proxy_certify_to_mars(self, data: bytes, term_id: int, client_addr: tuple) -> Optional[bytes]:
        """Proxy CERTIFY_REQ to real Mars, capture session key from response.
        
        Used when we can't decrypt the session key locally (RC5 16-byte block issue).
        Sends the client's CERTIFY_REQ to Mars, waits for CERTIFY_RESP, extracts
        the session key material, caches it, and returns the Mars response to the client.
        """
        # Resolve a Mars server to proxy to
        mars_host = self.upstream_host
        mars_port = self.upstream_port
        if mars_host in ("127.0.0.1", "0.0.0.0", ""):
            # P2P_URL points at us — resolve real Mars from DNS
            try:
                results = socket.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, socket.AF_INET)
                if results:
                    mars_host = results[0][4][0]
                    mars_port = 28800
                    self.log(f"  [MARS-PROXY] Resolved Mars: {mars_host}:{mars_port}")
            except Exception as e:
                self.log(f"  [MARS-PROXY] DNS resolution failed: {e}")
                return None
        
        self.log(f"  [MARS-PROXY] Forwarding CERTIFY_REQ to {mars_host}:{mars_port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(data, (mars_host, mars_port))
            
            # Wait for CERTIFY_RESP (and possibly CERTIFY_ACK first)
            resp_data = None
            for _ in range(10):  # up to 10 packets within timeout
                try:
                    pkt, from_addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(pkt) < 4:
                    continue
                ftype = pkt[1]
                if ftype == TYPE_CERTIFY_RESP:
                    resp_data = pkt
                    self.log(f"  [MARS-PROXY] Got CERTIFY_RESP from Mars ({len(pkt)}B)")
                    break
                elif ftype == TYPE_CERTIFY_REQ and self.is_ack(struct.unpack_from('<I', pkt, 0x14)[0]):
                    # CERTIFY_ACK — forward to client but keep waiting for RESP
                    self.log(f"  [MARS-PROXY] Got CERTIFY_ACK from Mars, forwarding")
                    # Queue the ACK to send to client
                    self._extra_responses.append((pkt, client_addr))
            
            sock.close()
            
            if not resp_data:
                self.log(f"  [MARS-PROXY] No CERTIFY_RESP from Mars (timeout)")
                return None
            
            # Extract session key from the CERTIFY_RESP
            # Mars's response contains server_key in payload[8:40] (per-frame encrypted)
            self._capture_session_key_from_resp(resp_data, term_id)
            
            # Also need the client's key to derive the full session key
            # The client_key was in the CERTIFY_REQ payload (already extracted above)
            # Re-extract it from the original data
            opt_flags = struct.unpack_from('<I', data, 0x14)[0]
            encrypt_mode = (opt_flags >> 16) & 3
            payload = data[0x18:]
            if encrypt_mode == 1:
                pfk = derive_per_frame_key(data[:0x18])
                rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
                dec_len = (len(payload) // 8) * 8
                if dec_len > 0:
                    payload = rc5.decrypt(bytes(payload[:dec_len]))
            
            if len(payload) >= 40:
                client_session_id = payload[0:8]
                encrypted_client_key = payload[8:40]
                
                # Extract server_key from Mars CERTIFY_RESP
                resp_opt = struct.unpack_from('<I', resp_data, 0x14)[0]
                resp_enc = (resp_opt >> 16) & 3
                resp_payload = resp_data[0x18:]
                if resp_enc == 1:
                    pfk_resp = derive_per_frame_key(resp_data[:0x18])
                    rc5_resp = RC5(block_bytes=8, rounds=6).setkey(pfk_resp)
                    dec_len_resp = (len(resp_payload) // 8) * 8
                    if dec_len_resp > 0:
                        resp_payload = rc5_resp.decrypt(bytes(resp_payload[:dec_len_resp]))
                
                if len(resp_payload) >= 40:
                    server_key_from_mars = resp_payload[8:40]
                    self.log(f"  [MARS-PROXY] Mars server_key={server_key_from_mars[:8].hex()}...")
                    
                    # The real session key = we can't compute it without decrypting
                    # the client's key. But the SDK and Mars both know it.
                    # Store the server_key_from_mars so we can try to derive later.
                    # For now, store what we captured.
                    
                    # Cache session_id for this client
                    self.state.addr_session_id[client_addr] = client_session_id
                    
                    # Mark client as certified
                    if term_id in self.state.clients:
                        self.state.clients[term_id].certified = True
                        _calling_on_certified(self, term_id)
            
            self.log(f"  [MARS-PROXY] Returning Mars CERTIFY_RESP to client")
            return resp_data
            
        except Exception as e:
            self.log(f"  [MARS-PROXY] Error: {e}")
            return None

    def _proxy_frame_to_mars(self, data: bytes, frame_name: str) -> Optional[bytes]:
        """Proxy a single frame to Mars and return the first response."""
        mars_host = self.upstream_host
        mars_port = self.upstream_port
        if mars_host in ("127.0.0.1", "0.0.0.0", ""):
            try:
                results = socket.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, socket.AF_INET)
                if results:
                    mars_host = results[0][4][0]
                    mars_port = 28800
            except Exception:
                return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(data, (mars_host, mars_port))
            self.log(f"  [MARS-PROXY] Forwarding {frame_name} to {mars_host}:{mars_port}")

            for _ in range(10):
                try:
                    pkt, _ = sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(pkt) < 4:
                    continue
                pkt_type = pkt[1]
                pkt_opt = struct.unpack_from('<I', pkt, 0x14)[0] if len(pkt) >= 0x18 else 0
                is_resp_pkt = bool(pkt_opt & (1 << 21))
                is_ack_pkt = bool(pkt_opt & (1 << 20))
                if is_resp_pkt or (not is_ack_pkt and pkt_type != data[1]):
                    self.log(f"  [MARS-PROXY] Got {frame_name} response from Mars ({len(pkt)}B)")
                    sock.close()
                    return pkt
                # ACKs are intermediate — keep waiting
            sock.close()
        except Exception as e:
            self.log(f"  [MARS-PROXY] Error proxying {frame_name}: {e}")
        return None

    def _handle_certify_local(self, data: bytes, addr: tuple, term_id: int) -> Optional[bytes]:
        """Handle CERTIFY in standalone relay mode.
        
        Performs the session key exchange:
        1. Parse client's 32-byte key contribution from CERTIFY_REQ payload
        2. Generate server's 32-byte random key
        3. Derive session key = client_key XOR server_key (Gwell SDK standard)
        4. Build CERTIFY_RESP (type 0x0D) with server key in payload
        5. Cache the derived session key
        """
        import random as _rand

        opt_flags = struct.unpack_from('<I', data, 0x14)[0]
        if self.is_ack(opt_flags):
            return None  # ACK from client, no response needed
        
        # --- Extract client key from CERTIFY_REQ payload ---
        encrypt_mode = (opt_flags >> 16) & 3
        payload = data[0x18:]
        self.log(f"  [DEBUG] Raw payload (first 48B): {payload[:48].hex()} encrypt_mode={encrypt_mode}")
        
        if encrypt_mode == 1:
            pfk = derive_per_frame_key(data[:0x18])
            self.log(f"  [DEBUG] Per-frame key: {pfk.hex()}")
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            dec_len = (len(payload) // 8) * 8
            if dec_len > 0:
                payload = rc5.decrypt(bytes(payload[:dec_len]))
            self.log(f"  [DEBUG] Decrypted payload (first 48B): {payload[:48].hex()}")
        
        if len(payload) < 40:
            self.log(f"  [RELAY] CERTIFY_REQ payload too short ({len(payload)}B), cannot extract client key")
            return None
        
        hash_checksum = struct.unpack_from('<I', payload, 4)[0]
        encrypted_session_key = payload[8:40]
        self.log(f"  [DEBUG] hash_checksum=0x{hash_checksum:08x} enc_key={encrypted_session_key.hex()}")
        
        session_key = self._decrypt_session_key(encrypted_session_key)
        hash_verified = False
        if session_key:
            computed_hash = self._giot_hash_string(session_key)
            if computed_hash == hash_checksum:
                self.log(f"  [RELAY] Session key VERIFIED! hash={hash_checksum:#x}")
                hash_verified = True
            else:
                self.log(f"  [RELAY] Session key hash mismatch: computed={computed_hash:#x} expected={hash_checksum:#x}")
                session_key = None
        
        client_session_id = payload[0:8]
        
        if session_key and hash_verified:
            # Correct session key — generate random server_key and XOR
            server_key = os.urandom(32)
            session_key = bytes(a ^ b for a, b in zip(session_key, server_key))
            self.state.session_keys[term_id] = session_key
            self.state.addr_session_keys[addr] = session_key
            self._persist_session_key(term_id, session_key)
            self.log(f"  [RELAY] Cached XOR'd session_key={session_key[:8].hex()}...")
        else:
            # Session key decryption failed — proxy CERTIFY to Mars to get the real key
            self.log(f"  [RELAY] Session key decryption failed, proxying CERTIFY to Mars...")
            mars_resp = self._proxy_certify_to_mars(data, term_id, addr)
            if mars_resp:
                return mars_resp
            # Mars proxy failed — use plaintext fallback
            server_key = bytes(32)
            self.log(f"  [RELAY] Mars proxy failed, using plaintext fallback")
        
        # Track doorbell's source port as its MTP port
        role = _calling_identify_role(self, term_id, addr)
        if role == "doorbell" and addr[1] > 0:
            self.state.doorbell_mtp_port = addr[1]
            self.log(f"  [RELAY] Doorbell MTP port captured: {addr[1]} (from CERTIFY source port)")
        
        # Mark client as certified
        if term_id in self.state.clients:
            self.state.clients[term_id].certified = True
            _calling_on_certified(self, term_id)
        
        # --- Build CERTIFY_RESP (type 0x0D) ---
        resp_len = 0x50  # 80 bytes
        resp = bytearray(resp_len)
        resp[0] = 0x7F
        resp[1] = TYPE_CERTIFY_RESP
        struct.pack_into('<H', resp, 2, resp_len)
        
        sqnum = self._next_sqnum()
        req_sqnum = self._extract_req_sqnum(data)
        term_id_bytes = struct.pack('<q', self.server_term_id)
        resp[4:12] = term_id_bytes
        struct.pack_into('<I', resp, 0x0C, sqnum)
        struct.pack_into('<I', resp, 0x10, req_sqnum)
        
        nonce = _rand.randint(0, 0x7FFF)
        resp_opt_flags = (nonce << 1) | (1 << 16) | (1 << 21)  # encrypt=1, resp=1
        struct.pack_into('<I', resp, 0x14, resp_opt_flags)
        
        struct.pack_into('<H', resp, 0x18, 0x0001)
        struct.pack_into('<H', resp, 0x1A, 0x0000)
        
        resp[HEADER_SIZE:HEADER_SIZE+8] = client_session_id
        resp[HEADER_SIZE+8:HEADER_SIZE+40] = server_key
        
        self.state.addr_session_id[addr] = client_session_id
        
        # Per-frame encrypt the CERTIFY_RESP payload (real Mars does this)
        pfk = derive_per_frame_key(bytes(resp[:0x18]))
        rc5_pf = RC5(block_bytes=8, rounds=6).setkey(pfk)
        payload_data = bytes(resp[0x18:])
        enc_payload = rc5_pf.encrypt(payload_data)
        resp[0x18:0x18+len(enc_payload)] = enc_payload
        
        # Per-frame encrypt sqnum+chkval (0x0C-0x13)
        enc_sqchk = rc5_pf.encrypt_block(bytes(resp[0x0C:0x14]))
        resp[0x0C:0x14] = enc_sqchk
        
        self.log(f"  [RELAY] -> CERTIFY_RESP to {addr[0]}:{addr[1]} ({resp_len}B) [per-frame encrypted]")
        return bytes(resp)

    def _persist_session_key(self, term_id: int, session_key: bytes):
        """Delegate to session_crypto.persist_session_key."""
        persist_session_key(self.session_cache_path, term_id, session_key)

    def _capture_session_key_from_resp(self, data: bytes, term_id: int):
        """Delegate to session_crypto.capture_session_key_from_response."""
        capture_session_key_from_response(self.state, data, term_id, self.session_cache_path)

    def get_session_key(self, term_id: int) -> Optional[bytes]:
        """Delegate to session_crypto.get_session_key."""
        return get_session_key(self.state, term_id, self.session_cache_path)

    def build_keepalive(self, target_addr: tuple) -> bytes:
        """Delegate to frame_builder.build_keepalive."""
        return _fb_build_keepalive(self, target_addr)

    def _build_keepalive_ack(self, request_data: bytes, addr: tuple) -> Optional[bytes]:
        """Delegate to frame_builder.build_keepalive_ack."""
        return _fb_build_keepalive_ack(self, request_data, addr)

    async def _keepalive_loop(self):
        """Periodically send KEEPALIVE frames to the doorbell to prevent sleep."""
        INTERVAL = 25
        MAX_MISSES = 3

        self.log(f"[KEEPALIVE] Loop started (interval={INTERVAL}s, max_misses={MAX_MISSES})")

        while True:
            await asyncio.sleep(INTERVAL)

            if not self.state.keepalive_enabled:
                continue

            if self.state.doorbell_addr == ('', 0):
                continue

            target_addr = self.state.doorbell_addr
            frame = self.build_keepalive(target_addr)

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

            if self.state.keepalive_misses >= MAX_MISSES:
                self.log(f"[KEEPALIVE] WARNING: {MAX_MISSES} consecutive keepalives "
                        f"unacknowledged — doorbell is dormant")
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
                sock.settimeout(1.0)
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
            tasks.append(asyncio.create_task(self._mtp_relay.tcp_listen()))

        # Broadcast listener on port 8900 — captures doorbell LAN announcements
        if self.mode == "relay":
            tasks.append(asyncio.create_task(broadcast_listen(self.state, self.local_ip)))

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
        
        upstream_sock = self.get_upstream_sock(term_id)
        
        fd = upstream_sock.fileno()
        self.upstream_to_client[fd] = (client_addr, client_port, client_sock, term_id)
        
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
        """Rewrite LIST_RESP to replace all server IPs with our local IP."""
        if len(data) < HEADER_SIZE + 8:
            return data
        
        try:
            pfk = derive_per_frame_key(data[:0x18])
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            payload = bytearray(data[HEADER_SIZE:])
            dec_len = (len(payload) // 8) * 8
            if dec_len == 0:
                return data
            decrypted = bytearray(rc5.decrypt(bytes(payload[:dec_len])))
            
            local_ip_bytes = socket.inet_aton(self.local_ip)
            replaced = 0
            
            for offset in range(0, dec_len - 3, 2):
                ip_candidate = decrypted[offset:offset+4]
                if (ip_candidate[0] not in (0, 10, 127, 192, 172, 255) and
                    ip_candidate != b'\x00\x00\x00\x00'):
                    if offset + 5 < dec_len:
                        port_val = struct.unpack_from('<H', decrypted, offset + 4)[0]
                        if port_val in (28800, 8443, 8000, 443, 51701):
                            old_ip = socket.inet_ntoa(bytes(ip_candidate))
                            decrypted[offset:offset+4] = local_ip_bytes
                            struct.pack_into('<H', decrypted, offset + 4, self.listen_ports[0])
                            replaced += 1
                            self.log(f"  [REWRITE] {old_ip}:{port_val} → {self.local_ip}:{self.listen_ports[0]}")
            
            if replaced > 0:
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
            for term_id, sock in list(self.upstream_socks.items()):
                try:
                    data, upstream_addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
                except (socket.timeout, BlockingIOError, OSError):
                    continue
                
                ftype = data[1] if len(data) > 1 else 0
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                resp_term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                
                opt = struct.unpack_from('<I', data, 0x14)[0] if len(data) >= 0x18 else 0
                self.log(f"  ← UPS {type_name} from {upstream_addr[0]}:{upstream_addr[1]} "
                        f"({len(data)}B) term_id={resp_term_id} opt=0x{opt:08x}")
                self.log(f"    UPS HEX: {self.hexdump(data, 256)}")
                
                if ftype == TYPE_LIST_RESP:
                    self.log(f"    [LIST_RESP] Passing through unmodified ({len(data)}B)")
                
                fd = sock.fileno()
                if fd in self.upstream_to_client:
                    client_addr, client_port, client_sock, _ = self.upstream_to_client[fd]
                    try:
                        client_sock.sendto(data, client_addr)
                        self.log(f"  → RELAY to {client_addr[0]}:{client_addr[1]}")
                    except OSError as e:
                        self.log(f"  ERROR relaying to client: {e}")
                elif resp_term_id in self.state.clients:
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
        """TCP signaling server for relay mode."""
        server = await asyncio.start_server(
            lambda r, w: self._tcp_signaling_handle(r, w, port),
            '0.0.0.0', port, reuse_address=True)
        self.log(f"  Listening on TCP :{port} (signaling)")
        async with server:
            await server.serve_forever()

    async def _tcp_signaling_handle(self, reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter, local_port: int):
        """Handle TCP signaling connection — same protocol as UDP but framed over TCP."""
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else '127.0.0.1'
        peer_port = peer[1] if peer else 0
        tcp_addr = (peer_ip, peer_port)
        self.log(f"← TCP signaling connection from {peer_ip}:{peer_port} on port {local_port}")
        
        try:
            while True:
                hdr = await reader.readexactly(4)
                proto = hdr[0]
                ftype = hdr[1]
                frm_len = struct.unpack_from('<H', hdr, 2)[0]
                
                if frm_len < 4 or frm_len > 4096:
                    self.log(f"  TCP-SIG: Invalid frame len={frm_len}, closing")
                    break
                
                rest = await reader.readexactly(frm_len - 4)
                frame_data = hdr + rest
                
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                self.log(f"  TCP-SIG ← {type_name} ({frm_len}B) from {peer_ip}:{peer_port}")
                
                resp = self.handle_packet(frame_data, tcp_addr, local_port)
                
                if resp:
                    writer.write(resp)
                    await writer.drain()
                    resp_type = resp[1] if len(resp) >= 2 else 0
                    resp_name = FRAME_TYPES.get(resp_type, f"0x{resp_type:02X}")
                    self.log(f"  TCP-SIG → {resp_name} ({len(resp)}B)")
                
                if self._extra_responses:
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
        
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port)
            self.log(f"  → TCP connected to upstream {self.upstream_host}:{self.upstream_port}")
        except Exception as e:
            self.log(f"  ERROR: Cannot connect to upstream: {e}")
            client_writer.close()
            return
        
        async def client_to_upstream():
            try:
                while True:
                    data = await client_reader.read(8192)
                    if not data:
                        break
                    if len(data) >= 2 and data[0] == 0x7F:
                        ftype = data[1]
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                        self.log(f"  TCP C→S {type_name} ({len(data)}B) term_id={term_id}")
                        if term_id != 0:
                            if term_id not in self.state.clients:
                                self.state.clients[term_id] = ClientSession(
                                    term_id=term_id, addr=client_addr, our_port=local_port)
                                self.log(f"  TCP NEW CLIENT: term_id={term_id} from {client_addr[0]}:{client_addr[1]}")
                            self.state.clients[term_id].last_seen = time.time()
                            self.state.clients[term_id].frames_in += 1
                            self.state.clients[term_id].tcp_writer = client_writer
                            if ftype == TYPE_CERTIFY_REQ and not self.is_ack(struct.unpack_from('<I', data, 0x14)[0]):
                                pass  # Wait for CERTIFY_RESP from server
                            elif ftype == TYPE_INIT_INFO_MSG:
                                self.state.clients[term_id].certified = True
                                _calling_on_certified(self, term_id)
                            elif ftype == TYPE_CALLING_REQ:
                                _calling_handle(self, data, client_addr, term_id)
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
                    if len(data) >= 2 and data[0] == 0x7F:
                        ftype = data[1]
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        term_id = self.decode_term_id(data) if len(data) >= HEADER_SIZE else 0
                        self.log(f"  TCP S→C {type_name} ({len(data)}B) term_id={term_id}")
                        if ftype == TYPE_CERTIFY_RESP and term_id != 0:
                            if term_id in self.state.clients:
                                self.state.clients[term_id].certified = True
                                _calling_on_certified(self, term_id)
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
    parser.add_argument('--keepalive', action='store_true', default=False,
                       help='Enable periodic KEEPALIVE to doorbell to prevent sleep')
    parser.add_argument('--session-cache', default='cache/session_keys.json',
                       help='Path to persistent session key cache (default: cache/session_keys.json)')
    parser.add_argument('--mtp-port', type=int, default=23000,
                       help='TCP port for MTP relay server (default: 23000)')
    args = parser.parse_args()

    if args.log_file and not os.environ.get('LOG_FILE'):
        import logging
        from log_config import BridgeFormatter
        fh = logging.FileHandler(args.log_file, mode='a')
        fh.setFormatter(BridgeFormatter('relay'))
        log.addHandler(fh)

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
        log.info("Relay stopped.")
        if relay.state.clients:
            log.info("Session summary (%d clients):", len(relay.state.clients))
            for tid, c in relay.state.clients.items():
                log.info("  %s: %s role=%s in=%d out=%d", tid, c.addr, c.role, c.frames_in, c.frames_out)


if __name__ == "__main__":
    main()
