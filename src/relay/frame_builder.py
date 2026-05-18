"""GUTES frame builder — constructs response frames for the relay protocol."""

import hashlib
import json
import os
import random as _rand
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_config import get_logger
log = get_logger('relay.frames')
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_encrypt
from constants import *
from models import RelayState
from session_crypto import (
    extract_request_sequence_number, verify_session_key,
    extract_calling_link_id, get_session_key,
)


def next_sqnum(relay) -> int:
    """Return and increment server sequence number."""
    sq = relay.server_sqnum
    relay.server_sqnum = (relay.server_sqnum + 1) & 0xFFFFFFFF
    return sq


def make_server_chkval(sqnum: int) -> int:
    """Generate a chkval for our server frames (simple hash of sqnum)."""
    h = hashlib.md5(struct.pack('<I', sqnum)).digest()
    return struct.unpack_from('<I', h)[0]


def encrypt_server_id(server_term_id: int, sqnum: int, chkval: int) -> bytes:
    """Encrypt a server term_id for a frame header."""
    return id_encrypt(
        struct.pack('<q', server_term_id),
        struct.pack('<I', chkval),
        struct.pack('<I', sqnum),
    )


def compute_chkval(frame: bytearray) -> int:
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


def build_detect_resp(relay, req_data: bytes) -> bytes:
    """Build DETECT_RESP that the SDK will accept.

    Key insight: The SDK dispatches responses via iv_gutes_on_rcvfrm_resp
    which matches pending requests by: pending_req.sqnum == response.chkval_field.
    
    So we need:
      - opt_resp=1 (bit 21 of opt_flags) to route through response matching
      - chkval field = the original DETECT_REQ's sqnum (extracted by decrypting)
    
    With opt_resp=1, the SDK skips chkval verification entirely and just
    uses the chkval field for request-response matching.
    """
    # Extract the request's sqnum by decrypting bytes 0x0C-0x13
    req_sqnum = extract_request_sequence_number(req_data)

    resp = bytearray(0x38)  # 56 bytes
    resp[0] = 0x7F
    resp[1] = TYPE_DETECT_RESP
    struct.pack_into('<H', resp, 2, 0x38)

    # Server's term_id (plaintext — no encryption since opt_encrypt=0)
    sqnum = next_sqnum(relay)
    term_id_bytes = struct.pack('<q', relay.server_term_id)
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
    uptime_ms = int((time.time() - relay.t0) * 1000) & 0xFFFFFFFF
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


def build_ack(relay, req_data: bytes, frame_type: int, addr: tuple = None) -> bytes:
    """Build a generic ACK frame for a reliable request.
    
    Detects whether the request uses session encryption (proto=0x7E, opt_encrypt=2)
    and builds the ACK accordingly.
    
    ACK format: header-only (0x1C bytes), same frame type.
    For session-encrypted: proto=0x7E, opt_encrypt=2, session-encrypted sqnum/chkval
    For unencrypted: proto=0x7F, opt_encrypt=0
    """
    state = relay.state
    req_sqnum = extract_request_sequence_number(req_data)
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
    term_id_bytes = struct.pack('<q', relay.server_term_id)
    ack[4:12] = term_id_bytes
    
    sqnum = next_sqnum(relay)
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
        session_key = state.addr_session_keys.get(addr) if addr else None
        if not session_key:
            # Fallback: try decoded term_id
            req_term_id = relay.decode_term_id(req_data)
            session_key = get_session_key(state, req_term_id, relay.session_cache_path)
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


def build_init_info_resp(relay, req_data: bytes, addr: tuple, req_sqnum: int) -> bytes:
    """Build INIT_INFO_RESP with session encryption (opt_encrypt=2).
    
    The chime firmware requires session-encrypted responses — opt_encrypt=0
    with bit25 bypass only works for the bridge SDK, not for device-side SDKs.
    
    Uses the same session encryption pattern as build_calling_ack:
    1. Build plaintext frame with payload
    2. Compute chkval
    3. Encrypt payload (0x18+) with session key
    4. Encrypt sqnum+chkval (0x0C-0x13) with session key
    5. Encrypt ID (0x04-0x0B) with GWELL_KEY + XOR with encrypted sqnum/chkval
    """
    state = relay.state
    
    # Get session key for this client
    session_key = state.addr_session_keys.get(addr)
    if not session_key:
        for a, sk in state.addr_session_keys.items():
            if a[0] == addr[0]:
                session_key = sk
                break
    
    # Build payload: flags2(2B) + ack_result(2B) + online_cnt(2B) + offline_cnt(2B) + device_entry(28B)
    device_id = getattr(relay, 'device_numeric_id', 429728659090583)
    
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
    resp[1] = TYPE_INIT_INFO_MSG  # 0xA6 — same as request, SDK matches via opt_resp
    struct.pack_into('<H', resp, 2, frame_size)
    
    # term_id — use session_id from CERTIFY
    session_id_bytes = state.addr_session_id.get(addr)
    if not session_id_bytes:
        for a, sid in state.addr_session_id.items():
            if a[0] == addr[0]:
                session_id_bytes = sid
                break
    if session_id_bytes and len(session_id_bytes) >= 8:
        resp[4:12] = session_id_bytes[:8]
    else:
        struct.pack_into('<q', resp, 4, relay.server_term_id)
    
    # sqnum = our own, chkval = request's plaintext sqnum (for response matching)
    sqnum = next_sqnum(relay)
    struct.pack_into('<I', resp, 0x0C, sqnum)
    struct.pack_into('<I', resp, 0x10, req_sqnum & 0xFFFFFFFF)
    
    # opt_flags: encrypt=2 (session), opt_resp=1 (bit 21), relay_flag=1 (bit 25)
    nonce = _rand.randint(0, 0x7FFF)
    opt_flags = (nonce << 1) | (2 << 16) | (1 << 21) | (1 << 25)
    struct.pack_into('<I', resp, 0x14, opt_flags)
    
    # Payload (plaintext)
    resp[CRYPTO_HDR:CRYPTO_HDR + len(payload)] = payload
    
    if session_key and verify_session_key(session_key, req_data):
        # Session key verified — use session encryption
        # chkval = req_sqnum for response matching (SDK matches pending_req.sqnum == resp.chkval)
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
        
        log.info(f"  [DEBUG] INIT_INFO_RESP session-encrypted with key={session_key[:8].hex()}...")
    else:
        # No session key — use opt_encrypt=0 fallback (works for bridge SDK)
        opt_flags = (1 << 21) | (1 << 25)  # opt_resp=1, bit25
        struct.pack_into('<I', resp, 0x14, opt_flags)
        log.info(f"  [DEBUG] INIT_INFO_RESP plaintext (no session key)")
    
    log.info(f"  [DEBUG] RESP hex: {resp[:24].hex()}")
    return bytes(resp)


def build_subscribe_resp(relay, addr: tuple, predicted_sqnum: int) -> bytes:
    """Build SUBSCRIBE_RESP (type=0xA1) with opt_encrypt=0, opt_resp=1, bit25=1.
    
    The SDK's gat_rcv_subscribe_dev_resp reads:
    - ack_result (frame offset 0x1A): 0 = success
    - error_code (frame offset 0x34): 0 = no error
    """
    state = relay.state
    payload_size = 0x34 - 0x18 + 2  # up to and including error_code field = 30 bytes
    payload = bytearray(payload_size)  # all zeros = success
    
    CRYPTO_HDR = 0x18
    frame_size = CRYPTO_HDR + payload_size
    resp = bytearray(frame_size)
    resp[0] = 0x7E  # Session protocol
    resp[1] = TYPE_SUBSCRIBE_RESP  # 0xA1
    struct.pack_into('<H', resp, 2, frame_size)
    
    # term_id = session_id from CERTIFY
    session_id_bytes = state.addr_session_id.get(addr)
    if session_id_bytes:
        resp[4:12] = session_id_bytes
    else:
        struct.pack_into('<q', resp, 4, relay.server_term_id)
    
    # sqnum and chkval = predicted request sqnum
    sqnum = next_sqnum(relay)
    struct.pack_into('<I', resp, 0x0C, sqnum)
    struct.pack_into('<I', resp, 0x10, predicted_sqnum & 0xFFFFFFFF)
    
    # opt_flags: opt_encrypt=0, opt_resp=1 (bit 21), relay_flag=1 (bit 25)
    opt_flags = (1 << 21) | (1 << 25)
    struct.pack_into('<I', resp, 0x14, opt_flags)
    
    # Payload (all zeros = success)
    resp[CRYPTO_HDR:] = payload
    
    log.info(f"  -> SUBSCRIBE_RESP to {addr[0]}:{addr[1]} ({frame_size}B) chkval={predicted_sqnum}")
    return bytes(resp)


def build_session_ctl_resp(relay, data: bytes, addr: tuple, predicted_sqnum: int) -> Optional[bytes]:
    """Build SESSION_CTL_RESP (type=0xB1) — success response.
    
    Same structure as SUBSCRIBE_RESP but with type 0xB1.
    """
    state = relay.state
    payload_size = 0x34 - 0x18 + 2  # 30 bytes
    payload = bytearray(payload_size)  # all zeros = success
    
    CRYPTO_HDR = 0x18
    frame_size = CRYPTO_HDR + payload_size
    resp = bytearray(frame_size)
    resp[0] = 0x7E  # Session protocol
    resp[1] = TYPE_SESSION_CTL_RESP  # 0xB1
    struct.pack_into('<H', resp, 2, frame_size)
    
    # term_id = session_id from CERTIFY
    session_id_bytes = state.addr_session_id.get(addr)
    if session_id_bytes:
        resp[4:12] = session_id_bytes
    else:
        struct.pack_into('<q', resp, 4, relay.server_term_id)
    
    sqnum = next_sqnum(relay)
    struct.pack_into('<I', resp, 0x0C, sqnum)
    struct.pack_into('<I', resp, 0x10, predicted_sqnum & 0xFFFFFFFF)
    
    # opt_flags: opt_encrypt=0, opt_resp=1 (bit 21), relay_flag=1 (bit 25)
    opt_flags = (1 << 21) | (1 << 25)
    struct.pack_into('<I', resp, 0x14, opt_flags)
    
    # Payload (all zeros = success)
    resp[CRYPTO_HDR:] = payload
    
    return bytes(resp)


def build_calling_ack(relay, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
    """Build session-encrypted CALLING ACK with doorbell's network address.
    
    CRITICAL DISCOVERY: iv_gutes_frm_decrypt IS called before iv_gutes_on_rcvfrm_ack!
    All incoming frames (except DETECT_RESP) are decrypted at line 18053 in iv_gutes_on_rcvpkt.
    
    For opt_encrypt=0 with opt_ack=1 (opt_resp=0): SDK validates chkval -> FAILS (our chkval=0).
    Real Mars uses opt_encrypt=2 (session) for the ACK. After SDK decrypts, it reads plaintext sqnum.
    
    ACK matching (after decryption): stored_req_sqnum == decrypted_ack_frame[0x0C]
    Callback iv_on_ackfrm_Calling reads decrypted payload at frame offsets 0x18, 0x20, 0x24.
    """
    state = relay.state
    # Get session key
    session_key = state.addr_session_keys.get(addr)
    if not session_key:
        for a, sk in state.addr_session_keys.items():
            if a[0] == addr[0]:
                session_key = sk
                break
    if not session_key:
        log.info(f"  [MTP] No session key for CALLING_ACK")
        return None
    
    # Get certify key for ID encryption
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'cache', 'auth.json')) as f:
            auth_data = json.load(f)
        token = auth_data['mars_access_token']
        try:
            token_bytes = bytes.fromhex(token[:128])
        except (ValueError, IndexError):
            import base64 as _b64
            token_bytes = _b64.b64decode(token)
        certify_key = token_bytes[0x30:0x40]
    except Exception:
        certify_key = session_key[:16]
    
    doorbell_ip_str = os.environ.get('DOORBELL_IP', '192.168.1.81')
    doorbell_port = 8899
    
    # Extract request's plaintext sqnum
    req_sqnum = extract_request_sequence_number(calling_data, addr, state)
    log.info(f"  [MTP] CALLING req_sqnum={req_sqnum} (for ACK matching)")
    
    # Build ACK frame — must be multiple of 8 bytes for encryption
    payload_size = 16  # padded to 8-byte multiple
    frame_size = 0x18 + payload_size  # 24 + 16 = 40 bytes
    resp = bytearray(frame_size)
    resp[0] = 0x7E  # session proto
    resp[1] = 0xA4  # Same type as request
    struct.pack_into('<H', resp, 2, frame_size)
    
    # term_id (plaintext, will be encrypted with certify key)
    session_id_bytes = state.addr_session_id.get(addr)
    if not session_id_bytes:
        for a, sid in state.addr_session_id.items():
            if a[0] == addr[0]:
                session_id_bytes = sid
                break
    if session_id_bytes and len(session_id_bytes) >= 8:
        resp[4:12] = session_id_bytes[:8]
    else:
        struct.pack_into('<q', resp, 4, relay.server_term_id)
    
    # sqnum = request's plaintext sqnum (will match after SDK decrypts)
    struct.pack_into('<I', resp, 0x0C, req_sqnum)
    # chkval will be computed below
    
    # opt_flags: encrypt=2 (session), opt_ack=1 (bit 20), relay_flag=1 (bit 25)
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
    chkval = compute_chkval(resp)
    struct.pack_into('<I', resp, 0x10, chkval)
    
    # --- Session encrypt ---
    rc5_session = RC5(block_bytes=8, rounds=6)
    rc5_session.setkey(session_key)
    
    # 1. Encrypt payload (0x18 to end)
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
    
    log.info(f"  [MTP] Built CALLING_ACK (session-enc): doorbell={doorbell_ip_str}:{doorbell_port} "
             f"req_sqnum={req_sqnum} frame_size={frame_size}")
    return bytes(resp)


def build_mtp_res_resp(relay, calling_data: bytes, addr: tuple, sender_term_id: int) -> Optional[bytes]:
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
    state = relay.state
    
    # Extract link_id from CALLING_REQ
    link_id = extract_calling_link_id(calling_data, addr, state)
    if link_id is None:
        log.info(f"  [MTP] Cannot extract link_id from CALLING, using counter")
        link_id = state.mtp_link_counter
        state.mtp_link_counter += 1
    
    doorbell_ip = os.environ.get('DOORBELL_IP', '192.168.1.81')
    doorbell_port = state.doorbell_mtp_port or int(os.environ.get('DOORBELL_PORT', '8899'))
    if state.doorbell_mtp_port:
        log.info(f"  [MTP] Using broadcast-discovered port {doorbell_port}")
    else:
        log.info(f"  [MTP] No broadcast port discovered, using fallback {doorbell_port}")
    
    # Build the frame — needs to be at least 0x7A bytes (122)
    CRYPTO_HDR = 0x18
    frame_size = 0x7A  # 122 bytes: header + payload up to relay counts
    resp = bytearray(frame_size)
    
    # --- Header ---
    resp[0] = 0x7E  # Session protocol
    resp[1] = 0xA3  # MTP_RES_RESP
    struct.pack_into('<H', resp, 2, frame_size)
    
    # term_id = session_id from CERTIFY
    session_id_bytes = state.addr_session_id.get(addr)
    if session_id_bytes:
        resp[4:12] = session_id_bytes
    else:
        struct.pack_into('<q', resp, 4, relay.server_term_id)
    
    # sqnum and chkval
    sqnum = next_sqnum(relay)
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
    resp[0x32] = 0x01
    struct.pack_into('>H', resp, 0x34, 0)  # SDK fills this
    struct.pack_into('>H', resp, 0x36, 0)
    struct.pack_into('>H', resp, 0x3A, 0)
    bridge_ip_bytes = socket.inet_aton(relay.local_ip)
    resp[0x3C:0x40] = bridge_ip_bytes
    resp[0x40:0x44] = bridge_ip_bytes
    
    # --- Called peer block (frame[0x56]-[0x78]) ---
    resp[0x56] = 0x01
    
    doorbell_ip_bytes = socket.inet_aton(doorbell_ip)
    fake_outer = socket.inet_aton('1.2.3.4')
    
    struct.pack_into('>H', resp, 0x58, doorbell_port)
    struct.pack_into('>H', resp, 0x5A, doorbell_port)
    struct.pack_into('>H', resp, 0x5C, 0)
    struct.pack_into('>H', resp, 0x5E, doorbell_port)
    
    resp[0x60:0x64] = fake_outer
    resp[0x64:0x68] = doorbell_ip_bytes
    
    # --- Relay list ---
    resp[0x78] = 0
    resp[0x79] = 0
    
    # --- Compute chkval ---
    chkval = compute_chkval(resp)
    struct.pack_into('<I', resp, 0x10, chkval)
    
    log.info(f"  [MTP] Built MTP_RES_RESP: link_id={link_id} "
            f"doorbell_lan={doorbell_ip}:{doorbell_port} "
            f"v4_cnt=0 v6_cnt=0 (LAN-only, no relay servers) "
            f"({frame_size}B)")
    
    return bytes(resp)


def build_list_resp(relay, list_req_data: bytes, reply_ip: str = None) -> bytes:
    """Build LIST_RESP with our relay as the only server."""
    num_servers = 1
    payload_size = 4 + num_servers * 36
    frame_size = HEADER_SIZE + payload_size
    
    resp = bytearray(frame_size)
    resp[0] = 0x7F
    resp[1] = TYPE_LIST_RESP
    struct.pack_into('<H', resp, 2, frame_size)

    # Server term_id (plaintext)
    sqnum = next_sqnum(relay)
    term_id_bytes = struct.pack('<q', relay.server_term_id)
    resp[4:12] = term_id_bytes
    struct.pack_into('<I', resp, 0x0C, sqnum)
    
    # opt_flags: encrypt=0, resp=0, ack=0, reliable=0, random nonce
    nonce = _rand.randint(0, 0x7FFF)
    opt_flags = (nonce << 1)
    struct.pack_into('<I', resp, 0x14, opt_flags)
    
    # flags2 and ack_result
    struct.pack_into('<H', resp, 0x18, 0x0000)
    struct.pack_into('<H', resp, 0x1A, 0x0000)
    
    # --- Payload (starts at HEADER_SIZE = 0x1C) ---
    ip_bytes = socket.inet_aton(reply_ip or relay.local_ip)
    main_port = relay.listen_ports[0]  # 28800
    
    struct.pack_into('<H', resp, HEADER_SIZE, 60)
    resp[HEADER_SIZE + 2] = num_servers
    
    entry_off = HEADER_SIZE + 4
    resp[entry_off:entry_off+4] = ip_bytes
    struct.pack_into('>H', resp, entry_off + 24, main_port)
    struct.pack_into('>H', resp, entry_off + 26, main_port)
    struct.pack_into('>H', resp, entry_off + 28, main_port)
    struct.pack_into('>H', resp, entry_off + 30, main_port)
    
    # Compute chkval
    chk = opt_flags & 0x00FFFFFF
    chk ^= struct.unpack_from('<I', resp, 0)[0]
    chk ^= struct.unpack_from('<I', resp, 4)[0]
    chk ^= struct.unpack_from('<I', resp, 8)[0]
    chk ^= struct.unpack_from('<I', resp, 0xC)[0]
    for off in range(0x18, frame_size - 3, 4):
        chk ^= struct.unpack_from('<I', resp, off)[0]
    chk &= 0xFFFFFFFF
    struct.pack_into('<I', resp, 0x10, chk)
    
    return bytes(resp)


def build_keepalive(relay, target_addr: tuple) -> bytes:
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
    frame = bytearray(HEADER_SIZE)  # 0x1C = 28 bytes, header only
    frame[0] = 0x7F
    frame[1] = TYPE_KEEPALIVE
    struct.pack_into('<H', frame, 2, HEADER_SIZE)  # frm_len = 0x1C

    # Server identity
    sqnum = next_sqnum(relay)
    chkval = make_server_chkval(sqnum)
    encrypted_id = encrypt_server_id(relay.server_term_id, sqnum, chkval)
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


def build_keepalive_ack(relay, request_data: bytes, addr: tuple) -> Optional[bytes]:
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
    sqnum = struct.unpack_from('<I', request_data, 0x0C)[0]  # Echo request sqnum
    chkval = 0
    encrypted_id = encrypt_server_id(relay.server_term_id, sqnum, chkval)
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
